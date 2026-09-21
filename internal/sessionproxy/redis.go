package sessionproxy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// RESP framing is bounded across nested aggregates. Values are forwarded
// unchanged and discarded after the corresponding reply.
func respRead(r *bufio.Reader, out *bytes.Buffer, depth int) error {
	if depth > 32 || out.Len() > maxFrame {
		return ErrProtocol
	}
	line, e := r.ReadSlice('\n')
	if e != nil {
		return e
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return ErrProtocol
	}
	if out.Len()+len(line) > maxFrame {
		return ErrProtocol
	}
	out.Write(line)
	kind := line[0]
	switch kind {
	case '+', '-', ':', ',', '(', '_', '#':
		return nil
	case '$', '!', '=':
		n, e := strconv.Atoi(string(line[1 : len(line)-2]))
		if e != nil || n < -1 || n > maxFrame-out.Len()-2 {
			return ErrProtocol
		}
		if n == -1 {
			return nil
		}
		data := make([]byte, n+2)
		if _, e = io.ReadFull(r, data); e != nil {
			return e
		}
		if !bytes.HasSuffix(data, []byte("\r\n")) {
			return ErrProtocol
		}
		out.Write(data)
		return nil
	case '*', '~', '>', '%', '|':
		n, e := strconv.Atoi(string(line[1 : len(line)-2]))
		if e != nil || n < -1 || n > 65536 {
			return ErrProtocol
		}
		if kind == '%' || kind == '|' {
			n *= 2
		}
		for i := 0; i < n; i++ {
			if e = respRead(r, out, depth+1); e != nil {
				return e
			}
		}
		if kind == '|' {
			return respRead(r, out, depth+1)
		}
		return nil
	}
	return ErrProtocol
}
func respFrame(r *bufio.Reader) ([]byte, error) {
	var out bytes.Buffer
	e := respRead(r, &out, 0)
	return out.Bytes(), e
}
func respArgs(frame []byte) ([][]byte, error) {
	r := bufio.NewReader(bytes.NewReader(frame))
	line, e := r.ReadString('\n')
	if e != nil || len(line) < 4 || line[0] != '*' {
		return nil, ErrProtocol
	}
	n, e := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if e != nil || n < 1 || n > 4096 {
		return nil, ErrProtocol
	}
	args := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		line, e = r.ReadString('\n')
		if e != nil || len(line) < 4 || line[0] != '$' {
			return nil, ErrProtocol
		}
		size, e := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
		if e != nil || size < 0 || size > maxFrame {
			return nil, ErrProtocol
		}
		v := make([]byte, size+2)
		if _, e = io.ReadFull(r, v); e != nil {
			return nil, e
		}
		if !bytes.HasSuffix(v, []byte("\r\n")) {
			return nil, ErrProtocol
		}
		args = append(args, v[:size])
	}
	if r.Buffered() != 0 {
		return nil, ErrProtocol
	}
	return args, nil
}

func serveRedis(client, backend net.Conn, r *recorder) error {
	c, b := bufio.NewReaderSize(client, 65536), bufio.NewReaderSize(backend, 65536)
	account := "unauthenticated"
	inTransaction := false
	var queued []*operation
	for {
		frame, e := respFrame(c)
		if e != nil {
			return e
		}
		args, e := respArgs(frame)
		if e != nil {
			return e
		}
		cmd := strings.ToUpper(string(args[0]))
		if len(cmd) > 64 {
			return ErrProtocol
		}
		for _, ch := range cmd {
			if (ch < 'A' || ch > 'Z') && ch != '_' {
				return ErrProtocol
			}
		}
		// Push and replication streams require a different response lifecycle.
		switch cmd {
		case "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "MONITOR", "SYNC", "PSYNC", "REPLCONF":
			return ErrProtocol
		}
		if (cmd == "MULTI" || cmd == "EXEC" || cmd == "DISCARD" || cmd == "RESET" || cmd == "QUIT") && len(args) != 1 {
			return ErrProtocol
		}
		if len(queued) >= 256 && cmd != "EXEC" && cmd != "DISCARD" || inTransaction && (cmd == "AUTH" || cmd == "HELLO" || cmd == "RESET" || cmd == "QUIT") {
			return ErrProtocol
		}
		candidate := account
		if cmd == "AUTH" {
			if len(args) == 2 {
				candidate = "default"
			} else if len(args) == 3 {
				candidate = string(args[1])
			} else {
				return ErrProtocol
			}
		}
		if cmd == "HELLO" {
			for i := 2; i < len(args); i++ {
				if strings.EqualFold(string(args[i]), "AUTH") {
					if i+2 >= len(args) {
						return ErrProtocol
					}
					candidate = string(args[i+1])
					i += 2
				} else if strings.EqualFold(string(args[i]), "SETNAME") {
					i++
				} else {
					return ErrProtocol
				}
			}
		}
		if candidate != account && candidate != r.binding.Account {
			return ErrIdentity
		}
		if cmd == "CLIENT" && len(args) > 1 {
			switch strings.ToUpper(string(args[1])) {
			case "TRACKING", "REPLY":
				return ErrProtocol
			}
		}
		if account == "unauthenticated" && candidate == account && cmd != "HELLO" && cmd != "PING" && cmd != "QUIT" {
			return ErrIdentity
		}
		text := cmd
		object := ""
		if len(args) > 1 {
			text += " [arguments redacted]"
		}
		if cmd == "GET" || cmd == "SET" || cmd == "DEL" || cmd == "HGET" || cmd == "HSET" || cmd == "EXISTS" {
			if len(args) > 1 {
				sum := sha256.Sum256(args[1])
				object = fmt.Sprintf("key-sha256:%x", sum[:])
				text = cmd + " " + object
			}
		}
		op, e := r.begin(account, strings.ToLower(cmd), text, object, nil)
		if e != nil {
			return e
		}
		if e = writeAll(backend, frame); e != nil {
			return e
		}
		clear(frame)
		reply, e := respFrame(b)
		if e != nil {
			return e
		}
		if len(reply) == 0 || reply[0] == '>' || reply[0] == '|' {
			return ErrProtocol
		}
		result := "success"
		if reply[0] == '-' || reply[0] == '!' {
			result = "failure"
		} else {
			account = candidate
		}
		if inTransaction && bytes.Equal(reply, []byte("+QUEUED\r\n")) {
			queued = append(queued, op)
		} else {
			if (cmd == "EXEC" || cmd == "DISCARD") && inTransaction {
				var outcomes []string
				if cmd == "EXEC" && result == "success" {
					outcomes, e = redisExecResults(reply)
					if e != nil {
						return e
					}
					if outcomes != nil && len(outcomes) != len(queued) {
						return ErrProtocol
					}
				}
				for i, pending := range queued {
					outcome := "skipped"
					if outcomes != nil {
						outcome = outcomes[i]
					}
					if e = pending.end(outcome); e != nil {
						return e
					}
				}
				queued = nil
				inTransaction = false
			}
			if cmd == "MULTI" && result == "success" {
				inTransaction = true
			}
			if cmd == "RESET" && result == "success" {
				account = "unauthenticated"
			}
			if e = op.end(result); e != nil {
				return e
			}
		}
		if e = writeAll(client, reply); e != nil {
			return e
		}
		if cmd == "QUIT" {
			return nil
		}
	}
}

func redisExecResults(reply []byte) ([]string, error) {
	if bytes.Equal(reply, []byte("*-1\r\n")) || bytes.Equal(reply, []byte("_\r\n")) {
		return nil, nil
	}
	reader := bufio.NewReaderSize(bytes.NewReader(reply), 65536)
	line, e := reader.ReadString('\n')
	if e != nil || len(line) < 4 || line[0] != '*' {
		return nil, ErrProtocol
	}
	count, e := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if e != nil || count < 0 || count > 256 {
		return nil, ErrProtocol
	}
	out := make([]string, count)
	for i := range out {
		part, e := respFrame(reader)
		if e != nil || len(part) == 0 {
			return nil, ErrProtocol
		}
		out[i] = "success"
		if part[0] == '-' || part[0] == '!' {
			out[i] = "failure"
		}
	}
	if _, e = reader.ReadByte(); e != io.EOF {
		return nil, ErrProtocol
	}
	return out, nil
}
