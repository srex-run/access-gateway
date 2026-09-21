package sessionproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const mysqlDisabled = uint32(1<<5 | 1<<7 | 1<<23 | 1<<24 | 1<<25 | 1<<26 | 1<<27 | 1<<28 | 1<<30)

type mysqlPacket struct {
	seq  byte
	data []byte
}

func mysqlRead(r io.Reader) (mysqlPacket, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return mysqlPacket{}, e
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n == 0 || n == 0xffffff {
		return mysqlPacket{}, ErrProtocol
	}
	p := mysqlPacket{seq: h[3], data: make([]byte, n)}
	_, e := io.ReadFull(r, p.data)
	return p, e
}
func (p mysqlPacket) write(w io.Writer) error {
	n := len(p.data)
	h := []byte{byte(n), byte(n >> 8), byte(n >> 16), p.seq}
	if e := writeAll(w, h); e != nil {
		return e
	}
	return writeAll(w, p.data)
}
func mysqlLen(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfc:
		if len(b) >= 3 {
			return uint64(binary.LittleEndian.Uint16(b[1:])), 3, true
		}
	case 0xfd:
		if len(b) >= 4 {
			return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
		}
	case 0xfe:
		if len(b) >= 9 {
			return binary.LittleEndian.Uint64(b[1:]), 9, true
		}
	case 0xfb, 0xff:
		return 0, 0, false
	default:
		return uint64(b[0]), 1, true
	}
	return 0, 0, false
}
func mysqlStatus(b []byte) uint16 {
	if len(b) >= 5 && b[0] == 0xfe && len(b) < 9 {
		return binary.LittleEndian.Uint16(b[3:])
	}
	if len(b) > 0 && b[0] == 0 {
		_, n, ok := mysqlLen(b[1:])
		if !ok {
			return 0
		}
		_, m, ok := mysqlLen(b[1+n:])
		if ok && len(b) >= 1+n+m+2 {
			return binary.LittleEndian.Uint16(b[1+n+m:])
		}
	}
	return 0
}

func serveMySQL(client, backend net.Conn, front, back *tls.Config, r *recorder) error {
	g, e := mysqlRead(backend)
	if e != nil {
		return fmt.Errorf("%w: %w", ErrTargetGreeting, e)
	}
	if g.seq != 0 || len(g.data) < 34 || g.data[0] != 10 {
		return ErrProtocol
	}
	z := bytes.IndexByte(g.data[1:], 0)
	if z < 0 {
		return ErrProtocol
	}
	lo := 1 + z + 1 + 4 + 8 + 1
	hi := lo + 2 + 1 + 2
	if len(g.data) < hi+2 {
		return ErrProtocol
	}
	caps := uint32(binary.LittleEndian.Uint16(g.data[lo:])) | uint32(binary.LittleEndian.Uint16(g.data[hi:]))<<16
	if caps&(1<<11) == 0 {
		return ErrProtocol
	}
	caps &^= mysqlDisabled
	binary.LittleEndian.PutUint16(g.data[lo:], uint16(caps))
	binary.LittleEndian.PutUint16(g.data[hi:], uint16(caps>>16))
	if e = g.write(client); e != nil {
		return e
	}
	ssl, e := mysqlRead(client)
	if e != nil {
		return e
	}
	if ssl.seq != 1 || len(ssl.data) != 32 {
		return ErrProtocol
	}
	flags := binary.LittleEndian.Uint32(ssl.data)
	if flags&(1<<11|1<<9) != (1<<11 | 1<<9) {
		return ErrProtocol
	}
	// Clients can report capabilities disabled in our greeting. Keep those
	// features disabled on the target in both parts of the TLS upgrade.
	negotiated := flags &^ mysqlDisabled
	binary.LittleEndian.PutUint32(ssl.data, negotiated)
	if e = ssl.write(backend); e != nil {
		return e
	}
	c, b := tls.Server(client, front), tls.Client(backend, back)
	if e = handshakeTLS(r.ctx, c, b); e != nil {
		if errors.Is(e, ErrTargetTLS) {
			// The client sends its login after TLS. Consume it before replying
			// with sequence 3, but never forward credentials to an untrusted peer.
			if auth, readErr := mysqlRead(c); readErr == nil {
				clear(auth.data)
				if auth.seq == 2 {
					message := "Gateway target TLS failed (" + TargetTLSFailureReason(e) + "). Check asset CA, certificate name or SHA-256 pin in the audit rule."
					packet := mysqlPacket{seq: 3, data: append([]byte{0xff, 0x51, 0x04, '#', 'H', 'Y', '0', '0', '0'}, message...)}
					_ = packet.write(c)
				}
			}
		}
		return e
	}
	auth, e := mysqlRead(c)
	if e != nil {
		return e
	}
	if auth.seq != 2 || len(auth.data) < 34 || binary.LittleEndian.Uint32(auth.data) != flags {
		return ErrProtocol
	}
	end := bytes.IndexByte(auth.data[32:], 0)
	if end < 0 {
		return ErrProtocol
	}
	account := string(auth.data[32 : 32+end])
	if account != r.binding.Account {
		return ErrIdentity
	}
	binary.LittleEndian.PutUint32(auth.data, negotiated)
	if e = auth.write(b); e != nil {
		return e
	}
	clear(auth.data)
	for steps := 0; ; steps++ {
		if steps > 16 {
			return ErrProtocol
		}
		p, e := mysqlRead(b)
		if e != nil {
			return e
		}
		if e = p.write(c); e != nil {
			return e
		}
		if p.data[0] == 0 {
			break
		}
		if p.data[0] == 0xff {
			return ErrIdentity
		}
		if p.data[0] == 1 && len(p.data) == 2 && p.data[1] == 3 {
			continue
		}
		if p.data[0] != 1 && p.data[0] != 0xfe {
			return ErrProtocol
		}
		answer, e := mysqlRead(c)
		if e != nil {
			return e
		}
		if e = answer.write(b); e != nil {
			return e
		}
		clear(answer.data)
	}
	c.SetDeadline(time.Time{})
	b.SetDeadline(time.Time{})
	statements := map[uint32]string{}
	for {
		p, e := mysqlRead(c)
		if e != nil {
			return e
		}
		if p.seq != 0 {
			return ErrProtocol
		}
		cmd := p.data[0]

		kind, text := "", ""
		var sid uint32
		switch cmd {
		case 1:
			kind, text = "quit", "QUIT"
		case 2:
			kind, text = "init_db", "USE "+SQLShape(string(p.data[1:]))
		case 3:
			query := string(p.data[1:])
			kind, text = r.mysqlStartup.operationType(query), SQLShape(query)
		case 4: // COM_FIELD_LIST, used by native clients for table/column completion.
			table, _, ok := bytes.Cut(p.data[1:], []byte{0})
			if !ok || len(table) == 0 {
				return ErrProtocol
			}
			kind, text = "field_list", "FIELD LIST "+SQLShape(string(table))
		case 0x16:
			if len(statements) >= 256 {
				return ErrProtocol
			}
			kind, text = "prepare", SQLShape(string(p.data[1:]))
		case 0x17, 0x18, 0x19, 0x1a:
			if len(p.data) < 5 {
				return ErrProtocol
			}
			sid = binary.LittleEndian.Uint32(p.data[1:])
			text = statements[sid]
			if text == "" {
				return ErrProtocol
			}
			kind = map[byte]string{0x17: "execute", 0x18: "bind_data", 0x19: "statement_close", 0x1a: "statement_reset"}[cmd]
			if cmd == 0x17 && (len(p.data) < 10 || p.data[5] != 0) {
				return ErrProtocol
			}
		case 0x0e:
			kind, text = "ping", "PING"
		case 0x1f:
			kind, text = "reset_connection", "RESET CONNECTION"
		default:
			return ErrProtocol
		}
		op, e := r.begin(account, kind, text, "", nil)
		if e != nil {
			return e
		}
		if e = p.write(b); e != nil {
			return e
		}
		if cmd == 1 || cmd == 0x18 || cmd == 0x19 {
			if cmd == 0x19 {
				delete(statements, sid)
			}
			if e = op.end("sent"); e != nil {
				return e
			}
			if cmd == 1 {
				return nil
			}
			continue
		}
		var result string
		if cmd == 0x16 {
			first, e := mysqlRead(b)
			if e != nil {
				return e
			}
			if e = first.write(c); e != nil {
				return e
			}
			result = "failure"
			if first.data[0] == 0 {
				if len(first.data) < 12 {
					return ErrProtocol
				}
				sid = binary.LittleEndian.Uint32(first.data[1:])
				cols := int(binary.LittleEndian.Uint16(first.data[5:]))
				params := int(binary.LittleEndian.Uint16(first.data[7:]))
				if cols > 4096 || params > 4096 {
					return ErrProtocol
				}
				for _, count := range []int{params, cols} {
					if count == 0 {
						continue
					}
					for i := 0; i < count+1; i++ {
						part, e := mysqlRead(b)
						if e != nil {
							return e
						}
						if i == count && (part.data[0] != 0xfe || len(part.data) >= 9) {
							return ErrProtocol
						}
						if e = part.write(c); e != nil {
							return e
						}
					}
				}
				statements[sid] = text
				result = "success"
			}
		} else if cmd == 4 {
			result, e = mysqlFieldListResult(c, b)
			if e != nil {
				return e
			}
		} else {
			result, e = mysqlResult(c, b)
			if e != nil {
				return e
			}
		}
		if cmd == 0x1f && result == "success" {
			clear(statements)
		}
		if e = op.end(result); e != nil {
			return e
		}
	}
}

// COM_FIELD_LIST has no column-count packet: stream definitions until EOF/ERR.
// The handshake disables CLIENT_DEPRECATE_EOF, so the terminator is always EOF.
func mysqlFieldListResult(client, backend io.ReadWriter) (string, error) {
	for columns := 0; ; columns++ {
		p, err := mysqlRead(backend)
		if err != nil {
			return "", err
		}
		if p.seq != byte(columns+1) || p.data[0] == 0xfb {
			return "", ErrProtocol
		}
		result := ""
		switch {
		case p.data[0] == 0xff:
			result = "failure"
		case p.data[0] == 0xfe && len(p.data) < 9:
			if len(p.data) != 5 {
				return "", ErrProtocol
			}
			result = "success"
		case columns >= 4096:
			return "", ErrProtocol
		}
		if err = p.write(client); err != nil {
			return "", err
		}
		if result != "" {
			return result, nil
		}
	}
}

// Result rows are streamed packet by packet, never accumulated or audited.
func mysqlResult(client, backend io.ReadWriter) (string, error) {
	for {
		p, e := mysqlRead(backend)
		if e != nil {
			return "", e
		}
		if p.data[0] == 0xfb {
			return "", ErrProtocol
		} // LOCAL INFILE is never exposed.
		if e = p.write(client); e != nil {
			return "", e
		}
		if p.data[0] == 0xff {
			return "failure", nil
		}
		if p.data[0] == 0 {
			if mysqlStatus(p.data)&8 != 0 {
				continue
			}
			return "success", nil
		}
		count, _, ok := mysqlLen(p.data)
		if !ok || count == 0 || count > 4096 {
			return "", ErrProtocol
		}
		for i := uint64(0); i <= count; i++ {
			p, e = mysqlRead(backend)
			if e != nil {
				return "", e
			}
			if i == count && (p.data[0] != 0xfe || len(p.data) >= 9) {
				return "", ErrProtocol
			}
			if e = p.write(client); e != nil {
				return "", e
			}
		}
		for {
			p, e = mysqlRead(backend)
			if e != nil {
				return "", e
			}
			if e = p.write(client); e != nil {
				return "", e
			}
			if p.data[0] == 0xff {
				return "failure", nil
			}
			if p.data[0] == 0xfe && len(p.data) < 9 {
				break
			}
		}
		if mysqlStatus(p.data)&8 == 0 {
			return "success", nil
		}
	}
}
