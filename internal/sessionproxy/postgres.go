package sessionproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type pgMessage struct {
	kind byte
	data []byte
}

func pgRead(r io.Reader) (pgMessage, error) {
	var h [5]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return pgMessage{}, e
	}
	n := int(binary.BigEndian.Uint32(h[1:]))
	if n < 4 || n > maxFrame {
		return pgMessage{}, ErrProtocol
	}
	p := pgMessage{h[0], make([]byte, n-4)}
	_, e := io.ReadFull(r, p.data)
	return p, e
}
func (p pgMessage) write(w io.Writer) error {
	h := make([]byte, 5)
	h[0] = p.kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(p.data)+4))
	if e := writeAll(w, h); e != nil {
		return e
	}
	return writeAll(w, p.data)
}
func pgStartup(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n < 8 || n > 64<<10 {
		return nil, ErrProtocol
	}
	b := make([]byte, n)
	copy(b, h[:])
	_, e := io.ReadFull(r, b[4:])
	return b, e
}
func pgString(data []byte) (string, []byte, bool) {
	i := bytes.IndexByte(data, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(data[:i]), data[i+1:], true
}

type pgPending struct {
	kind    byte
	op      *operation
	failed  bool
	skipped bool
}

func servePostgres(client, backend net.Conn, front, back *tls.Config, r *recorder, cancels *postgresCancelRegistry) error {
	ssl, e := pgStartup(client)
	if e != nil {
		return e
	}
	if binary.BigEndian.Uint32(ssl[4:]) == 80877102 {
		return servePostgresCancel(ssl, backend, back, r, cancels)
	}
	if len(ssl) != 8 || binary.BigEndian.Uint32(ssl[4:]) != 80877103 {
		return ErrProtocol
	}
	if e = writeAll(backend, ssl); e != nil {
		return e
	}
	var answer [1]byte
	if _, e = io.ReadFull(backend, answer[:]); e != nil {
		return e
	}
	if answer[0] != 'S' {
		return ErrProtocol
	}
	if e = writeAll(client, answer[:]); e != nil {
		return e
	}
	c, b := tls.Server(client, front), tls.Client(backend, back)
	if e = handshakeTLS(r.ctx, c, b); e != nil {
		return e
	}
	startup, e := pgStartup(c)
	if e != nil {
		return e
	}
	if binary.BigEndian.Uint32(startup[4:]) == 80877102 {
		return servePostgresCancel(startup, b, nil, r, cancels)
	}
	if binary.BigEndian.Uint32(startup[4:]) != 196608 {
		return ErrProtocol
	}
	fields := bytes.Split(startup[8:], []byte{0})
	account := ""
	if len(fields) < 3 || len(fields)%2 != 0 {
		return ErrProtocol
	}
	for i := 0; i+1 < len(fields) && len(fields[i]) > 0; i += 2 {
		if string(fields[i]) == "user" {
			if account != "" {
				return ErrProtocol
			}
			account = string(fields[i+1])
		}
		if string(fields[i]) == "replication" {
			return ErrProtocol
		}
	}
	if account != r.binding.Account {
		return ErrIdentity
	}
	if e = writeAll(b, startup); e != nil {
		return e
	}
	var cancelKey [8]byte
	authenticated, hasCancelKey := false, false
	for steps := 0; ; steps++ {
		if steps > 64 {
			return ErrProtocol
		}
		p, e := pgRead(b)
		if e != nil {
			return e
		}
		needReply := false
		if p.kind == 'R' {
			if len(p.data) < 4 {
				return ErrProtocol
			}
			code := binary.BigEndian.Uint32(p.data)
			switch code {
			case 0:
				authenticated = true
			case 12:
			case 3, 5, 11:
				needReply = true
			case 10:
				if !bytes.Contains(p.data[4:], []byte("SCRAM-SHA-256\x00")) {
					return ErrProtocol
				}
				p.data = append([]byte{0, 0, 0, 10}, []byte("SCRAM-SHA-256\x00\x00")...)
				needReply = true
			default:
				return ErrProtocol
			}
		}
		if p.kind == 'K' && cancels != nil {
			if len(p.data) != len(cancelKey) {
				return ErrProtocol
			}
			copy(cancelKey[:], p.data)
			hasCancelKey = true
		}
		if p.kind == 'Z' && authenticated && hasCancelKey {
			defer cancels.register(cancelKey, r.binding)()
		}
		if e = p.write(c); e != nil {
			return e
		}
		if p.kind == 'E' {
			return ErrIdentity
		}
		if p.kind == 'Z' {
			break
		}
		if needReply {
			reply, e := pgRead(c)
			if e != nil {
				return e
			}
			if reply.kind != 'p' {
				return ErrProtocol
			}
			if e = reply.write(b); e != nil {
				return e
			}
			clear(reply.data)
		}
	}
	c.SetDeadline(time.Time{})
	b.SetDeadline(time.Time{})
	var mu sync.Mutex
	pending := []*pgPending{}
	var copying atomic.Bool
	var invalidEpoch atomic.Uint64
	results := make(chan error, 2)
	go func() {
		err := func() error {
			statements, portals := map[string]string{}, map[string]string{}
			epoch := invalidEpoch.Load()
			for {
				p, e := pgRead(c)
				if e != nil {
					return e
				}
				if current := invalidEpoch.Load(); current != epoch {
					clear(statements)
					clear(portals)
					epoch = current
				}
				kind, text := "", ""
				queue := true
				switch p.kind {
				case 'Q':
					if len(p.data) == 0 || p.data[len(p.data)-1] != 0 {
						return ErrProtocol
					}
					kind, text = "query", SQLShape(string(p.data[:len(p.data)-1]))
				case 'P':
					name, rest, ok := pgString(p.data)
					if !ok || len(name) > 256 {
						return ErrProtocol
					}
					sql, _, ok := pgString(rest)
					if !ok || len(statements) >= 256 && statements[name] == "" {
						return ErrProtocol
					}
					text = SQLShape(sql)
					statements[name] = text
					kind = "parse"
				case 'B':
					name, rest, ok := pgString(p.data)
					if !ok || len(name) > 256 {
						return ErrProtocol
					}
					statement, _, ok := pgString(rest)
					if !ok || statements[statement] == "" || len(portals) >= 256 && portals[name] == "" {
						return ErrProtocol
					}
					text = statements[statement]
					portals[name] = text
					kind = "bind"
				case 'E':
					name, rest, ok := pgString(p.data)
					if !ok || len(rest) != 4 || portals[name] == "" {
						return ErrProtocol
					}
					kind, text = "execute", portals[name]
				case 'D', 'C':
					if len(p.data) < 2 {
						return ErrProtocol
					}
					name, _, ok := pgString(p.data[1:])
					if !ok {
						return ErrProtocol
					}
					if p.data[0] == 'S' {
						text = statements[name]
						if p.kind == 'C' {
							delete(statements, name)
						}
					} else if p.data[0] == 'P' {
						text = portals[name]
						if p.kind == 'C' {
							delete(portals, name)
						}
					} else {
						return ErrProtocol
					}
					kind = "describe"
					if p.kind == 'C' {
						kind = "close"
					}
				case 'S':
					kind, text = "sync", "SYNC"
				case 'H':
					queue = false
				case 'X':
					op, e := r.begin(account, "quit", "TERMINATE", "", nil)
					if e != nil {
						return e
					}
					if e = p.write(b); e != nil {
						return e
					}
					return op.end("sent")
				case 'd', 'c', 'f':
					if !copying.Load() {
						return ErrProtocol
					}
					queue = false
				default:
					return ErrProtocol
				}
				if queue {
					op, e := r.begin(account, kind, text, "", nil)
					if e != nil {
						return e
					}
					mu.Lock()
					if len(pending) >= 256 {
						mu.Unlock()
						return ErrProtocol
					}
					pending = append(pending, &pgPending{kind: p.kind, op: op})
					mu.Unlock()
				}
				if e = p.write(b); e != nil {
					return e
				}
			}
		}()
		c.Close()
		b.Close()
		results <- err
	}()
	go func() {
		err := func() error {
			recovering := false
			for {
				p, e := pgRead(b)
				if e != nil {
					return e
				}
				if p.kind == 'W' {
					return ErrProtocol
				}
				if p.kind == 'G' {
					copying.Store(true)
				}
				if p.kind == 'C' || p.kind == 'E' || p.kind == 'Z' {
					copying.Store(false)
				}
				mu.Lock()
				var finished []*pgPending
				if len(pending) > 0 {
					head := pending[0]
					done := false
					if p.kind == 'E' {
						invalidEpoch.Add(1)
						head.failed = true
						if head.kind != 'Q' {
							done = true
							recovering = true
						}
					}
					if p.kind == 'Z' && recovering {
						for len(pending) > 0 {
							v := pending[0]
							pending = pending[1:]
							v.skipped = v.kind != 'S'
							finished = append(finished, v)
							if v.kind == 'S' {
								break
							}
						}
						recovering = false
					} else {
						done = done || head.kind == 'Q' && p.kind == 'Z' || head.kind == 'S' && p.kind == 'Z' || head.kind == 'P' && p.kind == '1' || head.kind == 'B' && p.kind == '2' || head.kind == 'C' && p.kind == '3' || head.kind == 'D' && (p.kind == 'T' || p.kind == 'n') || head.kind == 'E' && (p.kind == 'C' || p.kind == 's' || p.kind == 'I')
						if done {
							pending = pending[1:]
							finished = append(finished, head)
						}
					}
				}
				mu.Unlock()
				for _, v := range finished {
					result := "success"
					if v.failed {
						result = "failure"
					}
					if v.skipped {
						result = "skipped"
					}
					if p.kind == 's' {
						result = "partial"
					}
					if e = v.op.end(result); e != nil {
						return e
					}
				}
				if e = p.write(c); e != nil {
					return e
				}
			}
		}()
		c.Close()
		b.Close()
		results <- err
	}()
	first := <-results
	second := <-results
	return pumpResult(first, second)
}
