package sessionproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

func sftpRead(r io.Reader) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n < 1 || n > 1<<20 {
		return nil, ErrProtocol
	}
	b := make([]byte, n+4)
	copy(b, h[:])
	_, e := io.ReadFull(r, b[4:])
	return b, e
}
func sftpString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > len(b)-4 {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func serveSFTP(client, backend ssh.Channel, r *recorder, account string) error {
	init, e := sftpRead(client)
	if e != nil {
		return e
	}
	if len(init) != 9 || init[4] != 1 || binary.BigEndian.Uint32(init[5:]) != 3 {
		return ErrProtocol
	}
	if e = writeAll(backend, init); e != nil {
		return e
	}
	version, e := sftpRead(backend)
	if e != nil {
		return e
	}
	if len(version) < 9 || version[4] != 2 || binary.BigEndian.Uint32(version[5:]) != 3 {
		return ErrProtocol
	}
	// Do not advertise extensions that have not been instrumented.
	version = version[:9]
	binary.BigEndian.PutUint32(version, 5)
	if e = writeAll(client, version); e != nil {
		return e
	}
	var mu sync.Mutex
	pending := map[uint32]*operation{}
	results := make(chan error, 2)
	go func() {
		err := func() error {
			for {
				p, e := sftpRead(client)
				if e != nil {
					return e
				}
				if len(p) < 9 {
					return ErrProtocol
				}
				kind := p[4]
				id := binary.BigEndian.Uint32(p[5:])
				name := map[byte]string{3: "open", 4: "close", 5: "read", 6: "write", 7: "lstat", 8: "fstat", 9: "setstat", 10: "fsetstat", 11: "opendir", 12: "readdir", 13: "remove", 14: "mkdir", 15: "rmdir", 16: "realpath", 17: "stat", 18: "rename", 19: "readlink", 20: "symlink"}[kind]
				if name == "" {
					return ErrProtocol
				}
				value, rest, ok := sftpString(p[9:])
				if !ok {
					return ErrProtocol
				}
				object := clean(string(value), 400)
				if kind == 4 || kind == 5 || kind == 6 || kind == 8 || kind == 10 || kind == 12 {
					sum := sha256.Sum256(value)
					object = fmt.Sprintf("handle-sha256:%x", sum[:])
				}
				text := "sftp " + name + " " + object
				if kind == 18 || kind == 20 {
					other, _, ok := sftpString(rest)
					if !ok {
						return ErrProtocol
					}
					text += " -> " + clean(string(other), 400)
				}
				op, e := r.begin(account, "sftp."+name, text, object, nil)
				if e != nil {
					return e
				}
				mu.Lock()
				if len(pending) >= 256 || pending[id] != nil {
					mu.Unlock()
					return ErrProtocol
				}
				pending[id] = op
				mu.Unlock()
				if e = writeAll(backend, p); e != nil {
					return e
				}
			}
		}()
		client.Close()
		backend.Close()
		results <- err
	}()
	go func() {
		err := func() error {
			for {
				p, e := sftpRead(backend)
				if e != nil {
					return e
				}
				if len(p) < 9 {
					return ErrProtocol
				}
				id := binary.BigEndian.Uint32(p[5:])
				mu.Lock()
				op := pending[id]
				delete(pending, id)
				mu.Unlock()
				if op == nil {
					return ErrProtocol
				}
				result := "success"
				if p[4] == 101 {
					if len(p) < 13 {
						return ErrProtocol
					}
					status := binary.BigEndian.Uint32(p[9:])
					if status == 1 {
						result = "eof"
					} else if status != 0 {
						result = "failure"
					}
				} else if p[4] < 102 || p[4] > 105 {
					return ErrProtocol
				}
				if e = op.end(result); e != nil {
					return e
				}
				if e = writeAll(client, p); e != nil {
					return e
				}
			}
		}()
		client.Close()
		backend.Close()
		results <- err
	}()
	first := <-results
	second := <-results
	return pumpResult(first, second)
}
