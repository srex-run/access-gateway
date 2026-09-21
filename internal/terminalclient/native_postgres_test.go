//go:build darwin || linux

package terminalclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/terminal"
)

// Use the installed psql, real PTY and OS sandbox. After displaying a result,
// psql calls PQconsumeInput to check notifications even when the server is idle.
// The injected socket must remain nonblocking for the next prompt to appear.
func TestNativePostgresPromptAfterQueries(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("requires psql and RUN_TERMINAL_SANDBOX_TESTS=1")
	}
	certificate, privateKey, serverTLS := nativeTestTLS(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	stream := &nativeTestStream{input: reader, ready: make(chan struct{}), changed: make(chan struct{}, 1)}
	queries := []string{"SELECT 1 AS ok;", "SELECT 1 / 0;", "SELECT 2 AS after_error;"}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Protocol: "postgresql", Account: "test", Certificate: certificate, ClientCertificate: certificate, ClientKey: privateKey, Start: terminal.Message{Type: "start", Cols: 100, Rows: 30, Database: "test", Password: "fixture-login"}}, stream, func(ctx context.Context, conn net.Conn) error {
			deadline, _ := ctx.Deadline()
			conn.SetDeadline(deadline)
			secure, err := nativePostgresHandshake(ctx, conn, serverTLS)
			if err != nil {
				return err
			}
			for index, want := range queries {
				kind, data, err := readNativePostgresMessage(secure)
				if err != nil || kind != 'Q' || string(data) != want+"\x00" {
					return fmt.Errorf("native query %d did not arrive: kind=%c err=%v", index+1, kind, err)
				}
				if index == 1 {
					err = writeNativePostgresMessage(secure, 'E', []byte("SERROR\x00C22012\x00Mdivision by zero\x00\x00"))
				} else {
					// One int4 column and one row, matching SELECT 1 / SELECT 2.
					column := append([]byte{0, 1}, []byte("ok\x00")...)
					column = binary.BigEndian.AppendUint32(column, 0)
					column = binary.BigEndian.AppendUint16(column, 0)
					column = binary.BigEndian.AppendUint32(column, 23)
					column = binary.BigEndian.AppendUint16(column, 4)
					column = binary.BigEndian.AppendUint32(column, 0xffffffff)
					column = binary.BigEndian.AppendUint16(column, 0)
					if err = writeNativePostgresMessage(secure, 'T', column); err != nil {
						return err
					}
					if err = writeNativePostgresMessage(secure, 'D', []byte{0, 1, 0, 0, 0, 1, byte('1' + index/2)}); err != nil {
						return err
					}
					err = writeNativePostgresMessage(secure, 'C', []byte("SELECT 1\x00"))
				}
				if err != nil {
					return err
				}
				if err = writeNativePostgresMessage(secure, 'Z', []byte{'I'}); err != nil {
					return err
				}
			}
			kind, _, err := readNativePostgresMessage(secure)
			if err != nil || kind != 'X' {
				return fmt.Errorf("psql quit: kind=%c err=%v", kind, err)
			}
			return nil
		})
	}()
	waitPrompt := func(count int, output string) {
		t.Helper()
		for strings.Count(stream.text(), "test=> ") < count || !strings.Contains(stream.text(), output) {
			select {
			case <-stream.changed:
			case err := <-done:
				t.Fatalf("psql exited before prompt %d: %v, output=%q", count, err, stream.text())
			case <-ctx.Done():
				t.Fatalf("psql prompt %d did not return: output=%q", count, stream.text())
			}
		}
	}
	waitPrompt(1, "test=> ")
	for index, query := range queries {
		if _, err := io.WriteString(writer, query+"\r"); err != nil {
			t.Fatal(err)
		}
		output := "(1 row)"
		if index == 1 {
			output = "division by zero"
		}
		waitPrompt(index+2, output)
	}
	if _, err := io.WriteString(writer, "\\q\r"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("psql did not exit cleanly: %v, output=%q", err, stream.text())
		}
	case <-ctx.Done():
		t.Fatal("psql survived terminal closure")
	}
}

func nativePostgresHandshake(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error) {
	var ssl [8]byte
	if _, err := io.ReadFull(conn, ssl[:]); err != nil || !bytes.Equal(ssl[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
		return nil, fmt.Errorf("PostgreSQL TLS request: %v", err)
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return nil, err
	}
	secure := tls.Server(conn, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	var size [4]byte
	if _, err := io.ReadFull(secure, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(size[:]))
	if length < 8 || length > 64<<10 {
		return nil, fmt.Errorf("invalid PostgreSQL startup length")
	}
	startup := make([]byte, length-4)
	if _, err := io.ReadFull(secure, startup); err != nil {
		return nil, err
	}
	if !bytes.Contains(startup[4:], []byte("user\x00test\x00")) || !bytes.Contains(startup[4:], []byte("database\x00test\x00")) {
		return nil, fmt.Errorf("PostgreSQL startup identity changed")
	}
	if binary.BigEndian.Uint32(startup[:4]) > 196608 {
		// libpq 18 can request protocol 3.2; this fixture acts as a 3.0 server.
		if err := writeNativePostgresMessage(secure, 'v', make([]byte, 8)); err != nil {
			return nil, err
		}
	}
	if err := writeNativePostgresMessage(secure, 'R', make([]byte, 4)); err != nil {
		return nil, err
	}
	for _, parameter := range []string{"server_version\x0016.15\x00", "client_encoding\x00UTF8\x00", "standard_conforming_strings\x00on\x00"} {
		if err := writeNativePostgresMessage(secure, 'S', []byte(parameter)); err != nil {
			return nil, err
		}
	}
	return secure, writeNativePostgresMessage(secure, 'Z', []byte{'I'})
}

func writeNativePostgresMessage(conn net.Conn, kind byte, data []byte) error {
	packet := binary.BigEndian.AppendUint32([]byte{kind}, uint32(len(data)+4))
	_, err := conn.Write(append(packet, data...))
	return err
}

func readNativePostgresMessage(conn net.Conn) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length < 4 || length > 64<<10 {
		return 0, nil, fmt.Errorf("invalid PostgreSQL message length")
	}
	data := make([]byte, length-4)
	_, err := io.ReadFull(conn, data)
	return header[0], data, err
}
