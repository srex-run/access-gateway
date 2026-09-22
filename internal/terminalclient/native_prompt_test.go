//go:build darwin || linux

package terminalclient

import (
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

// Exercise readline/libedit and deliberate closure with a local TLS fixture.
// No real database or user credentials are involved.
func TestNativeMySQLPromptAndClosure(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("requires a native client and RUN_TERMINAL_SANDBOX_TESTS=1")
	}
	for _, reason := range []error{terminal.ErrTerminalClosed, terminal.ErrSessionClosed} {
		t.Run(terminal.CloseReason(reason), func(t *testing.T) {
			testNativeMySQLPromptAndClosure(t, reason)
		})
	}
}

func testNativeMySQLPromptAndClosure(t *testing.T, closeReason error) {
	certificate, privateKey, serverTLS := nativeTestTLS(t)
	timeoutCtx, stop := context.WithTimeout(t.Context(), 15*time.Second)
	defer stop()
	ctx, cancel := context.WithCancelCause(timeoutCtx)
	defer cancel(nil)
	reader, writer := io.Pipe()
	defer writer.Close()
	stream := &nativeTestStream{input: reader, ready: make(chan struct{}), changed: make(chan struct{}, 1)}
	queries := make(chan string, 16)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{Protocol: "mysql", Account: "reader", Certificate: certificate, ClientCertificate: certificate, ClientKey: privateKey, Start: terminal.Message{Type: "start", Cols: 100, Rows: 30, Password: "fixture-login"}}, stream, func(ctx context.Context, conn net.Conn) error {
			deadline, _ := ctx.Deadline()
			_ = conn.SetDeadline(deadline)
			secure, err := nativePromptHandshake(ctx, conn, serverTLS)
			if err != nil {
				return err
			}
			if err = writeNativeMySQLPacket(secure, 3, []byte{0, 0, 0, 2, 0, 0, 0}); err != nil {
				return err
			}
			for {
				request, err := readNativeMySQLPacket(secure, 0)
				if err != nil {
					return err
				}
				if len(request) == 0 {
					return fmt.Errorf("empty command")
				}
				if request[0] == 1 {
					return nil
				}
				if request[0] != 3 {
					return fmt.Errorf("unexpected command %d", request[0])
				}
				queries <- string(request[1:])
				if string(request[1:]) == "select $$" {
					// New MySQL clients deliberately provoke a parse error to
					// discover dollar-quote support before displaying the prompt.
					if err := writeNativeMySQLPacket(secure, 1, []byte{0xff, 0x28, 0x04, '#', '4', '2', '0', '0', '0'}); err != nil {
						return err
					}
					continue
				}
				column := []byte{3, 'd', 'e', 'f', 0, 0, 0, 5, 'v', 'a', 'l', 'u', 'e', 0, 12, 33, 0, 255, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0}
				row := "terminal-fixture-row"
				packets := [][]byte{{1}, column, {0xfe, 0, 0, 2, 0}, append([]byte{byte(len(row))}, row...), {0xfe, 0, 0, 2, 0}}
				for index, payload := range packets {
					if err = writeNativeMySQLPacket(secure, byte(index+1), payload); err != nil {
						return err
					}
				}
			}
		})
	}()
	waitOutput := func(check func(string) bool) {
		t.Helper()
		for !check(stream.text()) {
			select {
			case <-stream.changed:
			case err := <-done:
				t.Fatalf("native client exited: %v, output=%s", err, stream.text())
			case <-ctx.Done():
				t.Fatalf("native prompt timeout: %s", stream.text())
			}
		}
	}
	waitOutput(func(output string) bool { return strings.Contains(output, "mysql> ") })
	// --silent hides the banner, but clients still query the version comment
	// and newer MySQL clients probe dollar quotes. Both precede user input.
	for len(queries) > 0 {
		if query := <-queries; query != "select @@version_comment limit 1" && query != "select $$" {
			t.Fatalf("unexpected native startup query: %q", query)
		}
	}
	assertNoQuery := func() {
		t.Helper()
		select {
		case query := <-queries:
			t.Fatalf("unsubmitted input reached the server: %q", query)
		case err := <-done:
			t.Fatalf("native client exited while editing: %v, output=%s", err, stream.text())
		case <-time.After(100 * time.Millisecond):
		}
	}
	assertQuery := func(want string) {
		t.Helper()
		select {
		case query := <-queries:
			if got := strings.Join(strings.Fields(query), " "); got != want {
				t.Fatalf("submitted query = %q, want %q", got, want)
			}
		default:
			t.Fatalf("submitted query %q did not reach the server", want)
		}
		if len(queries) != 0 {
			t.Fatalf("unexpected extra query: %q", <-queries)
		}
	}
	// Typing alone, Enter without a delimiter, and a delimiter without Enter
	// must all stay in the native client's edit/statement buffers.
	if _, err := io.WriteString(writer, "hs"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool { return strings.Contains(output, "hs") })
	assertNoQuery()
	if _, err := io.WriteString(writer, "\x15select\r"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool { return strings.Contains(output, "    -> ") })
	assertNoQuery()
	if _, err := io.WriteString(writer, "1;"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool { return strings.Contains(output, "1;") })
	assertNoQuery()
	if _, err := io.WriteString(writer, "\r"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool {
		return strings.Count(output, "mysql> ") >= 2 && strings.Contains(output, "terminal-fixture-row")
	})
	assertQuery("select 1")
	// Left, backspace and right edit SELECT 2 to SELECT 1 before submission.
	if _, err := io.WriteString(writer, "select 2;\x1b[D\x7f1\x1b[C\r"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool {
		return strings.Count(output, "mysql> ") >= 3 && strings.Count(output, "terminal-fixture-row") >= 2
	})
	assertQuery("select 1")
	// Browser closure and session termination must both discard unfinished SQL.
	beforeClose := len(stream.text())
	if _, err := io.WriteString(writer, "hs"); err != nil {
		t.Fatal(err)
	}
	waitOutput(func(output string) bool { return strings.Contains(output[beforeClose:], "hs") })
	assertNoQuery()
	if closeReason == terminal.ErrSessionClosed {
		cancel(closeReason)
	} else {
		_ = writer.Close()
	}
	select {
	case err := <-done:
		if terminal.CloseReason(err) != terminal.CloseReason(closeReason) {
			t.Fatalf("terminal closure = %v, want %v", err, closeReason)
		}
	case <-timeoutCtx.Done():
		t.Fatal("native client survived terminal closure")
	}
	if len(queries) != 0 {
		t.Fatalf("terminal closure submitted unfinished input: %q", <-queries)
	}
}

func nativePromptHandshake(ctx context.Context, conn net.Conn, serverTLS *tls.Config) (*tls.Conn, error) {
	const caps = uint32(1 | 1<<2 | 1<<9 | 1<<11 | 1<<13 | 1<<15 | 1<<19)
	greeting := append([]byte{10}, []byte("8.4.0-terminal-test\x00")...)
	fields := make([]byte, 31)
	binary.LittleEndian.PutUint32(fields, 1)
	copy(fields[4:], "12345678")
	binary.LittleEndian.PutUint16(fields[13:], uint16(caps&0xffff))
	fields[15] = 45
	binary.LittleEndian.PutUint16(fields[16:], 2)
	binary.LittleEndian.PutUint16(fields[18:], uint16(caps>>16))
	fields[20] = 21
	greeting = append(greeting, fields...)
	// The 20-byte scramble above is what mysql_native_password expects. Over
	// TLS a caching_sha2_password client skips the scramble and sends the
	// password in the clear as an extra packet, which this fixture's
	// sequence accounting does not model.
	greeting = append(greeting, []byte("abcdefghijkl\x00mysql_native_password\x00")...)
	if err := writeNativeMySQLPacket(conn, 0, greeting); err != nil {
		return nil, err
	}
	if _, err := readNativeMySQLPacket(conn, 1); err != nil {
		return nil, err
	}
	secure := tls.Server(conn, serverTLS)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	_, err := readNativeMySQLPacket(secure, 2)
	return secure, err
}
