//go:build darwin || linux

package terminalclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/terminal"
)

type nativeTestStream struct {
	input   *io.PipeReader
	mu      sync.Mutex
	output  bytes.Buffer
	ready   chan struct{}
	changed chan struct{}
	resize  func(int, int) error
}

func (s *nativeTestStream) Read(p []byte) (int, error) { return s.input.Read(p) }
func (s *nativeTestStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.output.Write(p)
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (s *nativeTestStream) Close() error { return s.input.Close() }
func (s *nativeTestStream) Send(m terminal.Message) error {
	if m.Type == "ready" {
		close(s.ready)
	}
	return nil
}
func (s *nativeTestStream) SetResize(resize func(int, int) error) { s.resize = resize }
func (s *nativeTestStream) text() string                          { s.mu.Lock(); defer s.mu.Unlock(); return s.output.String() }

func nativeTestTLS(t *testing.T) (string, string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The distinguished name cannot be left empty: curl rejects such a peer
	// with "couldn't get X509-issuer name", and MariaDB's
	// --ssl-verify-server-cert matches the loopback host against the common
	// name rather than the address in the subject alternative name.
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM([]byte(certificate))
	return certificate, privateKey, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, ClientCAs: clientCAs, ClientAuth: tls.RequireAndVerifyClientCert}
}

// Exercise the real native client, PTY and OS sandbox, including terminal
// resizing, ANSI/UTF-8 output, Ctrl+C and deadline cancellation.
func TestNativeHTTPTerminalAndCancellation(t *testing.T) {
	if os.Getenv("RUN_TERMINAL_SANDBOX_TESTS") != "1" {
		t.Skip("requires macOS or the Linux runtime image and RUN_TERMINAL_SANDBOX_TESTS=1")
	}
	certificate, privateKey, serverTLS := nativeTestTLS(t)
	for _, revoked := range []bool{false, true} {
		t.Run(fmt.Sprintf("revoked=%v", revoked), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer writer.Close()
			stream := &nativeTestStream{input: reader, ready: make(chan struct{}), changed: make(chan struct{}, 1)}
			done := make(chan error, 1)
			go func() {
				done <- Run(ctx, Options{Protocol: "http", Account: "admin", Certificate: certificate, ClientCertificate: certificate, ClientKey: privateKey, Start: terminal.Message{Type: "start", Cols: 100, Rows: 30, Password: "temporary-client-login"}}, stream, func(ctx context.Context, conn net.Conn) error {
					secure := tls.Server(conn, serverTLS)
					if err := secure.HandshakeContext(ctx); err != nil {
						return err
					}
					request, err := http.ReadRequest(bufio.NewReader(secure))
					if err != nil {
						return err
					}
					defer request.Body.Close()
					user, password, ok := request.BasicAuth()
					if request.Method != "GET" || request.URL.Path != "/health" || !ok || user != "admin" || password != "temporary-client-login" {
						return fmt.Errorf("native request/authentication mismatch")
					}
					_, err = io.WriteString(secure, "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nhealthy-response")
					return err
				})
			}()
			select {
			case <-stream.ready:
			case err := <-done:
				t.Fatalf("client start: %v, output=%s", err, stream.text())
			case <-ctx.Done():
				t.Fatal("client start timeout")
			}
			if revoked {
				cancel()
			} else {
				waitFor := func(description string, found func(string) bool) {
					t.Helper()
					for !found(stream.text()) {
						select {
						case <-stream.changed:
						case err := <-done:
							t.Fatalf("native terminal: %v, output=%s", err, stream.text())
						case <-ctx.Done():
							t.Fatalf("waiting for %s: %s", description, stream.text())
						}
					}
				}
				waitOutput := func(want string) {
					t.Helper()
					waitFor(fmt.Sprintf("%q", want), func(output string) bool { return strings.Contains(output, want) })
				}
				waitMatch := func(pattern *regexp.Regexp) {
					t.Helper()
					waitFor(pattern.String(), pattern.MatchString)
				}
				waitOutput("http> ")
				if err := stream.resize(40, 120); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte("stty size; printf '\\033[31m彩色输出\\033[0m\\n'\r")); err != nil {
					t.Fatal(err)
				}
				waitOutput("40 120")
				waitOutput("\x1b[31m彩色输出\x1b[0m")
				if _, err := writer.Write([]byte("printf '\\162eady-to-interrupt\\n'; sleep 30\r")); err != nil {
					t.Fatal(err)
				}
				// readline ends the accepted input line with "\x1b[?2004l\r"
				// instead of "\r\n" wherever bracketed paste is available, so
				// anchor this bare command's output to the start of its own line.
				waitMatch(regexp.MustCompile(`(?:\r|\n)ready-to-interrupt\r\n`))
				// A single interrupt can land in the instant between the marker
				// and sleep being forked, where the shell has nothing to interrupt
				// and absorbs it, so press Ctrl-C until the prompt comes back the
				// way an operator does. Typing the next command before the prompt
				// returns would lose it: the line discipline discards queued input
				// when it raises SIGINT.
				interrupted := len(stream.text())
				for !strings.Contains(stream.text()[interrupted:], "http> ") {
					if _, err := writer.Write([]byte{3}); err != nil {
						t.Fatal(err)
					}
					select {
					case <-time.After(250 * time.Millisecond):
					case err := <-done:
						t.Fatalf("native terminal: %v, output=%s", err, stream.text())
					case <-ctx.Done():
						t.Fatalf("Ctrl-C did not hand back the prompt: %s", stream.text())
					}
				}
				if _, err := writer.Write([]byte("GET /health\r")); err != nil {
					t.Fatal(err)
				}
				waitOutput("healthy-response")
				if _, err := writer.Write([]byte("exit\r")); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if !revoked && err != nil {
					t.Fatalf("client exit: %v output=%s", err, stream.text())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("terminal process survived cancellation/exit")
			}
			if strings.Contains(stream.text(), "temporary-client-login") {
				t.Fatal("initial password appeared in terminal output")
			}
		})
	}
}
