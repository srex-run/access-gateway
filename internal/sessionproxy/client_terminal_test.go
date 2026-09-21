package sessionproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/terminal"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

type diagnosticBrowserTerminal struct {
	browserTerminal
	onError func(terminal.Message)
}

func (s *diagnosticBrowserTerminal) Send(message terminal.Message) error {
	if message.Type == "error" {
		s.onError(message)
	}
	return s.browserTerminal.Send(message)
}

func TestClientTerminalDeliberateClosureDoesNotFailOperation(t *testing.T) {
	for _, cause := range []error{terminal.ErrSessionClosed, terminal.ErrSessionExpired, terminal.ErrTerminalClosed} {
		backend, asset := net.Pipe()
		sink := &recordingSink{}
		err := serveClientTerminal(context.Background(), Config{Protocol: "mysql"}, backend, Binding{Account: "admin"}, sink,
			terminal.Message{Type: "start", Cols: 100, Rows: 30}, &browserTerminal{}, nil,
			func(context.Context, terminalclient.Options, terminal.Stream, terminalclient.Bridge) error {
				return cause
			})
		backend.Close()
		asset.Close()
		if terminal.CloseReason(err) != terminal.CloseReason(cause) {
			t.Fatalf("close reason was lost: %v", err)
		}
		last := sink.events[len(sink.events)-1]
		if last.Phase != "completed" || last.Result != "success" {
			t.Fatalf("deliberate close failed the client operation: %+v", last)
		}
	}
}

func TestClientTerminalOutputRequiresAuditAcknowledgement(t *testing.T) {
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http"} {
		for _, failure := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "/success", true: "/audit-failure"}[failure], func(t *testing.T) {
				backend, asset := net.Pipe()
				defer backend.Close()
				defer asset.Close()
				stream := &browserTerminal{}
				sink := &recordingSink{}
				var audit Sink = sink
				if failure {
					audit = &failingTerminalSink{}
				}
				err := serveClientTerminal(context.Background(), Config{Protocol: protocol}, backend, Binding{Account: "admin"}, audit,
					terminal.Message{Type: "start", Password: "private-test-password", Cols: 100, Rows: 30}, stream, nil,
					func(_ context.Context, options terminalclient.Options, output terminal.Stream, _ terminalclient.Bridge) error {
						if options.Account != "admin" || options.Protocol != protocol {
							t.Fatal("client identity changed")
						}
						if strings.Contains(options.Certificate, "PRIVATE KEY") {
							t.Fatal("proxy key sent to client")
						}
						_, err := output.Write([]byte("native client response\r\n"))
						return err
					})
				if failure {
					if !errors.Is(err, ErrAudit) || stream.output.Len() != 0 {
						t.Fatalf("unaudited output delivered: %v", err)
					}
				} else {
					if err != nil || stream.output.String() != "native client response\r\n" {
						t.Fatalf("terminal output missing: %v", err)
					}
					for _, event := range sink.events {
						if event.NormalizedOperation != nil && strings.Contains(*event.NormalizedOperation, "private-test-password") {
							t.Fatal("initial password persisted")
						}
						if event.Metadata["account_verified"] != false {
							t.Fatal("client output was mistaken for verified protocol evidence")
						}
					}
				}
			})
		}
	}
}

func TestClientTerminalRejectsLocalConnectionWithoutIdentity(t *testing.T) {
	backend, asset := net.Pipe()
	defer backend.Close()
	defer asset.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reported := make(chan terminal.Message, 1)
	stream := &diagnosticBrowserTerminal{}
	err := serveClientTerminal(ctx, Config{Protocol: "http"}, backend, Binding{Account: "admin"}, &recordingSink{},
		terminal.Message{Type: "start", Cols: 80, Rows: 24}, stream, nil,
		func(ctx context.Context, options terminalclient.Options, _ terminal.Stream, bridge terminalclient.Bridge) error {
			stream.onError = func(message terminal.Message) {
				if ctx.Err() != nil {
					t.Error("diagnostic was sent after terminal cancellation")
				}
				reported <- message
			}
			client, front := net.Pipe()
			defer client.Close()
			defer front.Close()
			done := make(chan error, 1)
			go func() { defer front.Close(); done <- bridge(ctx, front) }()
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(options.Certificate))
			untrusted := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MaxVersion: tls.VersionTLS12})
			if err := untrusted.HandshakeContext(ctx); err == nil {
				t.Error("local process connected without the terminal identity")
			}
			client.Close()
			return <-done
		})
	if !errors.Is(err, ErrClientTLS) {
		t.Fatalf("missing client identity: %v", err)
	}
	select {
	case message := <-reported:
		if !strings.Contains(message.Data, "client_tls_handshake_failed") {
			t.Fatal("client did not receive the TLS failure cause")
		}
	default:
		t.Fatal("terminal was closed without reporting the failure")
	}
}
