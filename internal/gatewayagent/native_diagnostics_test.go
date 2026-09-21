package gatewayagent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNativeMySQLRejectionReasonsAndSafeDiagnosticLogs(t *testing.T) {
	privateMessage := "sensitive-server-message-must-not-be-forwarded"
	serverError := append([]byte{0xff, 0x6a, 0x04}, []byte(privateMessage)...)
	serverError = append([]byte{byte(len(serverError)), 0, 0, 0}, serverError...)
	for _, test := range []struct {
		name     string
		greeting []byte
		login    bool
		reason   string
	}{
		{"target TLS disabled", mysqlGreeting(false), false, "mysql_target_tls_unavailable"},
		{"server refused before greeting", serverError, false, "mysql_server_rejected_connection"},
		{"invalid server protocol", []byte{1, 0, 0, 0, 9}, false, "mysql_invalid_server_greeting"},
		{"client sent plaintext login", mysqlGreeting(true), true, "mysql_client_tls_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, listener, _, events := pipeController(t)
			var logs bytes.Buffer
			controller.logger = zerolog.New(&logs)
			backendDone := make(chan struct{})
			controller.dial = func(context.Context, string, string) (net.Conn, error) {
				gateway, target := net.Pipe()
				go func() {
					defer close(backendDone)
					defer target.Close()
					_ = target.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = target.Write(test.greeting)
					if n, _ := target.Read(make([]byte, 128)); n != 0 {
						t.Error("rejected connection forwarded data to target")
					}
				}()
				return tcpPipe{gateway}, nil
			}
			request := nativeRequest()
			if _, err := controller.Start(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			client := connectNative(t, listener)
			if test.login {
				if _, err := readMySQLPacket(client, 4096); err != nil {
					t.Fatal(err)
				}
				// The guard reads only the header and rejects oversized login
				// packets before receiving or forwarding password material.
				if _, err := client.Write([]byte{64, 0, 0, 1}); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := client.Read(make([]byte, 4096)); n != 0 || err == nil {
				t.Fatal("rejected greeting or login was exposed to the client")
			}
			event := waitForGatewayEvent(t, events, "auth_rejected")
			if event.Reason != test.reason {
				t.Fatalf("audit reason = %q; want %q", event.Reason, test.reason)
			}
			<-backendDone
			var logged map[string]any
			if err := json.Unmarshal(logs.Bytes(), &logged); err != nil {
				t.Fatalf("diagnostic log: %v", err)
			}
			if logged["session_id"] != request.SessionID || logged["reason"] != test.reason || logged["event_type"] != "auth_rejected" {
				t.Fatalf("log did not identify the failed session and stage: %v", logged)
			}
			if bytes.Contains(logs.Bytes(), []byte(privateMessage)) || logged["target"] != nil || logged["target_account"] != nil {
				t.Fatal("diagnostic log included private target information")
			}
		})
	}
}

func TestNativeHandshakeReportsPrematureClose(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed} {
		if nativeHandshakeReason(err) != "native_handshake_closed" {
			t.Fatalf("closed connection was misreported: %v", err)
		}
	}
}
