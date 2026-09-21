package gatewayagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// PostgreSQL's documented SSLRequest (length 8, code 80877103).
var postgresSSLRequest = []byte{0, 0, 0, 8, 4, 210, 22, 47}

func TestNativeTCPPostgreSQLTLSUpgrade(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			controller, listener, _, sink := pipeController(t)
			serverTLS, clientTLS := nativeTLSConfigs(t, version)
			backendWire, clientWire := &nativeWire{}, &nativeWire{}
			controller.dial = func(context.Context, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					_ = b.SetDeadline(time.Now().Add(5 * time.Second))
					request := make([]byte, 8)
					if _, err := io.ReadFull(b, request); err != nil || !bytes.Equal(request, postgresSSLRequest) {
						return
					}
					if _, err := b.Write([]byte{'S'}); err != nil {
						return
					}
					secure := tls.Server(b, serverTLS)
					_, _ = io.Copy(secure, secure)
				}()
				return tcpPipe{recordedNativeConn{Conn: a, wire: backendWire}}, nil
			}
			if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
				t.Fatal(err)
			}
			conn := recordedNativeConn{Conn: connectNative(t, listener), wire: clientWire}
			// Deliberately fragment the SSLRequest as TCP clients may do.
			for _, part := range [][]byte{postgresSSLRequest[:3], postgresSSLRequest[3:]} {
				if _, err := conn.Write(part); err != nil {
					t.Fatal(err)
				}
			}
			answer := make([]byte, 1)
			if _, err := io.ReadFull(conn, answer); err != nil || answer[0] != 'S' {
				t.Fatalf("PostgreSQL SSL response: %q, %v", answer, err)
			}
			secure := tls.Client(conn, clientTLS)
			// The client's own TLS stack verifies the target certificate. The
			// gateway has neither that trust configuration nor target credentials.
			payload := []byte("user=reader password=postgres-secret query=SELECT 1")
			nativeEcho(t, secure, payload)
			for segment, wire := range map[string]*nativeWire{"client-gateway": clientWire, "gateway-target": backendWire} {
				encoded := wire.snapshot()
				if !bytes.Contains(encoded, postgresSSLRequest) || bytes.Contains(encoded, payload) {
					t.Fatalf("%s did not preserve the encrypted PostgreSQL stream", segment)
				}
			}
			_ = conn.Close()
			event := waitForGatewayEvent(t, sink, "disconnected")
			if event.BytesUp == nil || *event.BytesUp <= int64(len(payload)) || event.BytesDown == nil || *event.BytesDown <= int64(len(payload)) {
				t.Fatalf("missing encrypted traffic audit: %+v", event)
			}
		})
	}
}

func TestNativeTCPPostgreSQLRejectsPlaintextAndTLSRefusal(t *testing.T) {
	for _, sample := range []struct {
		name, reason string
		request      []byte
		answer       byte
	}{
		{"plaintext startup", "postgresql_client_tls_required", []byte{0, 0, 0, 26, 0, 3, 0, 0, 'u', 's', 'e', 'r', 0, 's', 'e', 'c', 'r', 'e', 't', 0}, 0},
		{"invalid upgrade code", "postgresql_client_tls_required", []byte{0, 0, 0, 8, 0, 3, 0, 0}, 0},
		{"server refuses TLS", "postgresql_target_tls_unavailable", postgresSSLRequest, 'N'},
		{"invalid server response", "postgresql_invalid_ssl_response", postgresSSLRequest, 'X'},
	} {
		t.Run(sample.name, func(t *testing.T) {
			controller, listener, _, sink := pipeController(t)
			wire := &nativeWire{}
			controller.dial = func(context.Context, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					_ = b.SetDeadline(time.Now().Add(5 * time.Second))
					if sample.answer != 0 {
						if _, err := io.ReadFull(b, make([]byte, 8)); err != nil {
							return
						}
						_, _ = b.Write([]byte{sample.answer})
					}
					_, _ = io.Copy(io.Discard, b)
				}()
				return tcpPipe{recordedNativeConn{Conn: a, wire: wire}}, nil
			}
			if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
				t.Fatal(err)
			}
			conn := connectNative(t, listener)
			_, _ = conn.Write(sample.request)
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("plaintext fallback allowed: %d, %v", n, err)
			}
			event := waitForGatewayEvent(t, sink, "auth_rejected")
			if event.Reason != sample.reason {
				t.Fatalf("handshake audit reason = %q, want %q", event.Reason, sample.reason)
			}
			if sample.answer == 0 && len(wire.snapshot()) != 0 {
				t.Fatal("plaintext startup reached the target")
			}
		})
	}
}
