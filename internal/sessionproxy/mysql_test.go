package sessionproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func mysqlHandshakeGreeting(caps uint32) mysqlPacket {
	prefix := append([]byte{10}, []byte("8.0.40\x00")...)
	fields := make([]byte, 31)
	binary.LittleEndian.PutUint32(fields, 1)
	copy(fields[4:], "12345678")
	binary.LittleEndian.PutUint16(fields[13:], uint16(caps))
	fields[15] = 45
	binary.LittleEndian.PutUint16(fields[16:], 2)
	binary.LittleEndian.PutUint16(fields[18:], uint16(caps>>16))
	fields[20] = 21
	data := append(prefix, fields...)
	return mysqlPacket{seq: 0, data: append(data, []byte("abcdefghijkl\x00mysql_native_password\x00")...)}
}

func TestMySQLHandshakeNegotiatesCapabilities(t *testing.T) {
	const baseFlags = uint32(1 | 1<<2 | 1<<9 | 1<<11 | 1<<13 | 1<<15 | 1<<19)
	now := time.Now()
	fixture := newAuditTLSFixture(t, []string{"mysql.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(fixture.certificate))
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, tc := range []struct {
			name    string
			extra   uint32
			changed uint32
			account string
			wantErr error
		}{
			{name: "basic client", account: "reader"},
			{name: "modern client capabilities", extra: 1<<23 | 1<<24 | 1<<27 | 1<<28, account: "reader"},
			{name: "unnegotiated optional features", extra: mysqlDisabled, account: "reader"},
			{name: "changed authentication flags", extra: 1 << 24, changed: 1 << 24, account: "reader", wantErr: ErrProtocol},
			{name: "unapproved account", extra: 1 << 24, account: "root", wantErr: ErrIdentity},
		} {
			t.Run(tls.VersionName(version)+"/"+tc.name, func(t *testing.T) {
				client, front := net.Pipe()
				back, target := net.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				for _, conn := range []net.Conn{client, front, back, target} {
					defer conn.Close()
					conn.SetDeadline(now.Add(10 * time.Second))
				}
				stop := context.AfterFunc(ctx, func() { client.Close(); front.Close(); back.Close(); target.Close() })
				defer stop()
				serverTLS := &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{fixture.pair}, SessionTicketsDisabled: true}
				clientTLS := &tls.Config{MinVersion: version, MaxVersion: version, RootCAs: roots, ServerName: "mysql.test"}
				flags := baseFlags | tc.extra
				sink := &recordingSink{}
				proxyDone, targetDone := make(chan error, 1), make(chan error, 1)
				go func() {
					defer front.Close()
					defer back.Close()
					proxyDone <- serveMySQL(front, back, serverTLS, clientTLS, &recorder{ctx: ctx, binding: Binding{Account: "reader"}, protocol: "mysql", sink: sink})
				}()
				query := []byte("SELECT 'private-value'")
				go func() {
					defer target.Close()
					targetDone <- func() error {
						if err := mysqlHandshakeGreeting(baseFlags | mysqlDisabled).write(target); err != nil {
							return err
						}
						ssl, err := mysqlRead(target)
						if err != nil {
							return err
						}
						if ssl.seq != 1 || len(ssl.data) != 32 || binary.LittleEndian.Uint32(ssl.data) != baseFlags {
							return fmt.Errorf("target SSLRequest enabled unnegotiated capabilities")
						}
						secure := tls.Server(target, serverTLS)
						if err := secure.HandshakeContext(ctx); err != nil {
							return err
						}
						auth, err := mysqlRead(secure)
						if tc.wantErr != nil {
							if !errors.Is(err, io.EOF) {
								return fmt.Errorf("rejected authentication reached target: %v", err)
							}
							return nil
						}
						if err != nil {
							return err
						}
						if auth.seq != 2 || len(auth.data) < 34 || binary.LittleEndian.Uint32(auth.data) != baseFlags || !bytes.HasPrefix(auth.data[32:], []byte("reader\x00")) {
							return fmt.Errorf("target authentication flags or account changed")
						}
						ok := mysqlPacket{seq: 3, data: []byte{0, 0, 0, 2, 0, 0, 0}}
						if err := ok.write(secure); err != nil {
							return err
						}
						command, err := mysqlRead(secure)
						if err != nil {
							return err
						}
						if command.seq != 0 || !bytes.Equal(command.data, append([]byte{3}, query...)) {
							return fmt.Errorf("query payload changed")
						}
						ok.seq = 1
						if err := ok.write(secure); err != nil {
							return err
						}
						quit, err := mysqlRead(secure)
						if err == nil && (quit.seq != 0 || !bytes.Equal(quit.data, []byte{1})) {
							return fmt.Errorf("missing quit command")
						}
						return err
					}()
				}()
				greeting, err := mysqlRead(client)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(greeting.data, mysqlHandshakeGreeting(baseFlags).data) {
					t.Fatal("gateway advertised unsupported capabilities")
				}
				ssl := mysqlPacket{seq: 1, data: make([]byte, 32)}
				binary.LittleEndian.PutUint32(ssl.data, flags)
				ssl.data[8] = 45
				if err := ssl.write(client); err != nil {
					t.Fatal(err)
				}
				secure := tls.Client(client, clientTLS)
				if err := secure.HandshakeContext(ctx); err != nil {
					t.Fatalf("client TLS upgrade failed: %v", err)
				}
				auth := mysqlPacket{seq: 2, data: append(append([]byte{}, ssl.data...), []byte(tc.account+"\x00\x00mysql_native_password\x00")...)}
				binary.LittleEndian.PutUint32(auth.data, flags^tc.changed)
				if err := auth.write(secure); err != nil {
					t.Fatal(err)
				}
				if tc.wantErr == nil {
					if _, err := mysqlRead(secure); err != nil {
						t.Fatal(err)
					}
					if err := (mysqlPacket{seq: 0, data: append([]byte{3}, query...)}).write(secure); err != nil {
						t.Fatal(err)
					}
					if response, err := mysqlRead(secure); err != nil || response.seq != 1 || response.data[0] != 0 {
						t.Fatalf("query response: %+v %v", response, err)
					}
					if err := (mysqlPacket{seq: 0, data: []byte{1}}).write(secure); err != nil {
						t.Fatal(err)
					}
				}
				if err := <-proxyDone; !errors.Is(err, tc.wantErr) {
					t.Fatalf("proxy error = %v, want %v", err, tc.wantErr)
				}
				if err := <-targetDone; err != nil {
					t.Fatal(err)
				}
				if tc.wantErr != nil {
					if len(sink.events) != 0 {
						t.Fatal("rejected authentication recorded a query")
					}
				} else if len(sink.events) != 4 || sink.events[0].OperationType != "query" || *sink.events[0].NormalizedOperation != "SELECT ?" || sink.events[1].Result != "success" || sink.events[0].ActualAccount != "reader" {
					t.Fatalf("query audit was lost or exposed a literal: %+v", sink.events)
				}
			})
		}
	}
}

func TestMySQLTargetTLSFailureReturnsDiagnostic(t *testing.T) {
	const flags = uint32(1 | 1<<9 | 1<<11 | 1<<15 | 1<<19)
	now := time.Now()
	gateway := newAuditTLSFixture(t, []string{"gateway.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	target := newAuditTLSFixture(t, []string{"private-target.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newAuditTLSFixture(t, []string{"private-target.test"}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, tc := range []struct {
			name, ca, hostname, pin, reason string
			target                          auditTLSFixture
		}{
			{name: "untrusted CA", ca: gateway.certificate, hostname: "private-target.test", target: target, reason: "target_certificate_untrusted"},
			{name: "wrong name", ca: target.certificate, hostname: "wrong-private-target.test", target: target, reason: "target_certificate_name_mismatch"},
			{name: "expired certificate", ca: expired.certificate, hostname: "private-target.test", target: expired, reason: "target_certificate_expired_or_not_yet_valid"},
			{name: "wrong pin", hostname: "private-target.test", pin: gateway.pin, target: target, reason: "target_certificate_pin_rejected"},
		} {
			t.Run(tls.VersionName(version)+"/"+tc.name, func(t *testing.T) {
				config := Config{Certificate: gateway.certificate, PrivateKey: gateway.key, TargetCA: tc.ca, TargetServerName: tc.hostname, TargetCertificateSHA256: tc.pin}
				frontTLS, backTLS, err := config.TLS("private-address.test")
				if err != nil {
					t.Fatal(err)
				}
				frontTLS.MinVersion, frontTLS.MaxVersion, frontTLS.SessionTicketsDisabled = version, version, true
				backTLS.MinVersion, backTLS.MaxVersion = version, version
				client, front := net.Pipe()
				// TLS rejection alerts need buffering while the server sends its handshake.
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				back, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				for _, conn := range []net.Conn{client, front, back, server} {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				sink := &recordingSink{}
				proxyDone, targetDone := make(chan error, 1), make(chan error, 1)
				go func() {
					defer front.Close()
					defer back.Close()
					proxyDone <- serveMySQL(front, back, frontTLS, backTLS, &recorder{ctx: ctx, binding: Binding{Account: "reader"}, protocol: "mysql", sink: sink})
				}()
				go func() {
					targetDone <- func() error {
						if err := mysqlHandshakeGreeting(flags).write(server); err != nil {
							return err
						}
						if _, err := mysqlRead(server); err != nil {
							return err
						}
						secure := tls.Server(server, &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{tc.target.pair}, SessionTicketsDisabled: true})
						if err := secure.HandshakeContext(ctx); err != nil {
							return nil
						}
						if _, err := mysqlRead(secure); err == nil {
							return fmt.Errorf("untrusted target received client authentication")
						}
						return nil
					}()
				}()
				if _, err := mysqlRead(client); err != nil {
					t.Fatal(err)
				}
				ssl := mysqlPacket{seq: 1, data: make([]byte, 32)}
				binary.LittleEndian.PutUint32(ssl.data, flags)
				if err := ssl.write(client); err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM([]byte(gateway.certificate))
				secure := tls.Client(client, &tls.Config{MinVersion: version, MaxVersion: version, RootCAs: roots, ServerName: "gateway.test"})
				if err := secure.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				auth := mysqlPacket{seq: 2, data: append(append([]byte{}, ssl.data...), []byte("reader\x00private-login\x00")...)}
				if err := auth.write(secure); err != nil {
					t.Fatal(err)
				}
				response, err := mysqlRead(secure)
				if err != nil || response.seq != 3 || len(response.data) < 9 || response.data[0] != 0xff || binary.LittleEndian.Uint16(response.data[1:]) != 1105 || string(response.data[3:9]) != "#HY000" {
					t.Fatalf("missing MySQL TLS error response: %+v %v", response, err)
				}
				if !bytes.Contains(response.data, []byte(tc.reason)) || bytes.Contains(response.data, []byte("private-")) {
					t.Fatalf("TLS diagnostic omitted the reason or exposed private details: %s", response.data)
				}
				if err := <-proxyDone; !errors.Is(err, ErrTargetTLS) || TargetTLSFailureReason(err) != tc.reason {
					t.Fatalf("incorrect target TLS failure: %v", err)
				}
				if err := <-targetDone; err != nil {
					t.Fatal(err)
				}
				if len(sink.events) != 0 {
					t.Fatal("failed TLS handshake recorded a query")
				}
			})
		}
	}
}

func TestMySQLHandshakeRequiresTLS(t *testing.T) {
	for _, flags := range []uint32{1 << 9, 1 << 11, 0} {
		t.Run(fmt.Sprintf("flags_%x", flags), func(t *testing.T) {
			client, front := net.Pipe()
			back, target := net.Pipe()
			for _, conn := range []net.Conn{client, front, back, target} {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
			}
			done := make(chan error, 1)
			go func() {
				defer front.Close()
				defer back.Close()
				done <- serveMySQL(front, back, nil, nil, &recorder{})
			}()
			if err := mysqlHandshakeGreeting(1<<9 | 1<<11).write(target); err != nil {
				t.Fatal(err)
			}
			if _, err := mysqlRead(client); err != nil {
				t.Fatal(err)
			}
			request := mysqlPacket{seq: 1, data: make([]byte, 32)}
			binary.LittleEndian.PutUint32(request.data, flags)
			if err := request.write(client); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, ErrProtocol) {
				t.Fatalf("unencrypted handshake accepted: %v", err)
			}
			if _, err := mysqlRead(target); !errors.Is(err, io.EOF) {
				t.Fatalf("unencrypted login reached target: %v", err)
			}
		})
	}
}

func TestMySQLTargetClosingBeforeGreetingIsFailure(t *testing.T) {
	now := time.Now()
	fixture := newAuditTLSFixture(t, []string{"mysql.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	config := Config{Protocol: "mysql", Certificate: fixture.certificate, PrivateKey: fixture.key}
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{name: "closed without greeting"},
		{name: "truncated packet header", wire: []byte{40, 0}},
		{name: "truncated greeting", wire: []byte{40, 0, 0, 0, 10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, front := net.Pipe()
			back, target := net.Pipe()
			for _, conn := range []net.Conn{client, front, back, target} {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
			}
			sink := &recordingSink{}
			done := make(chan error, 1)
			go func() {
				defer front.Close()
				defer back.Close()
				_, _, err := Serve(context.Background(), config, front, back, Binding{Account: "reader", TargetHost: "mysql.test"}, sink)
				done <- err
			}()
			if len(tc.wire) > 0 {
				if _, err := target.Write(tc.wire); err != nil {
					t.Fatal(err)
				}
			}
			target.Close()
			if err := <-done; !errors.Is(err, ErrTargetGreeting) {
				t.Fatalf("early target close was reported as a normal disconnect: %v", err)
			}
			if len(sink.events) != 0 {
				t.Fatal("query audit recorded before receiving a target greeting")
			}
		})
	}
}
