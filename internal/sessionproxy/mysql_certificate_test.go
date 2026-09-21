package sessionproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestMySQLCertificateEnrollmentWithoutAuthentication(t *testing.T) {
	now := time.Now()
	valid := newAuditTLSFixture(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newAuditTLSFixture(t, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future := newAuditTLSFixture(t, nil, now.Add(time.Hour), now.Add(2*time.Hour))
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, tc := range []struct {
			name    string
			fixture auditTLSFixture
			invalid bool
		}{
			{name: "self-signed without SAN", fixture: valid},
			{name: "expired", fixture: expired, invalid: true},
			{name: "not yet valid", fixture: future, invalid: true},
		} {
			t.Run(tls.VersionName(version)+"/"+tc.name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				backend, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer backend.Close()
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(3 * time.Second))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- func() error {
						const flags = uint32(1 | 1<<9 | 1<<11 | 1<<15 | 1<<19)
						if err := mysqlHandshakeGreeting(flags).write(server); err != nil {
							return err
						}
						ssl, err := mysqlRead(server)
						if err != nil || ssl.seq != 1 || len(ssl.data) != 32 || binary.LittleEndian.Uint32(ssl.data)&(1<<9|1<<11) != 1<<9|1<<11 {
							return fmt.Errorf("invalid MySQL enrollment SSLRequest: %v", err)
						}
						secure := tls.Server(server, &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{tc.fixture.pair}, SessionTicketsDisabled: true})
						if err := secure.HandshakeContext(ctx); err != nil {
							if tc.invalid {
								return nil
							}
							return err
						}
						if n, _ := secure.Read(make([]byte, 1)); n != 0 {
							return fmt.Errorf("certificate enrollment sent authentication or a query")
						}
						return nil
					}()
				}()
				pin, err := InspectMySQLCertificate(ctx, backend)
				backend.Close()
				if tc.invalid {
					if !errors.Is(err, ErrIdentity) || pin != "" {
						t.Fatalf("invalid certificate enrolled: pin=%q err=%v", pin, err)
					}
				} else if err != nil || pin != tc.fixture.pin {
					t.Fatalf("wrong certificate enrolled: pin=%q err=%v", pin, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestMySQLCertificateEnrollmentRejectsUnsupportedTargets(t *testing.T) {
	for _, greeting := range []mysqlPacket{
		mysqlHandshakeGreeting(1 << 9),
		{seq: 0, data: []byte{0xff, 0x15, 0x04}},
		{seq: 0, data: []byte("HTTP/1.1 200 OK")},
	} {
		client, target := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		done := make(chan error, 1)
		go func() { done <- greeting.write(target) }()
		pin, err := InspectMySQLCertificate(ctx, client)
		if !errors.Is(err, ErrProtocol) || pin != "" {
			t.Fatalf("unsupported target enrolled: %q %v", pin, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		client.Close()
		target.Close()
		cancel()
	}
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pin, err := InspectMySQLCertificate(ctx, client); err == nil || pin != "" {
		t.Fatal("canceled certificate enrollment continued")
	}
}
