package sessionproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestTargetIdentityEnrollmentTLS(t *testing.T) {
	now := time.Now()
	identity := newAuditTLSFixture(t, []string{"target.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	for _, protocol := range []string{"mysql", "postgresql", "redis", "mongodb", "http"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(protocol+"/"+tls.VersionName(version), func(t *testing.T) {
				client, server := sshTestPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = server.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan error, 1)
				go func() {
					done <- func() error {
						switch protocol {
						case "mysql":
							if err := mysqlHandshakeGreeting(1 | 1<<9 | 1<<11 | 1<<15 | 1<<19).write(server); err != nil {
								return err
							}
							packet, err := mysqlRead(server)
							if err != nil || packet.seq != 1 || len(packet.data) != 32 {
								return fmt.Errorf("enrollment did not send only SSLRequest: %v", err)
							}
						case "postgresql":
							var request [8]byte
							if _, err := io.ReadFull(server, request[:]); err != nil {
								return err
							}
							if binary.BigEndian.Uint32(request[:4]) != 8 || binary.BigEndian.Uint32(request[4:]) != 80877103 {
								return errors.New("enrollment sent a PostgreSQL startup packet")
							}
							if err := writeAll(server, []byte{'S'}); err != nil {
								return err
							}
						}
						secure := tls.Server(server, &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{identity.pair}, SessionTicketsDisabled: true})
						if err := secure.HandshakeContext(ctx); err != nil {
							return err
						}
						if secure.ConnectionState().ServerName != "target.test" {
							return errors.New("target SNI was not forwarded")
						}
						if n, _ := secure.Read(make([]byte, 1)); n != 0 {
							return errors.New("enrollment sent application data or credentials")
						}
						return nil
					}()
				}()
				got, err := InspectTargetIdentity(ctx, client, protocol, "target.test")
				_ = client.Close()
				if err != nil || got.CertificateSHA256 != identity.pin || got.SSHHostPublicKey != "" {
					t.Fatalf("wrong enrolled identity: %+v %v", got, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestTargetIdentityEnrollmentRejectsExpiredAndDisabledTLS(t *testing.T) {
	for _, offset := range []time.Duration{-2 * time.Hour, time.Hour} {
		identity := newAuditTLSFixture(t, nil, time.Now().Add(offset), time.Now().Add(offset+time.Hour))
		client, server := sshTestPair(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		go func() {
			_ = tls.Server(server, &tls.Config{Certificates: []tls.Certificate{identity.pair}}).HandshakeContext(ctx)
		}()
		got, err := InspectTargetIdentity(ctx, client, "redis", "target.test")
		_ = client.Close()
		cancel()
		if !errors.Is(err, ErrIdentity) || got != (TargetIdentity{}) {
			t.Fatalf("expired/future certificate enrolled: %+v %v", got, err)
		}
	}
	client, server := sshTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _, _ = io.ReadFull(server, make([]byte, 8)); _, _ = server.Write([]byte{'N'}) }()
	if got, err := InspectTargetIdentity(ctx, client, "postgresql", "target.test"); !errors.Is(err, ErrProtocol) || got != (TargetIdentity{}) {
		t.Fatalf("plaintext PostgreSQL accepted: %+v %v", got, err)
	}
}

func TestTargetIdentityEnrollmentSSHStopsBeforeAuthentication(t *testing.T) {
	signer, _ := sshTestIdentity(t)
	client, server := sshTestPair(t)
	var authentication atomic.Int32
	config := &ssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
		authentication.Add(1)
		return nil, nil
	}}
	config.AddHostKey(signer)
	done := make(chan error, 1)
	go func() {
		conn, _, _, err := ssh.NewServerConn(server, config)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := InspectTargetIdentity(ctx, client, "ssh", "target.test")
	_ = client.Close()
	if err != nil || got.SSHHostPublicKey != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) || got.CertificateSHA256 != "" {
		t.Fatalf("wrong SSH identity: %+v %v", got, err)
	}
	if err := <-done; err == nil || authentication.Load() != 0 {
		t.Fatal("SSH enrollment authenticated to the target")
	}
}

func TestTargetIdentityEnrollmentCancellation(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			client, _ := sshTestPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := InspectTargetIdentity(ctx, client, protocol, "target.test"); err == nil || got != (TargetIdentity{}) {
				t.Fatal("canceled enrollment returned a usable identity")
			}
		})
	}
}

func TestTargetIdentityEnrollmentDeadlineInterruptsHandshake(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		t.Run(protocol, func(t *testing.T) {
			client, _ := sshTestPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			started := time.Now()
			if got, err := InspectTargetIdentity(ctx, client, protocol, "target.test"); err == nil || got != (TargetIdentity{}) {
				t.Fatal("interrupted handshake returned a usable identity")
			}
			if time.Since(started) > time.Second {
				t.Fatal("target enrollment ignored the caller deadline")
			}
		})
	}
}
