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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/terminal"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

type postgresCancelSink struct {
	mu sync.Mutex
	recordingSink
}

func (s *postgresCancelSink) AppendOperation(ctx context.Context, event operationaudit.SessionEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordingSink.AppendOperation(ctx, event)
}

func postgresTestTLS(conn net.Conn, config *tls.Config, server bool) (net.Conn, error) {
	ssl := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	if server {
		packet, err := pgStartup(conn)
		if err != nil || !bytes.Equal(packet, ssl) {
			return nil, fmt.Errorf("TLS request: %v", err)
		}
		if err := writeAll(conn, []byte{'S'}); err != nil {
			return nil, err
		}
		return tls.Server(conn, config), nil
	}
	if err := writeAll(conn, ssl); err != nil {
		return nil, err
	}
	var answer [1]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil || answer[0] != 'S' {
		return nil, fmt.Errorf("TLS answer: %v", err)
	}
	return tls.Client(conn, config), nil
}

func TestPostgresTerminalCancelAndContinue(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pair := func() (net.Conn, net.Conn) {
				a, b := net.Pipe()
				deadline, _ := ctx.Deadline()
				a.SetDeadline(deadline)
				b.SetDeadline(deadline)
				stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
				t.Cleanup(func() { stop(); a.Close(); b.Close() })
				return a, b
			}
			identity := newAuditTLSFixture(t, []string{"asset.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			serverTLS := &tls.Config{Certificates: []tls.Certificate{identity.pair}, MinVersion: tls.VersionTLS12}
			cfg := Config{Protocol: "postgresql", TargetCA: identity.certificate, TargetServerName: "asset.test"}
			binding := Binding{ConnectionID: "main", AssetID: "asset", Account: "test", TargetHost: "asset.test", TargetPort: 5432}
			packet := binary.BigEndian.AppendUint32(nil, 16)
			packet = binary.BigEndian.AppendUint32(packet, 80877102)
			packet = binary.BigEndian.AppendUint32(packet, 12345)
			packet = binary.BigEndian.AppendUint32(packet, 67890)
			back, asset := pair()
			queryStarted, cancelled := make(chan struct{}), make(chan struct{})
			targetDone := make(chan error, 1)
			go func() {
				defer asset.Close()
				targetDone <- func() error {
					secure, err := postgresTestTLS(asset, serverTLS, true)
					if err != nil {
						return err
					}
					if _, err = pgStartup(secure); err != nil {
						return err
					}
					for _, message := range []pgMessage{{'R', []byte{0, 0, 0, 0}}, {'K', packet[8:]}, {'Z', []byte{'I'}}} {
						if err = message.write(secure); err != nil {
							return err
						}
					}
					query, err := pgRead(secure)
					if err != nil || query.kind != 'Q' || string(query.data) != "SELECT pg_sleep(30);\x00" {
						return fmt.Errorf("long query: %v", err)
					}
					close(queryStarted)
					select {
					case <-cancelled:
					case <-ctx.Done():
						return ctx.Err()
					}
					for _, message := range []pgMessage{{'E', []byte("SERROR\x00C57014\x00Mcanceling statement due to user request\x00\x00")}, {'Z', []byte{'I'}}} {
						if err = message.write(secure); err != nil {
							return err
						}
					}
					query, err = pgRead(secure)
					if err != nil || query.kind != 'Q' || string(query.data) != "SELECT 1;\x00" {
						return fmt.Errorf("query after cancel: %v", err)
					}
					for _, message := range []pgMessage{{'C', []byte("SELECT 1\x00")}, {'Z', []byte{'I'}}} {
						if err = message.write(secure); err != nil {
							return err
						}
					}
					_, err = pgRead(secure)
					return err
				}()
			}()
			sink := &postgresCancelSink{}
			extra := func(ctx context.Context, client net.Conn, config Config) error {
				backend, target := pair()
				defer backend.Close()
				done := make(chan error, 1)
				go func() {
					defer target.Close()
					done <- func() error {
						secure, err := postgresTestTLS(target, serverTLS, true)
						if err != nil {
							return err
						}
						got, err := pgStartup(secure)
						if err != nil || !bytes.Equal(got, packet) {
							return fmt.Errorf("cancel request: %v", err)
						}
						close(cancelled)
						return nil
					}()
				}()
				cancelBinding := binding
				cancelBinding.ConnectionID = "cancel"
				_, _, err := Serve(ctx, config, client, backend, cancelBinding, sink)
				backend.Close()
				return errors.Join(err, <-done)
			}
			err := serveClientTerminal(ctx, cfg, back, binding, sink, terminal.Message{Type: "start", Cols: 80, Rows: 24, Database: "test"}, &browserTerminal{}, extra,
				func(ctx context.Context, options terminalclient.Options, _ terminal.Stream, bridge terminalclient.Bridge) error {
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM([]byte(options.Certificate))
					identity, err := tls.X509KeyPair([]byte(options.ClientCertificate), []byte(options.ClientKey))
					if err != nil {
						return err
					}
					clientTLS := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}
					client, front := pair()
					mainDone := make(chan error, 1)
					go func() { defer front.Close(); mainDone <- bridge(ctx, front) }()
					defer func() { client.Close(); <-mainDone }()
					secure, err := postgresTestTLS(client, clientTLS, false)
					if err != nil {
						return err
					}
					startup := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00test\x00database\x00test\x00\x00")...)
					binary.BigEndian.PutUint32(startup, uint32(len(startup)))
					if err = writeAll(secure, startup); err != nil {
						return err
					}
					for range 3 {
						if _, err = pgRead(secure); err != nil {
							return err
						}
					}
					if err = (pgMessage{'Q', []byte("SELECT pg_sleep(30);\x00")}).write(secure); err != nil {
						return err
					}
					select {
					case <-queryStarted:
					case <-ctx.Done():
						return ctx.Err()
					}
					cancelClient, cancelFront := pair()
					defer cancelClient.Close()
					cancelDone := make(chan error, 1)
					go func() { defer cancelFront.Close(); cancelDone <- bridge(ctx, cancelFront) }()
					var cancelStream net.Conn = cancelClient
					if encrypted {
						cancelStream, err = postgresTestTLS(cancelClient, clientTLS, false)
						if err != nil {
							return err
						}
					}
					if err = writeAll(cancelStream, packet); err != nil {
						return err
					}
					if _, err = cancelStream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
						return fmt.Errorf("cancel connection must close: %v", err)
					}
					if err = <-cancelDone; err != nil {
						return err
					}
					for _, want := range []byte{'E', 'Z'} {
						message, err := pgRead(secure)
						if err != nil || message.kind != want {
							return fmt.Errorf("query cancellation response %c: %v", want, err)
						}
					}
					if err = (pgMessage{'Q', []byte("SELECT 1;\x00")}).write(secure); err != nil {
						return err
					}
					for _, want := range []byte{'C', 'Z'} {
						message, err := pgRead(secure)
						if err != nil || message.kind != want {
							return fmt.Errorf("query after cancellation response %c: %v", want, err)
						}
					}
					return (pgMessage{'X', nil}).write(secure)
				})
			if err != nil {
				t.Fatalf("terminal cancellation interrupted the session: %v", err)
			}
			if err = <-targetDone; err != nil {
				t.Fatal(err)
			}
			var results []string
			for _, event := range sink.events {
				if event.Phase == "completed" && (event.OperationType == "query" || event.OperationType == "cancel") {
					results = append(results, event.OperationType+"/"+event.Result)
				}
			}
			for _, want := range []string{"query/failure", "query/success", "cancel/sent"} {
				if !strings.Contains(strings.Join(results, ","), want) {
					t.Fatalf("missing %s audit: %v", want, results)
				}
			}
		})
	}
}

func TestPostgresCancelAuthorization(t *testing.T) {
	owner := Binding{ConnectionID: "query", AssetID: "asset", Account: "test", TargetHost: "asset.test", TargetPort: 5432}
	key := [8]byte{0, 0, 0, 42, 1, 2, 3, 4}
	packet := append([]byte{0, 0, 0, 16, 4, 210, 22, 46}, key[:]...)
	registry := &postgresCancelRegistry{}
	release := registry.register(key, owner)
	defer release()
	for _, name := range []string{"valid", "public", "other-terminal", "other-account", "other-asset", "other-host", "other-port", "forged-key", "short", "wrong-length", "wrong-code", "audit-unavailable"} {
		t.Run(name, func(t *testing.T) {
			state := registry
			binding := owner
			binding.ConnectionID = "cancel"
			request := bytes.Clone(packet)
			want := ErrIdentity
			sink := &recordingSink{}
			switch name {
			case "valid":
				got, err := state.lookup(request, binding)
				if err != nil || got != owner {
					t.Fatalf("cancel was not bound to its authenticated query connection: %v", err)
				}
				return
			case "public":
				state, want = nil, ErrProtocol
			case "other-terminal":
				state = &postgresCancelRegistry{}
			case "other-account":
				binding.Account = "other"
			case "other-asset":
				binding.AssetID = "other"
			case "other-host":
				binding.TargetHost = "other.test"
			case "other-port":
				binding.TargetPort++
			case "forged-key":
				request[15]++
			case "short":
				request, want = request[:15], ErrProtocol
			case "wrong-length":
				request[3], want = 17, ErrProtocol
			case "wrong-code":
				request[7], want = 47, ErrProtocol
			case "audit-unavailable":
				sink.err, want = errors.New("offline"), ErrAudit
			}
			backend, target := net.Pipe()
			defer backend.Close()
			defer target.Close()
			backend.SetDeadline(time.Now())
			err := servePostgresCancel(request, backend, nil, &recorder{ctx: context.Background(), binding: binding, protocol: "postgresql", sink: sink}, state)
			if !errors.Is(err, want) {
				t.Fatalf("unauthorized cancellation = %v, want %v", err, want)
			}
			if name != "audit-unavailable" && len(sink.events) != 0 {
				t.Fatal("unauthorized cancellation was recorded as an authenticated operation")
			}
		})
	}
	release()
	if _, err := registry.lookup(packet, owner); !errors.Is(err, ErrIdentity) {
		t.Fatalf("closed query connection still accepts cancellation: %v", err)
	}
}

func TestPostgresCancelRequiresVerifiedTargetTLS(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			backend, target := net.Pipe()
			defer backend.Close()
			defer target.Close()
			deadline, _ := ctx.Deadline()
			backend.SetDeadline(deadline)
			target.SetDeadline(deadline)
			identity := newAuditTLSFixture(t, []string{"asset.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer target.Close()
				if !encrypted {
					if _, err := pgStartup(target); err == nil {
						_ = writeAll(target, []byte{'N'})
					}
					return
				}
				secure, err := postgresTestTLS(target, &tls.Config{Certificates: []tls.Certificate{identity.pair}, MinVersion: tls.VersionTLS12}, true)
				if err == nil {
					if _, err = pgStartup(secure); err == nil {
						t.Error("cancel packet reached an untrusted target")
					}
				}
			}()
			registry := &postgresCancelRegistry{}
			binding := Binding{Account: "test", TargetHost: "asset.test", TargetPort: 5432}
			key := [8]byte{0, 0, 0, 42, 1, 2, 3, 4}
			defer registry.register(key, binding)()
			packet := append([]byte{0, 0, 0, 16, 4, 210, 22, 46}, key[:]...)
			sink := &recordingSink{}
			err := servePostgresCancel(packet, backend, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "asset.test", MinVersion: tls.VersionTLS12}, &recorder{ctx: ctx, binding: binding, protocol: "postgresql", sink: sink}, registry)
			want := ErrProtocol
			if encrypted {
				want = ErrTargetTLS
			}
			if !errors.Is(err, want) {
				t.Fatalf("unverified cancel target: %v, want %v", err, want)
			}
			<-done
			if len(sink.events) != 2 || sink.events[1].Result != "failure" {
				t.Fatalf("TLS rejection audit: %+v", sink.events)
			}
		})
	}
}
