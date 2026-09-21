package gatewayagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"

	"github.com/srex-run/access-gateway/internal/gateway"
)

func nativeRequest() gateway.CreateSessionRequest {
	request := validGatewayRequest()
	request.ConnectionMode = gateway.ConnectionModeNative
	request.ClientPublicKey = ""
	request.TargetAccount = ""
	request.TargetPort = 3306
	return request
}

func connectNative(t *testing.T, listener *pipeListener) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := listener.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func nativeEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("native echo: %x, %v", got, err)
	}
}

type nativeWire struct {
	mu    sync.Mutex
	bytes []byte
}

func (w *nativeWire) append(value []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bytes = append(w.bytes, value...)
}
func (w *nativeWire) snapshot() []byte { w.mu.Lock(); defer w.mu.Unlock(); return bytes.Clone(w.bytes) }

type recordedNativeConn struct {
	net.Conn
	wire *nativeWire
}

func (c recordedNativeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.wire.append(b[:n])
	return n, err
}
func (c recordedNativeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.wire.append(b[:n])
	return n, err
}

func nativeTLSConfigs(t *testing.T, version uint16) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"database.internal"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(trusted)
	return &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}},
		&tls.Config{MinVersion: version, MaxVersion: version, RootCAs: roots, ServerName: "database.internal"}
}

func nativeTLSBackend(t *testing.T, controller *DirectController, config *tls.Config, mysql bool, serve func(net.Conn)) (*atomic.Int32, *nativeWire) {
	t.Helper()
	count, wire := &atomic.Int32{}, &nativeWire{}
	controller.dial = func(context.Context, string, string) (net.Conn, error) {
		count.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(6 * time.Second))
			if mysql {
				if _, err := b.Write(mysqlGreeting(true)); err != nil {
					return
				}
				if _, err := readMySQLPacket(b, 32); err != nil {
					return
				}
			}
			secure := tls.Server(b, config)
			if err := secure.Handshake(); err != nil {
				return
			}
			_ = b.SetDeadline(time.Time{})
			if serve != nil {
				serve(secure)
			} else {
				_, _ = io.Copy(secure, secure)
			}
		}()
		return tcpPipe{recordedNativeConn{Conn: a, wire: wire}}, nil
	}
	return count, wire
}

func mysqlGreeting(ssl bool) []byte {
	payload := []byte{10, '8', '.', '0', '.', '3', '6', 0}
	payload = append(payload, 1, 0, 0, 0)
	payload = append(payload, []byte("12345678")...)
	payload = append(payload, 0)
	capabilities := uint16(1 << 9)
	if ssl {
		capabilities |= 1 << 11
	}
	payload = binary.LittleEndian.AppendUint16(payload, capabilities)
	payload = append(payload, 45, 2, 0, 0, 0, 21)
	payload = append(payload, make([]byte, 10)...)
	// This makes the packet length 0x53 ('S'), exercising the SSH/MySQL probe
	// distinction without relying on target port numbers.
	payload = append(payload, []byte("abcdefghijkl\x00mysql_native_password\x00xx")...)
	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
}

func connectNativeTLS(t *testing.T, listener *pipeListener, config *tls.Config, mysql bool, wire *nativeWire) net.Conn {
	t.Helper()
	var conn net.Conn = connectNative(t, listener)
	if wire != nil {
		conn = recordedNativeConn{Conn: conn, wire: wire}
	}
	if mysql {
		if _, err := readMySQLPacket(conn, 4096); err != nil {
			t.Fatal(err)
		}
		request := make([]byte, 36)
		request[0], request[3], request[12] = 32, 1, 45
		binary.LittleEndian.PutUint32(request[4:], 1<<9|1<<11)
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
	}
	secure := tls.Client(conn, config)
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	return secure
}

func TestNativeTCPEncryptedOnBothSegments(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, mysql := range []bool{false, true} {
			name := tls.VersionName(version)
			if mysql {
				name += "/mysql"
			}
			t.Run(name, func(t *testing.T) {
				controller, listener, _, _ := pipeController(t)
				serverConfig, clientConfig := nativeTLSConfigs(t, version)
				_, backendWire := nativeTLSBackend(t, controller, serverConfig, mysql, nil)
				response, err := controller.Start(context.Background(), nativeRequest())
				if err != nil || response.ConnectionMode != gateway.ConnectionModeNative || response.ServerCertificate != "" {
					t.Fatalf("native session: %+v %v", response, err)
				}
				clientWire := &nativeWire{}
				conn := connectNativeTLS(t, listener, clientConfig, mysql, clientWire)
				payload := []byte("password=secret-native-payload-0123456789")
				nativeEcho(t, conn, payload)
				for segment, wire := range map[string]*nativeWire{"client-gateway": clientWire, "gateway-target": backendWire} {
					encoded := wire.snapshot()
					if len(encoded) == 0 || bytes.Contains(encoded, payload) {
						t.Fatalf("%s exposed plaintext", segment)
					}
				}
			})
		}
	}
}

func TestNativeTCPHTTPSAndHelloRetry(t *testing.T) {
	controller, listener, _, _ := pipeController(t)
	serverConfig, clientConfig := nativeTLSConfigs(t, tls.VersionTLS13)
	serverConfig.CurvePreferences = []tls.CurveID{tls.CurveP384}
	nativeTLSBackend(t, controller, serverConfig, false, func(conn net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Error(err)
			return
		}
		defer request.Body.Close()
		if request.Host != "database.internal" || request.URL.Path != "/healthz" {
			t.Errorf("HTTP authority changed: %s %s", request.Host, request.URL.Path)
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
		t.Fatal(err)
	}
	conn := connectNativeTLS(t, listener, clientConfig, false, nil)
	if _, err := io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: database.internal\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("HTTPS response: %s %v", body, err)
	}
}

func TestNativeTCPKeepsTargetCertificateVerification(t *testing.T) {
	controller, listener, _, _ := pipeController(t)
	serverConfig, clientConfig := nativeTLSConfigs(t, tls.VersionTLS13)
	nativeTLSBackend(t, controller, serverConfig, false, nil)
	if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
		t.Fatal(err)
	}
	clientConfig.ServerName = "different-target.internal"
	conn := tls.Client(connectNative(t, listener), clientConfig)
	var hostnameError x509.HostnameError
	if err := conn.Handshake(); !errors.As(err, &hostnameError) {
		t.Fatalf("target certificate mismatch was not preserved: %v", err)
	}
}

func TestNativeTCPRevokesPendingEncryptionHandshake(t *testing.T) {
	controller, listener, _, sink := pipeController(t)
	serverConfig, _ := nativeTLSConfigs(t, tls.VersionTLS13)
	nativeTLSBackend(t, controller, serverConfig, false, nil)
	request := nativeRequest()
	if _, err := controller.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	conn := connectNative(t, listener)
	waitForGatewayEvent(t, sink, "backend_connected")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := controller.Stop(ctx, request.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("pending handshake was not closed: %v", err)
	}
}

func TestNativeTCPSSHEncryptsBothSegments(t *testing.T) {
	controller, listener, _, _ := pipeController(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	password := "ssh-password-never-plaintext"
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, received []byte) (*ssh.Permissions, error) {
		if string(received) != password {
			return nil, errors.New("password mismatch")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	backendWire, clientWire := &nativeWire{}, &nativeWire{}
	controller.dial = func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			server, channels, requests, err := ssh.NewServerConn(b, serverConfig)
			if err != nil {
				return
			}
			defer server.Close()
			go ssh.DiscardRequests(requests)
			for channel := range channels {
				conn, requests, err := channel.Accept()
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}
		}()
		return tcpPipe{recordedNativeConn{Conn: a, wire: backendWire}}, nil
	}
	if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
		t.Fatal(err)
	}
	conn := recordedNativeConn{Conn: connectNative(t, listener), wire: clientWire}
	clientConfig := &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())}
	transport, channels, requests, err := ssh.NewClientConn(conn, "gateway.test:20000", clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(transport, channels, requests)
	defer client.Close()
	channel, messages, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(messages)
	payload := []byte("private-shell-command-output")
	if _, err := channel.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(channel, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("SSH echo: %s %v", got, err)
	}
	for segment, wire := range map[string]*nativeWire{"client-gateway": clientWire, "gateway-target": backendWire} {
		encoded := wire.snapshot()
		if bytes.Contains(encoded, payload) || bytes.Contains(encoded, []byte(password)) {
			t.Fatalf("%s exposed SSH data", segment)
		}
	}
}

func TestNativeTCPRejectsPlaintextAndNonTLSMySQL(t *testing.T) {
	for _, scenario := range []string{"http", "binary", "fake TLS prefix", "mysql login", "mysql target without TLS"} {
		t.Run(scenario, func(t *testing.T) {
			controller, listener, _, sink := pipeController(t)
			wire := &nativeWire{}
			controller.dial = func(context.Context, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					if scenario == "mysql login" || scenario == "mysql target without TLS" {
						_, _ = b.Write(mysqlGreeting(scenario == "mysql login"))
					}
					_, _ = io.Copy(io.Discard, b)
				}()
				return tcpPipe{recordedNativeConn{Conn: a, wire: wire}}, nil
			}
			if _, err := controller.Start(context.Background(), nativeRequest()); err != nil {
				t.Fatal(err)
			}
			conn := connectNative(t, listener)
			if scenario == "mysql login" {
				if _, err := readMySQLPacket(conn, 4096); err != nil {
					t.Fatal(err)
				}
				_, _ = conn.Write(append([]byte{64, 0, 0, 1}, bytes.Repeat([]byte{'p'}, 64)...))
			} else if scenario == "fake TLS prefix" {
				body := append([]byte{3, 3}, bytes.Repeat([]byte{'x'}, 32)...)
				body = append(body, 0, 0, 0, 1, 0)
				_, _ = conn.Write(nativeTestRecord(22, append([]byte{1, 0, 0, byte(len(body))}, body...)))
			} else if scenario == "binary" {
				_, _ = conn.Write([]byte{0, 0xff, 1, 2, 3})
			} else if scenario != "mysql target without TLS" {
				_, _ = conn.Write([]byte("GET /password=plaintext-secret HTTP/1.1\r\n\r\n"))
			}
			_, _ = conn.Read(make([]byte, 1))
			waitForGatewayEvent(t, sink, "auth_rejected")
			if bytes.Contains(wire.snapshot(), []byte("plaintext-secret")) || bytes.Contains(wire.snapshot(), bytes.Repeat([]byte{'p'}, 8)) {
				t.Fatal("plaintext credentials reached the backend")
			}
		})
	}
}

func TestNativeTCPAccessLimitsRevocationAndTTL(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "revoke"
		if expire {
			name = "ttl"
		}
		t.Run(name, func(t *testing.T) {
			controller, listener, _, sink := pipeController(t)
			serverConfig, clientConfig := nativeTLSConfigs(t, tls.VersionTLS13)
			count, _ := nativeTLSBackend(t, controller, serverConfig, false, nil)
			request := nativeRequest()
			if expire {
				request.TTLSeconds = 2
			}
			if _, err := controller.Start(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			var connections []net.Conn
			for i := 0; i < gateway.MaxSessionConnections; i++ {
				conn := connectNativeTLS(t, listener, clientConfig, false, nil)
				nativeEcho(t, conn, []byte("encrypted"))
				connections = append(connections, conn)
			}
			rejected := connectNative(t, listener)
			if _, err := rejected.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("capacity rejection: %v", err)
			}
			waitForGatewayEvent(t, sink, "capacity_rejected")
			if count.Load() != gateway.MaxSessionConnections {
				t.Fatal("capacity exceeded")
			}
			if !expire {
				if _, err := controller.Stop(context.Background(), request.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			for _, conn := range connections {
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("connection still active")
				}
			}
			status, err := controller.Status(context.Background(), request.SessionID)
			want := "not_found"
			if expire {
				want = sessionExpired
			}
			if err != nil || status.Status != want {
				t.Fatalf("closed status: %+v %v", status, err)
			}
		})
	}
}

func TestNativeTCPSourceAndAuditFailures(t *testing.T) {
	for _, failure := range []string{"source", "connect_attempt", "backend_connected"} {
		t.Run(failure, func(t *testing.T) {
			controller, listener, count, sink := pipeController(t)
			request := nativeRequest()
			if failure == "source" {
				request.SourceIP = "127.0.0.2"
			} else {
				sink.failType = failure
			}
			if _, err := controller.Start(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			conn := connectNative(t, listener)
			if _, err := conn.Write([]byte("must not reach backend")); err == nil {
				t.Fatal("rejected connection forwarded data")
			}
			wantDials := int32(0)
			if failure == "backend_connected" {
				wantDials = 1
			}
			if count.Load() != wantDials {
				t.Fatalf("unexpected backend dials: %d", count.Load())
			}
		})
	}
}

func TestNativeTCPRestartPreservesAuthority(t *testing.T) {
	ctx := context.Background()
	first, _, _, _ := pipeController(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStateStore(filepath.Join(directory, "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{3306}}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(first, store, catalog, time.Hour, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	request := nativeRequest()
	response, err := manager.Start(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	second, listener, _, _ := pipeController(t)
	serverConfig, clientConfig := nativeTLSConfigs(t, tls.VersionTLS13)
	nativeTLSBackend(t, second, serverConfig, false, nil)
	restarted, err := NewManager(second, store, catalog, time.Hour, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := store.Load(ctx)
	if err != nil || len(records) != 1 || records[0].ConnectionMode != gateway.ConnectionModeNative || records[0].SourceIP != request.SourceIP || records[0].ClientPublicKey != "" {
		t.Fatalf("persisted authority changed: %+v %v", records, err)
	}
	replayed, err := restarted.Start(ctx, request)
	if err != nil || replayed.ConnectionMode != gateway.ConnectionModeNative || replayed.ServerCertificate != "" || replayed.ExternalPort != response.ExternalPort || !replayed.ExpiresAt.Equal(response.ExpiresAt) {
		t.Fatalf("restart changed native authority: %+v %v", replayed, err)
	}
	nativeEcho(t, connectNativeTLS(t, listener, clientConfig, false, nil), []byte("restored"))
	for _, mode := range []string{gateway.ConnectionModeDirect, "", gateway.ConnectionModeTunnel} {
		changed := request
		changed.ConnectionMode = mode
		if _, err := restarted.Start(ctx, changed); err == nil {
			t.Fatalf("replay downgraded to %q", mode)
		}
	}
	for _, field := range []string{"source", "ttl"} {
		changed := request
		if field == "source" {
			changed.SourceIP = "127.0.0.2"
		} else {
			changed.TTLSeconds++
		}
		if _, err := restarted.Start(ctx, changed); err == nil {
			t.Fatalf("replay changed %s", field)
		}
	}
	status, err := restarted.Get(ctx, request.SessionID)
	if err != nil || status.ConnectionMode != gateway.ConnectionModeNative {
		t.Fatalf("recovered status: %+v %v", status, err)
	}
}
