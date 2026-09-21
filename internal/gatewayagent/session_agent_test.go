package gatewayagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

func TestSingleSessionAgentEncryptedTrafficScopedManagementAndShutdown(t *testing.T) {
	testSessionAgentTraffic(t, nil, false)
}

func TestSingleSessionHostAgentEncryptedTrafficScopedManagementAndShutdown(t *testing.T) {
	testHostSessionAgentTraffic(t, false)
}

func TestSingleSessionHostAgentProtocolAuditAndShutdown(t *testing.T) {
	testHostSessionAgentTraffic(t, true)
}

func testHostSessionAgentTraffic(t *testing.T, audited bool) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	management, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	network := &SessionNetwork{ListenerHost: "127.0.0.1", ListenerPort: listener.Addr().(*net.TCPAddr).Port, ManagementPort: management.Addr().(*net.TCPAddr).Port}
	_ = listener.Close()
	_ = management.Close()
	testSessionAgentTraffic(t, network, audited)
}

func testSessionAgentTraffic(t *testing.T, network *SessionNetwork, audited bool) {
	t.Helper()
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "approved target") }))
	defer backend.Close()
	host, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
	targetPort, _ := strconv.Atoi(port)
	var events, operations atomic.Int32
	credentials, _ := gatewayauth.NewSessionCredentials(make([]byte, 32))
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !credentials.Verify(r.Header.Get(gateway.AuditGatewayIDHeader), r.Header.Get(gatewayauth.SessionIDHeader), r.Header.Get(gateway.AuditSecretHeader), time.Now()) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/operations/batch") {
			var batch operationaudit.SessionBatch
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ids := make([]string, len(batch.Events))
			for i, event := range batch.Events {
				if event.Protocol != "http" || event.ConnectionID == "" || event.AssetID != testGatewayTargetID || event.NormalizedOperation == nil || *event.NormalizedOperation != "GET /" {
					t.Error("unexpected operation evidence")
				}
				ids[i] = event.EventID
				operations.Add(1)
			}
			_ = json.NewEncoder(w).Encode(gateway.ConnectionEventBatchResponse{Version: gateway.ConnectionEventBatchResponseVersion, AcceptedEventIDs: ids})
			return
		}
		var batch gateway.ConnectionEventBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ids := make([]string, len(batch.Events))
		for i, event := range batch.Events {
			ids[i] = event.EventID
			events.Add(1)
		}
		_ = json.NewEncoder(w).Encode(gateway.ConnectionEventBatchResponse{Version: gateway.ConnectionEventBatchResponseVersion, AcceptedEventIDs: ids})
	}))
	defer collector.Close()
	started := time.Now().UTC().Truncate(time.Second)
	cfg := SessionConfig{Version: 1, GatewayID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", TargetHost: host, StartedAt: started, ExpiresAt: started.Add(time.Minute),
		Request:         gateway.CreateSessionRequest{SessionID: testGatewaySessionID, TargetID: testGatewayTargetID, TargetPort: targetPort, SourceIP: "127.0.0.1", TargetAccount: "test", ConnectionMode: "native", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections},
		ControlPlaneURL: collector.URL, AuditAllowHTTP: true}
	if audited {
		pair := backend.TLS.Certificates[0]
		key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw}))
		cfg.Proxy = &sessionproxy.Config{Name: "https", Selector: sessionproxy.ProfileLabel + "=https", Protocol: "http", Port: targetPort, AuditEnabled: true,
			Certificate: cert, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})), TargetCA: cert}
		cfg.Request.ConnectionMode, cfg.Request.AuditPolicy = gateway.ConnectionModeAudit, cfg.Proxy.Policy()
	}
	cfg.Network = network
	managementAddress, listenerAddress := "127.0.0.1:8090", "127.0.0.1:20000"
	if network != nil {
		managementAddress = cfg.ManagementAddress()
		listenerAddress = net.JoinHostPort(network.ListenerHost, strconv.Itoa(network.ListenerPort))
	}
	var err error
	cfg.Certificate, cfg.PrivateKey, err = NewSessionIdentity(cfg.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuditToken = credentials.Issue(cfg.GatewayID, cfg.Request.SessionID, cfg.ExpiresAt.Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	stateDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	go func() { defer close(finished); done <- RunSessionAgent(ctx, cfg, stateDirectory, zerolog.Nop()) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(25 * time.Second):
			t.Error("session agent cleanup timed out")
		}
	})
	tlsConfig, err := cfg.ManagementTLS(false)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	management := &http.Client{Transport: transport, Timeout: time.Second}
	ready := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err := management.Get("https://" + managementAddress + "/status")
		if err == nil {
			response.Body.Close()
			ready = response.StatusCode == http.StatusOK
			if ready {
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("agent exited before ready: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("session agent never became ready")
	}
	foreign := cfg
	foreign.Certificate, foreign.PrivateKey, err = NewSessionIdentity(cfg.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	foreignTLS, _ := foreign.ManagementTLS(false)
	foreignTLS.RootCAs = tlsConfig.RootCAs
	foreignTransport := &http.Transport{TLSClientConfig: foreignTLS}
	defer foreignTransport.CloseIdleConnections()
	if response, err := (&http.Client{Transport: foreignTransport, Timeout: time.Second}).Post("https://"+managementAddress+"/stop", "application/json", nil); err == nil {
		response.Body.Close()
		t.Fatal("another session identity could stop the agent")
	}
	pool := x509.NewCertPool()
	pool.AddCert(backend.Certificate())
	dataTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer dataTransport.CloseIdleConnections()
	response, err := (&http.Client{Transport: dataTransport, Timeout: 3 * time.Second}).Get("https://" + listenerAddress + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "approved target" || events.Load() < 2 {
		t.Fatalf("encrypted forwarding / audit: %q %v events=%d", body, err, events.Load())
	}
	response, err = management.Post("https://"+managementAddress+"/stop", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("stop status=%d", response.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after closing its one session")
	}
	if audited && operations.Load() != 2 {
		t.Fatalf("agent exited without started/completed operation evidence: %d", operations.Load())
	}
	if connection, err := net.DialTimeout("tcp", listenerAddress, time.Second); err == nil {
		connection.Close()
		t.Fatal("session port remained open")
	}
}
