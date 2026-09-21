package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/terminal"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type terminalBackendStub struct {
	backendStub
	checks, opens int
}

type preflightBackend struct {
	terminalBackendStub
	err error
}

func (b *preflightBackend) AuthorizeTerminal(context.Context, string, string) (time.Time, error) {
	b.checks++
	return time.Now().Add(time.Minute), b.err
}

func TestWebTerminalPreflightReportsDenialWithoutOpeningWorker(t *testing.T) {
	for _, sample := range []struct {
		name      string
		err       error
		anonymous bool
		status    int
	}{
		{name: "ready", status: http.StatusOK},
		{name: "expired or not owner", err: service.ErrForbidden, status: http.StatusForbidden},
		{name: "logged out", anonymous: true, status: http.StatusUnauthorized},
	} {
		t.Run(sample.name, func(t *testing.T) {
			backend := &preflightBackend{err: sample.err}
			var logs bytes.Buffer
			server := testServer(t, backend, func(s *Server) {
				s.AllowDevAuth = true
				s.Logger = zerolog.New(&logs)
				s.Transport = newMemoryTransport(t)
			})
			req := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/sessions/"+testSessionID+"/terminal/preflight", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Origin", "http://localhost")
			if !sample.anonymous {
				req.Header.Set("X-User-ID", testUserID)
			}
			res := httptest.NewRecorder()
			server.Container().ServeHTTP(res, req)
			if res.Code != sample.status || backend.opens != 0 {
				t.Fatalf("status=%d opens=%d body=%s", res.Code, backend.opens, res.Body.String())
			}
			if sample.status >= 400 && (!strings.Contains(logs.String(), testSessionID) || !strings.Contains(logs.String(), "terminal_http")) {
				t.Fatal("HTTP denial was not logged with session scope")
			}
		})
	}
}

// Real HTTP upgrades and WebSocket frames over an in-memory connection keep
// this security/bridge test independent of a local listen permission.
type oneTerminalListener struct {
	conn     net.Conn
	accepted bool
	closed   chan struct{}
	once     sync.Once
}

func (l *oneTerminalListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *oneTerminalListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }
func (l *oneTerminalListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

type terminalPeerConn struct{ net.Conn }

func (c terminalPeerConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func dialMemoryTerminal(t *testing.T, handler http.Handler, headers http.Header) *websocket.Conn {
	t.Helper()
	left, right := net.Pipe()
	listener := &oneTerminalListener{conn: terminalPeerConn{right}, closed: make(chan struct{})}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close(); _ = server.Close() })
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second, NetDialContext: func(context.Context, string, string) (net.Conn, error) { return left, nil }}
	socket, response, err := dialer.Dial("ws://localhost/api/v1/sessions/"+testSessionID+"/terminal", headers)
	if err != nil {
		t.Fatalf("WebSocket upgrade failed: %v response=%v", err, response)
	}
	return socket
}

type liveTerminalBackend struct {
	backendStub
	socket *websocket.Conn
}

func (s *liveTerminalBackend) AuthorizeTerminal(context.Context, string, string) (time.Time, error) {
	return time.Now().Add(time.Minute), nil
}
func (s *liveTerminalBackend) OpenTerminal(context.Context, string, string, string) (*websocket.Conn, error) {
	return s.socket, nil
}

func TestWebTerminalBridgesWorkerFramesAndClosesOnDisconnect(t *testing.T) {
	received := make(chan string, 1)
	closed := make(chan struct{})
	upstream := dialMemoryTerminal(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrade := websocket.Upgrader{}
		socket, err := upgrade.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		defer close(closed)
		_, data, err := socket.ReadMessage()
		if err != nil {
			return
		}
		received <- string(data)
		if socket.WriteJSON(terminal.Message{Type: "ready"}) != nil {
			return
		}
		if socket.WriteMessage(websocket.BinaryMessage, []byte("worker-output")) != nil {
			return
		}
		_, _, _ = socket.ReadMessage()
	}), nil)
	backend := &liveTerminalBackend{socket: upstream}
	server := testServer(t, backend, func(s *Server) {
		s.AllowDevAuth = true
		s.LoginAttempts = &attemptStub{true}
	})
	// Production wraps the API in OpenTelemetry middleware. Exercise it with
	// the compression headers sent by browsers, not just the bare container.
	traced := otelhttp.NewHandler(server.Container(), "access-gateway.http")
	handled := make(chan struct{}, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { handled <- struct{}{} }()
		traced.ServeHTTP(w, r)
	})
	headers := http.Header{"Origin": []string{"http://localhost"}, "X-User-Id": []string{testUserID}, "Accept-Encoding": []string{"gzip, deflate, br"}}
	const first = `{"type":"start","password":"ephemeral-only","cols":80,"rows":24}`
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/sessions/"+testSessionID+"/terminal", nil)
	request.Header.Set("X-User-ID", testUserID)
	encryptTestRequest(t, server, request, first)
	sealed, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	plainBrowser := dialMemoryTerminal(t, handler, headers)
	_ = plainBrowser.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := plainBrowser.WriteMessage(websocket.TextMessage, []byte(first)); err != nil {
		t.Fatal(err)
	}
	var rejected terminal.Message
	if err := plainBrowser.ReadJSON(&rejected); err != nil || rejected.Type != "error" {
		t.Fatalf("plaintext WebSocket login was not rejected: %v", err)
	}
	_ = plainBrowser.Close()
	browser := dialMemoryTerminal(t, handler, headers)
	defer browser.Close()
	_ = browser.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := browser.WriteMessage(websocket.TextMessage, sealed); err != nil {
		t.Fatal(err)
	}
	var ready terminal.Message
	if err := browser.ReadJSON(&ready); err != nil || ready.Type != "ready" {
		t.Fatalf("worker did not signal shell readiness: %v", err)
	}
	typeID, output, err := browser.ReadMessage()
	if err != nil || typeID != websocket.BinaryMessage || string(output) != "worker-output" {
		t.Fatalf("worker frame: %d %q %v", typeID, output, err)
	}
	select {
	case got := <-received:
		if got != first {
			t.Fatal("initial frame changed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not receive input")
	}
	_ = browser.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("worker connection survived browser disconnect")
	}
	for range 2 {
		select {
		case <-handled:
		case <-time.After(3 * time.Second):
			t.Fatal("terminal handler did not finish")
		}
	}
}

func TestWebTerminalUpgradeLogsReasonAndHTTPMetadataWithoutCredentials(t *testing.T) {
	for _, sample := range []struct {
		name, header, value, reason string
		status                      int
	}{
		{"missing connection upgrade", "Connection", "keep-alive", "'upgrade' token not found in 'Connection' header", http.StatusBadRequest},
		{"missing websocket upgrade", "Upgrade", "", "'websocket' token not found in 'Upgrade' header", http.StatusUpgradeRequired},
		{"unsupported version", "Sec-WebSocket-Version", "12", "unsupported version", http.StatusBadRequest},
		{"missing handshake key", "Sec-WebSocket-Key", "", "'Sec-WebSocket-Key' header", http.StatusBadRequest},
		{"writer cannot hijack", "", "", "hijack", http.StatusInternalServerError},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var logs bytes.Buffer
			backend := &preflightBackend{}
			server := testServer(t, backend, func(s *Server) {
				s.AllowDevAuth = true
				s.LoginAttempts = &attemptStub{true}
				s.Transport = newMemoryTransport(t)
				s.Logger = zerolog.New(&logs)
			})
			req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/sessions/"+testSessionID+"/terminal", strings.NewReader(`{"private_key":"must-not-log-private-key","password":"must-not-log-password"}`))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://localhost")
			req.Header.Set("X-User-ID", testUserID)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set("Sec-WebSocket-Protocol", "must-not-log-protocol-token")
			req.Header.Set("Authorization", "Bearer must-not-log-authorization")
			req.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: "must-not-log-cookie"})
			if sample.header != "" {
				req.Header.Set(sample.header, sample.value)
			}
			res := httptest.NewRecorder()
			server.Container().ServeHTTP(res, req)
			if res.Code != sample.status || backend.opens != 0 {
				t.Fatalf("status=%d opens=%d", res.Code, backend.opens)
			}
			var record map[string]any
			if err := json.NewDecoder(&logs).Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record["stage"] != "websocket_upgrade" || record["session_id"] != testSessionID || record["http_status"] != float64(sample.status) {
				t.Fatalf("missing handshake context: %v", record)
			}
			if detail, ok := record["error"].(string); !ok || !strings.Contains(detail, sample.reason) {
				t.Fatalf("missing failure reason: %v", record)
			}
			if record["connection"] != req.Header.Get("Connection") || record["upgrade"] != req.Header.Get("Upgrade") || record["http_proto"] != "HTTP/1.1" || record["response_writer"] == "" {
				t.Fatal("missing diagnostic metadata")
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"must-not-log-", "dGhlIHNhbXBsZSBub25jZQ=="} {
				if bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("credential material appeared in upgrade log")
				}
			}
		})
	}
}

func TestWebTerminalChallengeUsesTheSharedEncryptedTransport(t *testing.T) {
	server := testServer(t, &backendStub{}, func(s *Server) {
		s.AllowDevAuth = true
		s.LoginAttempts = &attemptStub{true}
		s.Transport = newMemoryTransport(t)
	})
	path := "/api/v1/sessions/" + testSessionID + "/terminal"
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/auth/transport/challenges", strings.NewReader(`{"method":"GET","path":"`+path+`"}`))
	request.Header.Set("X-User-ID", testUserID)
	request.Header.Set("Origin", "http://localhost")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	var challenge securetransport.Challenge
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &challenge) != nil {
		t.Fatalf("terminal encryption challenge: %d %s", response.Code, response.Body.String())
	}
	if challenge.Method != http.MethodGet || challenge.Path != path || challenge.Subject != "user:"+testUserID || challenge.PublicKey == "" {
		t.Fatal("terminal challenge is not bound to the current user and WebSocket path")
	}
}

func TestWebTerminalEncryptedStartRejectsPlaintextTamperReplayAndWrongBinding(t *testing.T) {
	memory := newMemoryTransport(t)
	server := &Server{Transport: memory}
	binding := securetransport.Binding{Method: http.MethodGet, Path: "/api/v1/sessions/" + testSessionID + "/terminal", Subject: "user:" + testUserID}
	const first = `{"type":"start","private_key":"ephemeral-key","passphrase":"ephemeral-passphrase","cols":80,"rows":24}`
	for _, sample := range []string{"valid", "plaintext", "tampered", "replay", "actor", "path", "expired", "invalid start", "extra plaintext"} {
		t.Run(sample, func(t *testing.T) {
			ctx := context.Background()
			challenge, err := memory.Create(ctx, binding)
			if err != nil {
				t.Fatal(err)
			}
			input := first
			if sample == "invalid start" {
				input = `{"type":"input","data":"not a login"}`
			}
			envelope, _, err := testclient.Seal(challenge, []byte(input))
			if err != nil {
				t.Fatal(err)
			}
			attempt := binding
			switch sample {
			case "tampered":
				envelope.Envelope.Ciphertext[0] ^= 1
			case "actor":
				attempt.Subject = "user:another-user"
			case "path":
				attempt.Path = "/api/v1/sessions/another-session/terminal"
			case "expired":
				challenge.ExpiresAt = time.Now().Add(-time.Second)
				memory.challenges[challenge.ID] = challenge
			}
			data, _ := json.Marshal(envelope)
			if sample == "plaintext" {
				data = []byte(first)
			}
			if sample == "extra plaintext" {
				data = append(data[:len(data)-1], []byte(`,"password":"must-be-rejected"}`)...)
			}
			if sample == "replay" {
				plaintext, err := server.openTerminalStart(ctx, attempt, data)
				clear(plaintext)
				if err != nil {
					t.Fatal(err)
				}
			}
			plaintext, err := server.openTerminalStart(ctx, attempt, data)
			defer clear(plaintext)
			if sample == "valid" {
				if err != nil || string(plaintext) != first {
					t.Fatal("encrypted credentials did not round-trip")
				}
			} else if !errors.Is(err, securetransport.ErrInvalid) || plaintext != nil {
				t.Fatalf("unsafe initial frame accepted: %v", err)
			}
		})
	}
}

func (s *terminalBackendStub) AuthorizeTerminal(context.Context, string, string) (time.Time, error) {
	s.checks++
	return time.Time{}, service.ErrForbidden
}
func (s *terminalBackendStub) OpenTerminal(context.Context, string, string, string) (*websocket.Conn, error) {
	s.opens++
	return nil, service.ErrForbidden
}

func TestWebTerminalRejectsUnsafeOriginAndUnauthorizedSessions(t *testing.T) {
	for _, origin := range []string{"", "null", "https://attacker.example", "http://console.test", "https://console.test"} {
		t.Run(origin, func(t *testing.T) {
			backend := &terminalBackendStub{}
			server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true; s.publicOrigin, _ = url.Parse("https://console.test") })
			request := httptest.NewRequest(http.MethodGet, "https://console.test/api/v1/sessions/"+testSessionID+"/terminal", nil)
			request.Header.Set("X-User-ID", testUserID)
			request.Header.Set("Origin", origin)
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || backend.opens != 0 {
				t.Fatalf("unsafe terminal: %d opens=%d", response.Code, backend.opens)
			}
			if origin != "https://console.test" && backend.checks != 0 {
				t.Fatal("origin rejected after opening session")
			}
			if origin == "https://console.test" && backend.checks != 1 {
				t.Fatal("owner/session authorization was skipped")
			}
		})
	}
}
