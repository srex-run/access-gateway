package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/service"
)

type terminalDemoDefaultsBackend struct {
	backendStub
	value            service.TerminalDemoDefaults
	err              error
	calls            int
	actor, sessionID string
}

func (b *terminalDemoDefaultsBackend) GetTerminalDemoDefaults(_ context.Context, actor, sessionID string) (service.TerminalDemoDefaults, error) {
	b.calls++
	b.actor, b.sessionID = actor, sessionID
	return b.value, b.err
}

func TestTerminalDemoDefaultsRequiresEncryptedAuthorizedRequest(t *testing.T) {
	transport := newMemoryTransport(t)
	for _, sample := range []struct {
		name           string
		enabled        bool
		plaintext      bool
		anonymous      bool
		denyPermission bool
		denySession    bool
		body           string
		status         int
		calls          int
		encryptedReply bool
	}{
		{name: "enabled", enabled: true, status: http.StatusOK, calls: 1, encryptedReply: true},
		{name: "disabled", status: http.StatusOK, calls: 1, encryptedReply: true},
		{name: "plaintext", enabled: true, plaintext: true, status: http.StatusBadRequest},
		{name: "anonymous", anonymous: true, status: http.StatusUnauthorized},
		{name: "permission denied", denyPermission: true, status: http.StatusForbidden},
		{name: "not owner or expired", denySession: true, status: http.StatusForbidden, calls: 1, encryptedReply: true},
		{name: "body cannot enable demo", body: `{"enabled":true}`, status: http.StatusBadRequest, encryptedReply: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			backend := &terminalDemoDefaultsBackend{}
			if sample.enabled {
				backend.value = service.TerminalDemoDefaults{Enabled: true, Password: "123456", Database: "test"}
			}
			if sample.denySession {
				backend.err = service.ErrForbidden
			}
			var logs bytes.Buffer
			server := testServer(t, backend, func(s *Server) {
				s.AllowDevAuth = true
				s.LoginAttempts = &attemptStub{true}
				s.Transport = transport
				s.Logger = zerolog.New(&logs)
			})
			body := sample.body
			if body == "" {
				body = `{}`
			}
			request := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/sessions/"+testSessionID+"/terminal/demo-defaults", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://localhost")
			if !sample.anonymous {
				request.Header.Set("X-User-ID", testUserID)
			}
			var client *testclient.Client
			if !sample.plaintext && !sample.anonymous {
				client = encryptTestRequest(t, server, request, body)
			}
			if sample.denyPermission {
				backend.authorizeErr = service.ErrForbidden
			}
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != sample.status || backend.calls != sample.calls {
				t.Fatalf("status=%d calls=%d, want status=%d calls=%d", response.Code, backend.calls, sample.status, sample.calls)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("terminal defaults response must not be cached")
			}
			if sample.calls > 0 && (backend.actor != testUserID || backend.sessionID != testSessionID) {
				t.Fatal("terminal defaults lost actor/session scope")
			}
			if strings.Contains(response.Body.String(), "123456") || strings.Contains(logs.String(), "123456") {
				t.Fatal("demo password leaked outside encrypted response")
			}
			if (response.Header().Get("X-AG-Encrypted") == "1") != sample.encryptedReply {
				t.Fatal("unexpected response encryption")
			}
			if !sample.encryptedReply {
				return
			}
			plaintext, err := client.Open(response.Code, response.Body.Bytes())
			if err != nil {
				t.Fatalf("decrypt terminal defaults: %v", err)
			}
			defer clear(plaintext)
			if sample.status != http.StatusOK {
				return
			}
			var value map[string]any
			if err := json.Unmarshal(plaintext, &value); err != nil {
				t.Fatal(err)
			}
			if value["enabled"] != sample.enabled {
				t.Fatal("demo enabled state changed")
			}
			if sample.enabled {
				if value["password"] != "123456" || value["database"] != "test" {
					t.Fatal("encrypted demo defaults did not round trip")
				}
			} else if len(value) != 1 {
				t.Fatal("disabled demo mode disclosed defaults")
			}
		})
	}
}
