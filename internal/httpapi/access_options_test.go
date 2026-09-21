package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srex-run/access-gateway/internal/service"
)

type accessOptionsBackend struct {
	backendStub
	options service.AccessOptions
	actor   string
}

func (b *accessOptionsBackend) GetAccessOptions(_ context.Context, actor string) (service.AccessOptions, error) {
	b.actor = actor
	return b.options, nil
}

func TestAccessOptionsExposeDemoPolicyToAuthenticatedUsers(t *testing.T) {
	for _, demo := range []bool{false, true} {
		backend := &accessOptionsBackend{options: service.AccessOptions{ClientAccessEnabled: true, DemoMode: demo, DemoSessionTTLSeconds: 300}}
		server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
		request := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/access-options", nil)
		request.Header.Set("X-User-ID", testUserID)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != http.StatusOK || backend.actor != testUserID {
			t.Fatalf("access options status=%d actor=%q body=%s", response.Code, backend.actor, response.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["demo_mode"] != demo || body["demo_session_ttl_seconds"] != float64(300) || body["client_access_enabled"] != true {
			t.Fatalf("unexpected browser policy: %#v", body)
		}
	}
}

func TestAccessOptionsDemoModeStillRequiresAuthorization(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		backend := &accessOptionsBackend{options: service.AccessOptions{DemoMode: true, DemoSessionTTLSeconds: 300}}
		backend.authorizeErr = service.ErrForbidden
		server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
		request := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/access-options", nil)
		status := http.StatusUnauthorized
		if !anonymous {
			request.Header.Set("X-User-ID", testUserID)
			status = http.StatusForbidden
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != status || backend.actor != "" {
			t.Fatalf("unauthorized policy read: status=%d actor=%q", response.Code, backend.actor)
		}
	}
}
