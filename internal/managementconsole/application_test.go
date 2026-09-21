package managementconsole

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestApplicationServesFrontend(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":    {Data: []byte("<html>gateway frontend</html>")},
		"assets/app.js": {Data: []byte("console.log('gateway')")},
		"favicon.svg":   {Data: []byte("<svg></svg>")},
	}
	handler, err := NewApplicationHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("frontend request reached the API")
	}), assets)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/", 200, "<html>gateway frontend</html>"},
		{http.MethodGet, "/admin/settings?tab=github", 200, "<html>gateway frontend</html>"},
		{http.MethodGet, "/sessions/session-1", 200, "<html>gateway frontend</html>"},
		{http.MethodHead, "/sessions/session-1", 200, ""},
		{http.MethodGet, "/assets/app.js", 200, "console.log('gateway')"},
		{http.MethodGet, "/favicon.svg", 200, "<svg></svg>"},
		{http.MethodGet, "/assets/", 404, "404 page not found\n"},
		{http.MethodGet, "/assets/missing.js", 404, "404 page not found\n"},
		{http.MethodGet, "/missing.js", 404, "404 page not found\n"},
		{http.MethodPost, "/admin/settings", 405, "method not allowed\n"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != tc.status || response.Body.String() != tc.body {
				t.Fatalf("response = %d %q, want %d %q", response.Code, response.Body.String(), tc.status, tc.body)
			}
			if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'self'") || response.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatal("frontend security headers are missing")
			}
			if tc.status == 200 && strings.Contains(tc.body, "<html>") && response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("SPA entry must not be cached")
			}
		})
	}
}

func TestApplicationPreservesBackendRequests(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPatch, "/api/v1/admin/settings", http.StatusOK},
		{http.MethodGet, "/api/v1/auth/github/callback?code=test", http.StatusFound},
		{http.MethodGet, "/api/unknown", http.StatusNotFound},
		{http.MethodPost, "/internal/gateway/heartbeat", http.StatusAccepted},
		{http.MethodPost, "/internal/audit/events", http.StatusAccepted},
		{http.MethodPost, "/callbacks/feishu", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusServiceUnavailable},
		{http.MethodGet, "/metrics", http.StatusUnauthorized},
		{http.MethodPost, "/api", http.StatusNotFound},
		{http.MethodPost, "/internal", http.StatusNotFound},
		{http.MethodPost, "/callbacks", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, "https://gateway.example.com"+tc.path, strings.NewReader(`{"encrypted":"payload"}`))
			request.RemoteAddr = "192.0.2.1:12345"
			request.Header.Set("Origin", "https://gateway.example.com")
			request.Header.Set("Authorization", "Bearer test-token")
			request.AddCookie(&http.Cookie{Name: "access_gateway_session", Value: "test-session"})
			called := false
			api := http.HandlerFunc(func(response http.ResponseWriter, got *http.Request) {
				called = true
				if got != request || got.Host != "gateway.example.com" || got.RemoteAddr != "192.0.2.1:12345" || got.TLS == nil {
					t.Error("backend request identity was changed")
				}
				if got.Header.Get("Origin") != "https://gateway.example.com" || got.Header.Get("Authorization") != "Bearer test-token" || got.Header.Get("Cookie") != "access_gateway_session=test-session" {
					t.Error("backend authentication headers were changed")
				}
				body, readErr := io.ReadAll(got.Body)
				if readErr != nil || string(body) != `{"encrypted":"payload"}` {
					t.Error("backend request body was changed")
				}
				response.Header().Set("Content-Type", "application/json")
				http.SetCookie(response, &http.Cookie{Name: "access_gateway_session", Value: "updated", HttpOnly: true, Secure: true})
				if tc.status == http.StatusFound {
					response.Header().Set("Location", "/sessions")
				}
				response.WriteHeader(tc.status)
				_, _ = response.Write([]byte(`{"from":"backend"}`))
			})
			handler, err := NewApplicationHandler(api, fstest.MapFS{"index.html": {Data: []byte("frontend")}})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !called || response.Code != tc.status || response.Body.String() != `{"from":"backend"}` {
				t.Fatalf("backend response was replaced: %d %q", response.Code, response.Body.String())
			}
			if response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Header().Get("Set-Cookie"), "HttpOnly; Secure") {
				t.Fatal("backend response headers were changed")
			}
			if tc.status == http.StatusFound && response.Header().Get("Location") != "/sessions" {
				t.Fatal("login redirect was changed")
			}
		})
	}
}

func TestApplicationRejectsMissingComponents(t *testing.T) {
	api := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := NewApplicationHandler(nil, fstest.MapFS{"index.html": {Data: []byte("frontend")}}); err == nil {
		t.Fatal("missing API handler must fail at startup")
	}
	for _, assets := range []fstest.MapFS{nil, {}, {"assets/app.js": {Data: []byte("app")}}} {
		if _, err := NewApplicationHandler(api, assets); err == nil {
			t.Fatal("missing frontend build must fail at startup")
		}
	}
}
