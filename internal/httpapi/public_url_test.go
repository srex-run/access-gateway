package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/publicurl"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestPublicURLControlsBrowserOriginAndSessionCookies(t *testing.T) {
	for _, origin := range []string{"https://access.example.test:8443", "http://localhost:9527", "http://[::1]:9527"} {
		t.Run(origin, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
			server.publicOrigin, _ = publicurl.Parse(origin)
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/local/login", nil)
			request.Header.Set("X-Forwarded-Proto", "http")
			request.Header.Set("X-Forwarded-Host", "untrusted.example.test")
			if !server.sameRequestOrigin(request, origin) || !server.sameRequestOrigin(request, origin+"/login") {
				t.Fatal("public browser origin rejected behind an internal proxy")
			}
			for _, source := range []string{"http://127.0.0.1:8080", "https://untrusted.example.test", "null", "", origin + ".evil.test"} {
				if server.sameRequestOrigin(request, source) {
					t.Fatalf("unconfigured browser origin accepted: %s", source)
				}
			}
			request.Header.Set("Origin", origin)
			encryptTestRequest(t, server, request, `{"username":"alice","password":"correct-password"}`)
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("public origin login = %d: %s", response.Code, response.Body)
			}
			secure := strings.HasPrefix(origin, "https://")
			for _, cookie := range response.Result().Cookies() {
				if cookie.Secure != secure {
					t.Fatal("session cookie security depended on an internal proxy header")
				}
			}
			request.Header.Set("X-Forwarded-Proto", "https")
			response = httptest.NewRecorder()
			user := domain.User{ID: testUserID, AuthVersion: 3}
			restfulRequest, restfulResponse := restful.NewRequest(request), restful.NewResponse(response)
			server.setPendingMFA(restfulRequest, restfulResponse, &service.PendingMFA{Token: strings.Repeat("a", 43)})
			server.setVerifiedSession(restfulRequest, restfulResponse, user)
			request.AddCookie(&http.Cookie{Name: mfaCookieName, Value: strings.Repeat("a", 43)})
			server.clearPendingMFA(restfulRequest, restfulResponse)
			for _, cookie := range response.Result().Cookies() {
				if cookie.Secure != secure {
					t.Fatal("MFA cookie security diverged from PUBLIC_URL")
				}
			}
		})
	}
}
