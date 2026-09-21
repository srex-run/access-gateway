package httpapi

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/service"
)

type memoryTransport struct {
	mu         sync.Mutex
	key        *rsa.PrivateKey
	public     string
	challenges map[string]securetransport.Challenge
}

func newMemoryTransport(t *testing.T) *memoryTransport {
	t.Helper()
	key, public, err := securetransport.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &memoryTransport{key: key, public: public, challenges: map[string]securetransport.Challenge{}}
}

func (m *memoryTransport) Create(_ context.Context, binding securetransport.Binding) (securetransport.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := securetransport.Challenge{ID: id.New(), KeyID: "test-key", Binding: binding, PublicKey: m.public,
		Algorithm: securetransport.Algorithm, ExpiresAt: time.Now().Add(2 * time.Minute)}
	m.challenges[c.ID] = c
	return c, nil
}

func (m *memoryTransport) Open(_ context.Context, binding securetransport.Binding, request securetransport.Request) ([]byte, *securetransport.Reply, error) {
	m.mu.Lock()
	c, ok := m.challenges[request.ChallengeID]
	if ok && c.Binding == binding && c.ExpiresAt.After(time.Now()) {
		delete(m.challenges, c.ID)
	} else {
		ok = false
	}
	m.mu.Unlock()
	if !ok {
		return nil, nil, securetransport.ErrInvalid
	}
	return securetransport.Open(m.key, c, request.Envelope)
}

func encryptTestRequest(t *testing.T, server *Server, request *http.Request, plaintext string) *testclient.Client {
	t.Helper()
	if server.Transport == nil {
		server.Transport = newMemoryTransport(t)
	}
	binding, ok := server.transportBinding(restful.NewRequest(request), restful.NewResponse(httptest.NewRecorder()), request.Method, request.URL.Path)
	if !ok {
		t.Fatal("cannot bind test request")
	}
	challenge, err := server.Transport.Create(request.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	envelope, client, err := testclient.Seal(challenge, []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", "application/json")
	return client
}

func TestTransportRejectsPlaintextTamperReplayAndActorMixup(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &cloudBackendStub{}
	server.Service = backend
	for _, sample := range []string{"plaintext", "tampered", "actor", "path", "expired", "replay"} {
		t.Run(sample, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/cloud-accounts", strings.NewReader(`{"password":"plaintext-secret"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-User-ID", testUserID)
			request.Header.Set("Origin", "http://console.test")
			if sample != "plaintext" {
				encryptTestRequest(t, server, request, `{"provider":"aws","access_key":"secret-ak","secret_key":"secret-sk"}`)
				var envelope securetransport.Request
				_ = json.NewDecoder(request.Body).Decode(&envelope)
				if sample == "tampered" {
					envelope.Envelope.Ciphertext[0] ^= 1
				}
				if sample == "actor" {
					request.Header.Set("X-User-ID", testApprovalID)
				}
				if sample == "path" {
					request.Method = http.MethodPatch
					request.URL.Path += "/" + testUserID
				}
				if sample == "expired" {
					memory := server.Transport.(*memoryTransport)
					value := memory.challenges[envelope.ChallengeID]
					value.ExpiresAt = time.Now().Add(-time.Second)
					memory.challenges[value.ID] = value
				}
				body, _ := json.Marshal(envelope)
				request.Body = io.NopCloser(bytes.NewReader(body))
				if sample == "replay" {
					first := httptest.NewRecorder()
					server.Container().ServeHTTP(first, request)
					if first.Code != 201 {
						t.Fatalf("initial request: %d", first.Code)
					}
					request.Body = io.NopCloser(bytes.NewReader(body))
				}
			}
			calls := backend.calls
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != 400 || backend.calls != calls {
				t.Fatalf("guard failed: status %d calls %d", response.Code, backend.calls-calls)
			}
		})
	}
}

func TestTransportChallengeRequiresCSRFAndTargetPermission(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.Transport = newMemoryTransport(t)
	for _, sample := range []struct {
		origin, path string
		status       int
	}{
		{"http://evil.test", "/api/v1/auth/local/login", 403},
		{"", "/api/v1/auth/local/login", 403},
		{"http://console.test", "/api/v1/admin/cloud-accounts", 401},
		{"http://console.test", "/api/v1/auth/local/login", 200},
		{"http://console.test", "/api/v1/auth/local/login?password=leak", 400},
	} {
		body, _ := json.Marshal(map[string]string{"method": "POST", "path": sample.path})
		request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/transport/challenges", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", sample.origin)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != sample.status {
			t.Fatalf("challenge: status %d expected %d", response.Code, sample.status)
		}
	}
}

func TestTransportProtectsEverySensitiveRouteAndRejectsAliases(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &cloudBackendStub{}
	server.Service = backend
	container := server.Container()
	reached := 0
	container.Filter(func(_ *restful.Request, response *restful.Response, _ *restful.FilterChain) {
		reached++
		response.WriteHeader(http.StatusInternalServerError)
	})
	for _, route := range []struct{ method, path string }{
		{"POST", "/auth/local/login"}, {"POST", "/auth/ldap/login"}, {"POST", "/auth/password"},
		{"PATCH", "/admin/settings"}, {"POST", "/admin/cloud-accounts"}, {"PATCH", "/admin/cloud-accounts/" + testUserID},
		{"POST", "/admin/assets"}, {"POST", "/admin/gateways/" + testUserID + "/release"},
		{"PATCH", "/admin/assets/" + testSessionID},
		{"POST", "/admin/users"},
		{"POST", "/admin/settings/audit/certificates"},
		{"POST", "/admin/assets/audit/certificates"},
		{"POST", "/sessions/" + testSessionID + "/terminal/demo-defaults"},
	} {
		for _, alias := range []string{route.path, route.path + "/", strings.Replace(route.path, "/", "//", 1), strings.Replace(route.path, "/a", "/%61", 1)} {
			request := httptest.NewRequest(route.method, "http://console.test/api/v1"+alias, strings.NewReader(`{"password":"secret"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("X-User-ID", testUserID)
			response := httptest.NewRecorder()
			container.ServeHTTP(response, request)
			// go-restful canonicalizes doubled slashes before container filters.
			// The canonical destination must still reject the same plaintext body.
			if response.Code == http.StatusTemporaryRedirect {
				target, err := request.URL.Parse(response.Header().Get("Location"))
				if err != nil || target.Host != request.URL.Host {
					t.Fatal("unsafe canonical redirect")
				}
				request.URL = target
				request.Body = io.NopCloser(strings.NewReader(`{"password":"secret"}`))
				response = httptest.NewRecorder()
				container.ServeHTTP(response, request)
			}
			if response.Code < 400 || reached != 0 || backend.calls != 0 || strings.Contains(response.Body.String(), "secret\"") {
				t.Fatalf("plaintext accepted for %s %s: status %d", route.method, alias, response.Code)
			}
		}
	}
}

func TestTransportKeepsStrictJSONAndSessionBinding(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &cloudBackendStub{}
	server.Service = backend
	for _, sample := range []struct {
		body          string
		replaceCookie bool
	}{
		{`{"name":"cloud","credentials_ciphertext":"injected"}`, false},
		{`{} {}`, false}, {`[]`, false},
		{`{"provider":"aws"}`, true},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/cloud-accounts", nil)
		request.Header.Set("X-User-ID", testUserID)
		request.Header.Set("Origin", "http://console.test")
		request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: "first-session"})
		encryptTestRequest(t, server, request, sample.body)
		if sample.replaceCookie {
			request.Header.Set("Cookie", server.SessionCookieName+"=second-session")
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != 400 || backend.calls != 0 {
			t.Fatalf("encrypted JSON/session guard: status %d", response.Code)
		}
	}
}

func TestTransportHTTPChallengeAndLoginAcrossReplicas(t *testing.T) {
	accounts := &accountStub{}
	first := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	second := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	first.Transport = newMemoryTransport(t)
	second.Transport = first.Transport
	request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/transport/challenges", strings.NewReader(`{"method":"POST","path":"/api/v1/auth/local/login"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.test")
	response := httptest.NewRecorder()
	first.Container().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("challenge: %d", response.Code)
	}
	var challenge securetransport.Challenge
	if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	envelope, client, err := testclient.Seal(challenge, []byte(`{"username":"alice","password":"correct-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(envelope)
	request = httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/local/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.test")
	request.RemoteAddr = "192.0.2.99:10000" // Another console replica may proxy the submission.
	response = httptest.NewRecorder()
	second.Container().ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("X-AG-Encrypted") != "1" || len(response.Result().Cookies()) != 1 {
		t.Fatalf("encrypted login: %d", response.Code)
	}
	if _, err := client.Open(response.Code, response.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if accounts.localCalls != 1 {
		t.Fatal("password checker was not called exactly once")
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	response = httptest.NewRecorder()
	first.Container().ServeHTTP(response, request)
	if response.Code != 400 || accounts.localCalls != 1 {
		t.Fatal("cross-replica replay accepted")
	}
}

func TestTransportChallengeChecksAuthorizationBeforeCreatingKeys(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &backendStub{authorizeErr: service.ErrForbidden}
	server.Service = backend
	request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/transport/challenges", strings.NewReader(`{"method":"PATCH","path":"/api/v1/admin/settings"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.test")
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatalf("unauthorized challenge: %d", response.Code)
	}
}

func TestEncryptedPasswordChangePreservesLogoutCookie(t *testing.T) {
	accounts := &accountStub{}
	server := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	request := httptest.NewRequest(http.MethodPost, "https://console.test/api/v1/auth/password", nil)
	request.Header.Set("Origin", "https://console.test")
	request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.Sign(testUserID, time.Now().Add(time.Hour))})
	client := encryptTestRequest(t, server, request, `{"current_password":"current-password","new_password":"new-password-123"}`)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != 200 || accounts.passwordCalls != 1 {
		t.Fatalf("password change: status %d calls %d", response.Code, accounts.passwordCalls)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("logout cookie lost during response encryption")
	}
	plaintext, err := client.Open(response.Code, response.Body.Bytes())
	if err != nil || !strings.Contains(string(plaintext), "logged_out") {
		t.Fatalf("password change response: %v", err)
	}
}
