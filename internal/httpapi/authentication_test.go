package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

type accountStub struct {
	AuthenticationService
	sessionErr    error
	localCalls    int
	passwordCalls int
	syncCalls     int
	bindCalls     int
	boundUser     string
	boundVersion  int64
	lastProfile   authn.Profile
	account       service.Account
}

func (a *accountStub) GetAccount(context.Context, string) (service.Account, error) {
	return a.account, nil
}

func (a *accountStub) AuthenticateLocal(_ context.Context, username, password string) (domain.User, error) {
	a.localCalls++
	if username != "alice" || password != "correct-password" {
		return domain.User{}, service.ErrInvalidCredentials
	}
	return domain.User{ID: testUserID, Status: domain.UserStatusActive, AuthVersion: 3}, nil
}
func (a *accountStub) ValidateBrowserSession(context.Context, string, int64) error {
	return a.sessionErr
}

func (a *accountStub) ChangePassword(_ context.Context, userID, current, next string) error {
	if userID != testUserID || current != "current-password" || next != "new-password-123" {
		return service.ErrInvalidCredentials
	}
	a.passwordCalls++
	return nil
}
func (a *accountStub) SyncExternalUser(_ context.Context, profile authn.Profile) (domain.User, error) {
	a.syncCalls++
	a.lastProfile = profile
	return domain.User{ID: testUserID, Status: domain.UserStatusActive}, nil
}

func (a *accountStub) BindFeishuUser(_ context.Context, userID string, version int64, _ feishu.Profile) error {
	a.bindCalls++
	a.boundUser, a.boundVersion = userID, version
	return nil
}

type attemptStub struct{ allowed bool }

func (a *attemptStub) Allow(context.Context, repository.DBTX, string, int) (bool, error) {
	return a.allowed, nil
}

type loginStateMemory struct {
	mu     sync.Mutex
	values map[string]time.Time
}

func (s *loginStateMemory) Create(_ context.Context, _ repository.DBTX, value domain.OAuthState) (domain.OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[value.StateHash] = value.ExpiresAt
	return value, nil
}
func (s *loginStateMemory) Consume(_ context.Context, _ repository.DBTX, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry := s.values[hash]
	delete(s.values, hash)
	return expiry.After(time.Now()), nil
}

type redirectStub struct {
	calls   int
	profile authn.Profile
}

func (*redirectStub) AuthorizationURL(state, nonce, verifier string) (string, error) {
	return "https://auth.example.test/authorize?state=" + url.QueryEscape(state), nil
}
func (p *redirectStub) Exchange(_ context.Context, code, nonce, verifier string) (authn.Profile, error) {
	p.calls++
	if p.profile.Provider != "" {
		return p.profile, nil
	}
	return authn.Profile{Provider: "oidc", Issuer: "https://auth.example.test", Subject: "subject", Nickname: "Example"}, nil
}

func newAuthServer(t *testing.T, accounts *accountStub, attempts *attemptStub, states *loginStateMemory, provider *redirectStub) *Server {
	t.Helper()
	signer, _ := security.NewSessionSigner(strings.Repeat("s", 32))
	server, err := NewServerWithOptions(ServerOptions{Service: &backendStub{}, DB: databaseStub{}, Authentication: accounts,
		SessionSigner: signer, LoginAttempts: attempts, OAuthStates: states, Logger: zerolog.Nop(),
		AuthConfig:        authn.Config{LocalEnabled: true, OIDC: authn.OIDCConfig{Enabled: true, Name: "Company SSO"}},
		RedirectProviders: map[string]authn.RedirectProvider{"oidc": provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestAccountFeishuConfigurationVisibility(t *testing.T) {
	for _, test := range []struct {
		name       string
		config     settings.FeishuConfig
		configured bool
	}{
		{"unconfigured", settings.FeishuConfig{}, false},
		{"incomplete", settings.FeishuConfig{AppID: "app"}, false},
		{"configured", settings.FeishuConfig{AppID: "app", TenantKey: "tenant"}, true},
		{"login only", settings.FeishuConfig{LoginEnabled: true}, true},
		{"binding", settings.FeishuConfig{BindingEnabled: true}, true},
		{"notifications only", settings.FeishuConfig{NotificationsEnabled: true}, true},
		{"callbacks only", settings.FeishuConfig{CallbacksEnabled: true}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			accounts := &accountStub{account: service.Account{UserID: testUserID, Username: "alice", Nickname: "小艾", Providers: []string{"github"}, FeishuBound: true}}
			server := newAuthServer(t, accounts, &attemptStub{allowed: true}, &loginStateMemory{}, &redirectStub{})
			request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/account", nil)
			request = request.WithContext(settings.WithSnapshot(request.Context(), &settings.Snapshot{Feishu: test.config}))
			request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.SignVersioned(testUserID, 0, time.Now().Add(time.Hour))})
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			var account struct {
				Username             string `json:"username"`
				Nickname             string `json:"nickname"`
				FeishuConfigured     bool   `json:"feishu_configured"`
				FeishuBindingEnabled bool   `json:"feishu_binding_enabled"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &account); err != nil || response.Code != http.StatusOK {
				t.Fatalf("account response: %d %s %v", response.Code, response.Body, err)
			}
			if account.FeishuConfigured != test.configured || account.FeishuBindingEnabled != test.config.BindingEnabled || account.Username != "alice" || account.Nickname != "小艾" {
				t.Fatalf("account configuration: %+v", account)
			}
		})
	}
}

func TestPasswordLoginRequiresSameOriginAndLimitsAttempts(t *testing.T) {
	accounts := &accountStub{}
	attempts := &attemptStub{allowed: true}
	server := newAuthServer(t, accounts, attempts, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
	for _, test := range []struct {
		origin, password string
		allowed          bool
		status           int
	}{
		{"http://console.test", "correct-password", true, 200},
		{"http://console.test", "wrong-password", true, 401},
		{"", "correct-password", true, 403},
		{"http://attacker.test", "correct-password", true, 403},
		{"http://console.test", "correct-password", false, 429},
	} {
		attempts.allowed = test.allowed
		request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/local/login", strings.NewReader(`{"username":"alice","password":"`+test.password+`"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", test.origin)
		encryptTestRequest(t, server, request, `{"username":"alice","password":"`+test.password+`"}`)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("login status = %d, want %d: %s", response.Code, test.status, response.Body)
		}
		if test.status == 200 {
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatal("missing protected session cookie")
			}
			userID, version, ok := server.SessionSigner.VerifyVersioned(cookies[0].Value, time.Now())
			if !ok || userID != testUserID || version != 3 {
				t.Fatal("incorrect session identity")
			}
		} else if len(response.Result().Cookies()) != 0 {
			t.Fatal("failed login issued a session")
		}
	}
	if accounts.localCalls != 2 {
		t.Fatalf("blocked requests reached password checker: %d", accounts.localCalls)
	}
}

func TestOAuthStateSurvivesReplicaSwitchAndRejectsReplayAndMixup(t *testing.T) {
	accounts := &accountStub{}
	states := &loginStateMemory{values: map[string]time.Time{}}
	provider := &redirectStub{}
	first := newAuthServer(t, accounts, &attemptStub{true}, states, provider)
	second := newAuthServer(t, accounts, &attemptStub{true}, states, provider)
	begin := httptest.NewRecorder()
	first.Container().ServeHTTP(begin, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/oidc/login", nil))
	if begin.Code != http.StatusFound {
		t.Fatalf("start login = %d", begin.Code)
	}
	location, _ := url.Parse(begin.Header().Get("Location"))
	state := location.Query().Get("state")
	flowCookie := begin.Result().Cookies()[0]
	call := func(provider, state string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/"+provider+"/callback?code=code&state="+url.QueryEscape(state), nil)
		request.AddCookie(flowCookie)
		response := httptest.NewRecorder()
		second.Container().ServeHTTP(response, request)
		return response
	}
	if response := call("oauth2", state); response.Code != http.StatusForbidden {
		t.Fatal("accepted provider mixup")
	}
	if response := call("oidc", "wrong-state"); response.Code != http.StatusForbidden {
		t.Fatal("accepted wrong state")
	}
	if response := call("oidc", state); response.Code != http.StatusFound || response.Header().Get("Location") != "/" {
		t.Fatalf("callback = %d %s", response.Code, response.Body)
	}
	if response := call("oidc", state); response.Code != http.StatusForbidden {
		t.Fatal("accepted replay")
	}
	if provider.calls != 1 || accounts.syncCalls != 1 {
		t.Fatal("invalid callbacks reached provider or provisioned accounts")
	}
}

func TestDisabledProvidersAndInvalidatedSessions(t *testing.T) {
	accounts := &accountStub{sessionErr: service.ErrInvalidCredentials}
	server := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/providers", nil))
	if strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "feishu") || strings.Contains(response.Body.String(), "ldap") || !strings.Contains(response.Body.String(), "Company SSO") {
		t.Fatalf("provider metadata = %s", response.Body)
	}
	request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.SignVersioned(testUserID, 2, time.Now().Add(time.Hour))})
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("accepted invalidated session")
	}
}

type feishuTestTransport struct{}

func (feishuTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := `{"code":0,"app_access_token":"app-token"}`
	if request.URL.Path == "/token" {
		body = `{"code":0,"data":{"access_token":"user-token"}}`
	}
	if request.URL.Path == "/profile" {
		body = `{"code":0,"data":{"open_id":"open-user","tenant_key":"tenant","name":"Example","active":true}}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestFeishuBindingRequiresTheInitiatingBrowserAccount(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = feishuTestTransport{}
	t.Cleanup(func() { http.DefaultTransport = previous })
	client, err := feishu.NewOAuthClient(feishu.OAuthConfig{AppID: "app", AppSecret: "secret", TenantKey: "tenant", RedirectURL: "http://console.test/api/v1/auth/feishu/callback", AuthorizeURL: "https://feishu.test/authorize", AppAccessTokenURL: "https://feishu.test/app-token", TokenURL: "https://feishu.test/token", UserInfoURL: "https://feishu.test/profile"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &accountStub{}
	server := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
	server.OAuth, server.FeishuBindingEnabled = client, true
	for _, currentUser := range []string{testSessionID, testUserID} {
		start := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/feishu/bind", nil)
		start.Header.Set("Origin", "http://console.test")
		start.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.SignVersioned(testUserID, 3, time.Now().Add(time.Hour))})
		begin := httptest.NewRecorder()
		server.Container().ServeHTTP(begin, start)
		if begin.Code != http.StatusOK {
			t.Fatalf("begin binding = %d: %s", begin.Code, begin.Body)
		}
		var body struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(begin.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		location, _ := url.Parse(body.URL)
		callback := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/feishu/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
		callback.AddCookie(begin.Result().Cookies()[0])
		callback.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.SignVersioned(currentUser, 3, time.Now().Add(time.Hour))})
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, callback)
		if currentUser != testUserID {
			if response.Code != http.StatusForbidden || accounts.bindCalls != 0 {
				t.Fatal("another logged-in account completed binding")
			}
		} else if response.Code != http.StatusFound || response.Header().Get("Location") != "/account?feishu=bound" || accounts.bindCalls != 1 || accounts.boundUser != testUserID || accounts.boundVersion != 3 {
			t.Fatalf("binding callback = %d: %s", response.Code, response.Body)
		}
	}
}
