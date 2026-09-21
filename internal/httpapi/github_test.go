package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/authn"
)

func TestGitHubLoginCallbackAndMFAGating(t *testing.T) {
	for _, stage := range []string{"session", "mfa", "mfa-unavailable"} {
		t.Run(stage, func(t *testing.T) {
			accounts := &accountStub{}
			states := &loginStateMemory{values: map[string]time.Time{}}
			provider := &redirectStub{profile: authn.Profile{Provider: "github", Issuer: authn.GitHubIssuer, Subject: "123", Nickname: "octocat"}}
			first := newAuthServer(t, accounts, &attemptStub{true}, states, &redirectStub{})
			second := newAuthServer(t, accounts, &attemptStub{true}, states, &redirectStub{})
			for _, server := range []*Server{first, second} {
				server.AuthConfig.GitHub = authn.GitHubConfig{Enabled: true, Name: "GitHub"}
				server.RedirectProviders["github"] = provider
				if stage != "session" {
					mfa := &mfaStub{}
					if stage == "mfa-unavailable" {
						mfa.beginErr = errors.New("MFA store unavailable")
					}
					server.MFA = mfa
				}
			}
			metadata := httptest.NewRecorder()
			first.Container().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/providers", nil))
			var providers []loginProvider
			if err := json.Unmarshal(metadata.Body.Bytes(), &providers); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, option := range providers {
				found = found || option == (loginProvider{"github", "GitHub", "redirect"})
			}
			if !found {
				t.Fatal("GitHub missing from login page metadata")
			}
			begin := httptest.NewRecorder()
			first.Container().ServeHTTP(begin, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/github/login", nil))
			if begin.Code != http.StatusFound || len(begin.Result().Cookies()) != 1 {
				t.Fatalf("GitHub login start = %d: %s", begin.Code, begin.Body)
			}
			location, _ := url.Parse(begin.Header().Get("Location"))
			state := location.Query().Get("state")
			flowCookie := begin.Result().Cookies()[0]
			if flowCookie.Name != loginCookieName("github") || !flowCookie.HttpOnly || flowCookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("GitHub login flow cookie is not isolated and protected")
			}
			call := func(name, state string) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/"+name+"/callback?code=code&state="+url.QueryEscape(state), nil)
				cookie := *flowCookie
				cookie.Name = loginCookieName(name)
				request.AddCookie(&cookie)
				response := httptest.NewRecorder()
				second.Container().ServeHTTP(response, request)
				return response
			}
			if call("oidc", state).Code != http.StatusForbidden || call("github", "wrong-state").Code != http.StatusForbidden {
				t.Fatal("GitHub flow accepted provider or state mixup")
			}
			result := call("github", state)
			wantStatus, wantLocation := http.StatusFound, "/"
			if stage == "mfa" {
				wantLocation = "/mfa"
			} else if stage == "mfa-unavailable" {
				wantStatus, wantLocation = http.StatusInternalServerError, ""
			}
			if result.Code != wantStatus || result.Header().Get("Location") != wantLocation {
				t.Fatalf("GitHub callback = %d %s: %s", result.Code, result.Header().Get("Location"), result.Body)
			}
			fullSession, pendingMFA := false, false
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == second.SessionCookieName && cookie.Value != "" {
					userID, _, valid := second.SessionSigner.VerifyVersioned(cookie.Value, time.Now())
					if !valid || userID != testUserID {
						t.Fatal("GitHub callback issued an invalid session")
					}
					fullSession = true
				}
				pendingMFA = pendingMFA || cookie.Name == "access_gateway_mfa" && cookie.Value != "" && cookie.HttpOnly
			}
			if fullSession != (stage == "session") || pendingMFA != (stage == "mfa") {
				t.Fatal("GitHub login bypassed MFA or lost the pending challenge")
			}
			if call("github", state).Code != http.StatusForbidden || provider.calls != 1 || accounts.syncCalls != 1 || accounts.lastProfile != provider.profile {
				t.Fatal("GitHub callback replay accepted or incorrect identity synchronized")
			}
		})
	}
}

func TestDisabledGitHubIsNotAdvertisedOrInvoked(t *testing.T) {
	accounts := &accountStub{}
	server := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
	provider := &redirectStub{}
	server.RedirectProviders["github"] = provider
	result := httptest.NewRecorder()
	server.Container().ServeHTTP(result, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/providers", nil))
	var providers []loginProvider
	if err := json.Unmarshal(result.Body.Bytes(), &providers); err != nil {
		t.Fatal(err)
	}
	for _, option := range providers {
		if option.ID == "github" {
			t.Fatal("disabled GitHub advertised on login page")
		}
	}
	result = httptest.NewRecorder()
	server.Container().ServeHTTP(result, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/github/login", nil))
	if result.Code < 400 || len(result.Result().Cookies()) != 0 || accounts.syncCalls != 0 || provider.calls != 0 {
		t.Fatal("disabled GitHub provider started a login")
	}
}
