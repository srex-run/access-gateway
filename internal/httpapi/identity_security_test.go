package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

type mfaStub struct {
	MFAService
	beginErr      error
	consumed      bool
	completeCalls int
}

func (m *mfaStub) BeginMFA(context.Context, domain.User, bool) (*service.PendingMFA, error) {
	if m.beginErr != nil {
		return nil, m.beginErr
	}
	return &service.PendingMFA{Stage: "mfa-verify", Token: strings.Repeat("a", 43), ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (m *mfaStub) CompleteMFA(_ context.Context, token, code, kind string) (service.MFAResult, error) {
	m.completeCalls++
	if m.consumed || token != strings.Repeat("a", 43) || code != "123456" || kind != "verify" {
		return service.MFAResult{}, service.ErrMFAFailed
	}
	m.consumed = true
	return service.MFAResult{User: domain.User{ID: testUserID, AuthVersion: 3}}, nil
}

func (*mfaStub) ValidateMFASession(_ context.Context, _ string, verified bool) error {
	if !verified {
		return service.ErrInvalidCredentials
	}
	return nil
}

type invitationStub struct{ InvitationService }

func (*invitationStub) AcceptInvitation(context.Context, string, string) (domain.User, error) {
	return domain.User{ID: testUserID, AuthVersion: 3, Status: domain.UserStatusActive}, nil
}

func TestMFAPrimaryAndInvitationLoginDoNotIssueFullSessions(t *testing.T) {
	for _, path := range []string{"/auth/local/login", "/auth/invitation/accept"} {
		t.Run(path, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
			server.MFA = &mfaStub{}
			server.Invitations = &invitationStub{}
			body := `{"username":"alice","password":"correct-password"}`
			if strings.Contains(path, "invitation") {
				body = `{"token":"` + strings.Repeat("a", 43) + `","password":"correct-password"}`
			}
			req := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1"+path, nil)
			req.Header.Set("Origin", "http://console.test")
			client := encryptTestRequest(t, server, req, body)
			res := httptest.NewRecorder()
			server.Container().ServeHTTP(res, req)
			decoded, err := client.Open(res.Code, res.Body.Bytes())
			if err != nil || res.Code != 200 {
				t.Fatalf("primary login: %d %v", res.Code, err)
			}
			var pending service.PendingMFA
			if json.Unmarshal(decoded, &pending) != nil || pending.Stage != "mfa-verify" {
				t.Fatal("missing MFA stage")
			}
			var cookie *http.Cookie
			for _, value := range res.Result().Cookies() {
				if value.Name == server.SessionCookieName && value.Value != "" {
					t.Fatal("first factor issued full session")
				}
				if value.Name == mfaCookieName {
					cookie = value
				}
			}
			if cookie == nil || !cookie.HttpOnly || cookie.Path != "/api/v1/auth" || cookie.MaxAge != 300 || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("unsafe pending cookie")
			}
			protected := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/me", nil)
			protected.AddCookie(cookie)
			blocked := httptest.NewRecorder()
			server.Container().ServeHTTP(blocked, protected)
			if blocked.Code != http.StatusUnauthorized {
				t.Fatal("pending cookie granted ordinary API access")
			}
			for attempt := range 2 {
				verify := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/mfa/verify", nil)
				verify.Header.Set("Origin", "http://console.test")
				verify.AddCookie(cookie)
				encrypted := encryptTestRequest(t, server, verify, `{"code":"123456"}`)
				verified := httptest.NewRecorder()
				server.Container().ServeHTTP(verified, verify)
				if _, err := encrypted.Open(verified.Code, verified.Body.Bytes()); err != nil {
					t.Fatal(err)
				}
				if attempt == 1 {
					if verified.Code != http.StatusBadRequest {
						t.Fatal("MFA challenge replay accepted")
					}
					continue
				}
				found := false
				for _, full := range verified.Result().Cookies() {
					if full.Name == server.SessionCookieName {
						found = server.SessionSigner.MFAVerified(full.Value, time.Now())
					}
				}
				if verified.Code != 200 || !found {
					t.Fatal("second factor did not establish verified session")
				}
			}
		})
	}
}

func TestMFAExternalLoginAndLookupFailureStayGated(t *testing.T) {
	for _, fail := range []bool{false, true} {
		server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
		mfa := &mfaStub{}
		if fail {
			mfa.beginErr = errors.New("MFA store unavailable")
		}
		server.MFA = mfa
		start := httptest.NewRecorder()
		server.Container().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/oidc/login", nil))
		location, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		callback := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/oidc/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
		callback.AddCookie(start.Result().Cookies()[0])
		result := httptest.NewRecorder()
		server.Container().ServeHTTP(result, callback)
		if !fail && (result.Code != http.StatusFound || result.Header().Get("Location") != "/mfa") {
			t.Fatalf("SSO skipped MFA: %d", result.Code)
		}
		if fail && result.Code != http.StatusInternalServerError {
			t.Fatal("MFA lookup error allowed login")
		}
		for _, cookie := range result.Result().Cookies() {
			if cookie.Name == server.SessionCookieName && cookie.Value != "" {
				t.Fatal("SSO issued a session before MFA")
			}
		}
	}
}

func TestMFATransportRejectsCookieMixupAndCrossSite(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	mfa := &mfaStub{}
	server.MFA = mfa
	for _, origin := range []string{"http://console.test", "http://attacker.test", ""} {
		req := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/auth/mfa/verify", nil)
		req.Header.Set("Origin", origin)
		req.AddCookie(&http.Cookie{Name: mfaCookieName, Value: strings.Repeat("a", 43)})
		encryptTestRequest(t, server, req, `{"code":"123456"}`)
		if origin == "http://console.test" {
			req.Header.Set("Cookie", mfaCookieName+"="+strings.Repeat("b", 43))
		}
		res := httptest.NewRecorder()
		server.Container().ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest && res.Code != http.StatusForbidden {
			t.Fatalf("invalid request accepted: %d", res.Code)
		}
	}
	if mfa.completeCalls != 0 {
		t.Fatal("rejected transport reached verifier")
	}
}

func TestIdentitySecurityRoutesRequireEncryptionAndCorrectPermissions(t *testing.T) {
	for _, path := range []string{"/auth/mfa/enroll", "/auth/mfa/confirm", "/auth/mfa/verify", "/auth/invitation/preview", "/auth/invitation/accept", "/auth/account/mfa/enroll", "/auth/account/mfa/recovery-codes", "/auth/account/mfa/unbind", "/admin/invitations", "/admin/invitations/id/resend"} {
		if !encryptedRoute(http.MethodPost, "/api/v1"+path) {
			t.Fatalf("unencrypted sensitive route: %s", path)
		}
	}
	if permission, required := routePermission(http.MethodDelete, "/api/v1/admin/users/id/mfa"); !required || permission != "role:manage" {
		t.Fatal("MFA reset lacks administrator permission")
	}
	if permission, required := routePermission(http.MethodPost, "/api/v1/admin/invitations"); !required || permission != "user:manage" {
		t.Fatal("invitation lacks user management permission")
	}
}

func TestInvitationAndMFACanAcquireTransportChallenges(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.MFA, server.Invitations, server.Transport = &mfaStub{}, &invitationStub{}, newMemoryTransport(t)
	handler := server.Container()
	var pending *http.Cookie
	post := func(path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1"+path, bytes.NewReader(body))
		req.Header.Set("Origin", "http://console.test")
		req.Header.Set("Content-Type", "application/json")
		if pending != nil {
			req.AddCookie(pending)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	for _, step := range []struct{ path, body string }{
		{"/auth/invitation/accept", `{"token":"` + strings.Repeat("a", 43) + `","password":"correct-password"}`},
		{"/auth/mfa/verify", `{"code":"123456"}`},
	} {
		body, err := json.Marshal(map[string]string{"method": http.MethodPost, "path": "/api/v1" + step.path})
		if err != nil {
			t.Fatal(err)
		}
		response := post("/auth/transport/challenges", body)
		var challenge securetransport.Challenge
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &challenge) != nil {
			t.Fatalf("transport challenge for %s: %d", step.path, response.Code)
		}
		expectedSubject := "anonymous"
		if pending != nil {
			expectedSubject = "mfa:" + security.HashOpaqueToken(pending.Value)
		}
		if challenge.Subject != expectedSubject {
			t.Fatal("transport challenge used the wrong authentication context")
		}
		envelope, client, err := testclient.Seal(challenge, []byte(step.body))
		if err != nil {
			t.Fatal(err)
		}
		body, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		response = post(step.path, body)
		if response.Code != http.StatusOK || response.Header().Get("X-AG-Encrypted") != "1" {
			t.Fatalf("encrypted submission to %s: %d", step.path, response.Code)
		}
		if _, err := client.Open(response.Code, response.Body.Bytes()); err != nil {
			t.Fatal(err)
		}
		verified := false
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == mfaCookieName && cookie.Value != "" {
				pending = cookie
			}
			if cookie.Name == server.SessionCookieName && cookie.Value != "" {
				verified = server.SessionSigner.MFAVerified(cookie.Value, time.Now())
			}
		}
		if step.path == "/auth/invitation/accept" && (pending == nil || verified) {
			t.Fatal("invitation activation failed to establish only a pending MFA cookie")
		}
		if step.path == "/auth/mfa/verify" && !verified {
			t.Fatal("second factor failed to establish an MFA-verified session")
		}
	}
}
