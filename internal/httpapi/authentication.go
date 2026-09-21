package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful/v3"
	"golang.org/x/oauth2"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

type AuthenticationService interface {
	AuthenticateLocal(context.Context, string, string) (domain.User, error)
	SyncExternalUser(context.Context, authn.Profile) (domain.User, error)
	ValidateBrowserSession(context.Context, string, int64) error
	GetAccount(context.Context, string) (service.Account, error)
	ChangePassword(context.Context, string, string, string) error
	BindFeishuUser(context.Context, string, int64, feishu.Profile) error
	UnbindFeishuUser(context.Context, string, map[string]string) error
}

type LoginAttemptStore interface {
	Allow(context.Context, repository.DBTX, string, int) (bool, error)
}

type loginProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func (s *Server) loginProviders(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	providers := []loginProvider{}
	providers = append(providers, loginProvider{"local", "本地账号", "password"})
	if runtime.Auth.OIDC.Enabled {
		providers = append(providers, loginProvider{"oidc", runtime.Auth.OIDC.Name, "redirect"})
	}
	if runtime.Auth.LDAP.Enabled {
		providers = append(providers, loginProvider{"ldap", runtime.Auth.LDAP.Name, "password"})
	}
	if runtime.Auth.OAuth2.Enabled {
		providers = append(providers, loginProvider{"oauth2", runtime.Auth.OAuth2.Name, "redirect"})
	}
	if runtime.Auth.GitHub.Enabled {
		providers = append(providers, loginProvider{"github", runtime.Auth.GitHub.Name, "redirect"})
	}
	if runtime.Feishu.LoginEnabled {
		providers = append(providers, loginProvider{"feishu", "飞书", "redirect"})
	}
	_ = response.WriteEntity(providers)
}

func (s *Server) passwordLogin(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	provider := "local"
	if strings.HasSuffix(request.Request.URL.Path, "/ldap/login") {
		provider = "ldap"
	}
	if s.Authentication == nil || s.SessionSigner == nil || (provider == "ldap" && (!runtime.Auth.LDAP.Enabled || runtime.LDAP == nil)) {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil || len(body.Username) > 256 || len(body.Password) > 1024 || body.Password == "" {
		s.writeError(response, service.ErrInvalidCredentials)
		return
	}
	if !s.allowPasswordAttempt(request, response, provider+":"+strings.ToLower(strings.TrimSpace(body.Username))) {
		return
	}
	ctx, cancel := context.WithTimeout(request.Request.Context(), s.authTimeout(request.Request.Context()))
	defer cancel()
	var user domain.User
	var err error
	if provider == "local" {
		user, err = s.Authentication.AuthenticateLocal(ctx, body.Username, body.Password)
	} else {
		var profile authn.Profile
		profile, err = runtime.LDAP.Authenticate(ctx, body.Username, body.Password)
		if err != nil {
			s.writeError(response, service.ErrInvalidCredentials)
			return
		}
		user, err = s.Authentication.SyncExternalUser(ctx, profile)
	}
	if err != nil {
		s.writeError(response, err)
		return
	}
	if user.Status != domain.UserStatusActive {
		s.writeError(response, service.ErrInvalidCredentials)
		return
	}
	s.finishPrimaryLogin(request, response, user, false)
}

func (s *Server) allowPasswordAttempt(request *restful.Request, response *restful.Response, subject string) bool {
	ip, _, err := net.SplitHostPort(request.Request.RemoteAddr)
	if err != nil {
		ip = request.Request.RemoteAddr
	}
	for _, bucket := range []struct {
		key   string
		limit int
	}{{"account:" + subject, 10}, {"address:" + ip, 300}} {
		allowed, err := s.LoginAttempts.Allow(request.Request.Context(), s.DB, security.HashOpaqueToken(bucket.key), bucket.limit)
		if err != nil {
			s.writeError(response, err)
			return false
		}
		if !allowed {
			response.Header().Set("Retry-After", "300")
			_ = response.WriteHeaderAndEntity(http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
			return false
		}
	}
	return true
}

func (s *Server) externalLogin(request *restful.Request, response *restful.Response) {
	provider := request.PathParameter("provider")
	if !s.redirectEnabled(request.Request.Context(), provider, false) {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	authorizationURL, err := s.beginLogin(request, response, provider, "", 0)
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Location", authorizationURL)
	response.WriteHeader(http.StatusFound)
}

func (s *Server) redirectEnabled(ctx context.Context, provider string, binding bool) bool {
	runtime := s.authRuntime(ctx)
	if s.SessionSigner == nil || s.OAuthStates == nil {
		return false
	}
	if provider == "feishu" {
		return runtime.OAuth != nil && ((binding && runtime.Feishu.BindingEnabled) || (!binding && runtime.Feishu.LoginEnabled))
	}
	return runtime.RedirectProviders[provider] != nil && ((provider == "oidc" && runtime.Auth.OIDC.Enabled) || (provider == "oauth2" && runtime.Auth.OAuth2.Enabled) || (provider == "github" && runtime.Auth.GitHub.Enabled))
}

func (s *Server) beginLogin(request *restful.Request, response *restful.Response, provider, userID string, version int64) (string, error) {
	runtime := s.authRuntime(request.Request.Context())
	state, err := security.NewToken()
	if err != nil {
		return "", err
	}
	nonce, err := security.NewToken()
	if err != nil {
		return "", err
	}
	flow := security.LoginState{State: state, Provider: provider, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), UserID: userID, Version: version, ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}
	flow.SettingsRevision = runtime.Revision
	var authorizationURL string
	if provider == "feishu" {
		authorizationURL, err = runtime.OAuth.AuthorizationURL(state)
	} else {
		authorizationURL, err = runtime.RedirectProviders[provider].AuthorizationURL(state, nonce, flow.Verifier)
	}
	if err != nil {
		return "", err
	}
	if _, err := s.OAuthStates.Create(request.Request.Context(), s.DB, domain.OAuthState{StateHash: security.HashOpaqueToken(state), ExpiresAt: time.Unix(flow.ExpiresAt, 0)}); err != nil {
		return "", err
	}
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: loginCookieName(provider), Value: s.SessionSigner.SignLoginState(flow), Path: "/", MaxAge: 600, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteLaxMode})
	return authorizationURL, nil
}

func loginCookieName(provider string) string { return "access_gateway_login_" + provider }

func (s *Server) externalCallback(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	provider := request.PathParameter("provider")
	if provider != "feishu" && provider != "oidc" && provider != "oauth2" && provider != "github" {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	cookie, err := request.Request.Cookie(loginCookieName(provider))
	if err != nil {
		s.writeError(response, service.ErrForbidden)
		return
	}
	flow, valid := s.SessionSigner.VerifyLoginState(cookie.Value, time.Now())
	if !valid || flow.Provider != provider || flow.SettingsRevision != runtime.Revision || !hmacEqualString(flow.State, request.QueryParameter("state")) {
		s.writeError(response, service.ErrForbidden)
		return
	}
	if !s.redirectEnabled(request.Request.Context(), provider, flow.UserID != "") {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	consumed, err := s.OAuthStates.Consume(request.Request.Context(), s.DB, security.HashOpaqueToken(flow.State))
	if err != nil {
		s.writeError(response, err)
		return
	}
	if !consumed {
		s.writeError(response, service.ErrForbidden)
		return
	}
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: loginCookieName(provider), Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteLaxMode})
	if request.QueryParameter("error") != "" || request.QueryParameter("code") == "" {
		s.loginFailed(response, flow.UserID != "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Request.Context(), s.authTimeout(request.Request.Context()))
	defer cancel()
	var user domain.User
	if provider == "feishu" {
		profile, exchangeErr := runtime.OAuth.Exchange(ctx, request.QueryParameter("code"))
		if exchangeErr != nil {
			s.loginFailed(response, flow.UserID != "")
			return
		}
		if flow.UserID != "" {
			currentID, ok := s.currentUser(request, response)
			if !ok {
				return
			}
			if currentID != flow.UserID || s.Authentication == nil {
				s.writeError(response, service.ErrForbidden)
				return
			}
			if err := s.Authentication.BindFeishuUser(ctx, currentID, flow.Version, profile); err != nil {
				s.loginFailed(response, true)
				return
			}
			response.Header().Set("Location", "/account?feishu=bound")
			response.WriteHeader(http.StatusFound)
			return
		}
		user, err = s.Service.SyncFeishuUser(ctx, profile)
	} else {
		profile, exchangeErr := runtime.RedirectProviders[provider].Exchange(ctx, request.QueryParameter("code"), flow.Nonce, flow.Verifier)
		if exchangeErr != nil {
			s.loginFailed(response, false)
			return
		}
		user, err = s.Authentication.SyncExternalUser(ctx, profile)
	}
	if err != nil || user.Status != domain.UserStatusActive {
		s.loginFailed(response, false)
		return
	}
	s.finishPrimaryLogin(request, response, user, true)
}

func (s *Server) loginFailed(response *restful.Response, binding bool) {
	destination := "/login?error=authentication_failed"
	if binding {
		destination = "/account?error=feishu_binding_failed"
	}
	response.Header().Set("Location", destination)
	response.WriteHeader(http.StatusFound)
}

func (s *Server) setSessionCookie(request *restful.Request, response *restful.Response, user domain.User) {
	http.SetCookie(response.ResponseWriter, &http.Cookie{Name: s.SessionCookieName, Value: s.SessionSigner.SignVersioned(user.ID, user.AuthVersion, time.Now().Add(8*time.Hour)), Path: "/", MaxAge: 8 * 60 * 60, HttpOnly: true, Secure: s.secureRequest(request.Request), SameSite: http.SameSiteLaxMode})
}

func (s *Server) account(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if s.Authentication == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	account, err := s.Authentication.GetAccount(request.Request.Context(), userID)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(struct {
		service.Account
		LocalEnabled         bool `json:"local_enabled"`
		FeishuConfigured     bool `json:"feishu_configured"`
		FeishuBindingEnabled bool `json:"feishu_binding_enabled"`
	}{
		Account: account, LocalEnabled: true,
		FeishuConfigured:     (runtime.Feishu.AppID != "" && runtime.Feishu.TenantKey != "") || runtime.Feishu.LoginEnabled || runtime.Feishu.BindingEnabled || runtime.Feishu.NotificationsEnabled || runtime.Feishu.CallbacksEnabled,
		FeishuBindingEnabled: runtime.Feishu.BindingEnabled,
	})
}

func (s *Server) changePassword(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if s.Authentication == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(request.Request, &body, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	if !s.allowPasswordAttempt(request, response, "password-change:"+userID) {
		return
	}
	if err := s.Authentication.ChangePassword(request.Request.Context(), userID, body.CurrentPassword, body.NewPassword); err != nil {
		s.writeError(response, err)
		return
	}
	s.logout(request, response)
}

func (s *Server) bindFeishu(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if !s.redirectEnabled(request.Request.Context(), "feishu", true) {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	cookie, err := request.Request.Cookie(s.SessionCookieName)
	if err != nil {
		s.writeError(response, errUnauthenticated)
		return
	}
	cookieUser, version, valid := s.SessionSigner.VerifyVersioned(cookie.Value, time.Now())
	if !valid || cookieUser != userID {
		s.writeError(response, errUnauthenticated)
		return
	}
	authorizationURL, err := s.beginLogin(request, response, "feishu", userID, version)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(map[string]string{"url": authorizationURL})
}

func (s *Server) unbindFeishu(request *restful.Request, response *restful.Response) {
	runtime := s.authRuntime(request.Request.Context())
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if s.Authentication == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	enabled := map[string]string{}
	enabled["local"] = "local"
	if runtime.Auth.OIDC.Enabled {
		enabled["oidc"] = runtime.Auth.OIDC.Issuer
	}
	if runtime.Auth.OAuth2.Enabled {
		enabled["oauth2"] = runtime.Auth.OAuth2.UserInfoURL
	}
	if runtime.Auth.GitHub.Enabled {
		enabled["github"] = authn.GitHubIssuer
	}
	if runtime.Auth.LDAP.Enabled {
		enabled["ldap"] = runtime.Auth.LDAP.Issuer()
	}
	if err := s.Authentication.UnbindFeishuUser(request.Request.Context(), userID, enabled); err != nil {
		s.writeError(response, err)
		return
	}
	s.logout(request, response)
}

func (s *Server) authTimeout(ctx context.Context) time.Duration {
	timeout := s.authRuntime(ctx).Auth.Timeout
	if timeout <= 0 {
		return 10 * time.Second
	}
	return timeout
}
