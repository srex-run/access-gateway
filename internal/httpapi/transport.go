package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

type BrowserTransport interface {
	Create(context.Context, securetransport.Binding) (securetransport.Challenge, error)
	Open(context.Context, securetransport.Binding, securetransport.Request) ([]byte, *securetransport.Reply, error)
}

var encryptedResourcePath = regexp.MustCompile(`^/api/v1/(admin/(cloud-accounts|assets)/[^/]+|admin/gateways/[^/]+/release)$`)
var encryptedTerminalPath = regexp.MustCompile(`^/api/v1/sessions/[^/]+/terminal$`)
var encryptedTerminalDemoDefaultsPath = regexp.MustCompile(`^/api/v1/sessions/[^/]+/terminal/demo-defaults$`)

func anonymousIdentityRoute(path string) bool {
	return path == "/api/v1/auth/invitation/preview" || path == "/api/v1/auth/invitation/accept"
}

func pendingMFARoute(path string) bool {
	return path == "/api/v1/auth/mfa" || path == "/api/v1/auth/mfa/enroll" || path == "/api/v1/auth/mfa/confirm" || path == "/api/v1/auth/mfa/verify"
}

var invitationResendPath = regexp.MustCompile(`^/api/v1/admin/invitations/[^/]+/resend$`)

func identityEncryptedRoute(method, path string) bool {
	return method == http.MethodPost && (anonymousIdentityRoute(path) || pendingMFARoute(path) ||
		path == "/api/v1/auth/account/mfa/enroll" || path == "/api/v1/auth/account/mfa/recovery-codes" || path == "/api/v1/auth/account/mfa/unbind" ||
		path == "/api/v1/admin/invitations" || invitationResendPath.MatchString(path))
}

// This is a mandatory wire contract, independent of provider settings and body
// contents. Even edits that preserve existing credentials use the same contract.
func encryptedRoute(method, path string) bool {
	if method == http.MethodGet && encryptedTerminalPath.MatchString(path) {
		return true
	}
	if identityEncryptedRoute(method, path) {
		return true
	}
	if method == http.MethodPost {
		if encryptedTerminalDemoDefaultsPath.MatchString(path) {
			return true
		}
		switch path {
		case "/api/v1/auth/local/login", "/api/v1/auth/ldap/login", "/api/v1/auth/password", "/api/v1/admin/cloud-accounts", "/api/v1/admin/assets", "/api/v1/admin/users", "/api/v1/admin/settings/audit/certificates", "/api/v1/admin/assets/audit/certificates":
			return true
		}
		return encryptedResourcePath.MatchString(path) && !strings.HasPrefix(path, "/api/v1/admin/cloud-accounts/") && !strings.HasPrefix(path, "/api/v1/admin/assets/")
	}
	return method == http.MethodPatch && (path == "/api/v1/admin/settings" ||
		((strings.HasPrefix(path, "/api/v1/admin/cloud-accounts/") || strings.HasPrefix(path, "/api/v1/admin/assets/")) && encryptedResourcePath.MatchString(path)))
}

func (s *Server) transportBinding(request *restful.Request, response *restful.Response, method, path string) (securetransport.Binding, bool) {
	binding := securetransport.Binding{Method: method, Path: path}
	if pendingMFARoute(path) {
		token, ok := s.pendingToken(request, response)
		if !ok {
			return binding, false
		}
		binding.Subject = "mfa:" + security.HashOpaqueToken(token)
		return binding, true
	}
	if path == "/api/v1/auth/local/login" || path == "/api/v1/auth/ldap/login" || anonymousIdentityRoute(path) {
		// There is no authenticated actor yet. Avoid proxy-IP binding: a browser
		// may reach different console replicas between challenge and submission.
		binding.Subject = "anonymous"
		return binding, true
	}
	userID, ok := s.currentUser(request, response)
	if !ok {
		return binding, false
	}
	if permission, protected := routePermission(method, path); protected {
		if err := s.Service.Authorize(request.Request.Context(), userID, permission); err != nil {
			s.writeError(response, err)
			return binding, false
		}
	}
	binding.Subject = "user:" + userID
	if cookie, err := request.Request.Cookie(s.SessionCookieName); err == nil {
		binding.Subject += ":" + security.HashOpaqueToken(cookie.Value)
	}
	return binding, true
}

func transportAddress(request *http.Request) string {
	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return ip
}

func (s *Server) allowTransport(request *restful.Request, response *restful.Response, purpose string) bool {
	allowed, err := s.LoginAttempts.Allow(request.Request.Context(), s.DB,
		security.HashOpaqueToken("browser-transport:"+purpose+":"+transportAddress(request.Request)), 300)
	if err != nil {
		s.writeError(response, err)
		return false
	}
	if !allowed {
		response.Header().Set("Retry-After", "300")
		_ = response.WriteHeaderAndEntity(http.StatusTooManyRequests, map[string]string{"error": "too many encrypted requests"})
	}
	return allowed
}

func (s *Server) createTransportChallenge(request *restful.Request, response *restful.Response) {
	var input struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if decodeJSONBody(request.Request, &input, false) != nil || len(input.Path) > 512 ||
		strings.ContainsAny(input.Path, "?%#\\\r\n") || strings.Contains(input.Path, "..") || !encryptedRoute(input.Method, input.Path) {
		s.writeError(response, service.ErrValidation)
		return
	}
	binding, ok := s.transportBinding(request, response, input.Method, input.Path)
	if !ok || !s.allowTransport(request, response, "challenge") {
		return
	}
	if s.Transport == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	challenge, err := s.Transport.Create(request.Request.Context(), binding)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(challenge)
}

// Decrypt only after CSRF and authorization checks. The original HTTP body stays
// encrypted for outer middleware. Handler responses (including errors) are
// encrypted before reaching the proxy or response logging middleware.
func (s *Server) transportFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	// The terminal handler authenticates/decrypts the first WebSocket message;
	// an HTTP upgrade cannot carry the ordinary encrypted request body.
	if request.Request.Method == http.MethodGet && encryptedTerminalPath.MatchString(request.SelectedRoutePath()) {
		chain.ProcessFilter(request, response)
		return
	}
	if !encryptedRoute(request.Request.Method, request.SelectedRoutePath()) {
		chain.ProcessFilter(request, response)
		return
	}
	if request.Request.URL.RawQuery != "" || request.Request.URL.RawPath != "" ||
		strings.HasSuffix(request.Request.URL.Path, "/") || strings.Contains(request.Request.URL.Path, "//") {
		s.writeError(response, service.ErrValidation)
		return
	}
	binding, ok := s.transportBinding(request, response, request.Request.Method, request.Request.URL.Path)
	if !ok {
		return
	}
	var envelope securetransport.Request
	if decodeJSONBody(request.Request, &envelope, false) != nil || envelope.ChallengeID == "" || envelope.Envelope.Version != 1 {
		_ = response.WriteHeaderAndEntity(http.StatusBadRequest, map[string]string{"error": "encrypted request required; refresh the page and retry"})
		return
	}
	if !s.allowTransport(request, response, "open") {
		return
	}
	if s.Transport == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	plaintext, reply, err := s.Transport.Open(request.Request.Context(), binding, envelope)
	if err != nil {
		if errors.Is(err, securetransport.ErrInvalid) {
			_ = response.WriteHeaderAndEntity(http.StatusBadRequest, map[string]string{"error": "encrypted request is invalid or expired; retry"})
		} else {
			s.writeError(response, err)
		}
		return
	}
	defer clear(plaintext)
	defer reply.Clear()
	if !json.Valid(plaintext) || len(plaintext) == 0 || plaintext[0] != '{' {
		s.writeError(response, service.ErrValidation)
		return
	}
	inner := request.Request.Clone(request.Request.Context())
	inner.Body = io.NopCloser(bytes.NewReader(plaintext))
	inner.ContentLength = int64(len(plaintext))
	originalRequest := request.Request
	request.Request = inner
	defer func() { request.Request = originalRequest }()
	buffer := &transportResponseWriter{header: response.Header().Clone()}
	originalWriter := response.ResponseWriter
	response.ResponseWriter = buffer
	defer func() { response.ResponseWriter = originalWriter; clear(buffer.body.Bytes()) }()
	chain.ProcessFilter(request, response)
	if buffer.status == 0 {
		buffer.status = http.StatusOK
	}
	if buffer.err != nil {
		buffer.status = http.StatusInternalServerError
		clear(buffer.body.Bytes())
		buffer.body.Reset()
		_, _ = buffer.body.WriteString(`{"error":"response is too large"}`)
	}
	sealed, err := reply.Seal(buffer.status, buffer.body.Bytes())
	if err != nil {
		originalWriter.WriteHeader(http.StatusInternalServerError)
		return
	}
	for key, values := range buffer.header {
		originalWriter.Header()[key] = values
	}
	originalWriter.Header().Del("Content-Length")
	originalWriter.Header().Del("Content-Encoding")
	originalWriter.Header().Set("Content-Type", "application/json")
	originalWriter.Header().Set("X-AG-Encrypted", "1")
	originalWriter.WriteHeader(buffer.status)
	_ = json.NewEncoder(originalWriter).Encode(sealed)
}

type transportResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
	err    error
}

func (w *transportResponseWriter) Header() http.Header { return w.header }
func (w *transportResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *transportResponseWriter) Write(data []byte) (int, error) {
	if w.body.Len()+len(data) > 32<<20 {
		w.err = errors.New("encrypted response exceeds limit")
		return 0, w.err
	}
	w.WriteHeader(http.StatusOK)
	return w.body.Write(data)
}
