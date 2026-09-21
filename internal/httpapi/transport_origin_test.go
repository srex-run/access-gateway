package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/publicurl"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/service"
)

type transportRoleBackend struct {
	backendStub
	policy      *authz.Policy
	role        authz.Role
	permissions []authz.Permission
}

func (s *transportRoleBackend) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	s.permissions = append(s.permissions, permission)
	if !s.policy.Allowed(s.role, permission) {
		return service.ErrForbidden
	}
	return nil
}

func TestSettingsChallengeSeparatesOriginAndRolePermissions(t *testing.T) {
	policy, err := authz.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		publicURL string
		origin    string
		role      authz.Role
		status    int
		code      string
	}{
		{"admin using localhost with IP configuration", "http://127.0.0.1:9527", "http://localhost:9527", authz.RoleAdmin, 403, "origin_mismatch"},
		{"admin using configured IP", "http://127.0.0.1:9527", "http://127.0.0.1:9527", authz.RoleAdmin, 200, ""},
		{"admin after aligning PUBLIC_URL", "http://localhost:9527", "http://localhost:9527", authz.RoleAdmin, 200, ""},
		{"user without role management", "http://localhost:9527", "http://localhost:9527", authz.RoleUser, 403, ""},
		{"SRE without role management", "http://localhost:9527", "http://localhost:9527", authz.RoleSRE, 403, ""},
		{"unconfigured port", "http://localhost:9527", "http://localhost:9528", authz.RoleAdmin, 403, "origin_mismatch"},
		{"unconfigured scheme", "https://localhost:9527", "http://localhost:9527", authz.RoleAdmin, 403, "origin_mismatch"},
		{"untrusted origin", "http://localhost:9527", "http://attacker.test", authz.RoleAdmin, 403, "origin_mismatch"},
		{"missing origin", "http://localhost:9527", "", authz.RoleAdmin, 403, "origin_mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
			server.publicOrigin, err = publicurl.Parse(test.publicURL)
			if err != nil {
				t.Fatal(err)
			}
			backend := &transportRoleBackend{policy: policy, role: test.role}
			server.Service = backend
			transport := newMemoryTransport(t)
			server.Transport = transport
			request := httptest.NewRequest(http.MethodPost, "http://localhost:9527/api/v1/auth/transport/challenges",
				strings.NewReader(`{"method":"PATCH","path":"/api/v1/admin/settings"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", test.origin)
			request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.Sign(testUserID, time.Now().Add(time.Hour))})
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("challenge status=%d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			if test.code == "origin_mismatch" {
				if len(backend.permissions) != 0 {
					t.Fatal("origin rejection reached role authorization")
				}
			} else if len(backend.permissions) != 1 || backend.permissions[0] != authz.PermissionRoleManage {
				t.Fatalf("checked permissions=%v, want [role:manage]", backend.permissions)
			}
			if test.status != http.StatusOK {
				var body errorResponse
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Code != test.code || len(transport.challenges) != 0 {
					t.Fatalf("rejection code=%q, challenges=%d", body.Code, len(transport.challenges))
				}
				return
			}
			var challenge securetransport.Challenge
			if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil {
				t.Fatal(err)
			}
			if challenge.Method != http.MethodPatch || challenge.Path != "/api/v1/admin/settings" || !strings.HasPrefix(challenge.Subject, "user:"+testUserID+":") || len(transport.challenges) != 1 {
				t.Fatal("admin challenge lost its target or authenticated browser binding")
			}
		})
	}
}
