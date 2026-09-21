package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
)

type approvalPolicyBackend struct {
	consoleBackendStub
	policy *authz.Policy
	role   authz.Role
}

func (s *approvalPolicyBackend) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	if !s.policy.Allowed(s.role, permission) {
		return service.ErrForbidden
	}
	return nil
}

func TestOrdinaryUserCannotAccessPendingApprovals(t *testing.T) {
	policy, err := authz.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []authz.Role{authz.RoleUser, authz.RoleAdmin, authz.RoleSRE} {
		t.Run(string(role), func(t *testing.T) {
			backend := &approvalPolicyBackend{policy: policy, role: role}
			server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
			perform := func(method, path string) *httptest.ResponseRecorder {
				t.Helper()
				request := httptest.NewRequest(method, path, strings.NewReader(`{}`))
				request.Header.Set("X-User-ID", testUserID)
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				server.Container().ServeHTTP(response, request)
				return response
			}
			identity := perform(http.MethodGet, "/api/v1/auth/me")
			var body struct {
				Permissions []authz.Permission `json:"permissions"`
			}
			if identity.Code != http.StatusOK || json.Unmarshal(identity.Body.Bytes(), &body) != nil {
				t.Fatalf("identity: status=%d, body=%s", identity.Code, identity.Body.String())
			}
			allowed := role != authz.RoleUser
			if slices.Contains(body.Permissions, authz.PermissionApprovalManage) != allowed {
				t.Fatalf("incorrect pending tab permission: %v", body.Permissions)
			}
			for _, endpoint := range []struct{ method, path string }{
				{http.MethodGet, "/api/v1/approvals/pending"},
				{http.MethodPost, "/api/v1/approvals/" + testApprovalID + "/approve"},
				{http.MethodPost, "/api/v1/approvals/" + testApprovalID + "/reject"},
			} {
				response := perform(endpoint.method, endpoint.path)
				want := http.StatusForbidden
				if allowed {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Fatalf("%s %s: status=%d, want %d; body=%s", endpoint.method, endpoint.path, response.Code, want, response.Body.String())
				}
				if !allowed && backend.actorID != "" {
					t.Fatal("ordinary user reached the approval handler")
				}
			}
		})
	}
}
