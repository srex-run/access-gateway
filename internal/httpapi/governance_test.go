package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
)

type governanceAuthorizationStub struct {
	backendStub
	permissions []authz.Permission
}

func (s *governanceAuthorizationStub) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	s.permissions = append(s.permissions, permission)
	return service.ErrForbidden
}

// Exercise registered routes so a missing filter or a fallback to a different
// admin permission fails before any governance handler can read or mutate data.
func TestGovernanceEndpointPermissions(t *testing.T) {
	for _, test := range []struct {
		method     string
		path       string
		permission authz.Permission
	}{
		{http.MethodGet, "/api/v1/admin/permissions", authz.PermissionRoleManage},
		{http.MethodGet, "/api/v1/admin/roles", authz.PermissionRoleManage},
		{http.MethodPost, "/api/v1/admin/roles", authz.PermissionRoleManage},
		{http.MethodGet, "/api/v1/admin/role-bindings", authz.PermissionRoleManage},
		{http.MethodPost, "/api/v1/admin/role-bindings", authz.PermissionRoleManage},
		{http.MethodPost, "/api/v1/admin/role-bindings/preview", authz.PermissionRoleManage},
		{http.MethodGet, "/api/v1/admin/role-assignments?user_id=" + testUserID, authz.PermissionRoleManage},
		{http.MethodPost, "/api/v1/admin/role-assignments", authz.PermissionRoleManage},
		{http.MethodDelete, "/api/v1/admin/role-assignments/" + testSessionID, authz.PermissionRoleManage},
		{http.MethodGet, "/api/v1/admin/users", authz.PermissionUserRead},
		{http.MethodPost, "/api/v1/admin/users", authz.PermissionUserManage},
		{http.MethodGet, "/api/v1/admin/users/" + testUserID, authz.PermissionUserRead},
		{http.MethodPatch, "/api/v1/admin/users/" + testUserID, authz.PermissionUserManage},
		{http.MethodGet, "/api/v1/admin/users/" + testUserID + "/mfa", authz.PermissionUserRead},
		{http.MethodDelete, "/api/v1/admin/users/" + testUserID + "/mfa", authz.PermissionRoleManage},
		{http.MethodGet, "/api/v1/admin/workflows", authz.PermissionWorkflowManage},
		{http.MethodGet, "/api/v1/admin/asset-workflows", authz.PermissionCatalogManage},
		{http.MethodPost, "/api/v1/admin/workflows", authz.PermissionWorkflowManage},
		{http.MethodGet, "/api/v1/admin/ownerships", authz.PermissionWorkflowManage},
		{http.MethodPost, "/api/v1/admin/ownerships", authz.PermissionWorkflowManage},
		{http.MethodPost, "/api/v1/admin/ownerships/preview", authz.PermissionWorkflowManage},
		{http.MethodGet, "/api/v1/assets/" + testSessionID + "/labels", authz.PermissionDirectoryRead},
		{http.MethodPatch, "/api/v1/admin/assets/" + testSessionID + "/labels", authz.PermissionWorkflowManage},
		{http.MethodGet, "/api/v1/assets/" + testSessionID + "/workflow", authz.PermissionDirectoryRead},
		{http.MethodGet, "/api/v1/access-requests/" + testSessionID + "/workflow", authz.PermissionRequestManage},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			for _, authenticated := range []bool{false, true} {
				svc := &governanceAuthorizationStub{}
				server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
				request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
				request.Header.Set("Content-Type", "application/json")
				status := http.StatusUnauthorized
				if authenticated {
					request.Header.Set("X-User-ID", testUserID)
					status = http.StatusForbidden
				}
				response := httptest.NewRecorder()
				server.Container().ServeHTTP(response, request)
				if response.Code != status {
					t.Fatalf("authenticated=%v: status=%d, want %d; body=%s", authenticated, response.Code, status, response.Body.String())
				}
				if authenticated {
					if len(svc.permissions) != 1 || svc.permissions[0] != test.permission {
						t.Fatalf("checked permissions=%v, want [%s]", svc.permissions, test.permission)
					}
				} else if len(svc.permissions) != 0 {
					t.Fatalf("unauthenticated request checked permissions: %v", svc.permissions)
				}
			}
		})
	}
}
