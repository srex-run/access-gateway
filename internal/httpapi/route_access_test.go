package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestRegisteredRoutesRequireExplicitAccessPolicy(t *testing.T) {
	backend := &backendStub{authorizeErr: service.ErrForbidden}
	server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
	container := server.Container()
	parameter := regexp.MustCompile(`\{[^}]+\}`)
	count := 0
	for _, ws := range container.RegisteredWebServices() {
		for _, route := range ws.Routes() {
			count++
			permission, protected := routePermission(route.Method, route.Path)
			exception := routeAccessException(route.Method, route.Path)
			if !protected && exception == "" {
				t.Errorf("unclassified route: %s %s", route.Method, route.Path)
				continue
			}
			if protected && !authz.Known(permission) {
				t.Errorf("unknown permission: %s %s: %s", route.Method, route.Path, permission)
			}
			if !protected && exception != "authenticated" {
				continue
			}
			t.Run(route.Method+" "+route.Path, func(t *testing.T) {
				for _, authenticated := range []bool{false, true} {
					if authenticated && !protected {
						continue
					}
					req := httptest.NewRequest(route.Method, "http://console.test"+parameter.ReplaceAllString(route.Path, testSessionID), strings.NewReader(`{}`))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", "http://console.test")
					want := http.StatusUnauthorized
					if authenticated {
						req.Header.Set("X-User-ID", testUserID)
						want = http.StatusForbidden
					}
					res := httptest.NewRecorder()
					container.ServeHTTP(res, req)
					if res.Code != want {
						t.Fatalf("authenticated=%v status=%d want=%d body=%s", authenticated, res.Code, want, res.Body.String())
					}
				}
			})
		}
	}
	t.Logf("checked %d registered routes", count)
}

func TestUnclassifiedAPIRouteIsDeniedBeforeHandler(t *testing.T) {
	server := testServer(t, &backendStub{}, func(s *Server) { s.AllowDevAuth = true })
	container := server.Container()
	ws := new(restful.WebService).Path("/api/v1/unclassified").Produces(restful.MIME_JSON)
	called := false
	ws.Route(ws.GET("/resource").To(func(_ *restful.Request, _ *restful.Response) { called = true }))
	container.Add(ws)
	req := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/unclassified/resource", nil)
	req.Header.Set("X-User-ID", testUserID)
	res := httptest.NewRecorder()
	container.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || called {
		t.Fatal("unclassified API route was allowed")
	}
}

type auditReaderBackend struct {
	operationAuditSessionsStub
	allowed authz.Permission
}

func (b *auditReaderBackend) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	if permission == b.allowed {
		return nil
	}
	return service.ErrForbidden
}

func TestOperationAuditAllowsAuditReadersWithoutSessionManagement(t *testing.T) {
	for _, permission := range []authz.Permission{authz.PermissionAuditRead, authz.PermissionSessionManage, authz.PermissionDirectoryRead} {
		for _, path := range []string{"/operation-audit-events", "/operation-audit-sessions"} {
			backend := &auditReaderBackend{allowed: permission}
			server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
			req := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1"+path, nil)
			req.Header.Set("X-User-ID", testUserID)
			res := httptest.NewRecorder()
			server.Container().ServeHTTP(res, req)
			want, calls := http.StatusOK, 1
			if permission == authz.PermissionDirectoryRead {
				want, calls = http.StatusForbidden, 0
			}
			if res.Code != want || backend.calls != calls {
				t.Fatalf("%s %s: status=%d calls=%d", permission, path, res.Code, backend.calls)
			}
		}
	}
}
