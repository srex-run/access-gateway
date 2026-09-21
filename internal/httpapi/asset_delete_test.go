package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type assetDeleteStub struct {
	backendStub
	actor, asset string
	calls        int
	err          error
}

func (s *assetDeleteStub) DeleteAsset(_ context.Context, actor, asset string) error {
	s.actor, s.asset, s.calls = actor, asset, s.calls+1
	return s.err
}

func TestDeleteAssetRequiresCatalogPermission(t *testing.T) {
	for _, tc := range []struct {
		name            string
		anonymous       bool
		permission, err error
		status, calls   int
	}{
		{name: "allowed", status: http.StatusNoContent, calls: 1},
		{name: "anonymous", anonymous: true, status: http.StatusUnauthorized},
		{name: "forbidden", permission: service.ErrForbidden, status: http.StatusForbidden},
		{name: "missing", err: repository.ErrNotFound, status: http.StatusNotFound, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &assetDeleteStub{backendStub: backendStub{authorizeErr: tc.permission}, err: tc.err}
			server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true })
			req := httptest.NewRequest(http.MethodDelete, "http://console.test/api/v1/admin/assets/"+testSessionID, nil)
			if !tc.anonymous {
				req.Header.Set("X-User-ID", testUserID)
			}
			res := httptest.NewRecorder()
			server.Container().ServeHTTP(res, req)
			if res.Code != tc.status || backend.calls != tc.calls {
				t.Fatalf("status=%d calls=%d body=%s", res.Code, backend.calls, res.Body.String())
			}
			if tc.calls > 0 && (backend.actor != testUserID || backend.asset != testSessionID) {
				t.Fatal("wrong asset deletion scope")
			}
		})
	}
}
