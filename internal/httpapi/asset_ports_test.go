package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type assetPortListStub struct {
	backendStub
	values       []domain.AssetPort
	actor, asset string
	calls        int
}

func (s *assetPortListStub) ListAssetPorts(_ context.Context, actor, asset string) ([]domain.AssetPort, error) {
	s.actor, s.asset = actor, asset
	s.calls++
	return s.values, nil
}

func TestAssetPortsExposeAccountRequirementToApplicants(t *testing.T) {
	for _, forbidden := range []bool{false, true} {
		backend := &assetPortListStub{values: []domain.AssetPort{
			{ID: testApprovalID, AssetID: testSessionID, Port: 60022, Protocol: "tcp", TargetAccountRequired: true},
			{ID: testUserID, AssetID: testSessionID, Port: 22, Protocol: "tcp"},
		}}
		if forbidden {
			backend.authorizeErr = service.ErrForbidden
		}
		server := testServer(t, backend, func(server *Server) { server.AllowDevAuth = true })
		request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/assets/"+testSessionID+"/ports", nil)
		request.Header.Set("X-User-ID", testUserID)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if forbidden {
			if response.Code != http.StatusForbidden || backend.calls != 0 {
				t.Fatal("port requirements bypassed directory authorization")
			}
			continue
		}
		if response.Code != http.StatusOK || backend.actor != testUserID || backend.asset != testSessionID {
			t.Fatalf("list ports: %d %s", response.Code, response.Body.String())
		}
		var ports []map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &ports); err != nil || len(ports) != 2 {
			t.Fatalf("invalid ports response: %s", response.Body.String())
		}
		for i, port := range ports {
			if len(port) != 5 || port["target_account_required"] != (i == 0) {
				t.Fatalf("public port metadata is missing its account requirement: %v", port)
			}
		}
	}
}

type assetPortDeleteStub struct {
	backendStub
	actor, asset, port string
	calls              int
	err                error
}

func (s *assetPortDeleteStub) DeleteAssetPort(_ context.Context, actor, asset, port string) error {
	s.actor, s.asset, s.port = actor, asset, port
	s.calls++
	return s.err
}

func TestDeleteAssetPortRequiresCatalogPermission(t *testing.T) {
	const path = "/api/v1/admin/assets/" + testSessionID + "/ports/" + testApprovalID
	permission, protected := routePermission(http.MethodDelete, path)
	if !protected || permission != authz.PermissionCatalogManage {
		t.Fatal("asset port deletion must require catalog management permission")
	}
	for _, tc := range []struct {
		name       string
		permission error
		backendErr error
		status     int
		calls      int
	}{
		{name: "delete without request body", status: http.StatusNoContent, calls: 1},
		{name: "forbidden", permission: service.ErrForbidden, status: http.StatusForbidden},
		{name: "missing or foreign asset port", backendErr: repository.ErrNotFound, status: http.StatusNotFound, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &assetPortDeleteStub{backendStub: backendStub{authorizeErr: tc.permission}, err: tc.backendErr}
			server := testServer(t, backend, func(server *Server) { server.AllowDevAuth = true })
			request := httptest.NewRequest(http.MethodDelete, "http://console.test"+path, nil)
			request.Header.Set("X-User-ID", testUserID)
			request.Header.Set("Origin", "http://console.test")
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != tc.status || backend.calls != tc.calls {
				t.Fatalf("delete response: status=%d calls=%d body=%s", response.Code, backend.calls, response.Body.String())
			}
			if tc.calls > 0 && (backend.actor != testUserID || backend.asset != testSessionID || backend.port != testApprovalID) {
				t.Fatalf("wrong deletion scope: actor=%s asset=%s port=%s", backend.actor, backend.asset, backend.port)
			}
			if response.Code == http.StatusNoContent && response.Body.Len() != 0 {
				t.Fatal("successful deletion returned an unexpected body")
			}
		})
	}
}
