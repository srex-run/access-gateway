package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type managedAssetStub struct {
	backendStub
	calls int
}

type assetWorkflowOptionsStub struct {
	backendStub
	calls int
}

func (s *assetWorkflowOptionsStub) ListAssetWorkflows(context.Context, string) ([]approvalflow.Definition, error) {
	s.calls++
	return []approvalflow.Definition{{ID: testApprovalID, Name: "数据库审批", Enabled: true}}, nil
}

func TestAssetWorkflowOptionsRequireCatalogPermission(t *testing.T) {
	backend := &assetWorkflowOptionsStub{}
	server := testServer(t, backend, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/asset-workflows", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "数据库审批") {
		t.Fatalf("workflow choices unavailable: %d %s", response.Code, response.Body.String())
	}
	backend.authorizeErr = service.ErrForbidden
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || backend.calls != 1 {
		t.Fatal("unauthorized workflow choices reached service")
	}
}

func (s *managedAssetStub) ListManagedAssets(context.Context, string) ([]domain.Asset, error) {
	s.calls++
	return []domain.Asset{{ID: testUserID, RegionID: testSessionID, Name: "production-ecs", Status: domain.ResourceStatusDisabled, TargetCiphertext: "must-not-leak"}}, nil
}

func TestManagedAssetsRequireCatalogPermissionAndHideTargets(t *testing.T) {
	permission, protected := routePermission(http.MethodGet, "/api/v1/admin/assets")
	if !protected || permission != authz.PermissionCatalogManage {
		t.Fatal("managed assets must require catalog management permission")
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &managedAssetStub{}
	server.Service = backend
	request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/admin/assets", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "must-not-leak") || strings.Contains(response.Body.String(), "target_ciphertext") {
		t.Fatalf("unsafe asset response: %d %s", response.Code, response.Body.String())
	}
	var assets []assetResponse
	if err := json.Unmarshal(response.Body.Bytes(), &assets); err != nil || len(assets) != 1 || assets[0].Status != "disabled" {
		t.Fatalf("disabled assets missing from management list: %v", err)
	}
	backend.authorizeErr = service.ErrForbidden
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || backend.calls != 1 {
		t.Fatal("unauthorized list reached the backend")
	}
}

type assetUpdateStub struct {
	backendStub
	inputs []service.UpdateAssetInput
}

func (s *assetUpdateStub) UpdateAsset(_ context.Context, actorID, assetID string, input service.UpdateAssetInput) (domain.Asset, error) {
	if actorID != testUserID || assetID != testSessionID {
		return domain.Asset{}, service.ErrValidation
	}
	s.inputs = append(s.inputs, input)
	return domain.Asset{ID: assetID, Name: "updated-asset", TargetCiphertext: "encrypted-target-must-not-leak", ApprovalWorkflowID: input.ApprovalWorkflowID}, nil
}

func TestAssetUpdateRequiresEncryptedCatalogRequest(t *testing.T) {
	const path = "/api/v1/admin/assets/" + testSessionID
	permission, protected := routePermission(http.MethodPatch, path)
	if !protected || permission != authz.PermissionCatalogManage {
		t.Fatal("asset edits must require catalog management permission")
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &assetUpdateStub{}
	server.Service = backend
	for _, body := range []string{`{"target":"127.0.0.1"}`, `{"name":"updated-asset","approval_workflow_id":"` + testApprovalID + `"}`} {
		request := httptest.NewRequest(http.MethodPatch, "http://console.test"+path, nil)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://console.test")
		request.Header.Set("X-User-ID", testUserID)
		client := encryptTestRequest(t, server, request, body)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("X-AG-Encrypted") != "1" {
			t.Fatalf("asset update response: %d %s", response.Code, response.Body.String())
		}
		plaintext, err := client.Open(response.Code, response.Body.Bytes())
		if err != nil || strings.Contains(string(plaintext), "target") || strings.Contains(string(plaintext), "127.0.0.1") {
			t.Fatalf("unsafe asset response: %s %v", plaintext, err)
		}
		if strings.Contains(body, "approval_workflow_id") && !strings.Contains(string(plaintext), testApprovalID) {
			t.Fatal("asset response omitted the saved workflow assignment")
		}
	}
	if len(backend.inputs) != 2 || backend.inputs[0].Target == nil || *backend.inputs[0].Target != "127.0.0.1" || backend.inputs[0].Name != nil || backend.inputs[1].Target != nil {
		t.Fatalf("partial asset edits did not preserve omitted fields: %+v", backend.inputs)
	}
	if backend.inputs[0].ApprovalWorkflowID != nil || backend.inputs[1].ApprovalWorkflowID == nil || *backend.inputs[1].ApprovalWorkflowID != testApprovalID {
		t.Fatal("asset workflow assignment was not decoded")
	}
	for _, tc := range []struct {
		name, body string
		encrypt    bool
		forbidden  bool
		status     int
	}{
		{name: "plaintext", body: `{"target":"127.0.0.1"}`, status: http.StatusBadRequest},
		{name: "ciphertext injection", body: `{"target_ciphertext":"injected"}`, encrypt: true, status: http.StatusBadRequest},
		{name: "routing injection", body: `{"gateway_id":"other"}`, encrypt: true, status: http.StatusBadRequest},
		{name: "unauthorized", body: `{"name":"updated"}`, encrypt: true, forbidden: true, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend.authorizeErr = nil
			request := httptest.NewRequest(http.MethodPatch, "http://console.test"+path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("X-User-ID", testUserID)
			if tc.encrypt {
				encryptTestRequest(t, server, request, tc.body)
			}
			if tc.forbidden {
				backend.authorizeErr = service.ErrForbidden
			}
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != tc.status || len(backend.inputs) != 2 {
				t.Fatalf("rejected asset edit reached service: %d calls=%d", response.Code, len(backend.inputs))
			}
		})
	}
}
