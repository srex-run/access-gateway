package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/catalogrelease"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type cloudBackendStub struct {
	backendStub
	CloudService
	calls int
}

func (s *cloudBackendStub) ListCloudAccounts(context.Context, string) ([]domain.CloudAccount, error) {
	s.calls++
	return []domain.CloudAccount{{ID: testUserID, Name: "Cloud account", Provider: "aliyun", CredentialsCiphertext: "must-not-be-returned"}}, nil
}
func (s *cloudBackendStub) SaveCloudAccount(context.Context, string, string, service.CloudAccountInput) (domain.CloudAccount, error) {
	s.calls++
	return domain.CloudAccount{ID: testUserID, CredentialsCiphertext: "must-not-be-returned"}, nil
}
func (s *cloudBackendStub) ExportGatewayRelease(context.Context, string, string) (catalogrelease.Bundle, error) {
	s.calls++
	return catalogrelease.Bundle{Assets: []byte(`{"version":1,"assets":[]}`), Targets: []byte(`{"version":1,"targets":[]}`), Manifest: []byte(`{"version":1}`), Release: catalogrelease.Manifest{GatewayID: testUserID}}, nil
}

func TestCloudPermissionsAndCredentialResponses(t *testing.T) {
	for _, route := range []struct {
		method, path string
		permission   authz.Permission
	}{
		{http.MethodGet, "/api/v1/admin/cloud-accounts", authz.PermissionCatalogManage},
		{http.MethodPost, "/api/v1/admin/cloud-accounts", authz.PermissionRoleManage},
		{http.MethodPatch, "/api/v1/admin/cloud-accounts/" + testUserID, authz.PermissionRoleManage},
		{http.MethodPost, "/api/v1/admin/cloud-accounts/" + testUserID + "/sync", authz.PermissionCatalogManage},
		{http.MethodGet, "/api/v1/admin/cloud-sync-jobs", authz.PermissionCatalogManage},
		{http.MethodPost, "/api/v1/admin/gateways/" + testUserID + "/release", authz.PermissionCatalogManage},
	} {
		permission, protected := routePermission(route.method, route.path)
		if !protected || permission != route.permission {
			t.Fatalf("wrong cloud permissions for %s %s", route.method, route.path)
		}
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &cloudBackendStub{}
	server.Service = backend
	request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/admin/cloud-accounts", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "must-not-be-returned") {
		t.Fatalf("unsafe account response: %d", response.Code)
	}
	backend.authorizeErr = service.ErrForbidden
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || backend.calls != 1 {
		t.Fatal("unauthorized account read reached service")
	}
}

func TestCloudMutationsEnforceCSRFAndDecodeStrictly(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &cloudBackendStub{}
	server.Service = backend
	for _, sample := range []struct {
		body, origin string
		status       int
	}{
		{`{"provider":"aliyun","credentials_ciphertext":"injected"}`, "http://console.test", 400},
		{`{"name":"cloud","provider":"aliyun","access_key":"test-ak","secret_key":"test-sk","enabled":true}`, "https://attacker.test", 403},
	} {
		request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/cloud-accounts", strings.NewReader(sample.body))
		request.Header.Set("X-User-ID", testUserID)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", sample.origin)
		request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: "test-csrf-cookie"})
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != sample.status || backend.calls != 0 {
			t.Fatalf("cloud mutation guard: status %d expected %d", response.Code, sample.status)
		}
	}
}

func TestCloudGatewayArchiveIsPrivateAndComplete(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	server.Service = &cloudBackendStub{}
	request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/gateways/"+testUserID+"/release", nil)
	request.Header.Set("X-User-ID", testUserID)
	request.Header.Set("Origin", "http://console.test")
	client := encryptTestRequest(t, server, request, `{}`)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d", response.Code)
	}
	var archive struct {
		Filename string
		Data     []byte
	}
	plaintext, err := client.Open(response.Code, response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plaintext, &archive); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive.Data), int64(len(archive.Data)))
	if err != nil || len(reader.File) != 3 {
		t.Fatalf("invalid release archive: %v", err)
	}
	for index, file := range reader.File {
		if file.Name != []string{"assets.json", "targets.json", "manifest.json"}[index] || file.Mode().Perm() != 0600 {
			t.Fatal("archive file name or permissions changed")
		}
	}
}
