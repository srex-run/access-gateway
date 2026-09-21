package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

type assetAuditStub struct {
	backendStub
	calls            int
	certificateCalls int
	certificateInput settings.CertificateRequest
}

func (s *assetAuditStub) GenerateAssetAuditCertificate(_ context.Context, actor string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	s.certificateCalls++
	s.certificateInput = input
	if actor != testUserID || (input.Purpose != "gateway" && input.Purpose != "setup") || len(input.Hosts) != 0 {
		return settings.CertificateBundle{}, service.ErrValidation
	}
	return settings.CertificateBundle{Certificate: "public-certificate", PrivateKey: "asset-private-key", TargetCertificateSHA256: strings.Repeat("a", 64)}, nil
}

func TestAssetAuditSetupEncryptedDraft(t *testing.T) {
	const body = `{"purpose":"setup","protocol":"mysql","target":"draft.internal","target_port":33306,"hosts":[],"valid_days":365}`
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &assetAuditStub{}
	server.Service = backend
	request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/assets/audit/certificates", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://console.test")
	request.Header.Set("X-User-ID", testUserID)
	client := encryptTestRequest(t, server, request, body)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || backend.certificateInput.Target != "draft.internal" || backend.certificateInput.TargetPort != 33306 || backend.certificateInput.Protocol != "mysql" {
		t.Fatalf("draft setup was not decoded correctly: status=%d", response.Code)
	}
	plaintext, err := client.Open(response.Code, response.Body.Bytes())
	var bundle settings.CertificateBundle
	if err != nil || json.Unmarshal(plaintext, &bundle) != nil || bundle.PrivateKey != "asset-private-key" || bundle.TargetCertificateSHA256 != strings.Repeat("a", 64) {
		t.Fatal("complete setup was not returned over encrypted transport")
	}
	if strings.Contains(response.Body.String(), "asset-private-key") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("setup response leaked or cached private key material")
	}
}

func TestAssetCertificateGenerationWithoutClientHosts(t *testing.T) {
	const path = "/api/v1/admin/assets/audit/certificates"
	const body = `{"purpose":"gateway","hosts":[],"valid_days":365}`
	for _, tc := range []struct {
		name             string
		plain, forbidden bool
		status           int
	}{
		{"encrypted", false, false, http.StatusOK},
		{"plaintext", true, false, http.StatusBadRequest},
		{"unauthorized", false, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
			server.AllowDevAuth = true
			backend := &assetAuditStub{}
			server.Service = backend
			request := httptest.NewRequest(http.MethodPost, "http://console.test"+path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("X-User-ID", testUserID)
			response := httptest.NewRecorder()
			if tc.plain {
				server.Container().ServeHTTP(response, request)
			} else {
				client := encryptTestRequest(t, server, request, body)
				if tc.forbidden {
					backend.authorizeErr = service.ErrForbidden
				}
				server.Container().ServeHTTP(response, request)
				if tc.status == http.StatusOK {
					plaintext, err := client.Open(response.Code, response.Body.Bytes())
					var bundle settings.CertificateBundle
					if err != nil || json.Unmarshal(plaintext, &bundle) != nil || bundle.PrivateKey != "asset-private-key" {
						t.Fatal("certificate without client-supplied hosts did not return encrypted key material")
					}
				}
			}
			if response.Code != tc.status || strings.Contains(response.Body.String(), "asset-private-key") {
				t.Fatalf("unsafe certificate response: status=%d", response.Code)
			}
			if tc.status != http.StatusOK && backend.certificateCalls != 0 {
				t.Fatal("unprotected generation reached the service")
			}
		})
	}
}

func (s *assetAuditStub) GetAssetAudit(_ context.Context, actorID, assetID string) (service.AssetAuditView, error) {
	s.calls++
	return service.AssetAuditView{Revision: 1, Profiles: []settings.AuditProfile{{Name: "asset." + assetID + ".3306", Port: 3306, Protocol: "mysql"}}, HasSecrets: map[string]settings.AuditKeyStatus{}}, nil
}

func TestAssetAuditPermissionAndEncryptedGeneration(t *testing.T) {
	const readPath = "/api/v1/admin/assets/" + testSessionID + "/audit"
	const generatePath = "/api/v1/admin/assets/audit/certificates"
	for _, route := range []struct{ method, path string }{{http.MethodGet, readPath}, {http.MethodPost, generatePath}} {
		if permission, protected := routePermission(route.method, route.path); !protected || permission != authz.PermissionCatalogManage {
			t.Fatal("asset audit endpoint missing catalog permission")
		}
	}
	if !encryptedRoute(http.MethodPost, generatePath) {
		t.Fatal("generated private key response not encrypted")
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &assetAuditStub{}
	server.Service = backend
	request := httptest.NewRequest(http.MethodGet, "http://console.test"+readPath, nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || backend.calls != 1 {
		t.Fatalf("asset audit read: %d %s", response.Code, response.Body.String())
	}
	backend.authorizeErr = service.ErrForbidden
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || backend.calls != 1 {
		t.Fatal("unauthorized audit read reached service")
	}
}
