package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

type settingsStub struct {
	SystemSettingsService
	snapshot *settings.Snapshot
	err      error
	reads    int
}

type mysqlCertificateStub struct {
	backendStub
	calls int
	err   error
}

func (s *mysqlCertificateStub) GenerateMySQLAuditCertificate(_ context.Context, actor string, input settings.CertificateRequest) (settings.CertificateBundle, error) {
	s.calls++
	if actor != testUserID || input.AssetID != testSessionID || input.TargetPort != 33306 || input.Purpose != "mysql" {
		return settings.CertificateBundle{}, service.ErrValidation
	}
	return settings.CertificateBundle{Certificate: "gateway-certificate", PrivateKey: "generated-private-key", TargetCertificateSHA256: strings.Repeat("a", 64)}, s.err
}

func TestMySQLCertificateGenerationRequiresEncryptedAdministratorRequest(t *testing.T) {
	const path = "/api/v1/admin/settings/audit/certificates"
	const body = `{"purpose":"mysql","asset_id":"` + testSessionID + `","target_port":33306,"hosts":["gateway.test"]}`
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &mysqlCertificateStub{}
	server.Service = backend
	for _, tc := range []struct {
		name, body               string
		plain, forbidden, failed bool
		status                   int
	}{
		{name: "generated", body: body, status: http.StatusOK},
		{name: "probe failed", body: body, failed: true, status: http.StatusBadRequest},
		{name: "plaintext", body: body, plain: true, status: http.StatusBadRequest},
		{name: "unauthorized", body: body, forbidden: true, status: http.StatusForbidden},
		{name: "arbitrary target", body: `{"purpose":"mysql","target_host":"unapproved.test"}`, status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend.authorizeErr, backend.err = nil, nil
			if tc.failed {
				backend.err = &service.RequestValidationError{Message: "无法读取 MySQL 资产证书"}
			}
			before := backend.calls
			request := httptest.NewRequest(http.MethodPost, "http://console.test"+path, strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("X-User-ID", testUserID)
			response := httptest.NewRecorder()
			if tc.plain {
				server.Container().ServeHTTP(response, request)
			} else {
				client := encryptTestRequest(t, server, request, tc.body)
				if tc.forbidden {
					backend.authorizeErr = service.ErrForbidden
				}
				server.Container().ServeHTTP(response, request)
				if tc.status == http.StatusOK || tc.failed {
					plaintext, err := client.Open(response.Code, response.Body.Bytes())
					if err != nil {
						t.Fatal(err)
					}
					if tc.failed {
						if !strings.Contains(string(plaintext), "无法读取 MySQL 资产证书") {
							t.Fatal("certificate failure lost its public reason")
						}
					} else {
						var bundle settings.CertificateBundle
						if json.Unmarshal(plaintext, &bundle) != nil || bundle.PrivateKey != "generated-private-key" || bundle.TargetCertificateSHA256 != strings.Repeat("a", 64) {
							t.Fatal("one-click generation lost the certificate or target pin")
						}
					}
				}
			}
			if response.Code != tc.status || strings.Contains(response.Body.String(), "generated-private-key") {
				t.Fatalf("unsafe certificate response: status=%d", response.Code)
			}
			if tc.status != http.StatusOK && !tc.failed && backend.calls != before {
				t.Fatal("rejected request reached asset certificate enrollment")
			}
		})
	}
}

func (s *settingsStub) Current(context.Context) (*settings.Snapshot, error) { return s.snapshot, s.err }
func (s *settingsStub) Get(context.Context) (service.SettingsView, error) {
	s.reads++
	return service.SettingsView{Config: settings.Defaults()}, nil
}

func TestSettingsReloadRejectsInFlightOAuth(t *testing.T) {
	provider := &redirectStub{}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, provider)
	store := &settingsStub{snapshot: server.authRuntime(context.Background())}
	store.snapshot.Revision = 1
	server.Settings = store
	begin := httptest.NewRecorder()
	server.Container().ServeHTTP(begin, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/oidc/login", nil))
	if begin.Code != http.StatusFound {
		t.Fatalf("begin: %d", begin.Code)
	}
	location, _ := url.Parse(begin.Header().Get("Location"))
	next := *store.snapshot
	next.Revision = 2
	next.Auth.LocalEnabled = false
	store.snapshot = &next
	callback := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/oidc/callback?code=code&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(begin.Result().Cookies()[0])
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, callback)
	if response.Code != http.StatusForbidden || provider.calls != 0 {
		t.Fatal("callback used a changed provider configuration")
	}
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/providers", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"local"`) {
		t.Fatal("local recovery provider disappeared")
	}
	store.err = errors.New("database unavailable")
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/auth/providers", nil))
	if response.Code == http.StatusOK {
		t.Fatal("database failure served stale login configuration")
	}
}

func TestSystemSettingsRequirePlatformAdministrator(t *testing.T) {
	permission, protected := routePermission(http.MethodPost, "/api/v1/admin/settings/audit/certificates")
	if !protected || permission != authz.PermissionRoleManage {
		t.Fatal("audit certificate generation exposed to non-platform administrators")
	}
	for _, method := range []string{http.MethodGet, http.MethodPatch} {
		permission, protected := routePermission(method, "/api/v1/admin/settings")
		if !protected || permission != authz.PermissionRoleManage {
			t.Fatal("settings exposed to catalog administrators")
		}
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	store := &settingsStub{}
	server.Settings = store
	server.AllowDevAuth = true
	server.Service = &backendStub{authorizeErr: service.ErrForbidden}
	request := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/admin/settings", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || store.reads != 0 {
		t.Fatal("unauthorized user read system settings")
	}
}
