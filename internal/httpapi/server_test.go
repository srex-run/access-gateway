package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

const (
	testUserID     = "11111111-1111-4111-8111-111111111111"
	testSessionID  = "22222222-2222-4222-8222-222222222222"
	testApprovalID = "33333333-3333-4333-8333-333333333333"
)

type backendStub struct {
	BackendService
	closeCount       int
	decideErr        error
	authorizeErr     error
	authorizeCall    int
	catalogEntries   []domain.GatewayCatalogEntry
	catalogErr       error
	catalogCalls     int
	catalogGatewayID string
	gatewayEvents    []service.GatewayEventInput
	credentialRef    string
}

type gatewayAuthenticatorStub struct {
	accepted   bool
	err        error
	calls      int
	gatewayID  string
	credential string
}

func (s *gatewayAuthenticatorStub) Authenticate(_ context.Context, gatewayID, credential string) (bool, error) {
	s.calls++
	s.gatewayID = gatewayID
	s.credential = credential
	return s.accepted, s.err
}

func (s *backendStub) CheckActiveUser(context.Context, string) error { return nil }

func (s *backendStub) Authorize(context.Context, string, authz.Permission) error {
	s.authorizeCall++
	return s.authorizeErr
}

func (s *backendStub) GrantRole(context.Context, string, service.GrantRoleInput) (domain.RoleAssignment, error) {
	return domain.RoleAssignment{}, nil
}
func (s *backendStub) RevokeRole(context.Context, string, string) (domain.RoleAssignment, error) {
	return domain.RoleAssignment{}, nil
}
func (s *backendStub) ListRoleAssignments(context.Context, string, string) ([]domain.RoleAssignment, error) {
	return nil, nil
}

func (s *backendStub) ListGatewayCatalog(_ context.Context, _, gatewayID string) ([]domain.GatewayCatalogEntry, error) {
	s.catalogCalls++
	s.catalogGatewayID = gatewayID
	return s.catalogEntries, s.catalogErr
}

func (s *backendStub) UpdateGatewayAuthSecretRef(_ context.Context, _, gatewayID, reference string) (domain.Gateway, error) {
	s.catalogGatewayID = gatewayID
	s.credentialRef = reference
	return domain.Gateway{ID: gatewayID, UpdatedAt: time.Now().UTC()}, nil
}

func TestRoutePermissions(t *testing.T) {
	tests := []struct {
		method     string
		path       string
		permission authz.Permission
		protected  bool
	}{
		{http.MethodGet, "/healthz", "", false},
		{http.MethodGet, "/api/v1/auth/feishu/login", "", false},
		{http.MethodGet, "/api/v1/regions", authz.PermissionDirectoryRead, true},
		{http.MethodPost, "/api/v1/access-requests", authz.PermissionRequestManage, true},
		{http.MethodGet, "/api/v1/sessions/{session_id}", authz.PermissionSessionManage, true},
		{http.MethodGet, "/api/v1/audit-events", authz.PermissionAuditRead, true},
		{http.MethodGet, "/api/v1/operation-audit-events", authz.PermissionSessionManage, true},
		{http.MethodPost, "/api/v1/admin/assets", authz.PermissionCatalogManage, true},
		{http.MethodGet, "/api/v1/admin/gateways/{gateway_id}/catalog", authz.PermissionCatalogManage, true},
		{http.MethodPost, "/api/v1/admin/role-assignments", authz.PermissionRoleManage, true},
		{http.MethodPost, "/api/v1/admin/sessions/{session_id}/force-close", authz.PermissionSessionOverride, true},
	}
	for _, test := range tests {
		permission, protected := routePermission(test.method, test.path)
		if permission != test.permission || protected != test.protected {
			t.Errorf("routePermission(%q, %q) = %q, %v", test.method, test.path, permission, protected)
		}
	}
}

func (s *backendStub) ListRegions(context.Context) ([]domain.Region, error) {
	return []domain.Region{{ID: testSessionID, Code: "cn-test", Name: "Test", Status: domain.ResourceStatusEnabled}}, nil
}

func (s *backendStub) GetSession(context.Context, string, string) (service.SessionView, error) {
	sourceIP, account := "203.0.113.10", "readonly"
	return service.SessionView{
		Session: domain.Session{ID: testSessionID, Status: domain.SessionRunning, ConnectionMode: gateway.ConnectionModeNative},
		Request: domain.AccessRequest{TargetPort: 5432, SourceIP: &sourceIP, TargetAccount: &account}, GatewayEndpoint: "gateway.example:32001",
		GatewayHost: "gateway.example", GatewayPort: 32001,
	}, nil
}

func (s *backendStub) CloseSession(context.Context, string, string) (domain.Session, error) {
	s.closeCount++
	return domain.Session{ID: testSessionID, Status: domain.SessionClosed}, nil
}

func (s *backendStub) ForceCloseSession(context.Context, string, string, string) (domain.Session, error) {
	return domain.Session{}, service.ErrForbidden
}

func (s *backendStub) RecordGatewayEvent(_ context.Context, input service.GatewayEventInput) error {
	s.gatewayEvents = append(s.gatewayEvents, input)
	return nil
}

func (s *backendStub) DecideApprovalByExternalUser(context.Context, string, string, domain.ApprovalDecision, *string) (service.ApprovalResult, error) {
	if s.decideErr != nil {
		return service.ApprovalResult{}, s.decideErr
	}
	return service.ApprovalResult{}, nil
}

type databaseStub struct{}

func (databaseStub) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, errors.New("unexpected QueryContext")
}

func (databaseStub) QueryRowContext(context.Context, string, ...any) *sql.Row { return &sql.Row{} }

func (databaseStub) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errors.New("unexpected ExecContext")
}

func (databaseStub) PingContext(context.Context) error { return nil }

type callbackStoreStub struct {
	mu        sync.Mutex
	processed map[string]bool
	claims    int
	releases  int
}

func newCallbackStoreStub() *callbackStoreStub {
	return &callbackStoreStub{processed: make(map[string]bool)}
}

func (s *callbackStoreStub) Claim(_ context.Context, _ repository.DBTX, eventID string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims++
	return !s.processed[eventID], nil
}

func (s *callbackStoreStub) MarkProcessed(_ context.Context, _ repository.DBTX, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.processed[eventID] = true
	return nil
}

func (s *callbackStoreStub) Release(context.Context, repository.DBTX, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases++
	return nil
}

func testServer(t *testing.T, svc BackendService, options func(*Server)) *Server {
	t.Helper()
	server, err := NewServerWithOptions(ServerOptions{
		Service: svc,
		DB:      databaseStub{},
		Logger:  zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("NewServerWithOptions: %v", err)
	}
	if options != nil {
		options(server)
	}
	return server
}

func TestAuthenticationAndDevIdentity(t *testing.T) {
	svc := &backendStub{}
	server := testServer(t, svc, nil)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/regions", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("production dev-header status = %d body=%s", response.Code, response.Body.String())
	}

	server.AllowDevAuth = true
	response = httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "cn-test") {
		t.Fatalf("development auth response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestAuthorizationFilterDeniesAdminRouteBeforeHandler(t *testing.T) {
	svc := &backendStub{authorizeErr: service.ErrForbidden}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/regions", strings.NewReader(`{"code":"prod","name":"Production","status":"enabled"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || svc.authorizeCall != 1 {
		t.Fatalf("authorization response = %d calls=%d body=%s", response.Code, svc.authorizeCall, response.Body.String())
	}
}

func TestGatewayCatalogExportIsStableAndNonSecret(t *testing.T) {
	externalSource := "primary-cmdb"
	externalID := "cmdb-db-001"
	svc := &backendStub{catalogEntries: []domain.GatewayCatalogEntry{
		{TargetID: testSessionID, ExternalSource: &externalSource, ExternalID: &externalID, Ports: []int{5432, 6432}},
	}}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/gateways/"+testApprovalID+"/catalog", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)

	if response.Code != http.StatusOK || svc.catalogCalls != 1 || svc.catalogGatewayID != testApprovalID {
		t.Fatalf("catalog response = %d calls=%d gateway=%q body=%s", response.Code, svc.catalogCalls, svc.catalogGatewayID, response.Body.String())
	}
	var result gatewayCatalogResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode catalog response: %v", err)
	}
	if result.Version != 1 || result.GatewayID != testApprovalID || len(result.Assets) != 1 || result.Assets[0].TargetID != testSessionID || result.Assets[0].ExternalSource == nil || *result.Assets[0].ExternalSource != externalSource || result.Assets[0].ExternalID == nil || *result.Assets[0].ExternalID != externalID || len(result.Assets[0].Ports) != 2 || result.Assets[0].Ports[0] != 5432 || result.Assets[0].Ports[1] != 6432 {
		t.Fatalf("unexpected catalog response: %+v", result)
	}
	for _, forbidden := range []string{"target_ciphertext", "management_endpoint", "auth_secret_ref"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("catalog response leaked %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestUpdateGatewayCredentialReferenceDoesNotReturnReference(t *testing.T) {
	svc := &backendStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/gateways/"+testApprovalID+"/credential-reference", strings.NewReader(`{"auth_secret_ref":"gateway-cn-east-1"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || svc.catalogGatewayID != testApprovalID || svc.credentialRef != "gateway-cn-east-1" {
		t.Fatalf("credential reference response=%d gateway=%q ref=%q body=%s", response.Code, svc.catalogGatewayID, svc.credentialRef, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "auth_secret_ref") || strings.Contains(response.Body.String(), "gateway-cn-east-1") {
		t.Fatalf("credential reference leaked in response: %s", response.Body.String())
	}
}

func TestSessionResponseContainsDirectEndpointAndRetiredCredentialRoutesAreAbsent(t *testing.T) {
	svc := &backendStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })

	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+testSessionID, nil)
	getRequest.Header.Set("X-User-ID", testUserID)
	getResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), "gateway.example:32001") || strings.Contains(getResponse.Body.String(), "token") {
		t.Fatalf("GET session response = %d body=%s", getResponse.Code, getResponse.Body.String())
	}
	var body struct {
		ConnectionMode string `json:"connection_mode"`
		SourceIP       string `json:"source_ip"`
		TargetAccount  string `json:"target_account"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &body); err != nil || body.ConnectionMode != gateway.ConnectionModeNative || body.SourceIP != "203.0.113.10" || body.TargetAccount != "readonly" {
		t.Fatalf("native session fields: %+v, %v", body, err)
	}
	for _, endpoint := range []string{"token", "credential"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+testSessionID+"/"+endpoint, strings.NewReader(`{}`))
		request.Header.Set("X-User-ID", testUserID)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("removed %s route status = %d body=%s", endpoint, response.Code, response.Body.String())
		}
	}
}

func TestGatewayEventBatchAcknowledgesExactIDsAndRejectsDuplicates(t *testing.T) {
	secret := strings.Repeat("g", 32)
	svc := &backendStub{}
	server := testServer(t, svc, func(server *Server) { server.GatewayInternalSecret = secret })
	firstID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
	secondID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
	gatewayID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	request := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"`+firstID+`","gateway_id":"`+gatewayID+`"},{"event_id":"`+secondID+`","gateway_id":"`+gatewayID+`"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Gateway-Internal-Secret", secret)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(svc.gatewayEvents) != 2 {
		t.Fatalf("batch response=%d events=%d body=%s", response.Code, len(svc.gatewayEvents), response.Body.String())
	}
	var acknowledgement gateway.ConnectionEventBatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &acknowledgement); err != nil || acknowledgement.Version != gateway.ConnectionEventBatchResponseVersion || len(acknowledgement.AcceptedEventIDs) != 2 || acknowledgement.AcceptedEventIDs[0] != firstID || acknowledgement.AcceptedEventIDs[1] != secondID {
		t.Fatalf("batch acknowledgement=%+v err=%v", acknowledgement, err)
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"`+firstID+`","gateway_id":"`+gatewayID+`"},{"event_id":" `+firstID+` ","gateway_id":"`+gatewayID+`"}]}`))
	duplicate.Header.Set("Content-Type", "application/json")
	duplicate.Header.Set("X-Gateway-Internal-Secret", secret)
	duplicateResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusBadRequest || len(svc.gatewayEvents) != 2 {
		t.Fatalf("duplicate response=%d events=%d body=%s", duplicateResponse.Code, len(svc.gatewayEvents), duplicateResponse.Body.String())
	}
}

func TestGatewayEventPerGatewayAuthenticationBindsBatchIdentity(t *testing.T) {
	gatewayID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	otherGatewayID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	credential := "audit---0123456789abcdef0123456789"
	authenticator := &gatewayAuthenticatorStub{accepted: true}
	svc := &backendStub{}
	server := testServer(t, svc, func(server *Server) {
		server.GatewayAuditAuthMode = gatewayauth.ModePerGateway
		server.GatewayAuthenticator = authenticator
	})

	request := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1","gateway_id":"`+gatewayID+`"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
	request.Header.Set(gateway.AuditSecretHeader, credential)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(svc.gatewayEvents) != 1 || authenticator.calls != 1 || authenticator.gatewayID != gatewayID || authenticator.credential != credential {
		t.Fatalf("bound request status=%d events=%d auth=%+v body=%s", response.Code, len(svc.gatewayEvents), authenticator, response.Body.String())
	}

	mismatch := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2","gateway_id":"`+otherGatewayID+`"}]}`))
	mismatch.Header.Set("Content-Type", "application/json")
	mismatch.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
	mismatch.Header.Set(gateway.AuditSecretHeader, credential)
	mismatchResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(mismatchResponse, mismatch)
	if mismatchResponse.Code != http.StatusForbidden || len(svc.gatewayEvents) != 1 {
		t.Fatalf("mismatch status=%d events=%d body=%s", mismatchResponse.Code, len(svc.gatewayEvents), mismatchResponse.Body.String())
	}

	mixed := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3","gateway_id":"`+gatewayID+`"},{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4","gateway_id":"`+otherGatewayID+`"}]}`))
	mixed.Header.Set("Content-Type", "application/json")
	mixed.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
	mixed.Header.Set(gateway.AuditSecretHeader, credential)
	mixedResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(mixedResponse, mixed)
	if mixedResponse.Code != http.StatusForbidden || len(svc.gatewayEvents) != 1 {
		t.Fatalf("mixed batch status=%d events=%d body=%s", mixedResponse.Code, len(svc.gatewayEvents), mixedResponse.Body.String())
	}

	single := httptest.NewRequest(http.MethodPost, "/internal/gateway/events", strings.NewReader(`{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5","gateway_id":"`+otherGatewayID+`"}`))
	single.Header.Set("Content-Type", "application/json")
	single.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
	single.Header.Set(gateway.AuditSecretHeader, credential)
	singleResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(singleResponse, single)
	if singleResponse.Code != http.StatusForbidden || len(svc.gatewayEvents) != 1 {
		t.Fatalf("single mismatch status=%d events=%d body=%s", singleResponse.Code, len(svc.gatewayEvents), singleResponse.Body.String())
	}

	legacy := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(`{"events":[{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6","gateway_id":"`+gatewayID+`"}]}`))
	legacy.Header.Set("Content-Type", "application/json")
	legacy.Header.Set(gateway.InternalSecretHeader, strings.Repeat("s", 32))
	legacyResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusUnauthorized || len(svc.gatewayEvents) != 1 {
		t.Fatalf("legacy protocol status=%d events=%d body=%s", legacyResponse.Code, len(svc.gatewayEvents), legacyResponse.Body.String())
	}
}

func TestGatewayEventTransitionModeDoesNotDowngradeNewProtocol(t *testing.T) {
	gatewayID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	sharedSecret := strings.Repeat("s", 32)
	authenticator := &gatewayAuthenticatorStub{accepted: false}
	svc := &backendStub{}
	server := testServer(t, svc, func(server *Server) {
		server.GatewayAuditAuthMode = gatewayauth.ModeTransition
		server.GatewayInternalSecret = sharedSecret
		server.GatewayAuthenticator = authenticator
	})
	body := `{"events":[{"event_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1","gateway_id":"` + gatewayID + `"}]}`

	downgrade := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(body))
	downgrade.Header.Set("Content-Type", "application/json")
	downgrade.Header.Set(gateway.AuditGatewayIDHeader, gatewayID)
	downgrade.Header.Set(gateway.AuditSecretHeader, "wrong---0123456789abcdef0123456789")
	downgradeResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(downgradeResponse, downgrade)
	if downgradeResponse.Code != http.StatusUnauthorized || len(svc.gatewayEvents) != 0 {
		t.Fatalf("downgrade status=%d events=%d body=%s", downgradeResponse.Code, len(svc.gatewayEvents), downgradeResponse.Body.String())
	}

	legacy := httptest.NewRequest(http.MethodPost, "/internal/gateway/events/batch", strings.NewReader(body))
	legacy.Header.Set("Content-Type", "application/json")
	legacy.Header.Set(gateway.InternalSecretHeader, sharedSecret)
	legacyResponse := httptest.NewRecorder()
	server.Container().ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusOK || len(svc.gatewayEvents) != 1 || authenticator.calls != 1 {
		t.Fatalf("legacy status=%d events=%d auth_calls=%d body=%s", legacyResponse.Code, len(svc.gatewayEvents), authenticator.calls, legacyResponse.Body.String())
	}
}

func TestServerRequiresConfiguredGatewayAuditAuthentication(t *testing.T) {
	_, err := NewServerWithOptions(ServerOptions{
		Service: &backendStub{}, DB: databaseStub{}, Logger: zerolog.Nop(),
		GatewayAuditAuthMode: gatewayauth.ModePerGateway,
	})
	if err == nil || !strings.Contains(err.Error(), "authenticator") {
		t.Fatalf("missing authenticator error = %v", err)
	}
	_, err = NewServerWithOptions(ServerOptions{
		Service: &backendStub{}, DB: databaseStub{}, Logger: zerolog.Nop(),
		GatewayAuditAuthMode: gatewayauth.ModeTransition,
		GatewayAuthenticator: &gatewayAuthenticatorStub{accepted: true},
	})
	if err == nil || !strings.Contains(err.Error(), "shared secret") {
		t.Fatalf("missing transition secret error = %v", err)
	}
}

func TestCookieAuthenticatedWritesRequireSameOrigin(t *testing.T) {
	for _, test := range []struct {
		name     string
		origin   string
		referer  string
		expected int
	}{
		{name: "missing source", expected: http.StatusForbidden},
		{name: "cross site", origin: "https://attacker.example", expected: http.StatusForbidden},
		{name: "same origin", origin: "https://gateway.example", expected: http.StatusOK},
		{name: "same origin referer", referer: "https://gateway.example/console/requests", expected: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer, err := security.NewSessionSigner(strings.Repeat("s", 32))
			if err != nil {
				t.Fatalf("NewSessionSigner: %v", err)
			}
			svc := &backendStub{}
			server := testServer(t, svc, func(server *Server) { server.SessionSigner = signer })
			request := httptest.NewRequest(http.MethodPost, "https://gateway.example/api/v1/sessions/"+testSessionID+"/close", nil)
			request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: signer.Sign(testUserID, time.Now().Add(time.Hour))})
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.referer != "" {
				request.Header.Set("Referer", test.referer)
			}
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != test.expected {
				t.Fatalf("response = %d body=%s", response.Code, response.Body.String())
			}
			if test.expected == http.StatusForbidden && svc.closeCount != 0 {
				t.Fatalf("handler was called %d time(s)", svc.closeCount)
			}
		})
	}
}

func TestForceCloseMapsAuthorizationFailure(t *testing.T) {
	server := testServer(t, &backendStub{}, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/sessions/"+testSessionID+"/force-close", strings.NewReader(`{"reason":"operator request"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("force-close status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestFeishuCallbackVerifiesSignatureAndDeduplicates(t *testing.T) {
	const secret = "callback-secret"
	store := newCallbackStoreStub()
	server := testServer(t, &backendStub{}, func(server *Server) {
		server.FeishuCallbackSecret = secret
		server.FeishuTenantKey = "tenant-1"
		server.CallbackEvents = store
	})
	body := []byte(`{"header":{"event_id":"event-1","tenant_key":"tenant-1"},"event":{"operator":{"operator_id":{"open_id":"ou-approver"}},"action":{"value":{"approval_id":"` + testApprovalID + `","decision":"approved"}}}}`)

	for attempt, expectedStatus := range []string{"processed", "already_processed"} {
		response := performSignedCallback(server, body, secret, "nonce-1")
		if response.Code != http.StatusOK {
			t.Fatalf("callback attempt %d status = %d body=%s", attempt+1, response.Code, response.Body.String())
		}
		var result map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result["status"] != expectedStatus {
			t.Fatalf("callback attempt %d result=%v err=%v", attempt+1, result, err)
		}
	}
	if store.claims != 2 || store.releases != 0 {
		t.Fatalf("callback store claims=%d releases=%d", store.claims, store.releases)
	}

	request := httptest.NewRequest(http.MethodPost, "/callbacks/feishu", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Lark-Request-Timestamp", time.Now().Format("not-a-unix-timestamp"))
	request.Header.Set("X-Lark-Request-Nonce", "nonce-1")
	request.Header.Set("X-Lark-Signature", "invalid")
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || store.claims != 2 {
		t.Fatalf("invalid callback response=%d claims=%d", response.Code, store.claims)
	}
}

func TestFeishuCallbackReleasesClaimAfterProcessingFailure(t *testing.T) {
	const secret = "callback-secret"
	store := newCallbackStoreStub()
	svc := &backendStub{decideErr: errors.New("temporary failure")}
	server := testServer(t, svc, func(server *Server) {
		server.FeishuCallbackSecret = secret
		server.CallbackEvents = store
	})
	body := []byte(`{"header":{"event_id":"event-failed"},"approval_id":"` + testApprovalID + `","approver_id":"ou-approver","decision":"approved"}`)
	response := performSignedCallback(server, body, secret, "nonce-2")
	if response.Code != http.StatusInternalServerError || store.releases != 1 {
		t.Fatalf("failed callback response=%d releases=%d body=%s", response.Code, store.releases, response.Body.String())
	}
}

func TestURLVerificationRequiresValidSignature(t *testing.T) {
	server := testServer(t, &backendStub{}, func(server *Server) { server.FeishuCallbackSecret = "callback-secret" })
	body := []byte(`{"type":"url_verification","challenge":"challenge-value"}`)
	request := httptest.NewRequest(http.MethodPost, "/callbacks/feishu", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "challenge-value") {
		t.Fatalf("unsigned verification response=%d body=%s", response.Code, response.Body.String())
	}

	response = performSignedCallback(server, body, "callback-secret", "nonce-3")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "challenge-value") {
		t.Fatalf("signed verification response=%d body=%s", response.Code, response.Body.String())
	}
}

func performSignedCallback(server *Server, body []byte, secret, nonce string) *httptest.ResponseRecorder {
	unixText := strconv.FormatInt(time.Now().Unix(), 10)
	hash := sha256.New()
	_, _ = hash.Write([]byte(unixText + nonce + secret))
	_, _ = hash.Write(body)

	request := httptest.NewRequest(http.MethodPost, "/callbacks/feishu", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Lark-Request-Timestamp", unixText)
	request.Header.Set("X-Lark-Request-Nonce", nonce)
	request.Header.Set("X-Lark-Signature", hex.EncodeToString(hash.Sum(nil)))
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	return response
}
