package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

type consoleBackendStub struct {
	backendStub
	actorID  string
	decision domain.ApprovalDecision
	comment  *string
	limit    int
	offset   int
	denied   bool
}

func (s *consoleBackendStub) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	if s.authorizeErr != nil {
		return s.authorizeErr
	}
	if s.denied || permission == authz.PermissionRoleManage {
		return service.ErrForbidden
	}
	return nil
}

func (s *consoleBackendStub) ListPendingApprovals(_ context.Context, actorID string, limit, offset int) ([]domain.Approval, error) {
	s.actorID, s.limit, s.offset = actorID, limit, offset
	return []domain.Approval{{ID: testApprovalID, RequestID: testSessionID, ApproverID: actorID, ApprovalLevel: 2, Emergency: true}}, nil
}

func (s *consoleBackendStub) DecideApproval(_ context.Context, actorID, approvalID string, decision domain.ApprovalDecision, comment *string) (service.ApprovalResult, error) {
	s.actorID, s.decision, s.comment = actorID, decision, comment
	return service.ApprovalResult{Request: domain.AccessRequest{ID: testSessionID}, Approval: domain.Approval{ID: approvalID, Decision: &decision}}, s.decideErr
}

func TestConsoleIdentityRequiresAuthenticationAndFiltersPermissions(t *testing.T) {
	svc := &consoleBackendStub{}
	server := testServer(t, svc, func(s *Server) { s.AllowDevAuth = true })
	for _, authenticated := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		if authenticated {
			request.Header.Set("X-User-ID", testUserID)
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if !authenticated {
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous identity status = %d", response.Code)
			}
			continue
		}
		var result struct {
			UserID      string             `json:"user_id"`
			Permissions []authz.Permission `json:"permissions"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.UserID != testUserID || len(result.Permissions) != len(authz.Catalog())-1 || strings.Contains(response.Body.String(), "role:manage") {
			t.Fatalf("identity = %s", response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("identity must not be cached")
		}
	}
	svc.authorizeErr = errors.New("database unavailable")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("identity authorization failure = %d", response.Code)
	}
}

func TestConsoleApprovalsAdaptExistingServiceAndValidateBodies(t *testing.T) {
	svc := &consoleBackendStub{}
	server := testServer(t, svc, func(s *Server) { s.AllowDevAuth = true })
	for _, item := range []struct {
		path, body string
		status     int
	}{
		{"/approvals/pending?limit=21&offset=20", "", 200},
		{"/approvals/pending?limit=invalid", "", 400},
		{"/approvals/" + testApprovalID + "/approve", `{"comment":"verified"}`, 200},
		{"/approvals/" + testApprovalID + "/reject", `{"comment":"rejected"}`, 200},
		{"/approvals/" + testApprovalID + "/approve", `{"comment":"x","approver_id":"forged"}`, 400},
		{"/approvals/" + testApprovalID + "/approve", `{} {}`, 400},
	} {
		method := http.MethodGet
		if item.body != "" {
			method = http.MethodPost
		}
		request := httptest.NewRequest(method, "/api/v1"+item.path, strings.NewReader(item.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-User-ID", testUserID)
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != item.status {
			t.Fatalf("%s status = %d body=%s", item.path, response.Code, response.Body.String())
		}
		if item.status == 200 && svc.actorID != testUserID {
			t.Fatal("service must receive the authenticated actor")
		}
		if item.path == "/approvals/pending?limit=21&offset=20" {
			var values []approvalResponse
			if err := json.Unmarshal(response.Body.Bytes(), &values); err != nil || len(values) != 1 || !values[0].Emergency {
				t.Fatalf("pending approval lost its urgent marker: %s", response.Body.String())
			}
		}
	}
	if svc.limit != 21 || svc.offset != 20 || svc.decision != domain.ApprovalRejected || svc.comment == nil || *svc.comment != "rejected" {
		t.Fatalf("service adapter state = %+v", svc)
	}
	svc.denied = true
	request := httptest.NewRequest(http.MethodGet, "/api/v1/approvals/pending", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied approval status = %d", response.Code)
	}
}

func TestConsoleApprovalCookieWritesRetainCSRFProtection(t *testing.T) {
	svc := &consoleBackendStub{}
	signer, err := security.NewSessionSigner(strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(t, svc, func(s *Server) { s.SessionSigner = signer })
	for _, origin := range []string{"https://attacker.invalid", "http://console.example"} {
		request := httptest.NewRequest(http.MethodPost, "http://console.example/api/v1/approvals/"+testApprovalID+"/approve", strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: signer.Sign(testUserID, time.Now().Add(time.Hour))})
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		want := http.StatusOK
		if origin != "http://console.example" {
			want = http.StatusForbidden
		}
		if response.Code != want {
			t.Fatalf("origin %s status = %d, want %d", origin, response.Code, want)
		}
	}
}
