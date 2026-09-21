package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type operationAuditSessionsStub struct {
	backendStub
	actor  string
	filter domain.OperationAuditFilter
	groups []domain.OperationAuditSession
	err    error
	calls  int
}

func (s *operationAuditSessionsStub) ListOperationAuditSessions(_ context.Context, actor string, filter domain.OperationAuditFilter) ([]domain.OperationAuditSession, error) {
	s.actor, s.filter = actor, filter
	s.calls++
	return s.groups, s.err
}

func (s *operationAuditSessionsStub) ListOperationAuditEvents(_ context.Context, actor string, filter domain.OperationAuditFilter) ([]domain.OperationAuditEvent, error) {
	s.actor, s.filter = actor, filter
	s.calls++
	return nil, s.err
}

func TestOperationAuditSessionRoutes(t *testing.T) {
	svc := &operationAuditSessionsStub{groups: []domain.OperationAuditSession{{SessionRecord: domain.SessionRecord{ID: testSessionID, ApplicantName: "Applicant", AssetName: "MySQL"}, CommandCount: 12, SuccessCommandCount: 10, FailedCommandCount: 1, ActualAccounts: []string{"root"}, Protocols: []string{"mysql"}}}}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	get := func(path string, auth bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1"+path, nil)
		if auth {
			request.Header.Set("X-User-ID", testUserID)
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		return response
	}
	if response := get("/operation-audit-sessions", false); response.Code != http.StatusUnauthorized || svc.calls != 0 {
		t.Fatalf("anonymous collection access: %d", response.Code)
	}
	response := get("/operation-audit-sessions", true)
	if response.Code != http.StatusOK || svc.actor != testUserID || svc.filter.Limit != 10 || svc.filter.Offset != 0 {
		t.Fatalf("default session page: %d %+v", response.Code, svc.filter)
	}
	var groups []domain.OperationAuditSession
	if err := json.Unmarshal(response.Body.Bytes(), &groups); err != nil || len(groups) != 1 || groups[0].ID != testSessionID || groups[0].CommandCount != 12 {
		t.Fatalf("session summary response: %s %v", response.Body.String(), err)
	}
	query := "?limit=11&offset=10&session_id=" + testSessionID + "&subject_user_id=" + testUserID + "&actual_account=root&protocol=mysql&result=failed&from=2026-09-01T00:00:00Z&to=2026-09-12T00:00:00Z"
	for _, endpoint := range []string{"/operation-audit-sessions", "/operation-audit-events"} {
		if response := get(endpoint+query, true); response.Code != http.StatusOK || svc.filter.SessionID != testSessionID || svc.filter.SubjectUserID != testUserID || svc.filter.ActualAccount != "root" || svc.filter.Protocol != "mysql" || svc.filter.Result != "failed" || svc.filter.From == nil || svc.filter.To == nil || svc.filter.Limit != 11 || svc.filter.Offset != 10 {
			t.Fatalf("query contract %s: %d %+v", endpoint, response.Code, svc.filter)
		}
		for _, invalid := range []string{"?limit=201", "?offset=-1", "?from=invalid", "?to=invalid"} {
			calls := svc.calls
			if response := get(endpoint+invalid, true); response.Code != http.StatusBadRequest || calls != svc.calls {
				t.Fatalf("invalid query reached backend %s%s: %d", endpoint, invalid, response.Code)
			}
		}
	}
	svc.err = service.ErrForbidden
	if response := get("/operation-audit-sessions", true); response.Code != http.StatusForbidden {
		t.Fatalf("service rejection ignored: %d", response.Code)
	}
	svc.err = nil
	svc.authorizeErr = service.ErrForbidden
	calls := svc.calls
	if response := get("/operation-audit-sessions", true); response.Code != http.StatusForbidden || svc.calls != calls {
		t.Fatalf("role check bypassed: %d", response.Code)
	}
	permission, protected := routePermission(http.MethodGet, "/api/v1/operation-audit-sessions")
	if !protected || permission != authz.PermissionSessionManage {
		t.Fatalf("unexpected collection permission: %s %v", permission, protected)
	}
}
