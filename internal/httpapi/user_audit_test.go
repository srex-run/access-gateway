package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

type userAuditStub struct {
	backendStub
	filter domain.AuditFilter
}

func (s *userAuditStub) ListAuditEvents(_ context.Context, _ string, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	s.filter = filter
	return []domain.AuditEvent{{ID: testApprovalID, EventType: "asset.created", ActorType: "admin", ActorID: stringPointerForAudit(testUserID), ActorName: "Administrator", ActorUsername: "admin"}}, nil
}

func stringPointerForAudit(value string) *string { return &value }

func TestUserAuditClassificationResponse(t *testing.T) {
	svc := &userAuditStub{}
	server := testServer(t, svc, func(server *Server) { server.AllowDevAuth = true })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?category=resources&action=create&actor_id="+testUserID+"&limit=11&offset=10", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("audit list: %d %s", response.Code, response.Body.String())
	}
	if svc.filter.Category != "resources" || svc.filter.Action != "create" || svc.filter.ActorID != testUserID || svc.filter.Limit != 11 || svc.filter.Offset != 10 {
		t.Fatalf("audit filters lost: %+v", svc.filter)
	}
	var events []auditEventResponse
	if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Category != "resources" || events[0].Action != "create" || events[0].Label != "创建资产" || events[0].EventType != "asset.created" {
		t.Fatalf("audit classification missing: %+v", events)
	}
	if events[0].ActorName != "Administrator" || events[0].ActorUsername != "admin" {
		t.Fatalf("audit actor names missing: %+v", events[0])
	}
}
