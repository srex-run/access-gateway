//go:build integration

package integration_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestSessionRecordsVisibilityAndTrace(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	users := make([]domain.User, 6)
	for i, name := range []string{"Admin", "Applicant", "Approver", "Unrelated", "Auditor", "Disabled"} {
		status := domain.UserStatusActive
		if i == 5 {
			status = domain.UserStatusInactive
		}
		user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: name, Status: status})
		if err != nil {
			t.Fatal(err)
		}
		users[i] = user
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{users[0].ID: {}}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(ctx, users[0].ID, service.GrantRoleInput{UserID: users[4].ID, Role: string(authz.RoleAuditor)}); err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "session-record", Name: "Records", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "Payments MySQL", AssetType: "mysql", TargetCiphertext: "never-return-target", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	var sessions []domain.Session
	for index, applicant := range []domain.User{users[1], users[1], users[3]} {
		request, err := repos.requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: applicant.ID, AssetID: asset.ID, TargetPort: 3306, TargetAccount: stringPointer("root"), SourceIP: stringPointer("127.0.0.1"), Reason: "Investigate payments", TTLSeconds: 600, Status: domain.AccessRequestApproved, IdempotencyKey: id.New()})
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			approval, err := repos.approvals.Create(ctx, database, domain.Approval{ID: id.New(), RequestID: request.ID, ApproverID: users[2].ID, ApprovalLevel: 1, StepName: "Owner"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repos.approvals.Decide(ctx, database, approval.ID, users[2].ID, domain.ApprovalApproved, stringPointer("Approved investigation")); err != nil {
				t.Fatal(err)
			}
		}
		session, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning, ConnectionMode: gateway.ConnectionModeAudit, AuditPolicy: operationaudit.Policy{Profile: "mysql", Revision: strings.Repeat("a", 64), Protocol: "mysql"}})
		if err != nil {
			t.Fatal(err)
		}
		session, err = repos.sessions.MarkDirectRunning(ctx, database, session.ID, session.Version, "agent", 20000+index, 20000+index, "direct", "gateway", now, now.Add(time.Hour), "", "")
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}

	for _, test := range []struct{ user, count int }{{0, 3}, {1, 2}, {2, 1}, {3, 1}, {4, 3}} {
		values, err := svc.ListSessionRecords(ctx, users[test.user].ID, domain.SessionRecordFilter{ReadAll: true, ActorID: users[0].ID, Limit: 20})
		if err != nil || len(values) != test.count {
			t.Fatalf("visibility for %s: count=%d err=%v", users[test.user].Nickname, len(values), err)
		}
	}
	for _, user := range []domain.User{users[0], users[1], users[2], users[4]} {
		for _, byRequest := range []bool{false, true} {
			recordID := sessions[0].ID
			if byRequest {
				recordID = sessions[0].RequestID
			}
			value, err := svc.GetSessionRecord(ctx, user.ID, recordID, byRequest)
			if err != nil || value.Record.ApplicantName != "Applicant" || value.Record.AssetName != asset.Name || len(value.Workflow.Approvals) != 1 {
				t.Fatalf("record for %s: %+v %v", user.Nickname, value.Record, err)
			}
			if value.View.CanConnect != (user.ID == users[1].ID) || value.CanClose != (user.ID == users[0].ID || user.ID == users[1].ID) || value.Workflow.CanDecide {
				t.Fatalf("record read granted mutation rights to %s", user.Nickname)
			}
		}
	}
	for _, user := range []domain.User{users[2], users[4]} {
		if _, err := svc.CloseSession(ctx, user.ID, sessions[0].ID); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("reader %s could close another person's session: %v", user.Nickname, err)
		}
	}
	if _, err := svc.GetSessionRecord(ctx, users[3].ID, sessions[0].ID, false); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unrelated record access: %v", err)
	}
	if _, err := svc.ListSessionTrace(ctx, users[3].ID, sessions[0].ID, "", 20, 0); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unrelated trace access: %v", err)
	}
	if _, err := svc.ListSessionRecords(ctx, users[5].ID, domain.SessionRecordFilter{}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled user read records: %v", err)
	}
	if _, err := svc.ListSessionTrace(ctx, users[1].ID, sessions[0].ID, "invalid", 20, 0); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("invalid stage accepted: %v", err)
	}
	all, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for index, expected := range all {
		page, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Limit: 1, Offset: index})
		if err != nil || len(page) != 1 || page[0].ID != expected.ID {
			t.Fatalf("record pagination at %d: %+v %v", index, page, err)
		}
	}
	for _, search := range []string{"APPLICANT", "payments", sessions[0].ID, sessions[0].RequestID, "root"} {
		found, err := svc.ListSessionRecords(ctx, users[1].ID, domain.SessionRecordFilter{Search: search, Status: "running", Limit: 20})
		if err != nil || len(found) == 0 {
			t.Fatalf("search %q: %+v %v", search, found, err)
		}
	}
	if empty, err := svc.ListSessionRecords(ctx, users[1].ID, domain.SessionRecordFilter{Status: "closed", Limit: 20}); err != nil || len(empty) != 0 {
		t.Fatalf("status filter: %+v %v", empty, err)
	}

	evidence := repository.NewAccessEvidenceRepository()
	session := sessions[0]
	failedConnection, goodConnection := id.New(), id.New()
	for _, connection := range []struct{ id, event, result, reason string }{
		{failedConnection, "backend_connected", "success", ""},
		{failedConnection, "disconnected", "failure", "application_identity_rejected"},
		{goodConnection, "backend_connected", "success", ""},
	} {
		_, err := evidence.AppendConnectionEvent(ctx, database, domain.GatewayConnectionEvent{EventID: id.New(), SessionID: session.ID, ConnectionID: connection.id, EventType: connection.event, SourceIP: stringPointer("127.0.0.1"), BackendSourceIP: stringPointer("172.20.0.1"), Result: &connection.result, Reason: &connection.reason, OccurredAt: now.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
	}
	connectionView, err := svc.GetSessionRecord(ctx, users[2].ID, session.ID, false)
	if err != nil || len(connectionView.Evidence.VerifiedAccounts) != 0 || connectionView.Evidence.FailedConnections != 1 {
		t.Fatalf("TCP connections or failed authentication created a verified account: %+v %v", connectionView.Evidence, err)
	}
	if err := repos.sessionEvents.Append(ctx, database, domain.SessionEvent{ID: id.New(), SessionID: session.ID, EventType: "connection.backend_failed", ActorType: "gateway", Metadata: map[string]any{"reason": "duplicate"}}); err != nil {
		t.Fatal(err)
	}
	if err := repos.sessionEvents.Append(ctx, database, domain.SessionEvent{ID: id.New(), SessionID: session.ID, EventType: "session.started", ActorType: "system", Metadata: map[string]any{"private_key": "never-return-metadata"}}); err != nil {
		t.Fatal(err)
	}
	operationID := id.New()
	var completedID string
	for _, phase := range []string{"started", "completed"} {
		eventID := id.New()
		if phase == "completed" {
			completedID = eventID
		}
		_, err := evidence.AppendOperationEvent(ctx, database, domain.OperationAuditEvent{EventID: eventID, SessionID: &session.ID, ConnectionID: &goodConnection, Protocol: "mysql", AssetID: asset.ID, TargetPort: 3306, ActualAccount: "root", OperationType: "query", NormalizedOperation: stringPointer("SELECT ?"), Result: "success", BackendSourceIP: "172.20.0.1", BackendSourcePort: 42000, SourceRecordID: eventID, CorrelationStatus: "matched", OccurredAt: now.Add(2 * time.Minute), Metadata: map[string]any{"source": "session_proxy", "phase": phase, "operation_id": operationID, "account_verified": true}})
		if err != nil {
			t.Fatal(err)
		}
	}
	view, err := svc.GetSessionRecord(ctx, users[2].ID, session.ID, false)
	if err != nil || view.Evidence.OperationCount != 1 || view.Evidence.ConnectionCount != 2 || view.Evidence.FailedConnections != 1 || !slices.Equal(view.Evidence.VerifiedAccounts, []string{"root"}) {
		t.Fatalf("evidence summary: %+v %v", view.Evidence, err)
	}
	sourcePort := 42000
	expectedContext := domain.SessionEvidenceContext{
		Accounts:       []domain.SessionAccountEvidence{{Name: "root", Verified: true}},
		Protocols:      []string{"mysql"},
		BackendSources: []domain.SessionSourceEvidence{{IP: "172.20.0.1", Port: &sourcePort}},
		ClientSources:  []string{"127.0.0.1"},
	}
	if !reflect.DeepEqual(view.Evidence.Context, expectedContext) {
		t.Fatalf("session context was duplicated or lost fields: %+v", view.Evidence.Context)
	}
	trace, err := svc.ListSessionTrace(ctx, users[2].ID, session.ID, "", 100, 0)
	if err != nil || len(trace) != 7 || trace[0].ID != "operation:"+completedID {
		t.Fatalf("trace was incomplete, duplicated or unordered: %+v %v", trace, err)
	}
	for i, event := range trace {
		page, err := svc.ListSessionTrace(ctx, users[2].ID, session.ID, "", 1, i)
		if err != nil || len(page) != 1 || page[0].ID != event.ID {
			t.Fatalf("trace pagination %d: %+v %v", i, page, err)
		}
		if strings.HasPrefix(event.ID, "session:") && event.EventType == "connection.backend_failed" {
			t.Fatal("duplicate connection event in trace")
		}
		if event.EventType == "disconnected" && (event.Reason != "application_identity_rejected" || event.BackendSourceIP != "172.20.0.1" || event.SourceIP != "127.0.0.1" || event.AccountVerified) {
			t.Fatalf("failure evidence was lost or falsely verified: %+v", event)
		}
	}
	for stage, count := range map[string]int{"request": 1, "approval": 1, "session": 1, "connection": 3, "operation": 1} {
		items, err := svc.ListSessionTrace(ctx, users[2].ID, session.ID, stage, 20, 0)
		if err != nil || len(items) != count {
			t.Fatalf("trace stage %s: %+v %v", stage, items, err)
		}
	}

	if empty, err := svc.GetSessionRecord(ctx, users[0].ID, sessions[2].ID, false); err != nil || len(empty.Evidence.Context.Accounts) != 0 || len(empty.Evidence.Context.BackendSources) != 0 || empty.Evidence.OperationCount != 0 || empty.Evidence.ConnectionCount != 0 {
		t.Fatalf("empty evidence context: %+v %v", empty.Evidence, err)
	}
	for _, operation := range []struct {
		account  string
		verified bool
		ip       string
		port     int
	}{
		{"root", true, "172.20.0.1", 42000},
		{"root", false, "172.20.0.2", 42001},
		{"other", true, "172.20.0.2", 42001},
	} {
		eventID := id.New()
		_, err := evidence.AppendOperationEvent(ctx, database, domain.OperationAuditEvent{
			EventID: eventID, SessionID: &session.ID, ConnectionID: &goodConnection, Protocol: "mysql", AssetID: asset.ID, TargetPort: 3306,
			ActualAccount: operation.account, OperationType: "query", NormalizedOperation: stringPointer("SELECT ?"), Result: "success",
			BackendSourceIP: operation.ip, BackendSourcePort: operation.port, SourceRecordID: eventID, CorrelationStatus: "matched", OccurredAt: now.Add(3 * time.Minute),
			Metadata: map[string]any{"source": "session_proxy", "phase": "completed", "operation_id": id.New(), "account_verified": operation.verified},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	changed, err := svc.GetSessionRecord(ctx, users[2].ID, session.ID, false)
	if err != nil || changed.Evidence.OperationCount != 4 || len(changed.Evidence.Context.Accounts) != 3 || len(changed.Evidence.Context.BackendSources) != 2 || len(changed.Evidence.Context.Protocols) != 1 {
		t.Fatalf("distinct operations were collapsed or different identities merged: %+v %v", changed.Evidence, err)
	}

	testRequest, err := repos.requests.Create(ctx, database, domain.AccessRequest{
		ID: id.New(), ApplicantID: users[0].ID, AssetID: asset.ID, TargetPort: 3306,
		TargetAccount: stringPointer("root"), SourceIP: stringPointer("127.0.0.1"), Reason: "Admin test",
		TTLSeconds: 600, Status: domain.AccessRequestApproved, ApprovalMode: "admin_test", IdempotencyKey: id.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	testSession, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: testRequest.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning, ConnectionMode: gateway.ConnectionModeAudit})
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.audits.Append(ctx, database, domain.AuditEvent{ID: id.New(), EventType: "access_request.admin_test_started", ActorType: "admin", ActorID: &users[0].ID, RequestID: &testRequest.ID, SessionID: &testSession.ID}); err != nil {
		t.Fatal(err)
	}
	startEvents, err := svc.ListSessionTrace(ctx, users[0].ID, testSession.ID, "request", 10, 0)
	if err != nil || len(startEvents) != 1 || startEvents[0].EventType != "access_request.admin_test_started" || startEvents[0].ActorName != "Admin" || startEvents[0].Reason != "Admin test" {
		t.Fatalf("admin test produced duplicate start records: %+v %v", startEvents, err)
	}
}
