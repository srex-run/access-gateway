//go:build integration

package integration_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestSessionOperationAuditVisibility(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	users := make([]domain.User, 4)
	for i, name := range []string{"Admin", "Applicant", "Other applicant", "Disabled"} {
		status := domain.UserStatusActive
		if i == 3 {
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
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "audit-test", Name: "Audit", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Audit", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "mysql", AssetType: "mysql", TargetCiphertext: "fixture-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	evidence := repository.NewAccessEvidenceRepository()
	var sessions []domain.Session
	var completedIDs []string
	for index, user := range users[1:3] {
		request, err := repos.requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: user.ID, AssetID: asset.ID, TargetPort: 3306, TargetAccount: stringPointer("root"), Reason: "audit visibility", TTLSeconds: 600, Status: domain.AccessRequestApproved, IdempotencyKey: id.New()})
		if err != nil {
			t.Fatal(err)
		}
		session, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning, ConnectionMode: gateway.ConnectionModeAudit, AuditPolicy: operationaudit.Policy{Profile: "mysql", Revision: strings.Repeat("a", 64), Protocol: "mysql"}})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
		connectionID, backendIP, backendPort := id.New(), "192.0.2.10", 42000+index
		if _, err := evidence.AppendConnectionEvent(ctx, database, domain.GatewayConnectionEvent{EventID: id.New(), ConnectionID: connectionID, SessionID: session.ID, EventType: "backend_connected", BackendSourceIP: &backendIP, BackendSourcePort: &backendPort, OccurredAt: now.Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
		operationID := id.New()
		start := operationaudit.SessionEvent{Event: operationaudit.Event{
			EventID: id.New(), Protocol: "mysql", AssetID: asset.ID, TargetPort: 3306, ActualAccount: "root", OperationType: "query", NormalizedOperation: stringPointer("show databases;"), Result: "unknown", BackendSourceIP: backendIP, BackendSourcePort: backendPort, SourceRecordID: "proxy/" + operationID + "/started", OccurredAt: now,
		}, ConnectionID: connectionID, OperationID: operationID, Phase: "started"}
		completed := start
		completed.EventID, completed.Phase, completed.Result = id.New(), "completed", "success"
		completed.SourceRecordID = "proxy/" + operationID + "/completed"
		completedIDs = append(completedIDs, completed.EventID)
		if _, err := svc.RecordSessionOperations(ctx, id.New(), session.ID, []operationaudit.SessionEvent{start}); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("another gateway wrote command evidence: %v", err)
		}
		if _, err := svc.RecordSessionOperations(ctx, gw.ID, session.ID, []operationaudit.SessionEvent{completed}); !errors.Is(err, service.ErrValidation) {
			t.Fatalf("completion without intent was accepted: %v", err)
		}
		for range 2 {
			accepted, err := svc.RecordSessionOperations(ctx, gw.ID, session.ID, []operationaudit.SessionEvent{start, completed})
			if err != nil || len(accepted) != 2 || accepted[0] != start.EventID || accepted[1] != completed.EventID {
				t.Fatalf("operation persistence or replay failed: %v %v", accepted, err)
			}
		}
		stored, err := evidence.GetOperationEvent(ctx, database, start.EventID)
		if err != nil || stored.Result != "unknown" {
			t.Fatal("completion replaced original intent evidence")
		}
		// A connected native client can initialize without any user commands.
		// Preserve both probes, including the expected syntax error, while
		// excluding them from lists, pagination, traces, and summary counts.
		for _, probe := range []struct{ kind, sql, result string }{
			{"client_version_probe", "select @@version_comment limit ?", "success"},
			{"client_syntax_probe", "select", "failure"},
		} {
			probeStart := start
			probeStart.EventID, probeStart.OperationID = id.New(), id.New()
			probeStart.OperationType, probeStart.NormalizedOperation = probe.kind, stringPointer(probe.sql)
			probeStart.SourceRecordID = "proxy/" + probeStart.OperationID + "/started"
			probeStart.OccurredAt = now.Add(time.Millisecond)
			probeEnd := probeStart
			probeEnd.EventID, probeEnd.Phase, probeEnd.Result = id.New(), "completed", probe.result
			probeEnd.SourceRecordID = "proxy/" + probeStart.OperationID + "/completed"
			if _, err := svc.RecordSessionOperations(ctx, gw.ID, session.ID, []operationaudit.SessionEvent{probeStart, probeEnd}); err != nil {
				t.Fatal(err)
			}
			persisted, err := evidence.GetOperationEvent(ctx, database, probeEnd.EventID)
			if err != nil || persisted.Result != probe.result || persisted.OperationType != probe.kind {
				t.Fatalf("client initialization evidence was altered: %+v %v", persisted, err)
			}
		}
		trace, err := repos.sessions.ListTrace(ctx, database, session.ID, "operation", 1, 0)
		if err != nil || len(trace) != 1 || trace[0].EventType != "query" {
			t.Fatalf("client initialization appeared in the trace or consumed its first page: %+v %v", trace, err)
		}
		view, err := svc.GetSessionRecord(ctx, user.ID, session.ID, false)
		if err != nil || view.Evidence.OperationCount != 1 {
			t.Fatalf("client initialization inflated the operation count: %+v %v", view.Evidence, err)
		}
	}
	unmatchedID := id.New()
	if n, err := svc.RecordOperationAuditBatch(ctx, []service.OperationAuditInput{{EventID: unmatchedID, Protocol: "mysql", AssetID: asset.ID, TargetPort: 3306, ActualAccount: "root", OperationType: "query", NormalizedOperation: stringPointer("select ?"), Result: "success", BackendSourceIP: "192.0.2.99", BackendSourcePort: 49999, SourceRecordID: "asset/unmatched", OccurredAt: now}}); err != nil || n != 1 {
		t.Fatalf("unmatched operation: %d %v", n, err)
	}
	for index, user := range users[1:3] {
		own, err := svc.ListOperationAuditEvents(ctx, user.ID, domain.OperationAuditFilter{Limit: 10})
		if err != nil || len(own) != 1 || own[0].EventID != completedIDs[index] || own[0].NormalizedOperation == nil || *own[0].NormalizedOperation != "show databases;" || own[0].Result != "success" {
			t.Fatalf("own commands were missing, duplicated or mixed with another user: %+v %v", own, err)
		}
	}
	if other, err := svc.ListOperationAuditEvents(ctx, users[1].ID, domain.OperationAuditFilter{SessionID: sessions[1].ID, Limit: 10}); err != nil || len(other) != 0 {
		t.Fatalf("another session's commands leaked: %+v %v", other, err)
	}
	if _, err := svc.ListOperationAuditEvents(ctx, users[1].ID, domain.OperationAuditFilter{SubjectUserID: users[2].ID, Limit: 10}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("subject filter bypassed ownership: %v", err)
	}
	if _, err := svc.ListOperationAuditEvents(ctx, users[3].ID, domain.OperationAuditFilter{Limit: 10}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled user read command audit: %v", err)
	}
	if _, err := svc.ListAuditEvents(ctx, users[1].ID, domain.AuditFilter{Limit: 10}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("personal operation access exposed global security events: %v", err)
	}
	all, err := svc.ListOperationAuditEvents(ctx, users[0].ID, domain.OperationAuditFilter{Limit: 10})
	if err != nil || len(all) != 3 {
		t.Fatalf("admin cannot read all users and unmatched commands: %+v %v", all, err)
	}
	selected, err := svc.ListOperationAuditEvents(ctx, users[0].ID, domain.OperationAuditFilter{SubjectUserID: users[2].ID, Limit: 10})
	if err != nil || len(selected) != 1 || selected[0].EventID != completedIDs[1] {
		t.Fatalf("admin subject filter: %+v %v", selected, err)
	}

	t.Run("session command collections", func(t *testing.T) {
		// The same command can execute repeatedly; only its start/completion pair
		// is collapsed. Session pagination must not split this command collection.
		for i, result := range []string{"failed", "unknown", "http_204"} {
			eventID := id.New()
			_, err := evidence.AppendOperationEvent(ctx, database, domain.OperationAuditEvent{
				EventID: eventID, SessionID: &sessions[0].ID, Protocol: "mysql", AssetID: asset.ID, TargetPort: 3306,
				ActualAccount: "root", OperationType: "query", NormalizedOperation: stringPointer("show databases;"), Result: result,
				BackendSourceIP: "192.0.2.10", BackendSourcePort: 42000, SourceRecordID: eventID, CorrelationStatus: "matched",
				OccurredAt: now.Add(time.Duration(i+1) * time.Second), Metadata: map[string]any{},
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		all, err := svc.ListOperationAuditSessions(ctx, users[0].ID, domain.OperationAuditFilter{Limit: 10})
		if err != nil || len(all) != 2 || all[0].ID != sessions[0].ID || all[0].CommandCount != 4 || all[0].SuccessCommandCount != 2 || all[0].FailedCommandCount != 1 {
			t.Fatalf("session counts/order/deduplication: %+v %v", all, err)
		}
		if all[0].ApplicantName != users[1].Nickname || all[0].AssetName != asset.Name || len(all[0].ActualAccounts) != 1 || all[0].ActualAccounts[0] != "root" || len(all[0].Protocols) != 1 || all[0].Protocols[0] != "mysql" {
			t.Fatalf("session display fields: %+v", all[0])
		}
		for index, expected := range all {
			page, err := svc.ListOperationAuditSessions(ctx, users[0].ID, domain.OperationAuditFilter{Limit: 1, Offset: index})
			if err != nil || len(page) != 1 || page[0].ID != expected.ID || page[0].CommandCount != expected.CommandCount {
				t.Fatalf("session pagination split commands: %+v %v", page, err)
			}
		}
		for _, user := range users[1:3] {
			own, err := svc.ListOperationAuditSessions(ctx, user.ID, domain.OperationAuditFilter{Limit: 10})
			if err != nil || len(own) != 1 || own[0].ApplicantID != user.ID {
				t.Fatalf("session audit leaked another applicant: %+v %v", own, err)
			}
		}
		if _, err := svc.ListOperationAuditSessions(ctx, users[1].ID, domain.OperationAuditFilter{SubjectUserID: users[2].ID}); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("session subject bypass: %v", err)
		}
		if _, err := svc.ListOperationAuditSessions(ctx, users[3].ID, domain.OperationAuditFilter{}); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("disabled user read session commands: %v", err)
		}
		if other, err := svc.ListOperationAuditSessions(ctx, users[1].ID, domain.OperationAuditFilter{SessionID: sessions[1].ID}); err != nil || len(other) != 0 {
			t.Fatalf("session ID bypass: %+v %v", other, err)
		}
		from, to := now.Add(time.Second), now.Add(3*time.Second)
		for _, filter := range []domain.OperationAuditFilter{
			{SubjectUserID: users[2].ID}, {SessionID: sessions[0].ID, Result: "failed"},
			{ActualAccount: "root", Protocol: "mysql", AssetID: asset.ID}, {From: &from, To: &to},
			{Result: "unknown"}, {CorrelationStatus: "unmatched"}, {ActualAccount: "other-account"},
		} {
			filter.Limit = 10
			groups, err := svc.ListOperationAuditSessions(ctx, users[0].ID, filter)
			if err != nil {
				t.Fatal(err)
			}
			flat, err := svc.ListOperationAuditEvents(ctx, users[0].ID, filter)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int64{}
			for _, command := range flat {
				if command.SessionID != nil {
					counts[*command.SessionID]++
				}
			}
			if len(groups) != len(counts) {
				t.Fatalf("filtered session collection mismatch: %+v %+v", groups, counts)
			}
			for _, group := range groups {
				if group.CommandCount != counts[group.ID] {
					t.Fatalf("session counts disagree with command collection: %+v %+v", group, counts)
				}
			}
		}
		unmatched, err := svc.ListOperationAuditEvents(ctx, users[0].ID, domain.OperationAuditFilter{CorrelationStatus: "unmatched", Limit: 10})
		if err != nil || len(unmatched) != 1 || unmatched[0].EventID != unmatchedID {
			t.Fatalf("ungrouped evidence disappeared: %+v %v", unmatched, err)
		}
	})
}
