//go:build integration

package integration_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestForceCloseOpenSessionsAndAuthorizedRolePermissions(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	users := make([]domain.User, 7)
	for index, name := range []string{"Bootstrap admin", "Assigned admin", "Auditor", "Asset operator", "Custom recovery operator", "Disabled admin", "Applicant"} {
		status := domain.UserStatusActive
		if index == 5 {
			status = domain.UserStatusInactive
		}
		user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: name, Status: status})
		if err != nil {
			t.Fatal(err)
		}
		users[index] = user
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{users[0].ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force-close is an explicit permission: role names and unrelated admin
	// capabilities must neither grant it nor block an authorized custom role.
	for _, role := range []iam.Role{
		{Name: "asset-operator", Enabled: true, Permissions: []authz.Permission{authz.PermissionCatalogManage}},
		{Name: "recovery-operator", Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride}},
	} {
		if _, err := svc.SaveIAMRole(ctx, users[0].ID, role); err != nil {
			t.Fatal(err)
		}
	}
	for index, role := range []string{"admin", "auditor", "asset-operator", "recovery-operator", "admin"} {
		if _, err := svc.GrantRole(ctx, users[0].ID, service.GrantRoleInput{UserID: users[index+1].ID, Role: role}); err != nil {
			t.Fatal(err)
		}
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "force-close", Name: "Force-close", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Force-close", ManagementEndpoint: "https://gateway.test:8090", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "Force-close MySQL", AssetType: "mysql", TargetCiphertext: "unused-fixture-target", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	statuses := []domain.SessionStatus{domain.SessionProvisioning, domain.SessionRunning, domain.SessionRevoking, domain.SessionRevokeFailed, domain.SessionManualIntervention, domain.SessionClosed, domain.SessionExpired, domain.SessionFailed}
	sessions := make([]domain.Session, len(statuses))
	for index, status := range statuses {
		request, err := repos.requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: users[6].ID, AssetID: asset.ID, TargetPort: 3306, TargetAccount: stringPointer("root"), SourceIP: stringPointer("127.0.0.1"), Reason: "Maintenance", TTLSeconds: 600, Status: domain.AccessRequestApproved, IdempotencyKey: id.New()})
		if err != nil {
			t.Fatal(err)
		}
		session, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gw.ID, Status: status})
		if err != nil {
			t.Fatal(err)
		}
		sessions[index] = session
	}

	open, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Limit: 50})
	if err != nil || len(open) != 5 {
		t.Fatalf("open sessions: count=%d err=%v", len(open), err)
	}
	for index, record := range open {
		if !slices.Contains(statuses[:5], record.Status) {
			t.Fatalf("terminal session was selectable: %+v", record)
		}
		page, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Limit: 1, Offset: index})
		if err != nil || len(page) != 1 || page[0].ID != record.ID {
			t.Fatalf("open filter must precede pagination at %d: %+v %v", index, page, err)
		}
	}
	for _, search := range []string{strings.ToUpper(sessions[0].ID), sessions[0].RequestID} {
		found, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Search: search, Limit: 50})
		if err != nil || len(found) != 1 || found[0].ID != sessions[0].ID {
			t.Fatalf("open session search: %+v %v", found, err)
		}
	}
	for _, search := range []string{"ROOT", "force-close mysql", "Applicant"} {
		found, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Search: search, Limit: 50})
		if err != nil || len(found) != 5 {
			t.Fatalf("open session search %q: count=%d err=%v", search, len(found), err)
		}
	}
	if found, err := svc.ListSessionRecords(ctx, users[1].ID, domain.SessionRecordFilter{Status: "open", Limit: 50}); err != nil || len(found) != 5 {
		t.Fatalf("assigned platform administrator cannot see all open sessions: count=%d err=%v", len(found), err)
	}
	if found, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Search: sessions[5].ID, Limit: 50}); err != nil || len(found) != 0 {
		t.Fatalf("search selected a closed session: %+v %v", found, err)
	}
	for _, user := range []domain.User{users[2], users[3], users[5], users[6]} {
		if _, err := svc.ForceCloseSession(ctx, user.ID, sessions[0].ID, "Unauthorized reclaim"); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("%s force-close error: %v", user.Nickname, err)
		}
		permissions, err := svc.EffectivePermissions(ctx, user.ID)
		if user.Status == domain.UserStatusInactive {
			if !errors.Is(err, service.ErrForbidden) {
				t.Fatalf("inactive administrator received permissions: %v", err)
			}
		} else if err != nil || slices.Contains(permissions, authz.PermissionSessionOverride) {
			t.Fatalf("%s should not see force-close: %v %v", user.Nickname, permissions, err)
		}
	}
	for _, user := range []domain.User{users[0], users[1], users[4]} {
		permissions, err := svc.EffectivePermissions(ctx, user.ID)
		if err != nil || !slices.Contains(permissions, authz.PermissionSessionOverride) {
			t.Fatalf("%s missing force-close permission: %v %v", user.Nickname, permissions, err)
		}
		closed, err := svc.ForceCloseSession(ctx, user.ID, sessions[0].ID, "Maintenance reclaim")
		if err != nil || closed.Status != domain.SessionFailed {
			t.Fatalf("%s force-close or idempotent retry: status=%s err=%v", user.Nickname, closed.Status, err)
		}
	}
	if remaining, err := svc.ListSessionRecords(ctx, users[0].ID, domain.SessionRecordFilter{Status: "open", Limit: 50}); err != nil || len(remaining) != 4 {
		t.Fatalf("reclaimed session remains selectable: count=%d err=%v", len(remaining), err)
	}
}
