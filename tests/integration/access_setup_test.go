//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestAdminTestAccessAndUserDirectory(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		SystemSettings: clientAccessFixture(t, database, admin.ID, nil, "sessions.example.com"),
		DB:             database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		DefaultTTL: time.Hour, MaxTTL: time.Hour, AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const password = "temporary-test-password"
	user, err := svc.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Nickname: "Approver", Username: "approver", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateLocalUser(ctx, user.ID, service.CreateLocalUserInput{Nickname: "Forbidden", Username: "forbidden", Password: password}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("ordinary user created an account: %v", err)
	}
	directory, err := svc.ListUsers(ctx, admin.ID, "approv", true, 51, 0)
	if err != nil || len(directory) != 1 || directory[0].ID != user.ID {
		t.Fatalf("directory search: %v / %v", directory, err)
	}
	encoded, err := json.Marshal(directory)
	if err != nil || strings.Contains(string(encoded), password) || strings.Contains(string(encoded), "password_hash") {
		t.Fatal("directory contains credentials")
	}
	credential, err := repos.users.LocalCredential(ctx, database, "approver")
	if err != nil || credential.PasswordHash == password || !strings.HasPrefix(credential.PasswordHash, "$2") {
		t.Fatalf("password was not hashed: %v", err)
	}
	region, err := repos.regions.Create(ctx, database, domain.Region{ID: id.New(), Code: "test-access", Name: "Test", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Test", ManagementEndpoint: "https://gateway.test:8090", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "mysql", AssetType: "mysql", TargetCiphertext: "test-fixture-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 3600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repos.assets.CreatePort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 3306, Protocol: "tcp", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	input := service.CreateRequestInput{ApplicantID: admin.ID, RegionID: region.ID, AssetID: asset.ID, TargetPort: 3306, SourceIP: "127.0.0.1", TargetAccount: "readonly", Reason: "Validate encrypted MySQL path", TTLSeconds: 600, IdempotencyKey: "admin-test-access"}
	if _, err := svc.CreateAccessRequest(ctx, input); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("ordinary request skipped approvers: %v", err)
	}
	unauthorized := input
	unauthorized.ApplicantID = user.ID
	if _, err := svc.CreateTestAccessRequest(ctx, unauthorized); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("non-admin bypassed approval: %v", err)
	}
	created, err := svc.CreateTestAccessRequest(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.ApprovalMode != "admin_test" || created.Status != domain.AccessRequestApproved || created.TTLSeconds != 600 {
		t.Fatalf("test request state: %+v", created)
	}
	session, err := repos.sessions.GetByRequestID(ctx, database, created.ID)
	if err != nil || session.Status != domain.SessionProvisioning || session.ConnectionMode != gateway.ConnectionModeNative {
		t.Fatalf("test session: %+v / %v", session, err)
	}
	approvals, err := repos.approvals.ListByRequest(ctx, database, created.ID)
	if err != nil || len(approvals) != 0 {
		t.Fatalf("test generated approval records: %v", err)
	}
	var outboxCount, auditCount int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM outbox_events WHERE aggregate_type = 'session' AND aggregate_id = $1`, session.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE request_id = $1 AND event_type = 'access_request.admin_test_started'`, created.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 || auditCount != 1 {
		t.Fatalf("test not durably queued and audited: %d / %d", outboxCount, auditCount)
	}
	retried, err := svc.CreateTestAccessRequest(ctx, input)
	if err != nil || retried.ID != created.ID {
		t.Fatalf("test retry not idempotent: %v", err)
	}
	if _, err := svc.CreateAccessRequest(ctx, input); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("normal request reused test key: %v", err)
	}
	input.IdempotencyKey = "another-admin-test"
	if _, err := svc.CreateTestAccessRequest(ctx, input); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second active session accepted: %v", err)
	}
	_, err = svc.CreateAssetApprover(ctx, admin.ID, asset.ID, domain.AssetApprover{UserID: user.ID, ApprovalLevel: 1, Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListAssetApprovers(ctx, admin.ID, asset.ID)
	if err != nil || len(listed) != 1 || listed[0].Username != "approver" {
		t.Fatalf("approver names unavailable: %v / %v", listed, err)
	}
	if _, err := svc.PreviewAssetWorkflow(ctx, admin.ID, asset.ID); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("ordinary user was assigned an approval without permission: %v", err)
	}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "asset-approver", Enabled: true, Permissions: []authz.Permission{authz.PermissionApprovalManage}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: user.ID, Role: role.Name}); err != nil {
		t.Fatal(err)
	}
	if preview, err := svc.PreviewAssetWorkflow(ctx, admin.ID, asset.ID); err != nil || len(preview.Approvals) != 1 || preview.Approvals[0].UserID != user.ID {
		t.Fatalf("explicitly authorized approver missing from workflow: %v", err)
	}
	ordinary := input
	ordinary.ApplicantID = user.ID
	ordinary.IdempotencyKey = "self-approval-test"
	if _, err := svc.CreateAccessRequest(ctx, ordinary); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("self-approval policy changed: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE access_requests SET ttl_seconds = 601 WHERE id = $1`, created.ID); err == nil {
		t.Fatal("test TTL database guard accepted more than ten minutes")
	}
}
