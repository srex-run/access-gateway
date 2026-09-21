//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type notificationFixture struct {
	db                              *sql.DB
	svc                             *service.AccessService
	admin, applicant, first, second domain.User
	request                         domain.AccessRequest
	input                           service.CreateRequestInput
	gatewayID                       string
}

func newNotificationFixture(t *testing.T) notificationFixture {
	t.Helper()
	db, svc, admin := builtinRoleService(t)
	ctx := context.Background()
	repos := newRepositories()
	createUser := func(name string) domain.User {
		v, err := repos.users.Create(ctx, db, domain.User{ID: id.New(), Nickname: name, Status: domain.UserStatusActive})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	f := notificationFixture{db: db, svc: svc, admin: admin, applicant: createUser("Applicant"), first: createUser("First"), second: createUser("Second")}
	role, err := svc.SaveIAMRole(ctx, admin.ID, iam.Role{Name: "notification-reviewers", Enabled: true, Labels: label.Labels{"notification": "first"}, Permissions: []authz.Permission{authz.PermissionApprovalManage}})
	if err != nil {
		t.Fatal(err)
	}
	for _, userID := range []string{f.first.ID, f.second.ID} {
		if _, err := svc.GrantRole(ctx, admin.ID, service.GrantRoleInput{UserID: userID, Role: role.Name}); err != nil {
			t.Fatal(err)
		}
	}
	flow, err := svc.SaveWorkflow(ctx, admin.ID, approvalflow.Definition{Name: "Notification flow", Enabled: true, TimeoutSeconds: 600, Steps: []approvalflow.Step{
		{Name: "负责人会签", Kind: "role_selector", Mode: "all", Selector: "notification=first"},
		{Name: "平台管理", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/role=admin"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.Create(ctx, db, domain.Region{ID: id.New(), Code: "notifications", Name: "Notifications", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Local", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	f.gatewayID = gw.ID
	asset, err := repos.assets.Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "生产数据库", AssetType: "mysql", TargetCiphertext: "test-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled, ApprovalWorkflowID: &flow.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.assets.CreatePort(ctx, db, domain.AssetPort{ID: id.New(), AssetID: asset.ID, Port: 3306, Protocol: "tcp", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f.input = service.CreateRequestInput{ApplicantID: f.applicant.ID, RegionID: region.ID, AssetID: asset.ID, TargetPort: 3306, TargetAccount: "root", SourceIP: "127.0.0.1", Reason: "notification test", TTLSeconds: 600, IdempotencyKey: "notification-test"}
	f.request, err = svc.CreateAccessRequest(ctx, f.input)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNotificationsPersistAtApprovalTransitionsWithoutExternalServices(t *testing.T) {
	f := newNotificationFixture(t)
	ctx := context.Background()
	inbox := func(userID string, count int) domain.NotificationPage {
		t.Helper()
		v, err := f.svc.ListNotifications(ctx, userID, 20, 0)
		if err != nil || len(v.Items) != count {
			t.Fatalf("inbox count %d: %+v %v", count, v, err)
		}
		return v
	}
	first, second := inbox(f.first.ID, 1), inbox(f.second.ID, 1)
	inbox(f.admin.ID, 0)
	inbox(f.applicant.ID, 0)
	if first.UnreadCount != 1 || first.Items[0].RequestID != f.request.ID || !strings.Contains(first.Items[0].Content, "负责人会签") {
		t.Fatalf("first notification: %+v", first)
	}
	if repeat, err := f.svc.CreateAccessRequest(ctx, f.input); err != nil || repeat.ID != f.request.ID {
		t.Fatalf("repeat request: %v", err)
	}
	inbox(f.first.ID, 1)
	if err := f.svc.MarkNotificationRead(ctx, f.second.ID, second.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	approvals, err := newRepositories().approvals.ListByRequest(ctx, f.db, f.request.ID)
	if err != nil {
		t.Fatal(err)
	}
	byUser := map[string]string{}
	for _, approval := range approvals {
		byUser[approval.ApproverID] = approval.ID
	}
	if _, err := f.svc.DecideApproval(ctx, f.first.ID, byUser[f.first.ID], domain.ApprovalApproved, nil); err != nil {
		t.Fatal(err)
	}
	if v := inbox(f.second.ID, 1); v.UnreadCount != 0 || v.Items[0].ReadAt == nil {
		t.Fatal("same-level rescheduling reset read state")
	}
	inbox(f.admin.ID, 0)
	if _, err := f.svc.DecideApproval(ctx, f.second.ID, byUser[f.second.ID], domain.ApprovalApproved, nil); err != nil {
		t.Fatal(err)
	}
	if v := inbox(f.admin.ID, 1); v.UnreadCount != 1 || !strings.Contains(v.Items[0].Content, "平台管理") {
		t.Fatalf("next level: %+v", v)
	}
	comment := "reject for notification test"
	if _, err := f.svc.DecideApproval(ctx, f.admin.ID, byUser[f.admin.ID], domain.ApprovalRejected, &comment); err != nil {
		t.Fatal(err)
	}
	if v := inbox(f.applicant.ID, 1); v.Items[0].Title != "访问申请已拒绝" || v.Items[0].EventType != "request_result" {
		t.Fatalf("result: %+v", v)
	}
	if err := f.svc.MarkNotificationRead(ctx, f.applicant.ID, first.Items[0].ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-user read: %v", err)
	}
	if err := newRepositories().users.UpdateStatus(ctx, f.db, f.applicant.ID, domain.UserStatusInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ListNotifications(ctx, f.applicant.ID, 20, 0); err == nil {
		t.Fatal("inactive account read inbox")
	}
}

func TestNotificationRepositoryPaginationReadStateConstraintsAndRollback(t *testing.T) {
	f := newNotificationFixture(t)
	ctx := context.Background()
	repo := repository.NotificationRepository{}
	session, err := newRepositories().sessions.Create(ctx, f.db, domain.Session{ID: id.New(), RequestID: f.request.ID, GatewayID: f.gatewayID, Status: domain.SessionProvisioning})
	if err != nil {
		t.Fatal(err)
	}
	v := domain.Notification{ID: id.New(), UserID: f.applicant.ID, EventType: "session_ready", DedupeKey: "session:test", Title: "会话就绪", Content: "生产数据库已就绪", RequestID: f.request.ID, SessionID: &session.ID}
	if err := repo.Append(ctx, f.db, v); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(ctx, f.db, v.UserID, 20, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %+v %v", items, err)
	}
	want := v
	want.CreatedAt = items[0].CreatedAt
	if want.CreatedAt.IsZero() || !reflect.DeepEqual(items[0], want) {
		t.Fatalf("scan fields: got %+v want %+v", items[0], want)
	}
	duplicate := v
	duplicate.ID, duplicate.Title = id.New(), "must not overwrite"
	if err := repo.Append(ctx, f.db, duplicate); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkRead(ctx, f.db, f.first.ID, v.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("foreign notification changed: %v", err)
	}
	if count, err := repo.CountUnread(ctx, f.db, v.UserID); err != nil || count != 1 {
		t.Fatalf("dedupe/unread: %d %v", count, err)
	}
	if err := repo.MarkRead(ctx, f.db, v.UserID, v.ID); err != nil {
		t.Fatal(err)
	}
	readItems, err := repo.List(ctx, f.db, v.UserID, 20, 0)
	if err != nil || readItems[0].ReadAt == nil || readItems[0].Title != v.Title {
		t.Fatalf("read state: %+v %v", readItems, err)
	}
	if err := repo.MarkRead(ctx, f.db, v.UserID, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.Append(ctx, f.db, duplicate); err != nil {
		t.Fatal(err)
	}
	again, err := repo.List(ctx, f.db, v.UserID, 20, 0)
	if err != nil || !reflect.DeepEqual(again, readItems) {
		t.Fatal("duplicate changed read timestamp or message")
	}
	second := v
	second.ID, second.DedupeKey, second.SessionID = id.New(), "request:test", nil
	if err := repo.Append(ctx, f.db, second); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListNotifications(ctx, v.UserID, 1, 0)
	if err != nil || len(page.Items) != 1 || !page.HasMore || page.UnreadCount != 1 || page.Items[0].ID != second.ID || page.Items[0].SessionID != nil {
		t.Fatalf("first page: %+v %v", page, err)
	}
	page, err = f.svc.ListNotifications(ctx, v.UserID, 1, 1)
	if err != nil || len(page.Items) != 1 || page.HasMore || page.Items[0].ID != v.ID {
		t.Fatalf("second page: %+v %v", page, err)
	}
	empty, err := repo.List(ctx, f.db, v.UserID, 20, 2)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty page: %+v %v", empty, err)
	}
	for range 2 {
		if err := repo.MarkAllRead(ctx, f.db, v.UserID); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := repo.CountUnread(ctx, f.db, v.UserID); err != nil || count != 0 {
		t.Fatalf("mark all: %d %v", count, err)
	}
	if count, err := repo.CountUnread(ctx, f.db, f.first.ID); err != nil || count != 1 {
		t.Fatalf("mark all affected another user: %d %v", count, err)
	}
	rollback := errors.New("rollback notification")
	err = service.InTx(ctx, f.db, func(q repository.DBTX) error {
		next := v
		next.ID, next.DedupeKey = id.New(), "rollback"
		if err := repo.Append(ctx, q, next); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if all, err := repo.List(ctx, f.db, v.UserID, 20, 0); err != nil || len(all) != 2 {
		t.Fatalf("rollback leaked notification: %+v %v", all, err)
	}
	invalid := v
	invalid.ID, invalid.DedupeKey, invalid.UserID = id.New(), "invalid-user", id.New()
	if err := repo.Append(ctx, f.db, invalid); err == nil {
		t.Fatal("missing recipient accepted")
	}
	invalid.UserID, invalid.EventType = v.UserID, "unsupported"
	if err := repo.Append(ctx, f.db, invalid); err == nil {
		t.Fatal("unsupported event accepted")
	}
}
