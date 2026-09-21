//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

func authenticationService(t *testing.T, database *sql.DB) *service.AccessService {
	t.Helper()
	repos := newRepositories()
	svc, err := service.NewAccessService(service.ServiceOptions{DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(), FeishuTenantKey: "tenant", AdminUserIDs: map[string]struct{}{"admin-open-id": {}}})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestPlatformAuthenticationAccountsAndRevocation(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	users := repository.NewUserRepository()
	svc := authenticationService(t, database)
	hash, err := security.HashPassword("initial-password")
	if err != nil {
		t.Fatal(err)
	}
	local, err := users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Local User", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := users.CreateLocalCredential(ctx, database, repository.LocalCredential{UserID: local.ID, Username: "alice", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	loggedIn, err := svc.AuthenticateLocal(ctx, "ALICE", "initial-password")
	if err != nil || loggedIn.ID != local.ID || loggedIn.FeishuOpenID != "" {
		t.Fatalf("local login = %+v, %v", loggedIn, err)
	}
	if err := svc.ChangePassword(ctx, local.ID, "wrong-password", "changed-password"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatalf("wrong current password = %v", err)
	}
	if err := svc.ChangePassword(ctx, local.ID, "initial-password", "changed-password"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateBrowserSession(ctx, local.ID, loggedIn.AuthVersion); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("old session survived password change")
	}
	if _, err := svc.AuthenticateLocal(ctx, "alice", "initial-password"); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("old password survived password change")
	}
	loggedIn, err = svc.AuthenticateLocal(ctx, "alice", "changed-password")
	if err != nil {
		t.Fatal(err)
	}
	profile := authn.Profile{Provider: "oidc", Issuer: "https://auth.example.test", Subject: "stable-subject", Nickname: "External User", Email: "same@example.test"}
	external, err := svc.SyncExternalUser(ctx, profile)
	if err != nil || external.ID == local.ID {
		t.Fatalf("external account = %+v, %v", external, err)
	}
	var wait sync.WaitGroup
	for range 4 {
		wait.Go(func() {
			user, err := svc.SyncExternalUser(ctx, profile)
			if err != nil || user.ID != external.ID {
				t.Errorf("concurrent external login = %+v, %v", user, err)
			}
		})
	}
	wait.Wait()
	audits := repository.NewAuditEventRepository()
	if events, err := audits.List(ctx, database, domain.AuditFilter{EventType: "user.login"}); err != nil || len(events) != 0 {
		t.Fatalf("login created audit noise: %+v %v", events, err)
	}
	if events, err := audits.List(ctx, database, domain.AuditFilter{EventType: "user.external_created", SubjectUserID: external.ID}); err != nil || len(events) != 1 {
		t.Fatalf("external account creation must be recorded exactly once: %+v %v", events, err)
	}
	if events, err := audits.List(ctx, database, domain.AuditFilter{EventType: "user.password_changed", SubjectUserID: local.ID}); err != nil || len(events) != 1 {
		t.Fatalf("password mutation audit lost: %+v %v", events, err)
	}
	profile.Provider = "oauth2"
	other, err := svc.SyncExternalUser(ctx, profile)
	if err != nil || other.ID == external.ID {
		t.Fatal("identical email or subject merged unrelated providers")
	}
	if err := users.UpdateStatus(ctx, database, external.ID, domain.UserStatusInactive); err != nil {
		t.Fatal(err)
	}
	profile.Provider = "oidc"
	if _, err := svc.SyncExternalUser(ctx, profile); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("external login reactivated disabled account")
	}
	feishuProfile := feishu.Profile{OpenID: "admin-open-id", UnionID: "union", TenantKey: "tenant", Nickname: "Local User", Active: true}
	if err := svc.BindFeishuUser(ctx, local.ID, loggedIn.AuthVersion, feishuProfile); err != nil {
		t.Fatal(err)
	}
	if err := svc.Authorize(ctx, local.ID, authz.PermissionRoleManage); err != nil {
		t.Fatal("Feishu bootstrap role missing", err)
	}
	if err := svc.BindFeishuUser(ctx, other.ID, other.AuthVersion, feishuProfile); !errors.Is(err, service.ErrStateConflict) {
		t.Fatal("transferred another account's Feishu identity", err)
	}
	if err := svc.UnbindFeishuUser(ctx, local.ID, map[string]string{}); !errors.Is(err, service.ErrStateConflict) {
		t.Fatal("unbound last enabled login method", err)
	}
	if err := svc.UnbindFeishuUser(ctx, local.ID, map[string]string{"local": "local"}); !errors.Is(err, service.ErrValidation) {
		t.Fatal("unbound the last administrator", err)
	}
	recovery, err := svc.CreateLocalUser(ctx, local.ID, service.CreateLocalUserInput{Username: "recovery-admin", Nickname: "Recovery Administrator", Password: "recovery-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(ctx, local.ID, service.GrantRoleInput{UserID: recovery.ID, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnbindFeishuUser(ctx, local.ID, map[string]string{"local": "local"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Authorize(ctx, local.ID, authz.PermissionRoleManage); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("Feishu bootstrap admin survived unbinding", err)
	}
	if err := svc.ValidateBrowserSession(ctx, local.ID, loggedIn.AuthVersion); !errors.Is(err, service.ErrInvalidCredentials) {
		t.Fatal("old session survived unbinding")
	}
	if err := svc.BindFeishuUser(ctx, other.ID, other.AuthVersion, feishuProfile); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnbindFeishuUser(ctx, other.ID, map[string]string{"oauth2": "https://new-issuer.example"}); !errors.Is(err, service.ErrStateConflict) {
		t.Fatal("outdated issuer accepted as a usable login", err)
	}
	if err := svc.UnbindFeishuUser(ctx, other.ID, map[string]string{"oauth2": profile.Issuer}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginAttemptsAreSharedAndExpire(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	first, second := &repository.LoginAttemptRepository{}, &repository.LoginAttemptRepository{}
	hash := security.HashOpaqueToken("local:alice")
	for index := 0; index < 11; index++ {
		repo := first
		if index%2 == 0 {
			repo = second
		}
		allowed, err := repo.Allow(ctx, database, hash, 10)
		if err != nil || allowed != (index < 10) {
			t.Fatalf("attempt %d = %v, %v", index, allowed, err)
		}
	}
	if _, err := database.ExecContext(ctx, `UPDATE login_attempts SET expires_at = NOW() - INTERVAL '1 second' WHERE bucket_hash = $1`, hash); err != nil {
		t.Fatal(err)
	}
	if allowed, err := first.Allow(ctx, database, hash, 10); err != nil || !allowed {
		t.Fatalf("expired attempt window = %v, %v", allowed, err)
	}
}
