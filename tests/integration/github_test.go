//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestGitHubIdentityAndSettings(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	svc := authenticationService(t, database)
	profile := authn.Profile{Provider: "github", Issuer: authn.GitHubIssuer, Subject: "123", Nickname: "octocat", Email: "same@example.test"}
	user, err := svc.SyncExternalUser(ctx, profile)
	if err != nil || user.Email == nil || *user.Email != profile.Email {
		t.Fatalf("GitHub account creation: %+v, %v", user, err)
	}
	profile.Nickname = "renamed"
	repeat, err := svc.SyncExternalUser(ctx, profile)
	if err != nil || repeat.ID != user.ID {
		t.Fatalf("GitHub rename changed platform identity: %+v, %v", repeat, err)
	}
	profile.Subject = "456"
	other, err := svc.SyncExternalUser(ctx, profile)
	if err != nil || other.ID == user.ID {
		t.Fatal("GitHub accounts were merged by email", err)
	}
	for _, permission := range []authz.Permission{authz.PermissionRoleManage, authz.PermissionApprovalManage} {
		if err := svc.Authorize(ctx, user.ID, permission); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("GitHub signup granted %s: %v", permission, err)
		}
	}
	permissions, err := svc.EffectivePermissions(ctx, user.ID)
	if err != nil || !slices.Equal(permissions, []authz.Permission{authz.PermissionDirectoryRead, authz.PermissionRequestManage, authz.PermissionSessionManage}) {
		t.Fatalf("GitHub default permissions=%v: %v", permissions, err)
	}
	if pending, err := svc.ListPendingApprovals(ctx, user.ID, 10, 0); !errors.Is(err, service.ErrForbidden) || len(pending) != 0 {
		t.Fatalf("ordinary GitHub user could read pending approvals: %v", err)
	}
	if _, err := svc.DecideApproval(ctx, user.ID, user.ID, domain.ApprovalApproved, nil); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("ordinary GitHub user reached approval lookup without permission: %v", err)
	}
	roles, err := (repository.IAMRepository{}).ListRoles(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Name == "user" && !slices.Equal(role.Permissions, permissions) {
			t.Fatalf("migrated default role=%v, effective permissions=%v", role.Permissions, permissions)
		}
	}
	cipher, err := secretstore.NewAESGCM("test-encryption", security.DeriveKey(strings.Repeat("m", 32), "system-settings"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	config := settings.Defaults()
	config.BaseURL = "https://untrusted-input.example.test"
	config.Auth.LocalEnabled = false
	config.Auth.GitHub.Enabled, config.Auth.GitHub.ClientID = true, "github-client"
	secret, revision := "github-secret-only-in-ciphertext", int64(0)
	view, err := first.Save(ctx, user.ID, service.SettingsUpdate{Config: &config, Revision: &revision, Secrets: settings.SecretChanges{GitHub: &secret}})
	if err != nil || !view.HasSecrets.GitHub || view.Config.BaseURL != "https://console.example.test" {
		t.Fatalf("GitHub identity did not count as an available login: %v", err)
	}
	row, err := (&repository.SystemSettingsRepository{}).Get(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(row.ConfigJSON), secret) || strings.Contains(row.SecretsCiphertext, secret) {
		t.Fatal("GitHub secret was not encrypted and write-only")
	}
	if strings.Contains(string(row.ConfigJSON), "base_url") {
		t.Fatal("deployment PUBLIC_URL persisted as a second editable setting")
	}
	snapshot, err := second.Current(ctx)
	if err != nil || snapshot.Auth.GitHub.ClientSecret != secret || snapshot.RedirectProviders["github"] == nil || snapshot.Auth.GitHub.RedirectURL != "https://console.example.test/api/v1/auth/github/callback" {
		t.Fatalf("GitHub settings not reloaded across replicas: %v", err)
	}
	legacy := view.Config
	legacy.Auth.GitHub = authn.GitHubConfig{}
	view, err = first.Save(ctx, user.ID, service.SettingsUpdate{Config: &legacy, Revision: &view.Revision})
	if err != nil || !view.Config.Auth.GitHub.Enabled || view.Config.Auth.GitHub.ClientID != "github-client" || !view.HasSecrets.GitHub {
		t.Fatalf("older console discarded GitHub settings: %v", err)
	}
	config.Auth.GitHub.Enabled, config.Auth.LocalEnabled = false, true
	if _, err := first.Save(ctx, user.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled the only login available to the GitHub administrator: %v", err)
	}
	if err := repository.NewUserRepository().UpdateStatus(ctx, database, user.ID, domain.UserStatusInactive); err != nil {
		t.Fatal(err)
	}
	profile.Subject = "123"
	if _, err := svc.SyncExternalUser(ctx, profile); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("GitHub login reactivated a disabled account", err)
	}
}
