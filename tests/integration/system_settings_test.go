//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestSystemSettingsPersistenceSecretsAndReplicaReload(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	cipher, err := secretstore.NewAESGCM("test-encryption", security.DeriveKey(strings.Repeat("m", 32), "system-settings"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	second, _ := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	initial, err := second.Current(ctx)
	if err != nil || initial.Revision != 0 || !initial.Auth.LocalEnabled {
		t.Fatalf("bootstrap settings: %v", err)
	}
	users := repository.NewUserRepository()
	actor, err := users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Settings Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := security.HashPassword("settings-admin-password")
	if err := users.CreateLocalCredential(ctx, database, repository.LocalCredential{UserID: actor.ID, Username: "settings-admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	config := settings.Defaults()
	config.BaseURL = "https://console.example.test"
	secret := "secret-only-in-encrypted-storage"
	revision := int64(0)
	view, err := first.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &revision, Secrets: settings.SecretChanges{OIDC: &secret}})
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != 1 || !view.HasSecrets.OIDC {
		t.Fatal("saved settings missing version or secret status")
	}
	encoded, _ := json.Marshal(view)
	row, err := (&repository.SystemSettingsRepository{}).Get(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || strings.Contains(string(row.ConfigJSON), secret) || strings.Contains(row.SecretsCiphertext, secret) {
		t.Fatal("settings exposed plaintext secret")
	}
	runtime, err := second.Current(ctx)
	if err != nil || runtime.Revision != 1 || runtime.Auth.OIDC.ClientSecret != secret {
		t.Fatalf("replica did not reload committed configuration: %v", err)
	}
	if _, err := first.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &revision}); !errors.Is(err, service.ErrStateConflict) {
		t.Fatalf("accepted stale revision: %v", err)
	}

	view, err = first.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision})
	if err != nil || !view.HasSecrets.OIDC {
		t.Fatalf("omitted secret was cleared: %v", err)
	}
	clear := ""
	view, err = first.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision, Secrets: settings.SecretChanges{OIDC: &clear}})
	if err != nil || view.HasSecrets.OIDC {
		t.Fatalf("explicit secret clear failed: %v", err)
	}
	wrongCipher, _ := secretstore.NewAESGCM("test-encryption", security.DeriveKey(strings.Repeat("w", 32), "system-settings"))
	wrong, _ := service.NewSystemSettingsService(database, wrongCipher, "https://console.example.test")
	if _, err := wrong.Current(ctx); err == nil {
		t.Fatal("wrong encryption key decrypted settings")
	}

	config.Auth.OIDC.Enabled, config.Auth.LocalEnabled = true, false
	config.Auth.OIDC.ClientID, config.Auth.OIDC.Issuer = "client", "https://identity.example.test"
	view, err = first.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision, Secrets: settings.SecretChanges{OIDC: &secret}})
	if err != nil || !view.Config.Auth.LocalEnabled {
		t.Fatalf("legacy local_enabled=false disabled the permanent recovery login: %+v %v", view.Config.Auth, err)
	}
	runtime, err = second.Current(ctx)
	if err != nil || !runtime.Auth.LocalEnabled || runtime.Revision != view.Revision {
		t.Fatalf("replica lost the local recovery login: %v", err)
	}
	credential, err := users.LocalCredential(ctx, database, "settings-admin")
	if err != nil || credential.UserID != actor.ID || !security.CheckPassword(credential.PasswordHash, "settings-admin-password") {
		t.Fatalf("external provider configuration invalidated local recovery credentials: %v", err)
	}
	// An external-only administrator still needs an identity linked to the
	// exact enabled issuer; local login cannot help an account without a password.
	externalActor, err := users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "External Settings Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Save(ctx, externalActor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("administrator without any configured login saved settings: %v", err)
	}
	if err := users.CreateIdentity(ctx, database, "oidc", config.Auth.OIDC.Issuer, "admin-subject", externalActor.ID); err != nil {
		t.Fatal(err)
	}
	view, err = first.Save(ctx, externalActor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision})
	if err != nil {
		t.Fatal(err)
	}
	config.Auth.OIDC.Issuer = "https://different-identity.example.test"
	if _, err := first.Save(ctx, externalActor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision}); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("unrelated issuer counted as recovery login: %v", err)
	}

	config = view.Config
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, instance := range []*service.SystemSettingsService{first, second} {
		wg.Add(1)
		go func(instance *service.SystemSettingsService) {
			defer wg.Done()
			_, err := instance.Save(ctx, actor.ID, service.SettingsUpdate{Config: &config, Revision: &view.Revision})
			results <- err
		}(instance)
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, service.ErrStateConflict) || errors.Is(err, repository.ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent updates: success=%d conflict=%d", success, conflict)
	}
	audits, err := repository.NewAuditEventRepository().List(ctx, database, domain.AuditFilter{EventType: "system.settings_updated", Limit: 100})
	if err != nil || len(audits) != 6 {
		t.Fatalf("transactional audit count = %d, %v", len(audits), err)
	}
	encoded, _ = json.Marshal(audits)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), config.Auth.OIDC.Issuer) {
		t.Fatal("audit exposed authentication configuration")
	}
}
