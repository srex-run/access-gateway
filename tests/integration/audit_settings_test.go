//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestAuditSettingsEncryptedPersistenceAndRuntimeReload(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	cipher, err := secretstore.NewAESGCM("test-encryption", security.DeriveKey(strings.Repeat("m", 32), "system-settings"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	second, _ := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	users := repository.NewUserRepository()
	actor, err := users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Audit Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.HashPassword("audit-admin-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.CreateLocalCredential(ctx, database, repository.LocalCredential{UserID: actor.ID, Username: "audit-admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := second.AuditRegistry(ctx); err != nil {
		t.Fatal(err)
	}
	bundle, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	config := settings.Defaults()
	config.AuditProfiles = []settings.AuditProfile{{Name: "mysql-audit", Protocol: "mysql", Port: 3306, Certificate: bundle.Certificate, GatewayCA: bundle.CA, TargetCA: bundle.CA}}
	revision := int64(0)
	view, err := first.Save(ctx, actor.ID, service.SettingsUpdate{Revision: &revision, Config: &config, Secrets: settings.SecretChanges{AuditProfiles: map[string]settings.AuditKeyChanges{"mysql-audit": {PrivateKey: &bundle.PrivateKey}}}})
	if err != nil {
		t.Fatal(err)
	}
	row, err := (&repository.SystemSettingsRepository{}).Get(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(row.ConfigJSON), "PRIVATE KEY") || strings.Contains(row.SecretsCiphertext, bundle.PrivateKey) {
		t.Fatal("unencrypted private key exposed")
	}
	if strings.Contains(string(row.ConfigJSON), "BEGIN CERTIFICATE") || strings.Contains(row.SecretsCiphertext, bundle.Certificate) || strings.Contains(row.SecretsCiphertext, bundle.CA) {
		t.Fatal("unencrypted certificate or CA exposed in stored settings")
	}
	if !view.HasSecrets.AuditProfiles["mysql-audit"].PrivateKey {
		t.Fatal("key status missing")
	}
	registry, err := second.AuditRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := registry.Select(nil, 3306)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := sessionproxy.ResolveProfile(ctx, second, policy)
	if err != nil || grant.PrivateKey != bundle.PrivateKey || grant.Certificate != bundle.Certificate || grant.TargetCA != bundle.CA {
		t.Fatal("runtime did not load new settings")
	}
	config = view.Config
	view, err = first.Save(ctx, actor.ID, service.SettingsUpdate{Revision: &view.Revision, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionproxy.ResolveProfile(ctx, second, policy); err != nil {
		t.Fatal("unrelated save changed policy")
	}
	rotated, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	config = view.Config
	config.AuditProfiles[0].Certificate, config.AuditProfiles[0].GatewayCA = rotated.Certificate, rotated.CA
	view, err = first.Save(ctx, actor.ID, service.SettingsUpdate{Revision: &view.Revision, Config: &config, Secrets: settings.SecretChanges{AuditProfiles: map[string]settings.AuditKeyChanges{"mysql-audit": {PrivateKey: &rotated.PrivateKey}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionproxy.ResolveProfile(ctx, second, policy); err == nil {
		t.Fatal("old policy silently used rotated key")
	}
	if grant.PrivateKey != bundle.PrivateKey {
		t.Fatal("existing grant mutated during rotation")
	}
	reloaded, err := second.Get(ctx)
	if err != nil || reloaded.Revision != view.Revision || reloaded.Config.AuditProfiles[0].Certificate != rotated.Certificate || reloaded.Config.AuditProfiles[0].TargetCA != bundle.CA {
		t.Fatal("replica did not reload saved profile")
	}
	audits, err := repository.NewAuditEventRepository().List(ctx, database, domain.AuditFilter{EventType: "system.settings_updated", Limit: 100})
	if err != nil || len(audits) != 3 {
		t.Fatal("audit evidence missing")
	}
	encoded, _ = json.Marshal(audits)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("audit contains private key")
	}
}
