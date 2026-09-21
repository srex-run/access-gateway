//go:build integration

package integration_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestAssetAuditAtomicSaveAndRuntime(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Reader", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.HashPassword("asset-audit-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.users.CreateLocalCredential(ctx, database, repository.LocalCredential{UserID: admin.ID, Username: "audit-admin", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	cipher, err := secretstore.NewAESGCM("test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	system, err := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		PublicURL: "https://sessions.example.com:8443", GatewayMaxSessions: 75,
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: &sessionRuntimeStub{}, AssetEncryptor: cipher, Logger: zerolog.Nop(),
		DefaultTTL: time.Hour, MaxTTL: time.Hour, AdminUserIDs: map[string]struct{}{admin.ID: {}}, SystemSettings: system, AuditProfiles: system,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.GenerateAssetAuditCertificate(ctx, admin.ID, settings.CertificateRequest{Purpose: "gateway", Hosts: []string{"untrusted.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(bundle.Certificate))
	if block == nil {
		t.Fatal("gateway certificate missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.VerifyHostname("sessions.example.com") != nil || cert.VerifyHostname("untrusted.example.com") == nil {
		t.Fatal("gateway certificate identity was controlled by submitted hosts instead of PUBLIC_URL")
	}
	profile := settings.AuditProfile{AuditEnabled: true, Name: "mysql-audit", Protocol: "mysql", Port: 3306, Certificate: bundle.Certificate, GatewayCA: bundle.CA}
	config, zero := settings.Defaults(), int64(0)
	config.ClientAccessEnabled, config.ClientAccessHost = true, "sessions.example.com"
	config.AuditProfiles = []settings.AuditProfile{profile}
	if _, err := system.Save(ctx, admin.ID, service.SettingsUpdate{Config: &config, Revision: &zero, Secrets: settings.SecretChanges{AuditProfiles: map[string]settings.AuditKeyChanges{profile.Name: {PrivateKey: &bundle.PrivateKey}}}}); err != nil {
		t.Fatal(err)
	}
	input := service.CreateAssetInput{Name: "mysql", AssetType: "mysql", Target: "mysql.internal", MaxTTLSeconds: 600,
		Audit: &service.AssetAuditUpdate{Profiles: []settings.AuditProfile{profile}, Keys: map[string]settings.AuditKeyChanges{profile.Name: {PrivateKey: &bundle.PrivateKey}}}}
	asset, err := svc.CreateAsset(ctx, admin.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := repos.assets.ListPorts(ctx, database, asset.ID)
	if err != nil || len(ports) != 1 || ports[0].Port != 3306 {
		t.Fatal("asset and audit port were not created together")
	}
	route, err := repos.gateways.GetByID(ctx, database, asset.GatewayID)
	if err != nil || route.PublicEndpoint != "sessions.example.com" || route.MaxSessions != 75 || route.RegionID != asset.RegionID {
		t.Fatal("asset did not automatically bind the configured gateway")
	}
	bindings, err := repos.gateways.ListAssetBindings(ctx, database, asset.ID)
	if err != nil || len(bindings) != 1 || bindings[0].GatewayID != route.ID || !bindings[0].Enabled {
		t.Fatal("automatic gateway binding missing")
	}
	view, err := svc.GetAssetAudit(ctx, admin.ID, asset.ID)
	if err != nil || view.Revision != 1 || len(view.Profiles) != 1 || !view.HasSecrets[view.Profiles[0].Name].PrivateKey {
		t.Fatal("resource audit view missing")
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("private key returned by GET")
	}
	row, err := (repository.AssetAuditRepository{}).Get(ctx, database, asset.ID)
	if err != nil || strings.Contains(row.ConfigCiphertext, "CERTIFICATE") || strings.Contains(row.ConfigCiphertext, "PRIVATE KEY") {
		t.Fatal("audit config is not encrypted")
	}
	if _, err := svc.GetAssetAudit(ctx, reader.ID, asset.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("non-admin read audit configuration")
	}
	request, err := svc.CreateTestAccessRequest(ctx, service.CreateRequestInput{ApplicantID: admin.ID, RegionID: asset.RegionID, AssetID: asset.ID, TargetPort: 3306,
		SourceIP: "192.0.2.1", TargetAccount: "readonly", Reason: "audit test", TTLSeconds: 600, IdempotencyKey: "asset-audit"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := repos.sessions.GetByRequestID(ctx, database, request.ID)
	if err != nil || session.AuditPolicy.Profile != view.Profiles[0].Name {
		t.Fatal("session selected global profile instead of resource configuration")
	}
	grant, err := sessionproxy.ResolveProfile(ctx, system, session.AuditPolicy)
	if err != nil || grant.PrivateKey != bundle.PrivateKey {
		t.Fatal("runtime cannot resolve asset-owned certificate")
	}
	name := "renamed"
	if _, err := svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{Name: &name, Audit: &service.AssetAuditUpdate{Revision: 1, Profiles: view.Profiles}}); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.GetAssetAudit(ctx, admin.ID, asset.ID)
	if err != nil || updated.Revision != 2 || !updated.HasSecrets[view.Profiles[0].Name].PrivateKey {
		t.Fatal("omitted key was not preserved")
	}
	if _, err := sessionproxy.ResolveProfile(ctx, system, session.AuditPolicy); err != nil {
		t.Fatal("unchanged certificate no longer resolves")
	}
	badName := "must-roll-back"
	if _, err := svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{Name: &badName, Audit: &service.AssetAuditUpdate{Revision: 1, Profiles: view.Profiles}}); !errors.Is(err, service.ErrStateConflict) {
		t.Fatal("stale certificate configuration overwritten")
	}
	invalid := append([]settings.AuditProfile{}, view.Profiles...)
	invalid[0].Certificate = "invalid certificate"
	if _, err := svc.UpdateAsset(ctx, admin.ID, asset.ID, service.UpdateAssetInput{Name: &badName, Audit: &service.AssetAuditUpdate{Revision: 2, Profiles: invalid}}); !errors.Is(err, service.ErrValidation) {
		t.Fatal("invalid certificate saved")
	}
	actual, err := repos.assets.GetByID(ctx, database, asset.ID)
	if err != nil || actual.Name != name {
		t.Fatal("failed certificate update partially changed asset")
	}
	after, err := svc.GetAssetAudit(ctx, admin.ID, asset.ID)
	if err != nil || !reflect.DeepEqual(after, updated) {
		t.Fatal("failed update changed certificate state")
	}
	events, err := repos.audits.List(ctx, database, domain.AuditFilter{AssetID: asset.ID, EventType: "asset.updated", Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatal("resource save did not produce one operation event")
	}
	encoded, _ = json.Marshal(events)
	if strings.Contains(string(encoded), "CERTIFICATE") || strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("audit log leaked credentials")
	}
	// Existing resources load their matching global rule and claim their own
	// encrypted copy on first save, including an omitted existing private key.
	legacy, err := svc.CreateAsset(ctx, admin.ID, service.CreateAssetInput{Name: "legacy", AssetType: "mysql", Target: "legacy.internal", MaxTTLSeconds: 600})
	if err == nil && legacy.GatewayID != asset.GatewayID {
		t.Fatal("new assets did not reuse the default gateway")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAssetPort(ctx, admin.ID, legacy.ID, domain.AssetPort{Port: 3306, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	legacyView, err := svc.GetAssetAudit(ctx, admin.ID, legacy.ID)
	if err != nil || legacyView.Revision != 0 || len(legacyView.Profiles) != 1 || !legacyView.HasSecrets[profile.Name].PrivateKey {
		t.Fatal("legacy matching configuration not restored")
	}
	if _, err := svc.UpdateAsset(ctx, admin.ID, legacy.ID, service.UpdateAssetInput{Audit: &service.AssetAuditUpdate{Profiles: legacyView.Profiles}}); err != nil {
		t.Fatal(err)
	}
	legacyView, err = svc.GetAssetAudit(ctx, admin.ID, legacy.ID)
	if err != nil || legacyView.Revision != 1 || legacyView.Profiles[0].Name == view.Profiles[0].Name {
		t.Fatal("migration reused another resource identity")
	}
	// Persisting an empty resource configuration never falls back to the global rule.
	if _, err := svc.UpdateAsset(ctx, admin.ID, legacy.ID, service.UpdateAssetInput{Audit: &service.AssetAuditUpdate{Revision: 1, Profiles: []settings.AuditProfile{}}}); err != nil {
		t.Fatal(err)
	}
	if ports, err := repos.assets.ListPorts(ctx, database, legacy.ID); err != nil || len(ports) != 0 {
		t.Fatal("removed audit port still available in the catalog")
	}
	// Reintroducing a catalog port separately must still not revive the old
	// global certificate when an empty asset-owned configuration exists.
	if _, err := repos.assets.UpsertPort(ctx, database, domain.AssetPort{ID: id.New(), AssetID: legacy.ID, Port: 3306, Protocol: "tcp", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	nativeRequest, err := svc.CreateTestAccessRequest(ctx, service.CreateRequestInput{ApplicantID: admin.ID, RegionID: legacy.RegionID, AssetID: legacy.ID, TargetPort: 3306,
		SourceIP: "192.0.2.1", TargetAccount: "readonly", Reason: "missing audit", TTLSeconds: 600, IdempotencyKey: "empty-asset-audit"})
	if err != nil {
		t.Fatal(err)
	}
	nativeSession, err := repos.sessions.GetByRequestID(ctx, database, nativeRequest.ID)
	if err != nil || nativeSession.ConnectionMode != "native" || nativeSession.AuditPolicy.Profile != "" {
		t.Fatal("empty resource audit fell back to global rule")
	}
}
