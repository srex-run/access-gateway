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
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestWebTerminalDefaultGrantAndOwnerAuthorization(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	clock := time.Now()
	repos := newRepositories()
	owner, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Owner", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	other, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Other admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretstore.NewAESGCM("web-test", []byte(strings.Repeat("w", 32)))
	if err != nil {
		t.Fatal(err)
	}
	system, err := service.NewSystemSettingsService(database, cipher, "https://console.test")
	if err != nil {
		t.Fatal(err)
	}
	options := service.ServiceOptions{Clock: func() time.Time { return clock }, PublicURL: "https://console.test", DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets, Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox, Gateway: &sessionRuntimeStub{}, AssetEncryptor: cipher, SystemSettings: system, Logger: zerolog.Nop(), AdminUserIDs: map[string]struct{}{owner.ID: {}, other.ID: {}}}
	svc, err := service.NewAccessService(options)
	if err != nil {
		t.Fatal(err)
	}
	key, err := settings.GenerateAuditCertificate(settings.CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := svc.CreateAsset(ctx, owner.ID, service.CreateAssetInput{Name: "Web SSH", AssetType: "ssh", Target: "ssh.internal", MaxTTLSeconds: 600, Audit: &service.AssetAuditUpdate{Profiles: []settings.AuditProfile{{Name: "ssh", Port: 60022, Protocol: "ssh", AuditEnabled: true, TargetHostKeys: []string{key.SSHPublicKey}}}}})
	if err != nil {
		t.Fatal(err)
	}
	input := service.CreateRequestInput{ApplicantID: owner.ID, RegionID: asset.RegionID, AssetID: asset.ID, TargetPort: 60022, TargetAccount: "reader", Reason: "web test", TTLSeconds: 600, IdempotencyKey: "web-default-grant"}
	client := input
	client.SourceIP, client.IdempotencyKey = "192.0.2.1", "disabled-client-grant"
	if _, err = svc.CreateTestAccessRequest(ctx, client); !errors.Is(err, service.ErrValidation) {
		t.Fatalf("disabled client access: %v", err)
	}
	request, err := svc.CreateTestAccessRequest(ctx, input)
	if err != nil || request.SourceIP != nil {
		t.Fatalf("web request: %+v %v", request, err)
	}
	session, err := repos.sessions.GetByRequestID(ctx, database, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if session.ConnectionMode != "audit" || session.AuditPolicy.Protocol != "ssh" {
		t.Fatal("web session lost audit policy")
	}
	if _, err = svc.AuthorizeTerminal(ctx, owner.ID, session.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("provisioning session allowed")
	}
	_, err = database.ExecContext(ctx, `UPDATE sessions SET status='running', started_at=NOW(), listener_port=20000, external_port=20000, exposure_mode='direct', exposure_ref='direct/20000' WHERE id=$1`, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.AuthorizeTerminal(ctx, other.ID, session.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("non-owner admin allowed: %v", err)
	}
	if _, err = svc.AuthorizeTerminal(ctx, owner.ID, session.ID); err != nil {
		t.Fatal(err)
	}
	if defaults, err := svc.GetTerminalDemoDefaults(ctx, owner.ID, session.ID); err != nil || defaults != (service.TerminalDemoDefaults{}) {
		t.Fatalf("disabled demo mode exposed defaults: %+v, %v", defaults, err)
	}
	options.DemoMode = true
	demoService, err := service.NewAccessService(options)
	if err != nil {
		t.Fatal(err)
	}
	if defaults, err := demoService.GetTerminalDemoDefaults(ctx, owner.ID, session.ID); err != nil || defaults != (service.TerminalDemoDefaults{Enabled: true, Password: "123456", Database: "test"}) {
		t.Fatalf("demo defaults were not returned to the owner: %v", err)
	}
	if defaults, err := demoService.GetTerminalDemoDefaults(ctx, other.ID, session.ID); !errors.Is(err, service.ErrForbidden) || defaults != (service.TerminalDemoDefaults{}) {
		t.Fatalf("demo defaults exposed to a non-owner: %v", err)
	}
	view, err := svc.GetSession(ctx, owner.ID, session.ID)
	if err != nil || !view.CanWebConnect || view.CanConnect || view.GatewayEndpoint != "" || view.GatewayPort != 0 {
		t.Fatalf("web view exposes TCP: %+v %v", view, err)
	}
	clock = clock.Add(601 * time.Second)
	if _, err = svc.AuthorizeTerminal(ctx, owner.ID, session.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatal("expired session allowed")
	}
	if defaults, err := demoService.GetTerminalDemoDefaults(ctx, owner.ID, session.ID); !errors.Is(err, service.ErrForbidden) || defaults != (service.TerminalDemoDefaults{}) {
		t.Fatalf("demo defaults exposed after session expiry: %v", err)
	}
}
