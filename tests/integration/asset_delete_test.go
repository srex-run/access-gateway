//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestAssetDeletionPreservesHistoryAndRevokesSessions(t *testing.T) {
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
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: gateway.UnavailableClient{}, Logger: zerolog.Nop(),
		AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	region, err := repos.regions.EnsureDefault(ctx, database, id.New())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := repos.gateways.Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Delete fixture", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:20000", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := repos.assets.Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "Retained history", AssetType: "ssh", TargetCiphertext: "encrypted-fixture", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	request, err := repos.requests.Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: reader.ID, AssetID: asset.ID, TargetPort: 22, TargetAccount: stringPointer("reader"), Reason: "history", TTLSeconds: 600, Status: domain.AccessRequestApproved, IdempotencyKey: id.New()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := repos.sessions.Create(ctx, database, domain.Session{ID: id.New(), RequestID: request.ID, GatewayID: gw.ID, Status: domain.SessionProvisioning})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session, err = repos.sessions.MarkRunning(ctx, database, session.ID, session.Version, "fixture-token-hash", "fixture-process", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteAsset(ctx, reader.ID, asset.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("reader deletion: %v", err)
	}
	if _, err := repos.assets.GetByID(ctx, database, asset.ID); err != nil {
		t.Fatal("forbidden deletion changed asset")
	}
	for i := 0; i < 2; i++ {
		if err := svc.DeleteAsset(ctx, admin.ID, asset.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repos.assets.GetByID(ctx, database, asset.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("deleted asset still accessible")
	}
	for _, list := range []func() ([]domain.Asset, error){
		func() ([]domain.Asset, error) { return repos.assets.ListManaged(ctx, database) },
		func() ([]domain.Asset, error) { return repos.assets.ListActiveByRegion(ctx, database, region.ID) },
	} {
		values, err := list()
		if err != nil || len(values) != 0 {
			t.Fatalf("deleted directory entry: %d %v", len(values), err)
		}
	}
	if _, err := svc.UpdateAssetStatus(ctx, admin.ID, asset.ID, domain.ResourceStatusEnabled); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("deleted asset can be reenabled")
	}
	current, err := repos.sessions.GetByID(ctx, database, session.ID)
	if err != nil || current.Status != domain.SessionRevoking {
		t.Fatalf("session was not queued for revocation: %s %v", current.Status, err)
	}
	if _, err := svc.GetSessionRecord(ctx, reader.ID, session.ID, false); err != nil {
		t.Fatalf("history lost: %v", err)
	}
	if _, err := repos.requests.GetByID(ctx, database, request.ID); err != nil {
		t.Fatal("historical request lost")
	}
	var count int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE asset_id=$1 AND event_type='asset.deleted'`, asset.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("delete audit count=%d err=%v", count, err)
	}
	source, externalID, generation := "cmdb.test", "instance-1", id.New()
	asset.ID, asset.ExternalSource, asset.ExternalID, asset.SyncGeneration = id.New(), &source, &externalID, &generation
	external, err := repos.assets.UpsertExternal(ctx, database, asset)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteAsset(ctx, admin.ID, external.ID); err != nil {
		t.Fatal(err)
	}
	tombstone, err := repos.assets.GetByExternalIdentity(ctx, database, source, externalID)
	if err != nil || tombstone.DeletedAt == nil {
		t.Fatal("sync cannot identify deleted asset")
	}
	if _, err := repos.assets.UpsertExternal(ctx, database, asset); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("sync resurrected deleted asset: %v", err)
	}
}
