//go:build integration

package repository

import (
	"errors"
	"reflect"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestUpdateAssetConfiguration(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := testContext()
	region, err := NewRegionRepository().EnsureDefault(ctx, db, id.New())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGatewayRepository().Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:8443", Status: domain.ResourceStatusEnabled, MaxSessions: 100})
	if err != nil {
		t.Fatal(err)
	}
	assets := NewAssetRepository()
	original, err := assets.Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "mysql", AssetType: "mysql", TargetCiphertext: "original-ciphertext", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusDisabled})
	if err != nil {
		t.Fatal(err)
	}
	expected := original
	expected.Name, expected.AssetType, expected.TargetCiphertext = "mysql-renamed", "database", "new-ciphertext"
	expected.RiskLevel, expected.MaxTTLSeconds = domain.RiskLevelSensitive, 1800
	updated, err := assets.UpdateConfiguration(ctx, db, expected)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.UpdatedAt.After(original.UpdatedAt) {
		t.Fatal("configuration timestamp did not advance")
	}
	expected.UpdatedAt = updated.UpdatedAt
	if !reflect.DeepEqual(updated, expected) {
		t.Fatalf("configuration update changed unrelated fields: got %+v want %+v", updated, expected)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	candidate := updated
	candidate.Name = "rolled-back"
	if _, err := assets.UpdateConfiguration(ctx, tx, candidate); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	actual, err := assets.GetByID(ctx, db, original.ID)
	if err != nil || !reflect.DeepEqual(actual, updated) {
		t.Fatalf("rolled-back edit persisted: %+v %v", actual, err)
	}
	candidate = updated
	candidate.RiskLevel = "invalid"
	if _, err := assets.UpdateConfiguration(ctx, db, candidate); !errors.Is(err, ErrConstraint) {
		t.Fatalf("invalid policy was accepted: %v", err)
	}
	candidate.ID = id.New()
	if _, err := assets.UpdateConfiguration(ctx, db, candidate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing asset did not return ErrNotFound: %v", err)
	}
}

func TestDefaultGroupAndManagedAssets(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := testContext()
	regions := NewRegionRepository()
	first, err := regions.EnsureDefault(ctx, db, id.New())
	if err != nil {
		t.Fatal(err)
	}
	second, err := regions.EnsureDefault(ctx, db, id.New())
	if err != nil || first.ID != second.ID {
		t.Fatalf("default group was duplicated: %v", err)
	}
	other, err := regions.Create(ctx, db, domain.Region{ID: id.New(), Code: "legacy", Name: "Legacy", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	gateways := NewGatewayRepository()
	assets := NewAssetRepository()
	for index, region := range []domain.Region{first, other} {
		gateway, err := gateways.Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:8443", Status: domain.ResourceStatusEnabled, MaxSessions: 100})
		if err != nil {
			t.Fatal(err)
		}
		status := domain.ResourceStatusEnabled
		if index == 1 {
			status = domain.ResourceStatusDisabled
		}
		_, err = assets.Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gateway.ID, Name: "ecs", AssetType: "ecs", TargetCiphertext: "encrypted", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 3600, Status: status})
		if err != nil {
			t.Fatal(err)
		}
	}
	listed, err := assets.ListManaged(ctx, db)
	if err != nil || len(listed) != 2 {
		t.Fatalf("management list dropped groups or disabled assets: %+v %v", listed, err)
	}
	if _, err := regions.UpdateStatus(ctx, db, first.ID, domain.ResourceStatusDisabled); err != nil {
		t.Fatal(err)
	}
	preserved, err := regions.EnsureDefault(ctx, db, id.New())
	if err != nil || preserved.Status != domain.ResourceStatusDisabled {
		t.Fatalf("default group was silently re-enabled: %v", err)
	}
	available, err := gateways.ListActiveByRegion(ctx, db, "")
	if err != nil || len(available) != 1 || available[0].RegionID != other.ID {
		t.Fatalf("gateway choices include disabled groups: %+v %v", available, err)
	}
}
