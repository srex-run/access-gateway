//go:build integration

package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestAssetAuditPersistenceAndConflict(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := testContext()
	user, err := NewUserRepository().Create(ctx, db, domain.User{ID: id.New(), Nickname: "Audit admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	region, err := NewRegionRepository().EnsureDefault(ctx, db, id.New())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGatewayRepository().Create(ctx, db, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "gateway", ManagementEndpoint: "https://gateway.test", PublicEndpoint: "gateway.test:8443", Status: domain.ResourceStatusEnabled, MaxSessions: 100})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := NewAssetRepository().Create(ctx, db, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gw.ID, Name: "mysql", AssetType: "mysql", TargetCiphertext: "target-encrypted", RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	repo := AssetAuditRepository{}
	if _, err := repo.Get(ctx, db, asset.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row: %v", err)
	}
	wanted := AssetAudit{AssetID: asset.ID, ConfigCiphertext: "encrypted-audit", UpdatedBy: user.ID}
	if _, err := repo.Save(ctx, db, wanted, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing update inserted: %v", err)
	}
	saved, err := repo.Save(ctx, db, wanted, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted.Revision, wanted.UpdatedAt = 1, saved.UpdatedAt
	if saved.UpdatedAt.IsZero() || !reflect.DeepEqual(saved, wanted) {
		t.Fatal("save lost or reordered columns")
	}
	actual, err := repo.Get(ctx, db, asset.ID)
	if err != nil || !reflect.DeepEqual(actual, wanted) {
		t.Fatal("read lost or reordered columns")
	}
	if _, err := repo.Save(ctx, db, wanted, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale create overwrote row: %v", err)
	}
	changed := wanted
	changed.ConfigCiphertext = "rotated-encrypted-audit"
	changed, err = repo.Save(ctx, db, changed, 1)
	if err != nil || changed.Revision != 2 || changed.UpdatedAt.Before(saved.UpdatedAt) {
		t.Fatal("revision did not advance")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := repo.Save(ctx, tx, wanted, 2); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	actual, err = repo.Get(ctx, db, asset.ID)
	if err != nil || !reflect.DeepEqual(actual, changed) {
		t.Fatal("rolled-back secrets persisted")
	}
	for _, candidate := range []AssetAudit{
		{AssetID: id.New(), ConfigCiphertext: "encrypted", UpdatedBy: user.ID},
		{AssetID: asset.ID, ConfigCiphertext: "", UpdatedBy: user.ID},
		{AssetID: asset.ID, ConfigCiphertext: "encrypted", UpdatedBy: id.New()},
	} {
		expected := int64(2)
		if candidate.AssetID != asset.ID {
			expected = 0
		}
		if _, err := repo.Save(ctx, db, candidate, expected); !errors.Is(err, ErrConstraint) {
			t.Fatalf("invalid row accepted: %v", err)
		}
	}
	const readPlan = `EXPLAIN (ANALYZE, BUFFERS) SELECT ` + assetAuditColumns + ` FROM asset_audit_configs WHERE asset_id = $1`
	rows, err := db.QueryContext(ctx, readPlan, asset.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CollectRows(rows, scanQueryPlan)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("asset audit read plan:\n" + strings.Join(plan, "\n"))
	// EXPLAIN ANALYZE writes are contained in a transaction that is rolled back.
	planTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer planTx.Rollback()
	const savePlan = `EXPLAIN (ANALYZE, BUFFERS) INSERT INTO asset_audit_configs (asset_id, config_ciphertext, revision, updated_by)
		SELECT $1, $2, 1, $4 WHERE $3::bigint = 0 OR EXISTS
			(SELECT 1 FROM asset_audit_configs WHERE asset_id = $1 AND revision = $3)
		ON CONFLICT (asset_id) DO UPDATE SET config_ciphertext = EXCLUDED.config_ciphertext,
			revision = asset_audit_configs.revision + 1, updated_at = NOW(), updated_by = EXCLUDED.updated_by
		WHERE asset_audit_configs.revision = $3 RETURNING ` + assetAuditColumns
	rows, err = planTx.QueryContext(ctx, savePlan, asset.ID, "plan-ciphertext", 2, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = CollectRows(rows, scanQueryPlan)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("asset audit save plan:\n" + strings.Join(plan, "\n"))
}
