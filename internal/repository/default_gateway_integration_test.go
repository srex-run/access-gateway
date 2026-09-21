//go:build integration

package repository

import (
	"strings"
	"sync"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestDefaultGatewayConcurrentReuseAndRollback(t *testing.T) {
	db := openIntegrationDB(t)
	ctx := testContext()
	region, err := NewRegionRepository().Create(ctx, db, domain.Region{ID: id.New(), Code: id.New(), Name: "default gateway test", Status: domain.ResourceStatusEnabled})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewGatewayRepository()
	input := domain.Gateway{RegionID: region.ID, ManagementEndpoint: "https://session-runtime.invalid/local", PublicEndpoint: "access-gateway.srex.run", MaxSessions: 100}
	const count = 8
	values, failures := make([]domain.Gateway, count), make([]error, count)
	var group sync.WaitGroup
	for i := range count {
		group.Add(1)
		go func() {
			defer group.Done()
			candidate := input
			candidate.ID = id.New()
			values[i], failures[i] = repo.EnsureDefault(ctx, db, candidate)
		}()
	}
	group.Wait()
	for i, value := range values {
		if failures[i] != nil || value.ID != values[0].ID || value.RegionID != region.ID || value.Status != domain.ResourceStatusEnabled || value.MaxSessions != 100 || value.PublicEndpoint != input.PublicEndpoint {
			t.Fatalf("concurrent ensure did not reuse the configured gateway: %v", failures[i])
		}
	}
	input.ID, input.PublicEndpoint, input.MaxSessions = id.New(), "access.example.com", 50
	updated, err := repo.EnsureDefault(ctx, db, input)
	if err != nil || updated.ID != values[0].ID || updated.PublicEndpoint != input.PublicEndpoint || updated.MaxSessions != 50 {
		t.Fatalf("environment update replaced identity or left stale configuration: %v", err)
	}
	listed, err := repo.ListActiveByRegion(ctx, db, region.ID)
	if err != nil || len(listed) != 1 {
		t.Fatal("concurrent creation left duplicate routes")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	input.PublicEndpoint = "rollback.example.com"
	if _, err := repo.EnsureDefault(ctx, tx, input); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.QueryContext(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+ensureDefaultGatewaySQL, input.ID, input.RegionID, input.ManagementEndpoint, input.PublicEndpoint, input.MaxSessions)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CollectRows(rows, scanQueryPlan)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("default gateway UPSERT plan:\n" + strings.Join(plan, "\n"))
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	saved, err := repo.GetByID(ctx, db, updated.ID)
	if err != nil || saved.PublicEndpoint != updated.PublicEndpoint {
		t.Fatal("rolled-back gateway change persisted")
	}
}
