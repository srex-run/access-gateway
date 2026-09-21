package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

type RegionRepository struct{}

func NewRegionRepository() *RegionRepository {
	return &RegionRepository{}
}

func (r *RegionRepository) Create(ctx context.Context, q DBTX, value domain.Region) (domain.Region, error) {
	const query = `
		INSERT INTO regions (id, code, name, status)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + regionColumns
	created, err := scanRegion(q.QueryRowContext(ctx, query, value.ID, value.Code, value.Name, value.Status))
	if err != nil {
		return domain.Region{}, opError("create region", err)
	}
	return created, nil
}

func (r *RegionRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.Region, error) {
	const query = `SELECT ` + regionColumns + ` FROM regions WHERE id = $1`
	value, err := scanRegion(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Region{}, opError("get region by id", err)
	}
	return value, nil
}

// Preserve an existing default group's lifecycle state, including when disabled.
func (r *RegionRepository) EnsureDefault(ctx context.Context, q DBTX, id string) (domain.Region, error) {
	const query = `INSERT INTO regions (id, code, name, status)
		VALUES ($1, 'default', 'Default', 'enabled')
		ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
		RETURNING ` + regionColumns
	value, err := scanRegion(q.QueryRowContext(ctx, query, id))
	return value, opError("ensure default region", err)
}

func (r *RegionRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.Region, error) {
	const query = `SELECT ` + regionColumns + ` FROM regions WHERE id = $1 FOR UPDATE`
	value, err := scanRegion(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Region{}, opError("get region by id for update", err)
	}
	return value, nil
}

func (r *RegionRepository) GetByCode(ctx context.Context, q DBTX, code string) (domain.Region, error) {
	const query = `SELECT ` + regionColumns + ` FROM regions WHERE code = $1`
	value, err := scanRegion(q.QueryRowContext(ctx, query, code))
	if err != nil {
		return domain.Region{}, opError("get region by code", err)
	}
	return value, nil
}

func (r *RegionRepository) ListActive(ctx context.Context, q DBTX) ([]domain.Region, error) {
	const query = `SELECT ` + regionColumns + ` FROM regions WHERE status = 'enabled' ORDER BY code`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list active regions", err)
	}
	values, err := CollectRows(rows, scanRegion)
	if err != nil {
		return nil, opError("list active regions", err)
	}
	return values, nil
}

func (r *RegionRepository) UpdateStatus(ctx context.Context, q DBTX, id string, status domain.ResourceStatus) (domain.Region, error) {
	const query = `
		UPDATE regions
		SET status = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + regionColumns
	value, err := scanRegion(q.QueryRowContext(ctx, query, id, status))
	if err != nil {
		return domain.Region{}, opError("update region status", err)
	}
	return value, nil
}
