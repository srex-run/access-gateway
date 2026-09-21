package repository

import (
	"context"
	"errors"
	"time"
)

type AssetAudit struct {
	AssetID          string
	ConfigCiphertext string `json:"-"`
	Revision         int64
	UpdatedAt        time.Time
	UpdatedBy        string
}

type AssetAuditRepository struct{}

func (AssetAuditRepository) Get(ctx context.Context, q DBTX, assetID string) (AssetAudit, error) {
	const query = `SELECT ` + assetAuditColumns + ` FROM asset_audit_configs WHERE asset_id = $1`
	value, err := scanAssetAudit(q.QueryRowContext(ctx, query, assetID))
	return value, opError("get asset audit", err)
}

// Save uses optimistic concurrency in addition to the service's asset row lock.
func (AssetAuditRepository) Save(ctx context.Context, q DBTX, value AssetAudit, expected int64) (AssetAudit, error) {
	const query = `INSERT INTO asset_audit_configs (asset_id, config_ciphertext, revision, updated_by)
		SELECT $1, $2, 1, $4 WHERE $3::bigint = 0 OR EXISTS
			(SELECT 1 FROM asset_audit_configs WHERE asset_id = $1 AND revision = $3)
		ON CONFLICT (asset_id) DO UPDATE SET config_ciphertext = EXCLUDED.config_ciphertext,
			revision = asset_audit_configs.revision + 1, updated_at = NOW(), updated_by = EXCLUDED.updated_by
		WHERE asset_audit_configs.revision = $3
		RETURNING ` + assetAuditColumns
	result, err := scanAssetAudit(q.QueryRowContext(ctx, query, value.AssetID, value.ConfigCiphertext, expected, value.UpdatedBy))
	if errors.Is(err, ErrNotFound) {
		err = ErrConflict
	}
	return result, opError("save asset audit", err)
}
