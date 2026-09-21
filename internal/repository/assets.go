package repository

import (
	"context"
	"fmt"

	"github.com/srex-run/access-gateway/internal/domain"
)

type AssetRepository struct{}

func NewAssetRepository() *AssetRepository {
	return &AssetRepository{}
}

func (r *AssetRepository) Create(ctx context.Context, q DBTX, value domain.Asset) (domain.Asset, error) {
	const query = `
		INSERT INTO assets (
			id, region_id, gateway_id, name, asset_type, target_ciphertext,
			risk_level, max_ttl_seconds, status, approval_workflow_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING ` + assetColumns
	created, err := scanAsset(q.QueryRowContext(ctx, query,
		value.ID, value.RegionID, value.GatewayID, value.Name, value.AssetType,
		value.TargetCiphertext, value.RiskLevel, value.MaxTTLSeconds, value.Status, value.ApprovalWorkflowID,
	))
	if err != nil {
		return domain.Asset{}, opError("create asset", err)
	}
	return created, nil
}

func (r *AssetRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.Asset, error) {
	const query = `SELECT ` + assetColumns + ` FROM assets WHERE id = $1 AND deleted_at IS NULL`
	value, err := scanAsset(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Asset{}, opError("get asset by id", err)
	}
	return value, nil
}

func (r *AssetRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.Asset, error) {
	const query = `SELECT ` + assetColumns + ` FROM assets WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`
	value, err := scanAsset(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Asset{}, opError("get asset by id for update", err)
	}
	return value, nil
}

func (r *AssetRepository) GetByExternalIdentity(ctx context.Context, q DBTX, source, externalID string) (domain.Asset, error) {
	const query = `SELECT ` + assetColumns + ` FROM assets WHERE external_source = $1 AND external_id = $2`
	value, err := scanAsset(q.QueryRowContext(ctx, query, source, externalID))
	if err != nil {
		return domain.Asset{}, opError("get asset by external identity", err)
	}
	return value, nil
}

// Historical evidence and late gateway events must still resolve deleted assets.
func (r *AssetRepository) GetIncludingDeleted(ctx context.Context, q DBTX, id string) (domain.Asset, error) {
	value, err := scanAsset(q.QueryRowContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE id = $1`, id))
	return value, opError("get historical asset", err)
}

func (r *AssetRepository) Delete(ctx context.Context, q DBTX, id string) (domain.Asset, error) {
	value, err := scanAsset(q.QueryRowContext(ctx, `UPDATE assets SET status = 'disabled', deleted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL RETURNING `+assetColumns, id))
	return value, opError("delete asset", err)
}

func (r *AssetRepository) UpsertExternal(ctx context.Context, q DBTX, value domain.Asset) (domain.Asset, error) {
	const query = `
		INSERT INTO assets (
			id, region_id, gateway_id, name, asset_type, target_ciphertext,
			risk_level, max_ttl_seconds, status, external_source, external_id,
			sync_generation, last_synced_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
		ON CONFLICT (external_source, external_id)
		WHERE external_source IS NOT NULL AND external_id IS NOT NULL
		DO UPDATE SET
			region_id = EXCLUDED.region_id,
			gateway_id = EXCLUDED.gateway_id,
			name = EXCLUDED.name,
			asset_type = EXCLUDED.asset_type,
			target_ciphertext = EXCLUDED.target_ciphertext,
			risk_level = EXCLUDED.risk_level,
			max_ttl_seconds = EXCLUDED.max_ttl_seconds,
			status = EXCLUDED.status,
			sync_generation = EXCLUDED.sync_generation,
			last_synced_at = NOW(),
			updated_at = NOW()
		WHERE assets.deleted_at IS NULL
		RETURNING ` + assetColumns
	created, err := scanAsset(q.QueryRowContext(ctx, query,
		value.ID, value.RegionID, value.GatewayID, value.Name, value.AssetType,
		value.TargetCiphertext, value.RiskLevel, value.MaxTTLSeconds, value.Status,
		value.ExternalSource, value.ExternalID, value.SyncGeneration,
	))
	if err != nil {
		return domain.Asset{}, opError("upsert external asset", err)
	}
	return created, nil
}

func (r *AssetRepository) DisableExternalMissing(ctx context.Context, q DBTX, source, syncGeneration string) ([]domain.Asset, error) {
	const query = `
		UPDATE assets
		SET status = 'disabled', updated_at = NOW()
		WHERE external_source = $1
		  AND deleted_at IS NULL
		  AND sync_generation IS DISTINCT FROM $2::uuid
		  AND status <> 'disabled'
		RETURNING ` + assetColumns
	rows, err := q.QueryContext(ctx, query, source, syncGeneration)
	if err != nil {
		return nil, opError("disable missing external assets", err)
	}
	values, err := CollectRows(rows, scanAsset)
	if err != nil {
		return nil, opError("disable missing external assets", err)
	}
	return values, nil
}

func (r *AssetRepository) UpdateStatus(ctx context.Context, q DBTX, id string, status domain.ResourceStatus) (domain.Asset, error) {
	const query = `
		UPDATE assets
		SET status = $2, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING ` + assetColumns
	value, err := scanAsset(q.QueryRowContext(ctx, query, id, status))
	if err != nil {
		return domain.Asset{}, opError("update asset status", err)
	}
	return value, nil
}

func (r *AssetRepository) UpdateConfiguration(ctx context.Context, q DBTX, value domain.Asset) (domain.Asset, error) {
	const query = `
		UPDATE assets
		SET name = $2, asset_type = $3, target_ciphertext = $4,
			risk_level = $5, max_ttl_seconds = $6, approval_workflow_id = $7, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`
	result, err := q.ExecContext(ctx, query, value.ID, value.Name, value.AssetType, value.TargetCiphertext, value.RiskLevel, value.MaxTTLSeconds, value.ApprovalWorkflowID)
	if err != nil {
		return domain.Asset{}, opError("update asset configuration", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return domain.Asset{}, opError("update asset configuration rows affected", err)
	}
	if count == 0 {
		return domain.Asset{}, opError("update asset configuration", ErrNotFound)
	}
	return r.GetByID(ctx, q, value.ID)
}

func (r *AssetRepository) TryExternalSyncLock(ctx context.Context, q DBTX, source string) (bool, error) {
	const query = `
		SELECT pg_try_advisory_xact_lock(
			hashtextextended('asset-external-sync:' || $1::text, 0)
		) AS acquired`
	acquired, err := scanLockAcquired(q.QueryRowContext(ctx, query, source))
	if err != nil {
		return false, opError("try external asset sync lock", err)
	}
	return acquired, nil
}

func (r *AssetRepository) ListActiveByRegion(ctx context.Context, q DBTX, regionID string) ([]domain.Asset, error) {
	const query = `
		SELECT ` + assetColumns + `
		FROM assets
		WHERE region_id = $1 AND status = 'enabled' AND deleted_at IS NULL
		ORDER BY name, id`
	rows, err := q.QueryContext(ctx, query, regionID)
	if err != nil {
		return nil, opError("list active assets", err)
	}
	values, err := CollectRows(rows, scanAsset)
	if err != nil {
		return nil, opError("list active assets", err)
	}
	return values, nil
}

func (r *AssetRepository) ListManaged(ctx context.Context, q DBTX) ([]domain.Asset, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+assetColumns+` FROM assets WHERE deleted_at IS NULL ORDER BY name, id`)
	if err != nil {
		return nil, opError("list managed assets", err)
	}
	values, err := CollectRows(rows, scanAsset)
	return values, opError("list managed assets", err)
}

func (r *AssetRepository) ListPorts(ctx context.Context, q DBTX, assetID string) ([]domain.AssetPort, error) {
	const query = `
		SELECT ` + assetPortColumns + `
		FROM asset_ports
		WHERE asset_id = $1 AND enabled = TRUE
		ORDER BY port, protocol, id`
	rows, err := q.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, opError("list asset ports", err)
	}
	values, err := CollectRows(rows, scanAssetPort)
	if err != nil {
		return nil, opError("list asset ports", err)
	}
	return values, nil
}

func (r *AssetRepository) GetPort(ctx context.Context, q DBTX, assetID string, port int, protocol string) (domain.AssetPort, error) {
	const query = `
		SELECT ` + assetPortColumns + `
		FROM asset_ports
		WHERE asset_id = $1 AND port = $2 AND protocol = $3 AND enabled = TRUE`
	value, err := scanAssetPort(q.QueryRowContext(ctx, query, assetID, port, protocol))
	if err != nil {
		return domain.AssetPort{}, opError("get asset port", err)
	}
	return value, nil
}

func (r *AssetRepository) GetPortForUpdate(ctx context.Context, q DBTX, assetID string, port int, protocol string) (domain.AssetPort, error) {
	const query = `
		SELECT ` + assetPortColumns + `
		FROM asset_ports
		WHERE asset_id = $1 AND port = $2 AND protocol = $3
		FOR UPDATE`
	value, err := scanAssetPort(q.QueryRowContext(ctx, query, assetID, port, protocol))
	if err != nil {
		return domain.AssetPort{}, opError("get asset port for update", err)
	}
	return value, nil
}

func (r *AssetRepository) CreatePort(ctx context.Context, q DBTX, value domain.AssetPort) (domain.AssetPort, error) {
	const query = `
		INSERT INTO asset_ports (id, asset_id, port, protocol, enabled)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + assetPortColumns
	created, err := scanAssetPort(q.QueryRowContext(ctx, query, value.ID, value.AssetID, value.Port, value.Protocol, value.Enabled))
	if err != nil {
		return domain.AssetPort{}, opError("create asset port", err)
	}
	return created, nil
}

func (r *AssetRepository) DeletePort(ctx context.Context, q DBTX, assetID, portID string) (domain.AssetPort, error) {
	const query = `DELETE FROM asset_ports WHERE asset_id = $1 AND id = $2 RETURNING ` + assetPortColumns
	value, err := scanAssetPort(q.QueryRowContext(ctx, query, assetID, portID))
	return value, opError("delete asset port", err)
}

func (r *AssetRepository) UpsertPort(ctx context.Context, q DBTX, value domain.AssetPort) (domain.AssetPort, error) {
	const query = `
		INSERT INTO asset_ports (id, asset_id, port, protocol, enabled)
		VALUES ($1, $2, $3, $4, TRUE)
		ON CONFLICT (asset_id, port, protocol) DO UPDATE
		SET enabled = TRUE
		RETURNING ` + assetPortColumns
	created, err := scanAssetPort(q.QueryRowContext(ctx, query, value.ID, value.AssetID, value.Port, value.Protocol))
	if err != nil {
		return domain.AssetPort{}, opError("upsert asset port", err)
	}
	return created, nil
}

func (r *AssetRepository) DisablePortsExcept(ctx context.Context, q DBTX, assetID string, ports []int) (int64, error) {
	const query = `
		UPDATE asset_ports
		SET enabled = FALSE
		WHERE asset_id = $1 AND enabled = TRUE
		  AND NOT (port = ANY($2::integer[]))`
	result, err := q.ExecContext(ctx, query, assetID, ports)
	if err != nil {
		return 0, opError("disable stale asset ports", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, opError("disable stale asset ports rows affected", err)
	}
	if count < 0 {
		return 0, fmt.Errorf("disable stale asset ports: invalid rows affected")
	}
	return count, nil
}

func (r *AssetRepository) ListApprovers(ctx context.Context, q DBTX, assetID string) ([]domain.AssetApprover, error) {
	const query = `
		SELECT ` + approverColumns + `
		FROM asset_approvers
		WHERE asset_id = $1 AND enabled = TRUE
		ORDER BY approval_level, id`
	rows, err := q.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, opError("list asset approvers", err)
	}
	values, err := CollectRows(rows, scanApprover)
	if err != nil {
		return nil, opError("list asset approvers", err)
	}
	return values, nil
}

func (r *AssetRepository) CreateApprover(ctx context.Context, q DBTX, value domain.AssetApprover) (domain.AssetApprover, error) {
	const query = `
		INSERT INTO asset_approvers (id, asset_id, user_id, approval_level, role, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + approverColumns
	created, err := scanApprover(q.QueryRowContext(ctx, query,
		value.ID, value.AssetID, value.UserID, value.ApprovalLevel, value.Role, value.Enabled,
	))
	if err != nil {
		return domain.AssetApprover{}, opError("create asset approver", err)
	}
	return created, nil
}
