package repository

import (
	"context"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type GatewayRepository struct{}

func NewGatewayRepository() *GatewayRepository {
	return &GatewayRepository{}
}

const ensureDefaultGatewaySQL = `INSERT INTO gateways
	(id, region_id, name, management_endpoint, public_endpoint, status, max_sessions, is_default)
	VALUES ($1, $2, '默认网关', $3, $4, 'enabled', $5, TRUE)
	ON CONFLICT (region_id) WHERE is_default DO UPDATE
	SET management_endpoint = EXCLUDED.management_endpoint, public_endpoint = EXCLUDED.public_endpoint,
	    max_sessions = EXCLUDED.max_sessions, status = 'enabled', updated_at = NOW()
	RETURNING ` + gatewayColumns

// EnsureDefault reuses one internal route per region, including concurrent creates.
func (r *GatewayRepository) EnsureDefault(ctx context.Context, q DBTX, value domain.Gateway) (domain.Gateway, error) {
	value, err := scanGateway(q.QueryRowContext(ctx, ensureDefaultGatewaySQL,
		value.ID, value.RegionID, value.ManagementEndpoint, value.PublicEndpoint, value.MaxSessions))
	return value, opError("ensure default gateway", err)
}

func (r *GatewayRepository) Create(ctx context.Context, q DBTX, value domain.Gateway) (domain.Gateway, error) {
	const query = `
		INSERT INTO gateways (
			id, region_id, name, management_endpoint, public_endpoint, auth_secret_ref,
			status, max_sessions, last_heartbeat_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING ` + gatewayColumns
	created, err := scanGateway(q.QueryRowContext(ctx, query,
		value.ID, value.RegionID, value.Name, value.ManagementEndpoint, value.PublicEndpoint,
		value.AuthSecretRef, value.Status, value.MaxSessions, value.LastHeartbeatAt,
	))
	if err != nil {
		return domain.Gateway{}, opError("create gateway", err)
	}
	return created, nil
}

func (r *GatewayRepository) UpdateCapacity(ctx context.Context, q DBTX, id string, maxSessions int) (domain.Gateway, error) {
	const query = `
		UPDATE gateways
		SET max_sessions = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + gatewayColumns
	value, err := scanGateway(q.QueryRowContext(ctx, query, id, maxSessions))
	if err != nil {
		return domain.Gateway{}, opError("update gateway capacity", err)
	}
	return value, nil
}

func (r *GatewayRepository) UpdateAuthSecretRef(ctx context.Context, q DBTX, id, authSecretRef string) (domain.Gateway, error) {
	const query = `
		UPDATE gateways
		SET auth_secret_ref = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + gatewayColumns
	value, err := scanGateway(q.QueryRowContext(ctx, query, id, authSecretRef))
	if err != nil {
		return domain.Gateway{}, opError("update gateway auth secret reference", err)
	}
	return value, nil
}

func (r *GatewayRepository) UpdateStatus(ctx context.Context, q DBTX, id string, status domain.ResourceStatus) (domain.Gateway, error) {
	const query = `
		UPDATE gateways
		SET status = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + gatewayColumns
	value, err := scanGateway(q.QueryRowContext(ctx, query, id, status))
	if err != nil {
		return domain.Gateway{}, opError("update gateway status", err)
	}
	return value, nil
}

func (r *GatewayRepository) BindAsset(ctx context.Context, q DBTX, assetID, gatewayID string, priority int) error {
	const query = `
		INSERT INTO asset_gateway_bindings (asset_id, gateway_id, priority, enabled)
		VALUES ($1, $2, $3, TRUE)
		ON CONFLICT (asset_id, gateway_id) DO UPDATE
		SET priority = EXCLUDED.priority, enabled = TRUE, updated_at = NOW()`
	result, err := q.ExecContext(ctx, query, assetID, gatewayID, priority)
	if err != nil {
		return opError("bind asset gateway", err)
	}
	return affected("bind asset gateway", result)
}

func (r *GatewayRepository) DisableAssetBindingsExcept(ctx context.Context, q DBTX, assetID string, gatewayIDs []string) (int64, error) {
	const query = `
		UPDATE asset_gateway_bindings
		SET enabled = FALSE, updated_at = NOW()
		WHERE asset_id = $1 AND enabled = TRUE
		  AND NOT (gateway_id = ANY($2::uuid[]))`
	result, err := q.ExecContext(ctx, query, assetID, gatewayIDs)
	if err != nil {
		return 0, opError("disable stale asset gateway bindings", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, opError("disable stale asset gateway bindings rows affected", err)
	}
	return count, nil
}

func (r *GatewayRepository) ListAssetBindings(ctx context.Context, q DBTX, assetID string) ([]domain.AssetGatewayBinding, error) {
	const query = `
		SELECT ` + assetGatewayBindingColumns + `
		FROM asset_gateway_bindings
		WHERE asset_id = $1
		ORDER BY priority, gateway_id`
	rows, err := q.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, opError("list asset gateway bindings", err)
	}
	values, err := CollectRows(rows, scanAssetGatewayBinding)
	if err != nil {
		return nil, opError("list asset gateway bindings", err)
	}
	return values, nil
}

func (r *GatewayRepository) ListCatalogEntries(ctx context.Context, q DBTX, gatewayID string) ([]domain.GatewayCatalogEntry, error) {
	const query = `
		SELECT ` + gatewayCatalogEntryColumns + `
		FROM asset_gateway_bindings AS b
		JOIN gateways AS g
		  ON g.id = b.gateway_id
		 AND g.status = 'enabled'
		JOIN assets AS a
		  ON a.id = b.asset_id
		 AND a.region_id = g.region_id
		 AND a.status = 'enabled'
		JOIN asset_ports AS p
		  ON p.asset_id = a.id
		 AND p.enabled = TRUE
		WHERE b.gateway_id = $1
		  AND b.enabled = TRUE
		GROUP BY a.id, a.external_source, a.external_id
		ORDER BY a.id`
	rows, err := q.QueryContext(ctx, query, gatewayID)
	if err != nil {
		return nil, opError("list gateway catalog entries", err)
	}
	values, err := CollectRows(rows, scanGatewayCatalogEntry)
	if err != nil {
		return nil, opError("list gateway catalog entries", err)
	}
	return values, nil
}

func (r *GatewayRepository) UpdateAssetBinding(ctx context.Context, q DBTX, assetID, gatewayID string, enabled bool, priority int) (domain.AssetGatewayBinding, error) {
	const query = `
		UPDATE asset_gateway_bindings
		SET enabled = $3, priority = $4, updated_at = NOW()
		WHERE asset_id = $1 AND gateway_id = $2
		RETURNING ` + assetGatewayBindingColumns
	value, err := scanAssetGatewayBinding(q.QueryRowContext(ctx, query, assetID, gatewayID, enabled, priority))
	if err != nil {
		return domain.AssetGatewayBinding{}, opError("update asset gateway binding", err)
	}
	return value, nil
}

func (r *GatewayRepository) GetAssetBindingForUpdate(ctx context.Context, q DBTX, assetID, gatewayID string) (domain.AssetGatewayBinding, error) {
	const query = `
		SELECT ` + assetGatewayBindingColumns + `
		FROM asset_gateway_bindings
		WHERE asset_id = $1 AND gateway_id = $2
		FOR UPDATE`
	value, err := scanAssetGatewayBinding(q.QueryRowContext(ctx, query, assetID, gatewayID))
	if err != nil {
		return domain.AssetGatewayBinding{}, opError("get asset gateway binding for update", err)
	}
	return value, nil
}

func (r *GatewayRepository) GetByID(ctx context.Context, q DBTX, id string) (domain.Gateway, error) {
	const query = `SELECT ` + gatewayColumns + ` FROM gateways WHERE id = $1`
	value, err := scanGateway(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Gateway{}, opError("get gateway by id", err)
	}
	return value, nil
}

func (r *GatewayRepository) GetByIDForUpdate(ctx context.Context, q DBTX, id string) (domain.Gateway, error) {
	const query = `SELECT ` + gatewayColumns + ` FROM gateways WHERE id = $1 FOR UPDATE`
	value, err := scanGateway(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Gateway{}, opError("get gateway by id for update", err)
	}
	return value, nil
}

func (r *GatewayRepository) ListActiveByRegion(ctx context.Context, q DBTX, regionID string) ([]domain.Gateway, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+gatewayColumns+` FROM gateways
		WHERE ($1 = '' OR region_id::text = $1) AND status = 'enabled'
		AND region_id IN (SELECT id FROM regions WHERE status = 'enabled') ORDER BY name, id`, regionID)
	if err != nil {
		return nil, opError("list region gateways", err)
	}
	values, err := CollectRows(rows, scanGateway)
	return values, opError("list region gateways", err)
}

func (r *GatewayRepository) ListEnabled(ctx context.Context, q DBTX) ([]domain.Gateway, error) {
	const query = `
		SELECT ` + gatewayColumns + `
		FROM gateways
		WHERE status = 'enabled'
		ORDER BY id`
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, opError("list enabled gateways", err)
	}
	values, err := CollectRows(rows, scanGateway)
	if err != nil {
		return nil, opError("list enabled gateways", err)
	}
	return values, nil
}

func (r *GatewayRepository) RecordHeartbeat(ctx context.Context, q DBTX, id string) (domain.Gateway, error) {
	const query = `
		UPDATE gateways
		SET last_heartbeat_at = NOW()
		WHERE id = $1
		RETURNING ` + gatewayColumns
	value, err := scanGateway(q.QueryRowContext(ctx, query, id))
	if err != nil {
		return domain.Gateway{}, opError("record gateway heartbeat", err)
	}
	return value, nil
}

func (r *GatewayRepository) RecordHealth(ctx context.Context, q DBTX, id string, maxSessions int) (domain.Gateway, error) {
	const query = `
		UPDATE gateways
		SET last_heartbeat_at = NOW(), max_sessions = $2, updated_at = NOW()
		WHERE id = $1
		RETURNING ` + gatewayColumns
	value, err := scanGateway(q.QueryRowContext(ctx, query, id, maxSessions))
	if err != nil {
		return domain.Gateway{}, opError("record gateway health", err)
	}
	return value, nil
}

func (r *GatewayRepository) ListHealthyByRegion(ctx context.Context, q DBTX, regionID string, heartbeatAfter time.Time) ([]domain.Gateway, error) {
	const query = `
		SELECT ` + gatewayColumns + `
		FROM gateways
		WHERE region_id = $1 AND status = 'enabled' AND last_heartbeat_at >= $2
		ORDER BY last_heartbeat_at DESC NULLS LAST, id`
	rows, err := q.QueryContext(ctx, query, regionID, heartbeatAfter)
	if err != nil {
		return nil, opError("list healthy gateways", err)
	}
	values, err := CollectRows(rows, scanGateway)
	if err != nil {
		return nil, opError("list healthy gateways", err)
	}
	return values, nil
}

// ListAvailableForAsset returns deterministic routing candidates. A nil
// heartbeatAfter is reserved for transports without readiness support; the
// production HTTP transport always supplies a freshness boundary.
func (r *GatewayRepository) ListAvailableForAsset(ctx context.Context, q DBTX, assetID, excludeSessionID string, heartbeatAfter *time.Time) ([]domain.Gateway, error) {
	const query = `
		SELECT ` + gatewayColumnsQualified + `
		FROM asset_gateway_bindings AS binding
		JOIN assets AS asset ON asset.id = binding.asset_id
		JOIN gateways AS g ON g.id = binding.gateway_id AND g.region_id = asset.region_id
		CROSS JOIN LATERAL (
			SELECT COUNT(*)::integer AS active_sessions
			FROM sessions AS active_session
			WHERE active_session.gateway_id = g.id
			  AND active_session.id <> $2
			  AND (
				active_session.status IN ('running', 'revoking', 'revoke_failed', 'manual_intervention')
				OR (active_session.status = 'provisioning' AND active_session.version > 0)
			  )
		) AS gateway_load
		WHERE binding.asset_id = $1
		  AND binding.enabled = TRUE
		  AND asset.status = 'enabled'
		  AND g.status = 'enabled'
		  AND ($3::timestamptz IS NULL OR g.last_heartbeat_at >= $3)
		  AND gateway_load.active_sessions < g.max_sessions
		ORDER BY binding.priority, gateway_load.active_sessions,
		         g.last_heartbeat_at DESC NULLS LAST, g.id`
	rows, err := q.QueryContext(ctx, query, assetID, excludeSessionID, heartbeatAfter)
	if err != nil {
		return nil, opError("list available asset gateways", err)
	}
	values, err := CollectRows(rows, scanGateway)
	if err != nil {
		return nil, opError("list available asset gateways", err)
	}
	return values, nil
}

func (r *GatewayRepository) LockCapacity(ctx context.Context, q DBTX, gatewayID string) error {
	const query = `
		SELECT pg_advisory_xact_lock(
			hashtextextended('gateway-capacity:' || $1::text, 0)
		) AS lock_result, TRUE AS locked`
	if err := scanAdvisoryLock(q.QueryRowContext(ctx, query, gatewayID)); err != nil {
		return opError("lock gateway capacity", err)
	}
	return nil
}
