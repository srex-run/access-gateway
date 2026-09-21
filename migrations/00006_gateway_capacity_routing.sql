-- +goose Up
ALTER TABLE gateways
    ADD COLUMN max_sessions INTEGER NOT NULL DEFAULT 100
    CHECK (max_sessions > 0 AND max_sessions <= 100000);

CREATE TABLE asset_gateway_bindings (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0 AND priority <= 100000),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, gateway_id)
);

INSERT INTO asset_gateway_bindings (asset_id, gateway_id, priority)
SELECT id, gateway_id, 0
FROM assets;

CREATE INDEX idx_asset_gateway_bindings_gateway
    ON asset_gateway_bindings (gateway_id, asset_id)
    WHERE enabled = TRUE;

CREATE INDEX idx_sessions_gateway_capacity
    ON sessions (gateway_id, status, version, id)
    WHERE status IN ('provisioning', 'running', 'revoking', 'revoke_failed', 'manual_intervention');

-- +goose Down
DROP INDEX IF EXISTS idx_sessions_gateway_capacity;
DROP INDEX IF EXISTS idx_asset_gateway_bindings_gateway;
DROP TABLE IF EXISTS asset_gateway_bindings;
ALTER TABLE gateways DROP COLUMN IF EXISTS max_sessions;
