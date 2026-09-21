-- +goose Up
CREATE TABLE asset_audit_configs (
    asset_id UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    config_ciphertext TEXT NOT NULL CHECK (config_ciphertext <> ''),
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID NOT NULL REFERENCES users(id)
);

-- +goose Down
DROP TABLE asset_audit_configs;
