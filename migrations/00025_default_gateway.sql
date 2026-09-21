-- +goose Up
ALTER TABLE gateways ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX idx_gateways_default_region ON gateways (region_id) WHERE is_default;

-- +goose Down
DROP INDEX idx_gateways_default_region;
ALTER TABLE gateways DROP COLUMN is_default;
