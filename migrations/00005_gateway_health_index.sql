-- +goose Up
CREATE INDEX idx_gateways_enabled_id
    ON gateways (id)
    WHERE status = 'enabled';

-- +goose Down
DROP INDEX IF EXISTS idx_gateways_enabled_id;
