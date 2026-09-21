-- +goose Up
ALTER TABLE assets
    ADD COLUMN external_source VARCHAR(64),
    ADD COLUMN external_id VARCHAR(256),
    ADD COLUMN sync_generation UUID,
    ADD COLUMN last_synced_at TIMESTAMPTZ,
    ADD CONSTRAINT assets_external_sync_identity_check CHECK (
        (external_source IS NULL AND external_id IS NULL AND sync_generation IS NULL AND last_synced_at IS NULL)
        OR
        (external_source IS NOT NULL AND external_id IS NOT NULL AND sync_generation IS NOT NULL AND last_synced_at IS NOT NULL)
    );

CREATE UNIQUE INDEX idx_assets_external_identity
    ON assets (external_source, external_id)
    WHERE external_source IS NOT NULL AND external_id IS NOT NULL;

CREATE INDEX idx_assets_external_sync_generation
    ON assets (external_source, sync_generation, id)
    WHERE external_source IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_assets_external_sync_generation;
DROP INDEX IF EXISTS idx_assets_external_identity;
ALTER TABLE assets
    DROP CONSTRAINT IF EXISTS assets_external_sync_identity_check,
    DROP COLUMN IF EXISTS last_synced_at,
    DROP COLUMN IF EXISTS sync_generation,
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS external_source;
