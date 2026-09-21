-- +goose Up
ALTER TABLE assets ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE assets ADD CONSTRAINT assets_deleted_disabled CHECK (deleted_at IS NULL OR status = 'disabled');

-- +goose Down
ALTER TABLE assets DROP CONSTRAINT assets_deleted_disabled;
ALTER TABLE assets DROP COLUMN deleted_at;
