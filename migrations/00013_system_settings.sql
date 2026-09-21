-- +goose Up
CREATE TABLE system_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    config_json JSONB NOT NULL CHECK (jsonb_typeof(config_json) = 'object'),
    secrets_ciphertext TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID NOT NULL REFERENCES users(id)
);

-- +goose Down
DROP TABLE system_settings;
