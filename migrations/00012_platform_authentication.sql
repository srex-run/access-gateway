-- +goose Up
ALTER TABLE users ALTER COLUMN feishu_open_id DROP NOT NULL;
ALTER TABLE users ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 0;

CREATE TABLE local_accounts (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    username VARCHAR(64) NOT NULL UNIQUE CHECK (username = lower(username)),
    password_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE external_identities (
    provider VARCHAR(32) NOT NULL,
    issuer VARCHAR(1024) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, issuer, subject)
);
CREATE INDEX external_identities_user_idx ON external_identities(user_id);

CREATE TABLE login_attempts (
    bucket_hash CHAR(64) PRIMARY KEY,
    attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX login_attempts_expiry_idx ON login_attempts(expires_at);

-- +goose Down
-- Refuse a rollback that would discard accounts without a Feishu binding.
ALTER TABLE users ALTER COLUMN feishu_open_id SET NOT NULL;
DROP TABLE login_attempts;
DROP TABLE external_identities;
DROP TABLE local_accounts;
ALTER TABLE users DROP COLUMN auth_version;
