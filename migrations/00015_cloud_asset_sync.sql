-- +goose Up
CREATE TABLE cloud_accounts (
    id UUID PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE,
    provider VARCHAR(32) NOT NULL CHECK (provider IN ('aliyun', 'aws', 'huaweicloud')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    credentials_ciphertext TEXT NOT NULL CHECK (credentials_ciphertext <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE cloud_sync_jobs (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES cloud_accounts(id),
    account_revision BIGINT NOT NULL,
    actor_id UUID NOT NULL REFERENCES users(id),
    region_id UUID NOT NULL REFERENCES regions(id),
    input_json JSONB NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('queued', 'running', 'success', 'failed')),
    result_json JSONB NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CHECK ((status = 'running') = (lease_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE UNIQUE INDEX cloud_sync_one_active_account ON cloud_sync_jobs (account_id)
    WHERE status IN ('queued', 'running');
CREATE INDEX cloud_sync_queue ON cloud_sync_jobs (created_at, id)
    WHERE status IN ('queued', 'running');
CREATE INDEX cloud_sync_region_history ON cloud_sync_jobs (region_id, created_at DESC, id);

-- +goose Down
DROP TABLE cloud_sync_jobs;
DROP TABLE cloud_accounts;
