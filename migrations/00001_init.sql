-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY,
    feishu_open_id VARCHAR(128) NOT NULL UNIQUE,
    feishu_union_id VARCHAR(128),
    name VARCHAR(128) NOT NULL,
    email VARCHAR(256),
    department VARCHAR(256),
    status VARCHAR(32) NOT NULL CHECK (status IN ('active', 'inactive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE regions (
    id UUID PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('enabled', 'disabled', 'maintenance')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gateways (
    id UUID PRIMARY KEY,
    region_id UUID NOT NULL REFERENCES regions(id),
    name VARCHAR(128) NOT NULL,
    management_endpoint VARCHAR(512) NOT NULL,
    public_endpoint VARCHAR(512) NOT NULL,
    auth_secret_ref VARCHAR(512),
    status VARCHAR(32) NOT NULL CHECK (status IN ('enabled', 'disabled', 'maintenance')),
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE assets (
    id UUID PRIMARY KEY,
    region_id UUID NOT NULL REFERENCES regions(id),
    gateway_id UUID NOT NULL REFERENCES gateways(id),
    name VARCHAR(128) NOT NULL,
    asset_type VARCHAR(64) NOT NULL,
    target_ciphertext TEXT NOT NULL,
    risk_level VARCHAR(32) NOT NULL CHECK (risk_level IN ('normal', 'sensitive', 'critical')),
    max_ttl_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (max_ttl_seconds > 0),
    status VARCHAR(32) NOT NULL CHECK (status IN ('enabled', 'disabled', 'maintenance')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_ports (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id),
    port INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    protocol VARCHAR(32) NOT NULL DEFAULT 'tcp' CHECK (protocol = 'tcp'),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, port, protocol)
);

CREATE TABLE asset_approvers (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id),
    user_id UUID NOT NULL REFERENCES users(id),
    approval_level INTEGER NOT NULL DEFAULT 1 CHECK (approval_level > 0),
    role VARCHAR(64) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, user_id, approval_level)
);

CREATE TABLE access_requests (
    id UUID PRIMARY KEY,
    applicant_id UUID NOT NULL REFERENCES users(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    target_port INTEGER NOT NULL CHECK (target_port > 0 AND target_port <= 65535),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    ticket_no VARCHAR(128),
    emergency BOOLEAN NOT NULL DEFAULT FALSE,
    requested_start_at TIMESTAMPTZ,
    ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds > 0),
    status VARCHAR(32) NOT NULL CHECK (status IN ('pending_approval', 'approved', 'rejected', 'cancelled', 'approval_expired')),
    idempotency_key VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approvals (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES access_requests(id),
    approver_id UUID NOT NULL REFERENCES users(id),
    approval_level INTEGER NOT NULL CHECK (approval_level > 0),
    decision VARCHAR(32) CHECK (decision IN ('approved', 'rejected')),
    comment TEXT,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (request_id, approver_id, approval_level)
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE REFERENCES access_requests(id),
    gateway_id UUID NOT NULL REFERENCES gateways(id),
    token_hash VARCHAR(128),
    remote_process_id VARCHAR(128),
    status VARCHAR(32) NOT NULL CHECK (status IN ('provisioning', 'running', 'revoking', 'expired', 'closed', 'failed', 'revoke_failed', 'manual_intervention')),
    started_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    failure_reason TEXT,
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE session_events (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id),
    event_type VARCHAR(64) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_id UUID,
    subject_user_id UUID REFERENCES users(id),
    request_id UUID REFERENCES access_requests(id),
    session_id UUID REFERENCES sessions(id),
    region_id UUID REFERENCES regions(id),
    asset_id UUID REFERENCES assets(id),
    target_port INTEGER CHECK (target_port IS NULL OR (target_port > 0 AND target_port <= 65535)),
    source_ip VARCHAR(128),
    client_version VARCHAR(64),
    result VARCHAR(32),
    reason TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'processed', 'failed')),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX idx_gateways_region_status_heartbeat ON gateways (region_id, status, last_heartbeat_at DESC NULLS LAST);
CREATE INDEX idx_assets_region_status ON assets (region_id, status, name, id);
CREATE INDEX idx_asset_ports_asset_enabled ON asset_ports (asset_id, enabled, port, protocol);
CREATE INDEX idx_requests_applicant_status ON access_requests (applicant_id, status, created_at DESC);
CREATE INDEX idx_requests_asset_status ON access_requests (asset_id, status, created_at DESC);
CREATE INDEX idx_sessions_status_expires ON sessions (status, expires_at, id);
CREATE INDEX idx_session_events_session_created ON session_events (session_id, created_at, id);
CREATE INDEX idx_audit_events_created ON audit_events (created_at DESC, id DESC);
CREATE INDEX idx_audit_events_subject_created ON audit_events (subject_user_id, created_at DESC, id DESC);
CREATE INDEX idx_audit_events_asset_created ON audit_events (asset_id, created_at DESC, id DESC);
CREATE INDEX idx_outbox_pending_retry ON outbox_events (status, next_retry_at, created_at);

-- +goose Down
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS session_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS access_requests;
DROP TABLE IF EXISTS asset_approvers;
DROP TABLE IF EXISTS asset_ports;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS gateways;
DROP TABLE IF EXISTS regions;
DROP TABLE IF EXISTS users;
