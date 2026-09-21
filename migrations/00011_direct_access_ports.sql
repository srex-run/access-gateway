-- +goose Up
ALTER TABLE access_requests
    ADD COLUMN source_ip INET,
    ADD COLUMN target_account VARCHAR(128),
    ADD CONSTRAINT access_requests_target_account_check CHECK (
        target_account IS NULL OR length(trim(target_account)) BETWEEN 1 AND 128
    );

ALTER TABLE sessions
    ADD COLUMN listener_port INTEGER CHECK (listener_port IS NULL OR listener_port BETWEEN 1 AND 65535),
    ADD COLUMN external_port INTEGER CHECK (external_port IS NULL OR external_port BETWEEN 1 AND 65535),
    ADD COLUMN exposure_mode VARCHAR(32) CHECK (exposure_mode IS NULL OR exposure_mode IN ('direct', 'kubernetes_nodeport')),
    ADD COLUMN exposure_ref VARCHAR(253);

CREATE INDEX idx_sessions_exposure_ref
    ON sessions (exposure_mode, exposure_ref)
    WHERE exposure_ref IS NOT NULL;

CREATE TABLE gateway_connection_events (
    event_id UUID PRIMARY KEY,
    connection_id UUID NOT NULL,
    session_id UUID NOT NULL REFERENCES sessions(id),
    event_type VARCHAR(32) NOT NULL CHECK (event_type IN (
        'connect_attempt', 'source_rejected', 'capacity_rejected',
        'backend_connected', 'backend_failed', 'disconnected'
    )),
    source_ip INET,
    backend_source_ip INET,
    backend_source_port INTEGER CHECK (backend_source_port IS NULL OR backend_source_port BETWEEN 1 AND 65535),
    bytes_up BIGINT CHECK (bytes_up IS NULL OR bytes_up >= 0),
    bytes_down BIGINT CHECK (bytes_down IS NULL OR bytes_down >= 0),
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    result VARCHAR(32),
    reason VARCHAR(256),
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gateway_connection_events_session_time
    ON gateway_connection_events (session_id, occurred_at, event_id);
CREATE INDEX idx_gateway_connection_events_connection_time
    ON gateway_connection_events (connection_id, occurred_at, event_id);
CREATE INDEX idx_gateway_connection_events_backend_tuple
    ON gateway_connection_events (backend_source_ip, backend_source_port, occurred_at)
    WHERE backend_source_ip IS NOT NULL AND backend_source_port IS NOT NULL;

CREATE TABLE operation_audit_events (
    event_id VARCHAR(256) PRIMARY KEY,
    connection_id UUID,
    session_id UUID REFERENCES sessions(id),
    protocol VARCHAR(32) NOT NULL CHECK (protocol IN ('ssh', 'mysql', 'postgresql', 'mongodb')),
    asset_id UUID NOT NULL REFERENCES assets(id),
    target_port INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    actual_account VARCHAR(128) NOT NULL,
    operation_type VARCHAR(64) NOT NULL,
    statement_fingerprint VARCHAR(128),
    normalized_operation TEXT,
    object_name VARCHAR(512),
    result VARCHAR(32) NOT NULL,
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    backend_source_ip INET NOT NULL,
    backend_source_port INTEGER NOT NULL CHECK (backend_source_port BETWEEN 1 AND 65535),
    source_record_id VARCHAR(512) NOT NULL,
    correlation_status VARCHAR(32) NOT NULL CHECK (correlation_status IN ('matched', 'identity_mismatch', 'unmatched')),
    occurred_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_operation_audit_events_session_time
    ON operation_audit_events (session_id, occurred_at DESC, event_id)
    WHERE session_id IS NOT NULL;
CREATE INDEX idx_operation_audit_events_asset_time
    ON operation_audit_events (asset_id, occurred_at DESC, event_id);
CREATE INDEX idx_operation_audit_events_account_time
    ON operation_audit_events (actual_account, occurred_at DESC, event_id);
CREATE INDEX idx_operation_audit_events_unmatched
    ON operation_audit_events (occurred_at, event_id)
    WHERE correlation_status <> 'matched';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION prevent_access_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'access evidence is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER gateway_connection_events_append_only
BEFORE UPDATE OR DELETE ON gateway_connection_events
FOR EACH ROW EXECUTE FUNCTION prevent_access_evidence_mutation();

CREATE TRIGGER operation_audit_events_append_only
BEFORE UPDATE OR DELETE ON operation_audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_access_evidence_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS operation_audit_events_append_only ON operation_audit_events;
DROP TRIGGER IF EXISTS gateway_connection_events_append_only ON gateway_connection_events;
DROP FUNCTION IF EXISTS prevent_access_evidence_mutation();
DROP TABLE IF EXISTS operation_audit_events;
DROP TABLE IF EXISTS gateway_connection_events;
DROP INDEX IF EXISTS idx_sessions_exposure_ref;
ALTER TABLE sessions
    DROP COLUMN IF EXISTS exposure_ref,
    DROP COLUMN IF EXISTS exposure_mode,
    DROP COLUMN IF EXISTS external_port,
    DROP COLUMN IF EXISTS listener_port;
ALTER TABLE access_requests
    DROP CONSTRAINT IF EXISTS access_requests_target_account_check,
    DROP COLUMN IF EXISTS target_account,
    DROP COLUMN IF EXISTS source_ip;
