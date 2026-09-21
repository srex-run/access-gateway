-- +goose Up
ALTER TABLE sessions ADD COLUMN audit_policy JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sessions DROP CONSTRAINT sessions_connection_mode_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_connection_mode_check
    CHECK (connection_mode IN ('direct', 'tunnel', 'native', 'audit'));
ALTER TABLE sessions ADD CONSTRAINT sessions_audit_policy_check CHECK (
    connection_mode <> 'audit' OR (
        COALESCE(audit_policy->>'profile', '') <> '' AND
        COALESCE(audit_policy->>'revision', '') ~ '^[0-9a-f]{64}$' AND
        COALESCE(audit_policy->>'protocol', '') IN ('ssh','mysql','postgresql','redis','mongodb','http') AND
        tunnel_client_public_key = '' AND tunnel_server_certificate = ''
    )
);
CREATE UNIQUE INDEX operation_proxy_phase_unique ON operation_audit_events
    (session_id, (metadata->>'operation_id'), (metadata->>'phase'))
    WHERE metadata->>'source' = 'session_proxy';

-- +goose Down
-- Preserve immutable evidence and the policies that explain existing sessions.
SELECT 1;
