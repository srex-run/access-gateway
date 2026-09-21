-- +goose Up
ALTER TABLE operation_audit_events
    DROP CONSTRAINT operation_audit_events_protocol_check;
ALTER TABLE operation_audit_events
    ADD CONSTRAINT operation_audit_events_protocol_check
    CHECK (protocol IN ('ssh', 'mysql', 'redis', 'mongodb', 'postgresql', 'http'));

-- +goose Down
-- Preserve the expanded audit vocabulary: historical evidence is append-only
-- and cannot be deleted to reinstate a narrower constraint.
SELECT 1;
