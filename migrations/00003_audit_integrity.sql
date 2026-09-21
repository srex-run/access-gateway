-- +goose Up

-- Audit records are an evidence trail.  Application code only inserts them;
-- this trigger also protects the invariant if an account is accidentally
-- granted broad table privileges later.
CREATE OR REPLACE FUNCTION prevent_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events are append-only';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_event_mutation();

CREATE INDEX idx_requests_status_created
    ON access_requests (status, created_at, id);

-- +goose Down
DROP INDEX IF EXISTS idx_requests_status_created;
DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
DROP FUNCTION IF EXISTS prevent_audit_event_mutation();
