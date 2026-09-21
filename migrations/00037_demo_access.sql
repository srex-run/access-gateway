-- +goose Up
ALTER TABLE access_requests DROP CONSTRAINT access_requests_approval_mode_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_approval_mode_check
    CHECK (approval_mode IN ('required', 'admin_test', 'demo'));
ALTER TABLE access_requests ADD CONSTRAINT access_requests_demo_check
    CHECK (approval_mode <> 'demo' OR (
        ttl_seconds = 300 AND requested_start_at IS NULL
        AND status IN ('approved', 'cancelled')
    ));

-- +goose Down
-- Refuse rollback while demo requests exist rather than relabel their history.
ALTER TABLE access_requests DROP CONSTRAINT access_requests_demo_check;
ALTER TABLE access_requests DROP CONSTRAINT access_requests_approval_mode_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_approval_mode_check
    CHECK (approval_mode IN ('required', 'admin_test'));
