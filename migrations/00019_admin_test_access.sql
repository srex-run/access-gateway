-- +goose Up
ALTER TABLE access_requests ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'required';
ALTER TABLE access_requests ADD CONSTRAINT access_requests_approval_mode_check
    CHECK (approval_mode IN ('required', 'admin_test'));
ALTER TABLE access_requests ADD CONSTRAINT access_requests_admin_test_check
    CHECK (approval_mode <> 'admin_test' OR (
        ttl_seconds BETWEEN 1 AND 600 AND requested_start_at IS NULL AND emergency = FALSE
        AND status IN ('approved', 'cancelled')
    ));

-- +goose Down
ALTER TABLE access_requests DROP CONSTRAINT access_requests_admin_test_check;
ALTER TABLE access_requests DROP CONSTRAINT access_requests_approval_mode_check;
ALTER TABLE access_requests DROP COLUMN approval_mode;
