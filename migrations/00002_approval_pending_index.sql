-- +goose Up
CREATE INDEX idx_approvals_request_level_decision
    ON approvals (request_id, approval_level, decision);

CREATE INDEX idx_approvals_approver_pending
    ON approvals (approver_id, created_at, id)
    WHERE decision IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_approvals_approver_pending;
DROP INDEX IF EXISTS idx_approvals_request_level_decision;
