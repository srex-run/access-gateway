-- +goose Up
CREATE TABLE role_assignments (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    role VARCHAR(64) NOT NULL CHECK (role IN ('admin', 'auditor', 'catalog_admin', 'security_admin')),
    granted_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_role_assignments_user_role_active
    ON role_assignments (user_id, role)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_role_assignments_user_active
    ON role_assignments (user_id, created_at, id)
    WHERE revoked_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_role_assignments_user_active;
DROP INDEX IF EXISTS idx_role_assignments_user_role_active;
DROP TABLE IF EXISTS role_assignments;
