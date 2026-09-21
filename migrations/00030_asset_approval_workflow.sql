-- +goose Up
ALTER TABLE assets ADD COLUMN approval_workflow_id UUID REFERENCES approval_workflows(id);
CREATE INDEX idx_assets_approval_workflow ON assets (approval_workflow_id) WHERE approval_workflow_id IS NOT NULL;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'asset workflow assignments require a forward migration; approval routing must be retained';
END $$;
-- +goose StatementEnd
