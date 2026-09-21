-- +goose Up
-- Assets select approval workflows explicitly. A workflow no longer needs a
-- label selector, but historical selectors must remain available unchanged.
ALTER TABLE approval_workflows DROP CONSTRAINT approval_workflows_asset_selector_check;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'optional workflow selectors require a forward migration; explicitly assigned workflows must be retained';
END $$;
-- +goose StatementEnd
