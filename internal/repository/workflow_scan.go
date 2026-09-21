package repository

import (
	"encoding/json"

	"github.com/srex-run/access-gateway/internal/approvalflow"
)

const workflowColumns = `id, name, description, labels, asset_selector, timeout_seconds, steps, enabled, built_in, revision, created_at, updated_at`

func scanWorkflow(s RowScanner) (approvalflow.Definition, error) {
	var v approvalflow.Definition
	var labels, steps []byte
	err := s.Scan(
		&v.ID,             // id
		&v.Name,           // name
		&v.Description,    // description
		&labels,           // labels
		&v.AssetSelector,  // asset_selector
		&v.TimeoutSeconds, // timeout_seconds
		&steps,            // steps
		&v.Enabled,        // enabled
		&v.BuiltIn,        // built_in
		&v.Revision,       // revision
		&v.CreatedAt,      // created_at
		&v.UpdatedAt,      // updated_at
	)
	if err != nil {
		return v, opError("scan approval workflow", err)
	}
	if err := json.Unmarshal(labels, &v.Labels); err != nil {
		return v, opError("decode workflow labels", err)
	}
	err = json.Unmarshal(steps, &v.Steps)
	return v, opError("decode workflow steps", err)
}

const ownershipColumns = `id, name, asset_selector, user_selector, enabled, revision, created_at, updated_at`

func scanOwnership(s RowScanner) (approvalflow.Ownership, error) {
	var v approvalflow.Ownership
	err := s.Scan(
		&v.ID,            // id
		&v.Name,          // name
		&v.AssetSelector, // asset_selector
		&v.UserSelector,  // user_selector
		&v.Enabled,       // enabled
		&v.Revision,      // revision
		&v.CreatedAt,     // created_at
		&v.UpdatedAt,     // updated_at
	)
	return v, opError("scan ownership rule", err)
}

const assetPolicyColumns = `asset_id, labels, revision, updated_at, defaults_only`

func scanAssetPolicy(s RowScanner) (approvalflow.AssetPolicy, error) {
	var v approvalflow.AssetPolicy
	var labels []byte
	err := s.Scan(
		&v.AssetID,      // asset_id
		&labels,         // labels
		&v.Revision,     // revision
		&v.UpdatedAt,    // updated_at
		&v.DefaultsOnly, // defaults_only
	)
	if err != nil {
		return v, opError("scan asset labels", err)
	}
	err = json.Unmarshal(labels, &v.Labels)
	return v, opError("decode asset labels", err)
}
