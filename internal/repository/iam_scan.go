package repository

import (
	"encoding/json"

	"github.com/srex-run/access-gateway/internal/iam"
)

const iamRoleColumns = `name, description, permissions, labels, enabled, built_in, revision, created_at, updated_at`

func scanIAMRole(s RowScanner) (iam.Role, error) {
	var value iam.Role
	var permissions, labels []byte
	err := s.Scan(
		&value.Name,        // name
		&value.Description, // description
		&permissions,       // permissions
		&labels,            // labels
		&value.Enabled,     // enabled
		&value.BuiltIn,     // built_in
		&value.Revision,    // revision
		&value.CreatedAt,   // created_at
		&value.UpdatedAt,   // updated_at
	)
	if err != nil {
		return value, opError("scan IAM role", err)
	}
	if err := json.Unmarshal(permissions, &value.Permissions); err != nil {
		return value, opError("decode IAM permissions", err)
	}
	err = json.Unmarshal(labels, &value.Labels)
	return value, opError("decode IAM role labels", err)
}

const iamBindingColumns = `id, name, user_selector, role_selector, enabled, revision, created_at, updated_at`

func scanIAMBinding(s RowScanner) (iam.Binding, error) {
	var v iam.Binding
	err := s.Scan(
		&v.ID,           // id
		&v.Name,         // name
		&v.UserSelector, // user_selector
		&v.RoleSelector, // role_selector
		&v.Enabled,      // enabled
		&v.Revision,     // revision
		&v.CreatedAt,    // created_at
		&v.UpdatedAt,    // updated_at
	)
	return v, opError("scan IAM binding", err)
}
