package authz

import (
	"fmt"

	"github.com/mikespook/gorbac"
)

type Role string

const (
	RoleUser          Role = "user"
	RoleAdmin         Role = "admin"
	RoleAuditor       Role = "auditor"
	RoleCatalogAdmin  Role = "catalog_admin"
	RoleSecurityAdmin Role = "security_admin"
)

type Permission string

const (
	PermissionDirectoryRead   Permission = "directory:read"
	PermissionRequestManage   Permission = "request:manage"
	PermissionApprovalManage  Permission = "approval:manage"
	PermissionSessionManage   Permission = "session:manage"
	PermissionCatalogManage   Permission = "catalog:manage"
	PermissionAuditRead       Permission = "audit:read"
	PermissionSessionOverride Permission = "session:override"
	PermissionRoleManage      Permission = "role:manage"
)

var knownPermissions = []Permission{
	PermissionDirectoryRead,
	PermissionRequestManage,
	PermissionApprovalManage,
	PermissionSessionManage,
	PermissionCatalogManage,
	PermissionAuditRead,
	PermissionSessionOverride,
	PermissionRoleManage,
	PermissionUserRead,
	PermissionUserManage,
	PermissionWorkflowManage,
}

type Policy struct {
	rbac        *gorbac.RBAC
	permissions map[Permission]gorbac.Permission
}

func NewPolicy() (*Policy, error) {
	engine := gorbac.New()
	permissions := make(map[Permission]gorbac.Permission, len(knownPermissions))
	for _, permission := range knownPermissions {
		permissions[permission] = gorbac.NewStdPermission(string(permission))
	}
	user := gorbac.NewStdRole(string(RoleUser))
	for _, permission := range []Permission{
		PermissionDirectoryRead,
		PermissionRequestManage,
		PermissionSessionManage,
	} {
		if err := user.Assign(permissions[permission]); err != nil {
			return nil, fmt.Errorf("assign user permission %s: %w", permission, err)
		}
	}
	admin := gorbac.NewStdRole(string(RoleAdmin))
	for _, permission := range knownPermissions {
		if err := admin.Assign(permissions[permission]); err != nil {
			return nil, fmt.Errorf("assign admin permission %s: %w", permission, err)
		}
	}
	if err := engine.Add(user); err != nil {
		return nil, fmt.Errorf("add user role: %w", err)
	}
	if err := engine.Add(admin); err != nil {
		return nil, fmt.Errorf("add admin role: %w", err)
	}
	for role, assigned := range map[Role][]Permission{
		RoleAuditor:       {PermissionAuditRead},
		RoleCatalogAdmin:  {PermissionCatalogManage, PermissionUserRead},
		RoleSecurityAdmin: {PermissionAuditRead},
		RoleSRE:           {PermissionCatalogManage, PermissionAuditRead, PermissionUserRead, PermissionWorkflowManage},
	} {
		value := gorbac.NewStdRole(string(role))
		for _, permission := range append([]Permission{PermissionDirectoryRead, PermissionRequestManage, PermissionApprovalManage, PermissionSessionManage}, assigned...) {
			if err := value.Assign(permissions[permission]); err != nil {
				return nil, fmt.Errorf("assign %s permission %s: %w", role, permission, err)
			}
		}
		if err := engine.Add(value); err != nil {
			return nil, fmt.Errorf("add %s role: %w", role, err)
		}
	}
	return &Policy{rbac: engine, permissions: permissions}, nil
}

func (p *Policy) Allowed(role Role, permission Permission) bool {
	if p == nil || p.rbac == nil {
		return false
	}
	value, ok := p.permissions[permission]
	return ok && p.rbac.IsGranted(string(role), value, nil)
}

// AllowedPermissions evaluates a persisted role without falling back to its
// original built-in defaults. Each evaluation owns its gorbac role instance.
func (p *Policy) AllowedPermissions(assigned []Permission, permission Permission) bool {
	if p == nil {
		return false
	}
	target, ok := p.permissions[permission]
	if !ok {
		return false
	}
	role := gorbac.NewStdRole("persisted")
	for _, key := range assigned {
		value, known := p.permissions[key]
		if known {
			if err := role.Assign(value); err != nil {
				return false
			}
		}
	}
	return role.Permit(target)
}
