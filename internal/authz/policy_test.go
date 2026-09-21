package authz

import "testing"

func TestPolicySeparatesUserAndAdministratorPermissions(t *testing.T) {
	policy, err := NewPolicy()
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	for _, permission := range []Permission{
		PermissionDirectoryRead,
		PermissionRequestManage,
		PermissionSessionManage,
	} {
		if !policy.Allowed(RoleUser, permission) || !policy.Allowed(RoleAdmin, permission) {
			t.Errorf("inherited permission %q was not granted", permission)
		}
	}
	for _, permission := range []Permission{
		PermissionApprovalManage,
		PermissionCatalogManage,
		PermissionAuditRead,
		PermissionSessionOverride,
		PermissionRoleManage,
	} {
		if policy.Allowed(RoleUser, permission) || !policy.Allowed(RoleAdmin, permission) {
			t.Errorf("administrator permission %q has incorrect grants", permission)
		}
	}
	if policy.Allowed(RoleAdmin, Permission("unknown:permission")) {
		t.Fatal("unknown permission was granted")
	}
	if !policy.Allowed(RoleAuditor, PermissionAuditRead) || policy.Allowed(RoleAuditor, PermissionCatalogManage) {
		t.Fatal("auditor permissions are not isolated")
	}
	if !policy.Allowed(RoleCatalogAdmin, PermissionCatalogManage) || policy.Allowed(RoleCatalogAdmin, PermissionAuditRead) {
		t.Fatal("catalog administrator permissions are not isolated")
	}
	if !policy.Allowed(RoleSecurityAdmin, PermissionAuditRead) || policy.Allowed(RoleSecurityAdmin, PermissionRoleManage) {
		t.Fatal("security administrator permissions are not isolated")
	}
	for _, role := range []Role{RoleUser, RoleAuditor, RoleCatalogAdmin, RoleSecurityAdmin, RoleSRE} {
		if policy.Allowed(role, PermissionSessionOverride) {
			t.Errorf("non-platform administrator %s can force-close sessions", role)
		}
	}
}
