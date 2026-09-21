package service

import (
	"maps"
	"slices"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/iam"
	"github.com/srex-run/access-gateway/internal/label"
)

func TestApprovalPermissionRequiresExplicitRole(t *testing.T) {
	policy, err := authz.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	svc := &AccessService{authorizer: policy}
	user := iam.Role{Name: "user", BuiltIn: true, Enabled: true, Permissions: []authz.Permission{authz.PermissionDirectoryRead, authz.PermissionRequestManage, authz.PermissionSessionManage}}
	approver := iam.Role{Name: "approver", Enabled: true, Labels: label.Labels{"duty": "approver"}, Permissions: []authz.Permission{authz.PermissionApprovalManage}}
	for _, test := range []struct {
		name    string
		roles   []iam.Role
		binding []iam.Binding
		direct  []string
		allowed bool
	}{
		{name: "ordinary user", roles: []iam.Role{user}},
		{name: "owner labels alone", roles: []iam.Role{user, approver}},
		{name: "direct approval role", roles: []iam.Role{user, approver}, direct: []string{approver.Name}, allowed: true},
		{name: "explicit label binding", roles: []iam.Role{user, approver}, binding: []iam.Binding{{Enabled: true, UserSelector: "duty=owner", RoleSelector: "duty=approver"}}, allowed: true},
		{name: "disabled binding", roles: []iam.Role{user, approver}, binding: []iam.Binding{{UserSelector: "duty=owner", RoleSelector: "duty=approver"}}},
		{name: "platform administrator", roles: []iam.Role{user, {Name: "admin", BuiltIn: true, Enabled: true, Permissions: []authz.Permission{authz.PermissionApprovalManage}}}, direct: []string{"admin"}, allowed: true},
		{name: "legacy SRE", roles: []iam.Role{user, {Name: "sre", Enabled: true, Permissions: []authz.Permission{authz.PermissionApprovalManage}}}, direct: []string{"sre"}, allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			roles := iam.NewResolver(test.roles, test.binding).Resolve(label.Labels{"duty": "owner"}, test.direct)
			if got := svc.allowedRoles(roles, authz.PermissionApprovalManage); got != test.allowed {
				t.Fatalf("approval authorization=%v, want %v", got, test.allowed)
			}
			permissions := svc.rolePermissions(roles)
			if got := slices.Contains(permissions, authz.PermissionApprovalManage); got != test.allowed {
				t.Fatalf("identity exposes approval permission=%v, want %v", got, test.allowed)
			}
			for _, permission := range []authz.Permission{authz.PermissionDirectoryRead, authz.PermissionRequestManage, authz.PermissionSessionManage} {
				if !slices.Contains(permissions, permission) {
					t.Fatalf("ordinary user lost %s", permission)
				}
			}
		})
	}
}

func TestForceClosePermissionRequiresExplicitEnabledRole(t *testing.T) {
	policy, err := authz.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	svc := &AccessService{authorizer: policy}
	admin := iam.Role{Name: string(authz.RoleAdmin), BuiltIn: true, Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride}}
	custom := iam.Role{Name: "custom-override", Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride, authz.PermissionAuditRead}}
	tests := []struct {
		name    string
		roles   []iam.Role
		allowed bool
	}{
		{name: "no roles"},
		{name: "platform admin", roles: []iam.Role{admin}, allowed: true},
		{name: "custom override", roles: []iam.Role{custom}, allowed: true},
		{name: "custom force-close only", roles: []iam.Role{{Name: "recovery", Enabled: true, Permissions: admin.Permissions}}, allowed: true},
		{name: "disabled custom role", roles: []iam.Role{{Name: custom.Name, Permissions: custom.Permissions}}},
		{name: "removed force-close", roles: []iam.Role{{Name: custom.Name, Enabled: true, Permissions: []authz.Permission{authz.PermissionAuditRead}}}},
		{name: "admin name alone", roles: []iam.Role{{Name: "admin", BuiltIn: true, Enabled: true}}},
		{name: "mixed with platform admin", roles: []iam.Role{custom, admin}, allowed: true},
	}
	for _, role := range []authz.Role{authz.RoleUser, authz.RoleAuditor, authz.RoleCatalogAdmin, authz.RoleSecurityAdmin, authz.RoleSRE} {
		tests = append(tests, struct {
			name    string
			roles   []iam.Role
			allowed bool
		}{name: string(role), roles: []iam.Role{{Name: string(role), BuiltIn: role == authz.RoleUser, Enabled: true, Permissions: []authz.Permission{authz.PermissionAuditRead, authz.PermissionSessionManage}}}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := svc.allowedRoles(test.roles, authz.PermissionSessionOverride); got != test.allowed {
				t.Fatalf("force-close authorization = %v, want %v", got, test.allowed)
			}
			if got := slices.Contains(svc.rolePermissions(test.roles), authz.PermissionSessionOverride); got != test.allowed {
				t.Fatalf("effective permissions expose force-close = %v, want %v", got, test.allowed)
			}
		})
	}
	if !svc.allowedRoles([]iam.Role{custom}, authz.PermissionAuditRead) {
		t.Fatal("custom role lost its unrelated audit permission")
	}
}

func TestBuiltinRoleUsesSavedPermissions(t *testing.T) {
	policy, err := authz.NewPolicy()
	if err != nil {
		t.Fatal(err)
	}
	svc := &AccessService{authorizer: policy}
	for _, name := range []string{"user", "admin", "sre"} {
		t.Run(name, func(t *testing.T) {
			role := iam.Role{Name: name, BuiltIn: name != "sre", Enabled: true, Permissions: []authz.Permission{authz.PermissionDirectoryRead}}
			if svc.allowedRoles([]iam.Role{role}, authz.PermissionApprovalManage) {
				t.Fatal("original role defaults restored a removed permission")
			}
			role.Permissions = []authz.Permission{authz.PermissionApprovalManage}
			if !svc.allowedRoles([]iam.Role{role}, authz.PermissionApprovalManage) || svc.allowedRoles([]iam.Role{role}, authz.PermissionDirectoryRead) {
				t.Fatal("saved permissions were not reflected in authorization")
			}
			role.Enabled = false
			if svc.allowedRoles([]iam.Role{role}, authz.PermissionApprovalManage) {
				t.Fatal("disabled role granted a permission")
			}
		})
	}
}

func TestRoleEditsPreserveCoreAccessAndManagedLabels(t *testing.T) {
	admin := iam.Role{Name: "admin", BuiltIn: true, Enabled: true, Revision: 1, Permissions: []authz.Permission{authz.PermissionRoleManage, authz.PermissionSessionOverride}, Labels: label.Labels{"access-gateway.io/role": "admin", "access-gateway.io/approval": "platform"}}
	for _, test := range []struct {
		name    string
		edit    func(*iam.Role)
		allowed bool
	}{
		{name: "description", edit: func(role *iam.Role) { role.Description = "平台维护人员" }, allowed: true},
		{name: "custom label", edit: func(role *iam.Role) { role.Labels["team"] = "ops" }, allowed: true},
		{name: "optional permission", edit: func(role *iam.Role) { role.Permissions = []authz.Permission{authz.PermissionRoleManage} }, allowed: true},
		{name: "disable administrator", edit: func(role *iam.Role) { role.Enabled = false }},
		{name: "remove management", edit: func(role *iam.Role) { role.Permissions = []authz.Permission{authz.PermissionAuditRead} }},
		{name: "change managed label", edit: func(role *iam.Role) { role.Labels["access-gateway.io/role"] = "user" }},
		{name: "delete managed label", edit: func(role *iam.Role) { delete(role.Labels, "access-gateway.io/approval") }},
		{name: "inject empty managed label", edit: func(role *iam.Role) { role.Labels["access-gateway.io/new"] = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := admin
			input.Labels = maps.Clone(admin.Labels)
			test.edit(&input)
			if err := validateRoleChange(input, &admin); (err == nil) != test.allowed {
				t.Fatalf("allowed=%v, error=%v", test.allowed, err)
			}
		})
	}
	user := iam.Role{Name: "user", BuiltIn: true, Enabled: true, Permissions: []authz.Permission{authz.PermissionDirectoryRead}, Labels: label.Labels{"access-gateway.io/role": "user"}}
	input := user
	input.Permissions = []authz.Permission{authz.PermissionRequestManage}
	if err := validateRoleChange(input, &user); err != nil {
		t.Fatalf("edit baseline permissions: %v", err)
	}
	input.Enabled = false
	if err := validateRoleChange(input, &user); err == nil {
		t.Fatal("baseline role could be disabled")
	}
	auditor := iam.Role{Name: "auditor", BuiltIn: true, Enabled: true, Permissions: []authz.Permission{authz.PermissionAuditRead}, Labels: label.Labels{"access-gateway.io/role": "auditor"}}
	input = auditor
	input.Enabled = false
	if err := validateRoleChange(input, &auditor); err != nil {
		t.Fatalf("auditor cannot retain its disabled state after becoming built-in: %v", err)
	}
	custom := iam.Role{Name: "custom", Enabled: true, Permissions: []authz.Permission{authz.PermissionSessionOverride}}
	if err := validateRoleChange(custom, nil); err != nil {
		t.Fatalf("custom role cannot acquire force-close: %v", err)
	}
	if err := validateRoleChange(custom, &custom); err != nil {
		t.Fatalf("custom role cannot retain force-close when edited: %v", err)
	}
	custom.Permissions = []authz.Permission{authz.PermissionAuditRead}
	custom.BuiltIn = true
	if err := validateRoleChange(custom, nil); err == nil {
		t.Fatal("request could create a built-in role")
	}
	legacy := iam.Role{Name: "sre", Enabled: true, Permissions: []authz.Permission{authz.PermissionAuditRead}, Labels: label.Labels{"access-gateway.io/role": "sre"}}
	if err := validateRoleChange(legacy, &legacy); err != nil {
		t.Fatalf("converted legacy role cannot preserve its labels: %v", err)
	}
}
