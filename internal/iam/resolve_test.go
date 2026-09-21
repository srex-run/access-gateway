package iam

import (
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/label"
	"testing"
)

func TestExplicitBindingsControlMembership(t *testing.T) {
	roles := []Role{{Name: "user", Enabled: true}, {Name: "sre", Enabled: true, Labels: label.Labels{"duty": "ops"}}, {Name: "admin", Enabled: true, Labels: label.Labels{"duty": "admin"}}, {Name: "disabled", Enabled: false, Labels: label.Labels{"duty": "ops"}}}
	subject := label.Labels{"team": "ops", "admin": "true"}
	if got := Resolve(subject, roles, nil, nil); len(got) != 1 || got[0].Name != "user" {
		t.Fatalf("labels alone granted roles: %+v", got)
	}
	bindings := []Binding{{Enabled: true, UserSelector: "team=ops", RoleSelector: "duty=ops"}}
	got := Resolve(subject, roles, bindings, nil)
	if len(got) != 2 || got[1].Name != "sre" {
		t.Fatalf("explicit binding: %+v", got)
	}
	bindings[0].Enabled = false
	if got := Resolve(subject, roles, bindings, nil); len(got) != 1 {
		t.Fatalf("disabled binding granted role: %+v", got)
	}
	if got := Resolve(label.Labels{}, roles, []Binding{{Enabled: true, UserSelector: "", RoleSelector: ""}}, nil); len(got) != 1 {
		t.Fatal("empty selectors granted a role")
	}
	if got := Resolve(nil, roles, nil, []string{"admin", "disabled"}); len(got) != 2 || got[1].Name != "admin" {
		t.Fatalf("compatibility binding: %+v", got)
	}
}

func TestRoleValidationRejectsWildcardAndSystemLabels(t *testing.T) {
	r := Role{Name: "ops-reader", Permissions: []authz.Permission{authz.PermissionAuditRead}, Labels: label.Labels{"duty": "ops"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Permissions = []authz.Permission{"*"}
	if r.Validate() == nil {
		t.Fatal("wildcard permission accepted")
	}
	r.Permissions = []authz.Permission{authz.PermissionAuditRead}
	r.Labels = label.Labels{"access-gateway.io/approval": "platform"}
	if r.Validate() == nil {
		t.Fatal("system-owned role label accepted")
	}
}

func TestRoleSelectorRejectsDisabledRole(t *testing.T) {
	roles := []Role{{Name: "sre", Enabled: false, Labels: label.Labels{"duty": "ops"}}}
	if MatchesRole("duty=ops", roles) {
		t.Fatal("disabled role was eligible for a binding or approval step")
	}
	roles[0].Enabled = true
	if !MatchesRole("duty=ops", roles) {
		t.Fatal("enabled role did not match")
	}
	if MatchesRole("", roles) || MatchesRole("duty in (", roles) {
		t.Fatal("invalid selector matched a role")
	}
}
