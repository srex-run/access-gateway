package iam

import "github.com/srex-run/access-gateway/internal/label"

type GrantSource struct {
	Kind         string `json:"kind"`
	ID           string `json:"id,omitempty"`
	Name         string `json:"name"`
	Revision     int64  `json:"revision,omitempty"`
	UserSelector string `json:"user_selector,omitempty"`
	RoleSelector string `json:"role_selector,omitempty"`
}

type DirectGrant struct {
	Role   string
	Source GrantSource
}

type RoleGrant struct {
	Role    Role          `json:"role"`
	Sources []GrantSource `json:"sources"`
}

type compiledBinding struct {
	subject label.Selector
	roles   []int
	source  GrantSource
}

// Resolver compiles selectors once for a consistent directory snapshot. The
// same membership traversal serves authorization and permission explanations.
type Resolver struct {
	roles    []Role
	byName   map[string]int
	bindings []compiledBinding
}

func NewResolver(roles []Role, bindings []Binding) *Resolver {
	r := &Resolver{roles: []Role{}, byName: map[string]int{}}
	for _, role := range roles {
		if role.Enabled {
			r.byName[role.Name] = len(r.roles)
			r.roles = append(r.roles, role)
		}
	}
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		subject, err := label.BindingSelector(binding.UserSelector)
		if err != nil {
			continue
		}
		selector, err := label.BindingSelector(binding.RoleSelector)
		if err != nil {
			continue
		}
		compiled := compiledBinding{subject: subject, source: GrantSource{Kind: "binding", ID: binding.ID, Name: binding.Name, Revision: binding.Revision, UserSelector: binding.UserSelector, RoleSelector: binding.RoleSelector}}
		for index, role := range r.roles {
			if selector.Matches(role.Labels) {
				compiled.roles = append(compiled.roles, index)
			}
		}
		if len(compiled.roles) > 0 {
			r.bindings = append(r.bindings, compiled)
		}
	}
	return r
}

func (r *Resolver) visit(subject label.Labels, direct []DirectGrant, grant func(int, GrantSource)) {
	if index, ok := r.byName["user"]; ok {
		grant(index, GrantSource{Kind: "baseline", Name: "默认用户角色"})
	}
	for _, assignment := range direct {
		if index, ok := r.byName[assignment.Role]; ok {
			grant(index, assignment.Source)
		}
	}
	for _, binding := range r.bindings {
		if binding.subject.Matches(subject) {
			for _, index := range binding.roles {
				grant(index, binding.source)
			}
		}
	}
}

func (r *Resolver) Resolve(subject label.Labels, explicit []string) []Role {
	direct := make([]DirectGrant, 0, len(explicit))
	for _, name := range explicit {
		direct = append(direct, DirectGrant{Role: name})
	}
	granted := make([]bool, len(r.roles))
	r.visit(subject, direct, func(index int, _ GrantSource) { granted[index] = true })
	result := []Role{}
	for index, role := range r.roles {
		if granted[index] {
			result = append(result, role)
		}
	}
	return result
}

func (r *Resolver) Explain(subject label.Labels, direct []DirectGrant) []RoleGrant {
	sources := make([][]GrantSource, len(r.roles))
	r.visit(subject, direct, func(index int, source GrantSource) { sources[index] = append(sources[index], source) })
	result := []RoleGrant{}
	for index, role := range r.roles {
		if len(sources[index]) > 0 {
			result = append(result, RoleGrant{Role: role, Sources: sources[index]})
		}
	}
	return result
}

// Resolve unions explicit compatibility grants and auditable selector bindings.
// Roles are flat; a disabled role cannot participate in either path.
func Resolve(subject label.Labels, roles []Role, bindings []Binding, explicit []string) []Role {
	return NewResolver(roles, bindings).Resolve(subject, explicit)
}

func MatchesRole(selector string, roles []Role) bool {
	parsed, err := label.BindingSelector(selector)
	if err != nil {
		return false
	}
	for _, role := range roles {
		if role.Enabled && parsed.Matches(role.Labels) {
			return true
		}
	}
	return false
}
