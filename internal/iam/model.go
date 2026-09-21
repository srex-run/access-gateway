// Package iam owns user-center and flat role-definition contracts. Persistent
// bindings and authorization are integrated by service, never by UI labels.
package iam

import (
	"fmt"
	"regexp"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/label"
)

type Role struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Permissions []authz.Permission `json:"permissions"`
	Labels      label.Labels       `json:"labels"`
	Enabled     bool               `json:"enabled"`
	BuiltIn     bool               `json:"built_in"`
	Revision    int64              `json:"revision"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

var roleName = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,62}$`)

func (r Role) Validate() error {
	if !roleName.MatchString(r.Name) || len(r.Description) > 512 {
		return fmt.Errorf("角色名称或描述无效")
	}
	if len(r.Permissions) == 0 || len(r.Permissions) > len(authz.Catalog()) {
		return fmt.Errorf("请选择有效权限")
	}
	seen := map[authz.Permission]bool{}
	for _, p := range r.Permissions {
		if !authz.Known(p) || seen[p] {
			return fmt.Errorf("未知或重复权限：%s", p)
		}
		seen[p] = true
	}
	return label.ValidateEditable(r.Labels)
}

// Binding is the auditable authorization object; labels by themselves confer no role.
type Binding struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	UserSelector string    `json:"user_selector"`
	RoleSelector string    `json:"role_selector"`
	Enabled      bool      `json:"enabled"`
	Revision     int64     `json:"revision"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (b Binding) Validate() error {
	if len(b.Name) < 1 || len(b.Name) > 128 {
		return fmt.Errorf("请输入绑定名称（最多 128 字节）")
	}
	if _, err := label.BindingSelector(b.UserSelector); err != nil {
		return err
	}
	_, err := label.BindingSelector(b.RoleSelector)
	return err
}
