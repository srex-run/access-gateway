// Package label 实现 Access Gateway 的资源标签与标签选择器。
//
// # Label 是分类机制，不是权限机制
//
// 绝不要用「给 User 加一个 admin=true 标签就获得管理员权限」这类设计：
// 任何能修改标签的人都能自我提权，且授权行为不可审计、不可解释。
//
// 正确做法是 Explicit Binding + Selector：
//
//	RoleBinding{ RoleUID: "admin", SubjectSelector: "team=platform" }
//
// Binding 是显式、可审计的一等资源，Selector 只决定动态成员范围。
// 授权边界见 docs/identity-workflows.md。
//
// 本包内部语义参考 Kubernetes，但类型完全属于 Access Gateway ——
// 不向业务层暴露第三方标签库的类型。
package label

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	// MaxLabels 是单个资源允许的最大标签数。
	MaxLabels = 64
	// MaxRequirements 是单个选择器允许的最大条件数。
	MaxRequirements = 32

	// MaxKeyNameLength 是标签键名部分的最大长度。
	MaxKeyNameLength = 63
	// MaxKeyPrefixLength 是标签键前缀部分的最大长度。
	MaxKeyPrefixLength = 253
	// MaxValueLength 是标签值的最大长度。
	MaxValueLength = 63
)

const (
	// PrefixSystem 是系统托管标签的保留前缀，只有系统代码可写。
	PrefixSystem = "access-gateway.io/"
	// PrefixSecurity 保留安全标签语义，不代表独立权限。
	// 所属服务对所有可编辑标签执行相同的授权检查：角色标签需要 role:manage，
	// 用户标签同时需要 user:manage 和 role:manage，资源标签需要 workflow:manage。
	PrefixSecurity = "security.access-gateway.io/"
)

// Operator 是选择器条件的比较操作符。
type Operator int

const (
	// OpEquals 匹配 key=value。
	OpEquals Operator = iota
	// OpNotEquals 匹配 key!=value。
	OpNotEquals
	// OpIn 匹配 key in (a,b)。
	OpIn
	// OpNotIn 匹配 key notin (a,b)。
	OpNotIn
	// OpExists 匹配 key（键存在）。
	OpExists
	// OpNotExists 匹配 !key（键不存在）。
	OpNotExists
)

// String 返回操作符的字面形式。
func (o Operator) String() string {
	switch o {
	case OpEquals:
		return "="
	case OpNotEquals:
		return "!="
	case OpIn:
		return "in"
	case OpNotIn:
		return "notin"
	case OpExists:
		return ""
	case OpNotExists:
		return "!"
	default:
		return "?"
	}
}

// Labels 是资源的标签集合。
//
// Labels 是 map，本身不是并发安全的；跨 goroutine 传递时先 Copy。
type Labels map[string]string

// Copy 返回一份深拷贝。
func (l Labels) Copy() Labels {
	if l == nil {
		return nil
	}

	out := make(Labels, len(l))
	for k, v := range l {
		out[k] = v
	}

	return out
}

// Has 报告键是否存在。
func (l Labels) Has(key string) bool {
	_, ok := l[key]

	return ok
}

// Get 返回键对应的值，不存在时返回空字符串。
func (l Labels) Get(key string) string {
	return l[key]
}

// Validate 校验所有键值的格式与数量限制。
func (l Labels) Validate() error {
	if len(l) > MaxLabels {
		return fmt.Errorf("too many labels: %d exceeds limit %d", len(l), MaxLabels)
	}

	for k, v := range l {
		if err := ValidateKey(k); err != nil {
			return fmt.Errorf("invalid label key %q: %w", k, err)
		}

		if err := ValidateValue(v); err != nil {
			return fmt.Errorf("invalid value for label %q: %w", k, err)
		}
	}

	return nil
}

// String 返回稳定排序的字面形式，形如 a=1,b=2。
func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}

	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+l[k])
	}

	return strings.Join(parts, ",")
}

// IsSystemKey 报告键是否属于系统托管前缀。
func IsSystemKey(key string) bool {
	return strings.HasPrefix(key, PrefixSystem)
}

// IsSecurityKey 报告键是否属于安全保留前缀。
//
// 该前缀下的标签只能由具备安全管理权限的角色修改。
func IsSecurityKey(key string) bool {
	return strings.HasPrefix(key, PrefixSecurity)
}

// IsReservedKey 报告键是否属于任一保留前缀。
func IsReservedKey(key string) bool {
	return IsSystemKey(key) || IsSecurityKey(key)
}

var (
	errEmptyKey      = errors.New("key must not be empty")
	errEmptyKeyName  = errors.New("key name must not be empty")
	errTooManyShlash = errors.New("key must contain at most one '/'")
)

// ValidateKey 校验标签键格式：[prefix/]name。
func ValidateKey(key string) error {
	if key == "" {
		return errEmptyKey
	}

	name := key

	if idx := strings.Index(key, "/"); idx >= 0 {
		prefix := key[:idx]
		name = key[idx+1:]

		if strings.Contains(name, "/") {
			return errTooManyShlash
		}

		if err := validatePrefix(prefix); err != nil {
			return err
		}
	}

	if name == "" {
		return errEmptyKeyName
	}

	if len(name) > MaxKeyNameLength {
		return fmt.Errorf("key name length %d exceeds limit %d", len(name), MaxKeyNameLength)
	}

	return validateNameChars(name)
}

// validatePrefix 校验键的前缀部分（DNS 子域名形式）。
func validatePrefix(prefix string) error {
	if prefix == "" {
		return errors.New("key prefix must not be empty")
	}

	if len(prefix) > MaxKeyPrefixLength {
		return fmt.Errorf("key prefix length %d exceeds limit %d", len(prefix), MaxKeyPrefixLength)
	}

	for _, part := range strings.Split(prefix, ".") {
		if part == "" {
			return errors.New("key prefix must not contain empty dns label")
		}

		if err := validateDNSLabel(part); err != nil {
			return err
		}
	}

	return nil
}

// validateDNSLabel 校验单个 DNS label：小写字母数字与连字符，首尾为字母数字。
func validateDNSLabel(s string) error {
	if !isAlphanumericLower(s[0]) || !isAlphanumericLower(s[len(s)-1]) {
		return fmt.Errorf("dns label %q must start and end with an alphanumeric character", s)
	}

	for i := range len(s) {
		c := s[i]
		if !isAlphanumericLower(c) && c != '-' {
			return fmt.Errorf("dns label %q contains invalid character %q", s, string(c))
		}
	}

	return nil
}

// validateNameChars 校验键名或值的字符集：字母数字与 -_.，首尾为字母数字。
func validateNameChars(s string) error {
	if !isAlphanumeric(s[0]) || !isAlphanumeric(s[len(s)-1]) {
		return fmt.Errorf("%q must start and end with an alphanumeric character", s)
	}

	for i := range len(s) {
		c := s[i]
		if !isAlphanumeric(c) && c != '-' && c != '_' && c != '.' {
			return fmt.Errorf("%q contains invalid character %q", s, string(c))
		}
	}

	return nil
}

// ValidateValue 校验标签值。空值是合法的，表示「键存在但无值」。
func ValidateValue(value string) error {
	if value == "" {
		return nil
	}

	if len(value) > MaxValueLength {
		return fmt.Errorf("value length %d exceeds limit %d", len(value), MaxValueLength)
	}

	return validateNameChars(value)
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isAlphanumericLower(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
