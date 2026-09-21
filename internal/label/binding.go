package label

import (
	"fmt"
	"strings"
)

// BindingSelector uses Parse's selector semantics, but explicit bindings
// must never accidentally grant every subject through an empty selector.
func BindingSelector(value string) (Selector, error) {
	if strings.TrimSpace(value) == "" || len(value) > 1024 {
		return Nothing(), fmt.Errorf("匹配条件不能为空，且不能超过 1024 字节")
	}
	selector, err := Parse(value)
	if err != nil {
		return Nothing(), fmt.Errorf("标签匹配条件无效: %w", err)
	}
	if selector.Empty() {
		return Nothing(), fmt.Errorf("绑定必须有明确的标签匹配条件")
	}
	return selector, nil
}

func MatchesBinding(selector string, labels Labels) bool {
	parsed, err := BindingSelector(selector)
	return err == nil && parsed.Matches(labels)
}

// ValidateEditable rejects system-managed keys. Authorization for all other
// labels is enforced by the owning service because selectors may reference any key.
func ValidateEditable(value Labels) error {
	if err := value.Validate(); err != nil {
		return err
	}
	for key := range value {
		if IsSystemKey(key) {
			return fmt.Errorf("%s 为系统托管标签", key)
		}
	}
	return nil
}
