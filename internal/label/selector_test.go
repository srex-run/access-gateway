package label_test

import (
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/label"
)

func TestParseAllOperators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantOp   label.Operator
		wantKey  string
		wantVals []string
	}{
		{"equals", "environment=production", label.OpEquals, "environment", []string{"production"}},
		{"double equals", "environment==production", label.OpEquals, "environment", []string{"production"}},
		{"not equals", "environment!=dev", label.OpNotEquals, "environment", []string{"dev"}},
		{"in", "region in (cn,us)", label.OpIn, "region", []string{"cn", "us"}},
		{"notin", "tier notin (test,demo)", label.OpNotIn, "tier", []string{"test", "demo"}},
		{"exists", "team", label.OpExists, "team", nil},
		{"not exists", "!deprecated", label.OpNotExists, "deprecated", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sel, err := label.Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) = %v", tt.input, err)
			}

			reqs := sel.Requirements()
			if len(reqs) != 1 {
				t.Fatalf("got %d requirements, want 1", len(reqs))
			}

			r := reqs[0]
			if r.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", r.Key, tt.wantKey)
			}

			if r.Operator != tt.wantOp {
				t.Errorf("Operator = %v, want %v", r.Operator, tt.wantOp)
			}

			if len(r.Values) != len(tt.wantVals) {
				t.Fatalf("Values = %v, want %v", r.Values, tt.wantVals)
			}

			for i := range r.Values {
				if r.Values[i] != tt.wantVals[i] {
					t.Errorf("Values[%d] = %q, want %q", i, r.Values[i], tt.wantVals[i])
				}
			}
		})
	}
}

func TestParseMultipleRequirements(t *testing.T) {
	t.Parallel()

	sel, err := label.Parse("environment=production,region in (cn,us),!deprecated, team")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := len(sel.Requirements()); got != 4 {
		t.Fatalf("requirements = %d, want 4", got)
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()

	labels := label.Labels{
		"environment": "production",
		"region":      "cn",
		"team":        "platform",
	}

	tests := []struct {
		selector string
		want     bool
	}{
		{"", true},
		{"environment=production", true},
		{"environment=dev", false},
		{"environment!=dev", true},
		{"environment!=production", false},
		{"region in (cn,us)", true},
		{"region in (us,eu)", false},
		{"region notin (us,eu)", true},
		{"region notin (cn)", false},
		{"team", true},
		{"missing", false},
		{"!missing", true},
		{"!team", false},
		{"environment=production,region=cn", true},
		{"environment=production,region=us", false},
		// 否定操作符在键不存在时也匹配
		{"missing!=anything", true},
		{"missing notin (a,b)", true},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			t.Parallel()

			sel, err := label.Parse(tt.selector)
			if err != nil {
				t.Fatalf("Parse(%q) = %v", tt.selector, err)
			}

			if got := sel.Matches(labels); got != tt.want {
				t.Errorf("Matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRejectsInvalidSelectors(t *testing.T) {
	t.Parallel()

	invalid := map[string]string{
		"trailing comma":     "a=1,",
		"leading comma":      ",a=1",
		"unknown operator":   "a foo (1)",
		"unclosed paren":     "a in (1,2",
		"missing paren":      "a in 1,2",
		"bad key":            "-bad=1",
		"double bang":        "!!a",
		"empty in set":       "a in ()",
		"missing comma":      "a=1 b=2",
		"invalid value char": "a=v$x",
	}

	for name, s := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := label.Parse(s); err == nil {
				t.Errorf("Parse(%q) = nil error, want failure", s)
			}
		})
	}
}

// TestParseDoesNotPanicOnFuzzyInput 验证畸形输入不会 panic。
func TestParseDoesNotPanicOnFuzzyInput(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"", " ", ",", "!", "=", "(", ")", "in", "notin", "a in", "a in (", "a=", "!=",
		"a!", "a!b", strings.Repeat("a,", 100), strings.Repeat("(", 50),
		"a in (,)", "a in (,,)", "  ,  ", "a==", "a===b",
	}

	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse(%q) panicked: %v", in, r)
				}
			}()

			_, _ = label.Parse(in)
		}()
	}
}

// TestStringRoundTrip 验证 Parse(s.String()) 与 s 等价。
func TestStringRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"environment=production",
		"environment!=dev",
		"region in (cn,us)",
		"tier notin (test,demo)",
		"team",
		"!deprecated",
		"environment=production,region in (cn,us),!deprecated",
	}

	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			t.Parallel()

			sel, err := label.Parse(in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			reparsed, err := label.Parse(sel.String())
			if err != nil {
				t.Fatalf("Parse(%q) = %v", sel.String(), err)
			}

			if reparsed.String() != sel.String() {
				t.Errorf("round trip mismatch: %q != %q", reparsed.String(), sel.String())
			}
		})
	}
}

func TestEverythingAndNothing(t *testing.T) {
	t.Parallel()

	labels := label.Labels{"a": "1"}

	if !label.Everything().Matches(labels) {
		t.Error("Everything should match any labels")
	}

	if !label.Everything().Matches(nil) {
		t.Error("Everything should match nil labels")
	}

	if label.Nothing().Matches(labels) {
		t.Error("Nothing should match no labels")
	}

	if label.Nothing().Matches(nil) {
		t.Error("Nothing should match nil labels either")
	}

	if !label.Everything().Empty() {
		t.Error("Everything should report Empty")
	}
}

func TestSelectorRejectsTooManyRequirements(t *testing.T) {
	t.Parallel()

	parts := make([]string, 0, label.MaxRequirements+1)
	for i := range label.MaxRequirements + 1 {
		parts = append(parts, keyN(i)+"=v")
	}

	if _, err := label.Parse(strings.Join(parts, ",")); err == nil {
		t.Errorf("Parse should reject more than %d requirements", label.MaxRequirements)
	}
}

func TestRequirementValidateOperatorValueArity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  label.Requirement
		ok   bool
	}{
		{"exists with value", label.Requirement{Key: "a", Operator: label.OpExists, Values: []string{"x"}}, false},
		{"exists without value", label.Requirement{Key: "a", Operator: label.OpExists}, true},
		{"equals without value", label.Requirement{Key: "a", Operator: label.OpEquals}, false},
		{"equals with two values", label.Requirement{Key: "a", Operator: label.OpEquals, Values: []string{"x", "y"}}, false},
		{"in without values", label.Requirement{Key: "a", Operator: label.OpIn}, false},
		{"in with values", label.Requirement{Key: "a", Operator: label.OpIn, Values: []string{"x"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.req.Validate()
			if tt.ok && err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}

			if !tt.ok && err == nil {
				t.Error("Validate = nil, want error")
			}
		})
	}
}

// TestSelectorMatchesEmptyValue 验证 key= 表示「存在且值为空」。
func TestSelectorMatchesEmptyValue(t *testing.T) {
	t.Parallel()

	sel, err := label.Parse("marker=")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !sel.Matches(label.Labels{"marker": ""}) {
		t.Error("marker= should match a label with an empty value")
	}

	if sel.Matches(label.Labels{"marker": "x"}) {
		t.Error("marker= should not match a non-empty value")
	}
}
