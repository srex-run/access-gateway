package label_test

import (
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/label"
)

func TestValidateKey(t *testing.T) {
	t.Parallel()

	valid := []string{
		"team",
		"environment",
		"tier-1",
		"app.kubernetes.io_name",
		"access-gateway.io/managed-by",
		"security.access-gateway.io/privileged",
		"a",
		"a1",
	}

	for _, k := range valid {
		t.Run("valid/"+k, func(t *testing.T) {
			t.Parallel()

			if err := label.ValidateKey(k); err != nil {
				t.Errorf("ValidateKey(%q) = %v, want nil", k, err)
			}
		})
	}

	invalid := map[string]string{
		"empty":            "",
		"leading dash":     "-team",
		"trailing dash":    "team-",
		"invalid char":     "team$name",
		"two slashes":      "a/b/c",
		"empty prefix":     "/name",
		"empty name":       "prefix/",
		"name too long":    strings.Repeat("a", 64),
		"prefix too long":  strings.Repeat("a", 254) + "/name",
		"empty dns label":  "a..b/name",
		"uppercase prefix": "Access Gateway.io/name",
	}

	for name, k := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			t.Parallel()

			if err := label.ValidateKey(k); err == nil {
				t.Errorf("ValidateKey(%q) = nil, want error", k)
			}
		})
	}
}

func TestValidateValue(t *testing.T) {
	t.Parallel()

	if err := label.ValidateValue(""); err != nil {
		t.Errorf("empty value should be valid, got %v", err)
	}

	if err := label.ValidateValue("production"); err != nil {
		t.Errorf("ValidateValue(production) = %v", err)
	}

	if err := label.ValidateValue(strings.Repeat("a", 64)); err == nil {
		t.Error("over-long value should be rejected")
	}

	if err := label.ValidateValue("-bad"); err == nil {
		t.Error("value starting with dash should be rejected")
	}
}

func TestLabelsValidateEnforcesCount(t *testing.T) {
	t.Parallel()

	labels := make(label.Labels)
	for i := range label.MaxLabels + 1 {
		labels[keyN(i)] = "v"
	}

	if err := labels.Validate(); err == nil {
		t.Errorf("Validate should reject more than %d labels", label.MaxLabels)
	}
}

func keyN(i int) string {
	return "k" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
}

func TestLabelsCopyIsIndependent(t *testing.T) {
	t.Parallel()

	original := label.Labels{"team": "platform"}
	clone := original.Copy()
	clone["team"] = "changed"
	clone["new"] = "added"

	if original["team"] != "platform" {
		t.Errorf("Copy mutated the original: %v", original)
	}

	if original.Has("new") {
		t.Error("Copy leaked a new key into the original")
	}

	if label.Labels(nil).Copy() != nil {
		t.Error("Copy of nil should be nil")
	}
}

func TestLabelsStringIsStable(t *testing.T) {
	t.Parallel()

	labels := label.Labels{"z": "1", "a": "2", "m": "3"}

	const want = "a=2,m=3,z=1"
	for range 20 {
		if got := labels.String(); got != want {
			t.Fatalf("String = %q, want stable %q", got, want)
		}
	}
}

func TestReservedPrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key        string
		isSystem   bool
		isSecurity bool
	}{
		{"access-gateway.io/managed-by", true, false},
		{"security.access-gateway.io/privileged", false, true},
		{"team", false, false},
		{"example.com/custom", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()

			if got := label.IsSystemKey(tt.key); got != tt.isSystem {
				t.Errorf("IsSystemKey = %v, want %v", got, tt.isSystem)
			}

			if got := label.IsSecurityKey(tt.key); got != tt.isSecurity {
				t.Errorf("IsSecurityKey = %v, want %v", got, tt.isSecurity)
			}

			wantReserved := tt.isSystem || tt.isSecurity
			if got := label.IsReservedKey(tt.key); got != wantReserved {
				t.Errorf("IsReservedKey = %v, want %v", got, wantReserved)
			}
		})
	}
}
