package security

import (
	"strings"
	"testing"
)

func TestExternalUsername(t *testing.T) {
	for _, test := range []struct {
		name, hint, email, want string
	}{
		{"provider handle", " OctoCat ", "other@example.com", "octocat"},
		{"email as login", " Alice@company.test ", "other@example.com", "alice"},
		{"email fallback", "张三", " Zhang.San@example.com ", "zhang.san"},
		{"short handle", "a", "", "a"},
		{"long handle", strings.Repeat("a", 65), "alice@example.com", "alice"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ExternalUsername(test.hint, test.email, "oidc", "issuer/subject"); got != test.want {
				t.Fatalf("username=%q, want %q", got, test.want)
			}
		})
	}
	first := ExternalUsername("中文昵称", "", "oidc", "issuer/subject")
	if !accountUsername.MatchString(first) || first != ExternalUsername("", "", "oidc", "issuer/subject") {
		t.Fatalf("fallback must be stable ASCII: %q", first)
	}
	if first == ExternalUsername("", "", "oidc", "another-issuer/subject") {
		t.Fatal("different identity issuers shared a fallback")
	}
}
