package security

import (
	"testing"
)

func TestTokenIsHighEntropyAndHashesAreStable(t *testing.T) {
	first, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	second, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken second: %v", err)
	}
	if len(first) < 43 || first == second {
		t.Fatalf("tokens are not high entropy: first=%q second=%q", first, second)
	}
	secret := "0123456789abcdef0123456789abcdef"
	if HashToken(secret, first) != HashToken(secret, first) || HashToken(secret, first) == HashToken(secret, second) {
		t.Fatalf("token hash behavior is invalid")
	}
	if len(HashOpaqueToken(first)) != 64 || HashOpaqueToken(first) == HashOpaqueToken(second) {
		t.Fatalf("opaque token digest behavior is invalid")
	}
}
