package security

import (
	"strings"
	"testing"
	"time"
)

func TestSessionExpiryRequiresValidSignature(t *testing.T) {
	signer, err := NewSessionSigner(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	deadline := now.Add(time.Hour)
	cookie := signer.SignMFA("user", 3, deadline)
	if got, ok := signer.ExpiresAt(cookie, now); !ok || !got.Equal(deadline) {
		t.Fatalf("expiry=%v valid=%v", got, ok)
	}
	for _, value := range []string{cookie + "tampered", "invalid", signer.Sign("user", now)} {
		if _, ok := signer.ExpiresAt(value, now); ok {
			t.Fatal("unverified or expired cookie yielded a usable deadline")
		}
	}
}
