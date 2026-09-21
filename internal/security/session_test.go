package security

import (
	"strings"
	"testing"
	"time"
)

func TestSessionSignerRoundTripAndTamperDetection(t *testing.T) {
	signer, err := NewSessionSigner(strings.Repeat("s", 32))
	if err != nil {
		t.Fatalf("NewSessionSigner: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	value := signer.Sign("user-1", expires)
	if got, ok := signer.Verify(value, time.Now()); !ok || got != "user-1" {
		t.Fatalf("Verify = %q, %v", got, ok)
	}
	if got, ok := signer.Verify(value+"x", time.Now()); ok || got != "" {
		t.Fatalf("tampered cookie accepted: %q, %v", got, ok)
	}
	if got, ok := signer.Verify(signer.Sign("user-1", time.Now().Add(-time.Second)), time.Now()); ok || got != "" {
		t.Fatalf("expired cookie accepted: %q, %v", got, ok)
	}
}
