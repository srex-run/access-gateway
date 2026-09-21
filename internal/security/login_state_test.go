package security

import (
	"strings"
	"testing"
	"time"
)

func TestLoginStateIsSignedExpiredAndSeparatedFromSessions(t *testing.T) {
	signer, _ := NewSessionSigner(strings.Repeat("s", 32))
	now := time.Now()
	state := LoginState{State: "opaque-state", Provider: "oidc", Nonce: "nonce", Verifier: "verifier", UserID: "bound-user", Version: 2, ExpiresAt: now.Add(time.Minute).Unix()}
	cookie := signer.SignLoginState(state)
	actual, ok := signer.VerifyLoginState(cookie, now)
	if !ok || actual != state {
		t.Fatal("valid login state did not round trip")
	}
	for _, invalid := range []string{cookie + "x", signer.Sign("user", now.Add(time.Minute)), strings.Repeat("a", 4000)} {
		if _, ok := signer.VerifyLoginState(invalid, now); ok {
			t.Fatal("accepted invalid login state")
		}
	}
	if _, ok := signer.VerifyLoginState(cookie, now.Add(2*time.Minute)); ok {
		t.Fatal("accepted expired login state")
	}
	if _, ok := signer.Verify(cookie, now); ok {
		t.Fatal("login state accepted as a session")
	}
}

func TestVersionedAndLegacySessions(t *testing.T) {
	signer, _ := NewSessionSigner(strings.Repeat("s", 32))
	now := time.Now()
	user, version, ok := signer.VerifyVersioned(signer.SignVersioned("user", 3, now.Add(time.Minute)), now)
	if !ok || user != "user" || version != 3 {
		t.Fatal("versioned session did not round trip")
	}
	user, version, ok = signer.VerifyVersioned(signer.Sign("user", now.Add(time.Minute)), now)
	if !ok || user != "user" || version != 0 {
		t.Fatal("legacy session not accepted as version zero")
	}
}

func TestLocalPasswords(t *testing.T) {
	hash, err := HashPassword("correct-password-12")
	if err != nil || !CheckPassword(hash, "correct-password-12") || CheckPassword(hash, "wrong") || CheckPassword("", "wrong") {
		t.Fatal("password validation failed")
	}
	for _, invalid := range []string{"short", strings.Repeat("x", 73)} {
		if _, err := HashPassword(invalid); err == nil {
			t.Fatal("accepted invalid password length")
		}
	}
	if username, err := NormalizeUsername(" Alice.User "); err != nil || username != "alice.user" {
		t.Fatal("username normalization failed")
	}
	if _, err := NormalizeUsername("a/b"); err == nil {
		t.Fatal("accepted invalid username")
	}
}

func TestMissingPasswordHashNeverAuthenticates(t *testing.T) {
	for _, password := range []string{"", "arbitrary-password", "unused-login-timing-placeholder"} {
		if CheckPassword("", password) {
			t.Fatal("an account without a password authenticated")
		}
	}
}
