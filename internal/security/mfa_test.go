package security

import (
	"strings"
	"testing"
	"time"
)

func TestMFASessionProofIsSignedAndSeparate(t *testing.T) {
	signer, err := NewSessionSigner(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	plain := signer.SignVersioned("user", 7, now.Add(time.Hour))
	verified := signer.SignMFA("user", 7, now.Add(time.Hour))
	if signer.MFAVerified(plain, now) || !signer.MFAVerified(verified, now) {
		t.Fatal("MFA proof confused with primary authentication")
	}
	user, version, valid := signer.VerifyVersioned(verified, now)
	if !valid || user != "user" || version != 7 {
		t.Fatal("MFA cookie lost identity or version")
	}
	if signer.MFAVerified(verified+"x", now) || signer.MFAVerified(verified, now.Add(2*time.Hour)) {
		t.Fatal("tampered or expired proof accepted")
	}
	for _, invalid := range []string{"user:7:anything", "user:7:mfa:extra", "user:-1:mfa"} {
		if _, _, valid := signer.VerifyVersioned(signer.Sign(invalid, now.Add(time.Hour)), now); valid {
			t.Fatalf("invalid claims accepted: %s", invalid)
		}
	}
}

func TestRecoveryCodesHaveEntropyAndAreUserScoped(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes("user-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatal("wrong recovery code count")
	}
	seen := map[string]bool{}
	for i, code := range codes {
		if len(code) != 35 || seen[code] {
			t.Fatal("recovery codes malformed or duplicated")
		}
		seen[code] = true
		hash, valid := RecoveryCodeHash("user-a", " "+strings.ToLower(code)+" ")
		other, _ := RecoveryCodeHash("user-b", code)
		if !valid || hash != hashes[i] || len(hash) != 64 || hash == code || hash == other {
			t.Fatal("recovery hash not normalized and user scoped")
		}
	}
	for _, invalid := range []string{"123456", strings.Repeat("g", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		if _, valid := RecoveryCodeHash("user-a", invalid); valid {
			t.Fatal("malformed recovery code accepted")
		}
	}
}
