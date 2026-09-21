package security

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var accountUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ExternalUsername keeps a provider's login handle when possible. The caller
// still resolves collisions without linking identities by username or email.
func ExternalUsername(hint, email, provider, subject string) string {
	for _, candidate := range []string{hint, strings.SplitN(hint, "@", 2)[0], strings.SplitN(email, "@", 2)[0]} {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if accountUsername.MatchString(candidate) {
			return candidate
		}
	}
	// Subject IDs may contain Unicode or punctuation and are not display names.
	// The digest is stable across repeated logins and safe as an ASCII handle.
	sum := sha256.Sum256([]byte(provider + "\x00" + subject))
	return provider + "_" + hex.EncodeToString(sum[:16])
}
