package security

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Each code has 128 random bits; only its user-scoped SHA-256 hash is persisted.
func NewRecoveryCodes(userID string) ([]string, []string, error) {
	codes, hashes := make([]string, 10), make([]string, 10)
	for i := range codes {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, nil, err
		}
		value := strings.ToUpper(hex.EncodeToString(raw[:]))
		codes[i] = value[:8] + "-" + value[8:16] + "-" + value[16:24] + "-" + value[24:]
		hashes[i], _ = RecoveryCodeHash(userID, codes[i])
	}
	return codes, hashes, nil
}

func RecoveryCodeHash(userID, code string) (string, bool) {
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != 32 {
		return "", false
	}
	if _, err := hex.DecodeString(code); err != nil {
		return "", false
	}
	return HashOpaqueToken("mfa-recovery:" + userID + ":" + code), true
}
