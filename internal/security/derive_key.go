package security

import (
	"crypto/hmac"
	"crypto/sha256"
)

// DeriveKey separates encryption and session-signing keys by purpose.
func DeriveKey(encryptionKey, purpose string) []byte {
	mac := hmac.New(sha256.New, []byte(encryptionKey))
	_, _ = mac.Write([]byte("access-gateway/v1/" + purpose))
	return mac.Sum(nil)
}
