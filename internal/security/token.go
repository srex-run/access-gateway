package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func NewToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func HashToken(secret, token string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	_, _ = hash.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

// HashOpaqueToken creates a non-secret lookup key for high-entropy values such
// as OAuth state. The preimage is never persisted.
func HashOpaqueToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
