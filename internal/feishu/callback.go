package feishu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VerifyCallback validates a timestamped HMAC envelope used by the callback adapter.
// The concrete Feishu signing adapter can translate Feishu's headers into this function.
func VerifyCallback(secret, timestamp, eventID, signature string, body []byte, now time.Time, maxSkew time.Duration) error {
	if secret == "" || timestamp == "" || eventID == "" || signature == "" {
		return fmt.Errorf("callback signature fields are required")
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid callback timestamp: %w", err)
	}
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	if delta := now.Sub(time.Unix(seconds, 0)); delta > maxSkew || delta < -maxSkew {
		return fmt.Errorf("callback timestamp is outside allowed window")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write([]byte(eventID))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	provided := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(signature)), "sha256=")
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return fmt.Errorf("invalid callback signature")
	}
	return nil
}

// VerifyLarkCallback implements Feishu/Lark's native callback signature:
// SHA-256(timestamp + nonce + encrypt_key + raw_body). It is kept separate
// from VerifyCallback because some deployments normalize callbacks through an
// internal adapter that signs a timestamp/event-id HMAC envelope instead.
func VerifyLarkCallback(secret, timestamp, nonce, signature string, body []byte, now time.Time, maxSkew time.Duration) error {
	if secret == "" || timestamp == "" || nonce == "" || signature == "" {
		return fmt.Errorf("Lark callback signature fields are required")
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid callback timestamp: %w", err)
	}
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	if delta := now.Sub(time.Unix(seconds, 0)); delta > maxSkew || delta < -maxSkew {
		return fmt.Errorf("callback timestamp is outside allowed window")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(timestamp))
	_, _ = hash.Write([]byte(nonce))
	_, _ = hash.Write([]byte(secret))
	_, _ = hash.Write(body)
	expected := hex.EncodeToString(hash.Sum(nil))
	provided := strings.ToLower(strings.TrimSpace(signature))
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return fmt.Errorf("invalid callback signature")
	}
	return nil
}
