package feishu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestVerifyCallback(t *testing.T) {
	secret, timestamp, eventID, body := "secret", "1700000000", "evt-1", []byte(`{"approval_id":"a"}`)
	hash := hmac.New(sha256.New, []byte(secret))
	_, _ = hash.Write([]byte(timestamp + "." + eventID + "."))
	_, _ = hash.Write(body)
	signature := hex.EncodeToString(hash.Sum(nil))
	if err := VerifyCallback(secret, timestamp, eventID, signature, body, time.Unix(1700000000, 0), time.Minute); err != nil {
		t.Fatalf("VerifyCallback: %v", err)
	}
	if err := VerifyCallback(secret, timestamp, eventID, signature, []byte("tampered"), time.Unix(1700000000, 0), time.Minute); err == nil {
		t.Fatal("tampered callback was accepted")
	}
}

func TestVerifyLarkCallback(t *testing.T) {
	secret, timestamp, nonce, body := "encrypt-key", "1700000000", "nonce-1", []byte(`{"event":{"type":"card.action"}}`)
	hash := sha256.New()
	_, _ = hash.Write([]byte(timestamp + nonce + secret))
	_, _ = hash.Write(body)
	signature := hex.EncodeToString(hash.Sum(nil))
	if err := VerifyLarkCallback(secret, timestamp, nonce, signature, body, time.Unix(1700000000, 0), time.Minute); err != nil {
		t.Fatalf("VerifyLarkCallback: %v", err)
	}
	if err := VerifyLarkCallback(secret, timestamp, nonce, signature, []byte("tampered"), time.Unix(1700000000, 0), time.Minute); err == nil {
		t.Fatal("tampered Lark callback was accepted")
	}
}
