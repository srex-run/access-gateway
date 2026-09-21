package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type SessionSigner struct {
	secret []byte
}

const (
	maxSessionCookieBytes  = 4096
	maxSessionPayloadBytes = 512
)

func NewSessionSigner(secret string) (*SessionSigner, error) {
	if len([]byte(secret)) < 32 {
		return nil, fmt.Errorf("session secret must contain at least 32 bytes")
	}
	return &SessionSigner{secret: []byte(secret)}, nil
}

func (s *SessionSigner) Sign(userID string, expiresAt time.Time) string {
	payload := userID + "." + strconv.FormatInt(expiresAt.Unix(), 10)
	hash := hmac.New(sha256.New, s.secret)
	_, _ = hash.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + signature
}

func (s *SessionSigner) SignVersioned(userID string, version int64, expiresAt time.Time) string {
	return s.Sign(userID+":"+strconv.FormatInt(version, 10), expiresAt)
}

func (s *SessionSigner) SignMFA(userID string, version int64, expiresAt time.Time) string {
	return s.Sign(userID+":"+strconv.FormatInt(version, 10)+":mfa", expiresAt)
}

func (s *SessionSigner) MFAVerified(value string, now time.Time) bool {
	subject, valid := s.Verify(value, now)
	parts := strings.Split(subject, ":")
	return valid && len(parts) == 3 && parts[2] == "mfa"
}

func (s *SessionSigner) VerifyVersioned(value string, now time.Time) (string, int64, bool) {
	subject, valid := s.Verify(value, now)
	if !valid {
		return "", 0, false
	}
	parts := strings.Split(subject, ":")
	if len(parts) == 3 && parts[2] == "mfa" {
		parts = parts[:2]
	}
	if len(parts) == 1 {
		return subject, 0, true
	}
	if len(parts) != 2 || parts[0] == "" {
		return "", 0, false
	}
	version, err := strconv.ParseInt(parts[1], 10, 64)
	return parts[0], version, err == nil && version >= 0
}

func (s *SessionSigner) Verify(value string, now time.Time) (string, bool) {
	if s == nil || len([]byte(value)) == 0 || len([]byte(value)) > maxSessionCookieBytes {
		return "", false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return "", false
	}
	if len(parts[0]) > maxSessionPayloadBytes || len(parts[1]) > 128 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	if len(payload) == 0 || len(payload) > maxSessionPayloadBytes {
		return "", false
	}
	fields := strings.Split(string(payload), ".")
	if len(fields) != 2 || fields[0] == "" {
		return "", false
	}
	expiresUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || !time.Unix(expiresUnix, 0).After(now) {
		return "", false
	}
	hash := hmac.New(sha256.New, s.secret)
	_, _ = hash.Write(payload)
	expected := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return "", false
	}
	return fields[0], true
}

// ExpiresAt returns the deadline only after validating the signed cookie.
func (s *SessionSigner) ExpiresAt(value string, now time.Time) (time.Time, bool) {
	if _, valid := s.Verify(value, now); !valid {
		return time.Time{}, false
	}
	encoded, _, _ := strings.Cut(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(encoded)
	_, expiry, _ := strings.Cut(string(payload), ".")
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	return time.Unix(seconds, 0), err == nil
}
