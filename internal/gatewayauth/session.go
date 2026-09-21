package gatewayauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/id"
)

const SessionIDHeader = "X-Gateway-Session-ID"

// SessionCredentials grants audit access to one session without sharing a
// gateway-wide credential with an ephemeral workload.
type SessionCredentials struct{ key []byte }

func NewSessionCredentials(key []byte) (*SessionCredentials, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session audit signing key must contain 32 bytes")
	}
	return &SessionCredentials{key: append([]byte(nil), key...)}, nil
}

func (c *SessionCredentials) Issue(gatewayID, sessionID string, expiresAt time.Time) string {
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	return expiry + "." + c.signature(gatewayID, sessionID, expiry)
}

func (c *SessionCredentials) Verify(gatewayID, sessionID, token string, now time.Time) bool {
	if c == nil || !id.IsUUID(gatewayID) || !id.IsUUID(sessionID) || len(token) > 128 {
		return false
	}
	expiry, signature, found := strings.Cut(token, ".")
	seconds, err := strconv.ParseInt(expiry, 10, 64)
	return found && err == nil && now.Before(time.Unix(seconds, 0)) &&
		hmac.Equal([]byte(signature), []byte(c.signature(gatewayID, sessionID, expiry)))
}

func (c *SessionCredentials) signature(gatewayID, sessionID, expiry string) string {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write([]byte("session-audit/v1\n" + gatewayID + "\n" + sessionID + "\n" + expiry))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
