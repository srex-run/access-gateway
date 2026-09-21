package gatewayauth

import (
	"strings"
	"testing"
	"time"
)

func TestSessionCredentialsBindGatewaySessionAndExpiry(t *testing.T) {
	credentials, err := NewSessionCredentials([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	const gatewayID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const sessionID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const otherID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	token := credentials.Issue(gatewayID, sessionID, now.Add(time.Minute))
	if !credentials.Verify(gatewayID, sessionID, token, now) {
		t.Fatal("valid token rejected")
	}
	if credentials.Verify(otherID, sessionID, token, now) || credentials.Verify(gatewayID, otherID, token, now) || credentials.Verify(gatewayID, sessionID, token, now.Add(time.Minute)) || credentials.Verify(gatewayID, sessionID, token+"x", now) {
		t.Fatal("credential was accepted outside its grant")
	}
	var absent *SessionCredentials
	if absent.Verify(gatewayID, sessionID, token, now) {
		t.Fatal("missing verifier accepted token")
	}
}
