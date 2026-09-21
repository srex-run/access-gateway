package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type LoginState struct {
	State            string `json:"state"`
	Provider         string `json:"provider"`
	Nonce            string `json:"nonce,omitempty"`
	Verifier         string `json:"verifier,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	Version          int64  `json:"version,omitempty"`
	SettingsRevision int64  `json:"settings_revision,omitempty"`
	ExpiresAt        int64  `json:"expires_at"`
}

func (s *SessionSigner) SignLoginState(state LoginState) string {
	payload, _ := json.Marshal(state)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("login-state:" + encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *SessionSigner) VerifyLoginState(value string, now time.Time) (LoginState, bool) {
	var state LoginState
	if s == nil || len(value) > 3000 {
		return state, false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return state, false
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("login-state:" + parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return state, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &state) != nil || state.State == "" || state.Provider == "" || state.ExpiresAt <= now.Unix() {
		return LoginState{}, false
	}
	return state, true
}
