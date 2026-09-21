// Package testclient implements the wire client for Go contract/integration
// tests. Production browser code lives in apps/web/src/shared/api/transport.mjs.
package testclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/srex-run/access-gateway/internal/securetransport"
)

type Client struct {
	Challenge securetransport.Challenge
	response  cipher.AEAD
}

func Seal(challenge securetransport.Challenge, plaintext []byte) (securetransport.Request, *Client, error) {
	block, _ := pem.Decode([]byte(challenge.PublicKey))
	if block == nil {
		return securetransport.Request{}, nil, fmt.Errorf("invalid test public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return securetransport.Request{}, nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return securetransport.Request{}, nil, fmt.Errorf("invalid test public key type")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return securetransport.Request{}, nil, err
	}
	defer clear(seed)
	request, err := derive(seed, "request")
	if err != nil {
		return securetransport.Request{}, nil, err
	}
	response, err := derive(seed, "response")
	if err != nil {
		return securetransport.Request{}, nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return securetransport.Request{}, nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, seed, nil)
	if err != nil {
		return securetransport.Request{}, nil, err
	}
	envelope := securetransport.Envelope{Version: 1, KeyID: challenge.KeyID, EncryptedKey: wrapped, Nonce: nonce,
		Ciphertext: request.Seal(nil, nonce, plaintext, challenge.AAD("request"))}
	return securetransport.Request{ChallengeID: challenge.ID, Envelope: envelope}, &Client{Challenge: challenge, response: response}, nil
}

func (c *Client) Open(status int, body []byte) ([]byte, error) {
	var response securetransport.Response
	if json.Unmarshal(body, &response) != nil || response.Version != 1 || response.ChallengeID != c.Challenge.ID || len(response.Nonce) != 12 {
		return nil, securetransport.ErrInvalid
	}
	return c.response.Open(nil, response.Nonce, response.Ciphertext, c.Challenge.AAD("response:"+strconv.Itoa(status)))
}

func derive(seed []byte, direction string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, seed, nil, "access-gateway/browser-transport/v1/"+direction, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
