package securetransport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"
)

const Algorithm = "RSA-OAEP-256+A256GCM"
const MaxPlaintext = 512 << 10

var ErrInvalid = errors.New("encrypted request is invalid or expired")

type Binding struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Subject string `json:"subject"`
}

type Challenge struct {
	Binding
	ID        string    `json:"id"`
	KeyID     string    `json:"kid"`
	PublicKey string    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Envelope struct {
	Version      int    `json:"version"`
	KeyID        string `json:"kid"`
	EncryptedKey []byte `json:"encrypted_key"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

type Request struct {
	ChallengeID string   `json:"challenge_id"`
	Envelope    Envelope `json:"envelope"`
}

type Response struct {
	Version     int    `json:"version"`
	ChallengeID string `json:"challenge_id"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
}

func GenerateKey() (*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func (c Challenge) AAD(direction string) []byte {
	return []byte(strings.Join([]string{"access-gateway/browser-transport/v1", direction, c.ID, c.KeyID, c.Method, c.Path, c.Subject}, "\n"))
}

// The one-time challenge is consumed before Open. Its binding and key ID must
// come from trusted storage, never from the submitted envelope.
func Open(key *rsa.PrivateKey, challenge Challenge, envelope Envelope) ([]byte, *Reply, error) {
	if key == nil || envelope.Version != 1 || envelope.KeyID != challenge.KeyID ||
		len(envelope.EncryptedKey) != key.Size() || len(envelope.Nonce) != 12 ||
		len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > MaxPlaintext+16 {
		return nil, nil, ErrInvalid
	}
	seed, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, envelope.EncryptedKey, nil)
	if err != nil || len(seed) != 32 {
		clear(seed)
		return nil, nil, ErrInvalid
	}
	defer clear(seed)
	requestKey, err := deriveKey(seed, "request")
	if err != nil {
		return nil, nil, ErrInvalid
	}
	defer clear(requestKey)
	gcm, err := newGCM(requestKey)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, challenge.AAD("request"))
	if err != nil {
		return nil, nil, ErrInvalid
	}
	responseKey, err := deriveKey(seed, "response")
	if err != nil {
		clear(plaintext)
		return nil, nil, ErrInvalid
	}
	return plaintext, &Reply{challenge: challenge, key: responseKey}, nil
}

type Reply struct {
	challenge Challenge
	key       []byte
}

func (r *Reply) Clear() { clear(r.key) }

func (r *Reply) Seal(status int, plaintext []byte) (Response, error) {
	gcm, err := newGCM(r.key)
	if err != nil {
		return Response{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Response{}, err
	}
	return Response{Version: 1, ChallengeID: r.challenge.ID, Nonce: nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, r.challenge.AAD("response:"+strconv.Itoa(status)))}, nil
}

func deriveKey(seed []byte, direction string) ([]byte, error) {
	return hkdf.Key(sha256.New, seed, nil, "access-gateway/browser-transport/v1/"+direction, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
