package secretstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const envelopeVersion = "agk1"

type Encryptor interface {
	Encrypt(ctx context.Context, plaintext, associatedData []byte) (string, error)
}

type Cipher interface {
	Encryptor
	Decrypt(ctx context.Context, envelope string, associatedData []byte) ([]byte, error)
}

type AESGCM struct {
	keyID string
	aead  cipher.AEAD
}

// Keyring encrypts with one primary key and decrypts envelopes produced by
// any configured key. Keeping the previous key during a rolling deployment
// prevents a token created by a new replica from becoming unreadable on an
// old replica (and vice versa).
type Keyring struct {
	primary *AESGCM
	keys    map[string]*AESGCM
}

func NewAESGCMFromFile(keyID, path string) (*AESGCM, error) {
	encoded, err := ReadProtectedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	defer clear(encoded)
	key, err := decodeKey(encoded)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return NewAESGCM(keyID, key)
}

func NewAESGCM(keyID string, key []byte) (*AESGCM, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || len(keyID) > 128 || strings.ContainsAny(keyID, ".\r\n") {
		return nil, fmt.Errorf("encryption key ID is invalid")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create encryption AEAD: %w", err)
	}
	return &AESGCM{keyID: keyID, aead: aead}, nil
}

func NewKeyring(primary *AESGCM, additional ...*AESGCM) (*Keyring, error) {
	if primary == nil || primary.aead == nil {
		return nil, fmt.Errorf("primary encryption key is required")
	}
	keys := make(map[string]*AESGCM, len(additional)+1)
	keys[primary.keyID] = primary
	for _, value := range additional {
		if value == nil || value.aead == nil {
			return nil, fmt.Errorf("encryption keyring contains an invalid key")
		}
		if _, exists := keys[value.keyID]; exists {
			return nil, fmt.Errorf("encryption keyring contains duplicate key ID %q", value.keyID)
		}
		keys[value.keyID] = value
	}
	return &Keyring{primary: primary, keys: keys}, nil
}

// NewKeyringFromDirectory loads one protected key file per key ID. The file
// name is the envelope key ID, and primaryKeyID selects the key used for new
// ciphertext. At most 16 keys are accepted to keep rotation configuration
// bounded and auditable.
func NewKeyringFromDirectory(primaryKeyID, directory string) (*Keyring, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("encryption keyring directory must be an absolute path")
	}
	entry, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat encryption keyring directory: %w", err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() || entry.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("encryption keyring directory must be a protected non-symlink directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read encryption keyring directory: %w", err)
	}
	if len(entries) < 1 || len(entries) > 16 {
		return nil, fmt.Errorf("encryption keyring must contain between 1 and 16 keys")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	keys := make([]*AESGCM, 0, len(entries))
	for _, file := range entries {
		if file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("encryption keyring contains a non-regular entry")
		}
		key, loadErr := NewAESGCMFromFile(file.Name(), filepath.Join(directory, file.Name()))
		if loadErr != nil {
			return nil, fmt.Errorf("load encryption key %q: %w", file.Name(), loadErr)
		}
		keys = append(keys, key)
	}
	var primary *AESGCM
	additional := make([]*AESGCM, 0, len(keys)-1)
	for _, key := range keys {
		if key.keyID == primaryKeyID {
			primary = key
		} else {
			additional = append(additional, key)
		}
	}
	if primary == nil {
		return nil, fmt.Errorf("primary encryption key ID %q is unavailable", primaryKeyID)
	}
	return NewKeyring(primary, additional...)
}

func (e *AESGCM) Encrypt(ctx context.Context, plaintext, associatedData []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("encrypt secret: %w", err)
	}
	if e == nil || e.aead == nil || len(plaintext) == 0 {
		return "", fmt.Errorf("encryption input is invalid")
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate encryption nonce: %w", err)
	}
	sealed := e.aead.Seal(nonce, nonce, plaintext, associatedData)
	return envelopeVersion + "." + base64.RawURLEncoding.EncodeToString([]byte(e.keyID)) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (e *AESGCM) Decrypt(ctx context.Context, envelope string, associatedData []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	if e == nil || e.aead == nil {
		return nil, fmt.Errorf("decryption is not configured")
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 3 || parts[0] != envelopeVersion {
		return nil, fmt.Errorf("ciphertext envelope is invalid")
	}
	keyID, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || string(keyID) != e.keyID {
		return nil, fmt.Errorf("ciphertext key ID is unavailable")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sealed) <= e.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext payload is invalid")
	}
	nonce := sealed[:e.aead.NonceSize()]
	plaintext, err := e.aead.Open(nil, nonce, sealed[e.aead.NonceSize():], associatedData)
	if err != nil {
		return nil, fmt.Errorf("authenticate ciphertext: %w", err)
	}
	return plaintext, nil
}

func (k *Keyring) Encrypt(ctx context.Context, plaintext, associatedData []byte) (string, error) {
	if k == nil || k.primary == nil {
		return "", fmt.Errorf("encryption keyring is not configured")
	}
	return k.primary.Encrypt(ctx, plaintext, associatedData)
}

func (k *Keyring) Decrypt(ctx context.Context, envelope string, associatedData []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	if k == nil || len(k.keys) == 0 {
		return nil, fmt.Errorf("decryption keyring is not configured")
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 3 || parts[0] != envelopeVersion {
		return nil, fmt.Errorf("ciphertext envelope is invalid")
	}
	encodedKeyID, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ciphertext key ID is invalid")
	}
	key := k.keys[string(encodedKeyID)]
	if key == nil {
		return nil, fmt.Errorf("ciphertext key ID is unavailable")
	}
	return key.Decrypt(ctx, envelope, associatedData)
}

func decodeKey(encoded []byte) ([]byte, error) {
	value := []byte(trimLineEnding(string(encoded)))
	defer clear(value)
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, err := encoding.DecodeString(string(value))
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		clear(decoded)
	}
	if len(value) == 32 {
		return append([]byte(nil), value...), nil
	}
	return nil, fmt.Errorf("encryption key must contain exactly 32 bytes or their base64 encoding")
}
