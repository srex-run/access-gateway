package secretstore

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedFileEnvironmentAndEnvelopeEncryption(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "asset-key")
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(key)+"\n"), 0o640); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("TEST_SECRET", "")
	t.Setenv("TEST_SECRET_FILE", keyPath)
	value, err := FromEnvironment("TEST_SECRET")
	if err != nil || value == "" || value[len(value)-1] == '\n' {
		t.Fatalf("FromEnvironment value=%q err=%v", value, err)
	}
	encryptor, err := NewAESGCMFromFile("key-2026-09", keyPath)
	if err != nil {
		t.Fatalf("NewAESGCMFromFile: %v", err)
	}
	aad := []byte("asset-id")
	ciphertext, err := encryptor.Encrypt(context.Background(), []byte("10.0.0.8"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plaintext, err := encryptor.Decrypt(context.Background(), ciphertext, aad)
	if err != nil || string(plaintext) != "10.0.0.8" {
		t.Fatalf("Decrypt plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)
	if _, err := encryptor.Decrypt(context.Background(), ciphertext, []byte("other-asset")); err == nil {
		t.Fatal("ciphertext accepted with different associated data")
	}
}

func TestProtectedFileRejectsUnsafePermissionsAndConflictingSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := ReadProtectedFile(path); err == nil {
		t.Fatal("world-readable secret was accepted")
	}
	t.Setenv("CONFLICT_SECRET", "value")
	t.Setenv("CONFLICT_SECRET_FILE", path)
	if _, err := FromEnvironment("CONFLICT_SECRET"); err == nil {
		t.Fatal("conflicting secret sources were accepted")
	}
}

func TestDirectoryCredentialResolverLoadsRotationBundle(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod directory: %v", err)
	}
	path := filepath.Join(directory, "gateway-cn-east-1")
	current := "current-0123456789abcdef0123456789"
	previous := "previous-0123456789abcdef01234567"
	if err := os.WriteFile(path, []byte(current+"\n"+previous+"\n"), 0o600); err != nil {
		t.Fatalf("write credential bundle: %v", err)
	}
	resolver, err := NewDirectoryCredentialResolver(directory)
	if err != nil {
		t.Fatalf("NewDirectoryCredentialResolver: %v", err)
	}
	credentials, err := resolver.Resolve(context.Background(), "gateway-cn-east-1")
	if err != nil || len(credentials) != 2 || string(credentials[0]) != current || string(credentials[1]) != previous {
		t.Fatalf("Resolve credentials=%q err=%v", credentials, err)
	}
	clearCredentials(credentials)
	for _, reference := range []string{"../secret", "/absolute", ".hidden", "trailing-", " spaced"} {
		if _, err := resolver.Resolve(context.Background(), reference); err == nil {
			t.Fatalf("invalid reference %q was accepted", reference)
		}
	}
}

func TestDirectoryCredentialResolverRejectsUnsafeInputs(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatalf("chmod directory: %v", err)
	}
	if _, err := NewDirectoryCredentialResolver(directory); err == nil {
		t.Fatal("group-accessible credential directory was accepted")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("chmod directory: %v", err)
	}
	path := filepath.Join(directory, "gateway-1")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatalf("write invalid credential: %v", err)
	}
	resolver, err := NewDirectoryCredentialResolver(directory)
	if err != nil {
		t.Fatalf("NewDirectoryCredentialResolver: %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), "gateway-1"); err == nil {
		t.Fatal("short credential was accepted")
	}
	missingReference := "missing-gateway-reference"
	if _, err := resolver.Resolve(context.Background(), missingReference); err == nil {
		t.Fatal("missing credential reference was accepted")
	} else if strings.Contains(err.Error(), missingReference) || strings.Contains(err.Error(), directory) {
		t.Fatalf("credential resolver error leaked its reference path: %v", err)
	}
}

func TestKeyringDecryptsPreviousKeyAndEncryptsWithPrimary(t *testing.T) {
	directory := t.TempDir()
	for name, value := range map[string]string{
		"token-key-previous": "0123456789abcdef0123456789abcdef",
		"token-key-current":  "abcdef0123456789abcdef0123456789",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	previous, err := NewAESGCMFromFile("token-key-previous", filepath.Join(directory, "token-key-previous"))
	if err != nil {
		t.Fatalf("load previous key: %v", err)
	}
	oldEnvelope, err := previous.Encrypt(context.Background(), []byte("old-token"), []byte("session-id"))
	if err != nil {
		t.Fatalf("encrypt old token: %v", err)
	}
	keyring, err := NewKeyringFromDirectory("token-key-current", directory)
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	plaintext, err := keyring.Decrypt(context.Background(), oldEnvelope, []byte("session-id"))
	if err != nil || string(plaintext) != "old-token" {
		t.Fatalf("decrypt old envelope = %q, %v", plaintext, err)
	}
	clear(plaintext)
	newEnvelope, err := keyring.Encrypt(context.Background(), []byte("new-token"), []byte("session-id"))
	if err != nil {
		t.Fatalf("encrypt with primary: %v", err)
	}
	currentPrefix := envelopeVersion + "." + base64.RawURLEncoding.EncodeToString([]byte("token-key-current")) + "."
	if len(newEnvelope) <= len(currentPrefix) || newEnvelope[:len(currentPrefix)] != currentPrefix {
		t.Fatalf("new envelope does not use current key: %q", newEnvelope)
	}
}
