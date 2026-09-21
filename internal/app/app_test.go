package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/config"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
)

func TestConfiguredAssetCipherUsesEncryptionKeyByDefault(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{EncryptionKey: strings.Repeat("m", 32)}
	cipher, err := configuredAssetCipher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const target = "10.0.0.8"
	assetID := []byte("11111111-1111-4111-8111-111111111111")
	envelope, err := cipher.Encrypt(ctx, []byte(target), assetID)
	if err != nil || strings.Contains(envelope, target) {
		t.Fatalf("target encryption failed: %v", err)
	}
	restarted, err := configuredAssetCipher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := restarted.Decrypt(ctx, envelope, assetID)
	if err != nil || string(plaintext) != target {
		t.Fatalf("target did not survive cipher reinitialization: %v", err)
	}
	if _, err := restarted.Decrypt(ctx, envelope, []byte("another-asset")); err == nil {
		t.Fatal("target decrypted under a different asset identity")
	}
	wrongKey, err := configuredAssetCipher(config.Config{EncryptionKey: strings.Repeat("x", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongKey.Decrypt(ctx, envelope, assetID); err == nil {
		t.Fatal("target decrypted under a different encryption key")
	}
	otherPurpose, err := secretstore.NewAESGCM("asset-master-v1", security.DeriveKey(cfg.EncryptionKey, "cloud-assets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherPurpose.Decrypt(ctx, envelope, assetID); err == nil {
		t.Fatal("asset encryption key was not separated from cloud encryption")
	}
}

func TestConfiguredAssetCipherPreservesExplicitKey(t *testing.T) {
	ctx := context.Background()
	key := []byte(strings.Repeat("k", 32))
	keyPath := filepath.Join(t.TempDir(), "asset-key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := secretstore.NewAESGCM("existing-key-v1", key)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("asset-id")
	existing, err := legacy.Encrypt(ctx, []byte("mysql.internal.example.com"), aad)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := configuredAssetCipher(config.Config{
		EncryptionKey: strings.Repeat("m", 32), AssetEncryptionKeyFile: keyPath, AssetEncryptionKeyID: "existing-key-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := cipher.Decrypt(ctx, existing, aad)
	if err != nil || string(plaintext) != "mysql.internal.example.com" {
		t.Fatalf("existing target did not decrypt: %v", err)
	}
	created, err := cipher.Encrypt(ctx, []byte("10.0.0.8"), aad)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = legacy.Decrypt(ctx, created, aad)
	if err != nil || string(plaintext) != "10.0.0.8" {
		t.Fatalf("new target did not use the configured asset key: %v", err)
	}
}

func TestRenamedEncryptionKeyDecryptsExistingAssetEnvelope(t *testing.T) {
	cipher, err := configuredAssetCipher(config.Config{EncryptionKey: "compatibility-test-encryption-key"})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed legacy envelope, independent of the current Encrypt implementation.
	const envelope = "agk1.YXNzZXQtbWFzdGVyLXYx.AAECAwQFBgcICQoLuMaGBK6ZXPLJcUxBvXaaXKxidsgYi4De"
	plaintext, err := cipher.Decrypt(context.Background(), envelope, []byte("11111111-1111-4111-8111-111111111111"))
	if err != nil || string(plaintext) != "10.0.0.8" {
		t.Fatal("existing asset could not be decrypted after the configuration rename")
	}
}

func TestConfiguredAssetCipherRejectsInvalidExplicitKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "asset-key")
	cfg := config.Config{EncryptionKey: strings.Repeat("m", 32), AssetEncryptionKeyFile: keyPath, AssetEncryptionKeyID: "key-v1"}
	if _, err := configuredAssetCipher(cfg); err == nil {
		t.Fatal("missing explicit asset key silently fell back to the encryption key")
	}
	if err := os.WriteFile(keyPath, []byte("invalid-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredAssetCipher(cfg); err == nil {
		t.Fatal("invalid explicit asset key silently fell back to the encryption key")
	}
}
