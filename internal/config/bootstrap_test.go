package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptionKeyRequiredForSettingsAndLogin(t *testing.T) {
	clearOptionalConfig(t)
	t.Setenv("ENCRYPTION_KEY", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Fatalf("missing encryption key: %v", err)
	}
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("m", 32))
	t.Setenv("AUTH_LOCAL_ENABLED", "invalid-retired-value")
	t.Setenv("OIDC_ENABLED", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("provider settings must come from database: %v", err)
	}
}

func TestEncryptionKeyFilePreservesValueAndRejectsAmbiguousSources(t *testing.T) {
	clearOptionalConfig(t)
	const key = "unchanged-encryption-key-32-bytes-minimum"
	file := filepath.Join(t.TempDir(), "encryption-key")
	if err := os.WriteFile(file, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("ENCRYPTION_KEY_FILE", file)
	cfg, err := Load()
	if err != nil || cfg.EncryptionKey != key {
		t.Fatalf("encryption key file was not loaded unchanged: %v", err)
	}
	t.Setenv("ENCRYPTION_KEY", key)
	if _, err := Load(); err == nil {
		t.Fatal("ambiguous encryption key sources were accepted")
	}
}
