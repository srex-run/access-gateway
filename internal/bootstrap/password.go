package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
)

// Persist the password before committing the account so interrupted attempts
// can reuse it. Never publish a partially written file or overwrite a secret.
func initialPassword(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("BOOTSTRAP_ADMIN_PASSWORD_FILE must be an absolute path for first initialization")
	}
	password, err := readPassword(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return password, err
	}
	directory := filepath.Dir(path)
	entry, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("open bootstrap password directory: %w", err)
	}
	if !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("bootstrap password directory must be private and not a symlink")
	}
	password, err = security.NewToken()
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, ".bootstrap-password-*")
	if err != nil {
		return "", fmt.Errorf("create bootstrap password: %w", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.WriteString(password + "\n"); err != nil {
		return "", fmt.Errorf("write bootstrap password: %w", err)
	}
	if err := file.Chmod(0o400); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("publish bootstrap password: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return "", fmt.Errorf("persist bootstrap password directory: %w", err)
	}
	return readPassword(path)
}

func readPassword(path string) (string, error) {
	encoded, err := secretstore.ReadProtectedFile(path)
	if err != nil {
		return "", fmt.Errorf("read bootstrap password file: %w", err)
	}
	defer clear(encoded)
	return strings.TrimSuffix(strings.TrimSuffix(string(encoded), "\n"), "\r"), nil
}
