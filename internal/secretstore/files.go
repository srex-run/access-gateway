package secretstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxSecretFileBytes          = 64 << 10
	maxCredentialReferenceBytes = 253
	minCredentialBytes          = 32
	maxCredentialBytes          = 512
	maxCredentialsPerBundle     = 4
)

type CredentialResolver interface {
	Resolve(context.Context, string) ([][]byte, error)
}

// DirectoryCredentialResolver resolves a database reference to one protected
// file below a dedicated directory. A file may contain a current credential
// and up to three previous credentials, one per line, for zero-downtime
// rotation across control-plane replicas.
type DirectoryCredentialResolver struct {
	directory string
}

func NewDirectoryCredentialResolver(directory string) (*DirectoryCredentialResolver, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("credential directory must be an absolute path")
	}
	entry, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat credential directory: %w", err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() || entry.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential directory must be a private non-symlink directory")
	}
	return &DirectoryCredentialResolver{directory: directory}, nil
}

func (r *DirectoryCredentialResolver) Resolve(ctx context.Context, reference string) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resolve credential: %w", err)
	}
	if r == nil || r.directory == "" {
		return nil, fmt.Errorf("credential resolver is not configured")
	}
	if err := ValidateCredentialReference(reference); err != nil {
		return nil, err
	}
	encoded, err := ReadProtectedFile(filepath.Join(r.directory, reference))
	if err != nil {
		// ReadProtectedFile may return an *os.PathError whose path ends with the
		// database-backed reference. Keep that identifier out of request logs.
		return nil, fmt.Errorf("credential reference file is unavailable or unsafe")
	}
	defer clear(encoded)
	encoded = bytes.TrimSuffix(encoded, []byte{'\n'})
	encoded = bytes.TrimSuffix(encoded, []byte{'\r'})
	lines := bytes.Split(encoded, []byte{'\n'})
	if len(lines) < 1 || len(lines) > maxCredentialsPerBundle {
		return nil, fmt.Errorf("credential bundle must contain between 1 and %d credentials", maxCredentialsPerBundle)
	}
	credentials := make([][]byte, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if err := ValidateCredential(line); err != nil {
			clearCredentials(credentials)
			return nil, err
		}
		for _, existing := range credentials {
			if bytes.Equal(existing, line) {
				clearCredentials(credentials)
				return nil, fmt.Errorf("credential bundle contains a duplicate credential")
			}
		}
		credentials = append(credentials, bytes.Clone(line))
	}
	return credentials, nil
}

func ValidateCredentialReference(reference string) error {
	if reference == "" || len(reference) > maxCredentialReferenceBytes || strings.TrimSpace(reference) != reference {
		return fmt.Errorf("credential reference is invalid")
	}
	for index := 0; index < len(reference); index++ {
		value := reference[index]
		alphaNumeric := value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
		if alphaNumeric {
			continue
		}
		if index == 0 || index == len(reference)-1 || value != '-' && value != '_' && value != '.' {
			return fmt.Errorf("credential reference is invalid")
		}
	}
	return nil
}

func ValidateCredential(value []byte) error {
	if len(value) < minCredentialBytes || len(value) > maxCredentialBytes {
		return fmt.Errorf("credential must contain between %d and %d bytes", minCredentialBytes, maxCredentialBytes)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("credential must contain visible ASCII characters only")
		}
	}
	return nil
}

func clearCredentials(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}

func FromEnvironment(name string) (string, error) {
	value, valueSet := os.LookupEnv(name)
	filePath, fileSet := os.LookupEnv(name + "_FILE")
	filePath = strings.TrimSpace(filePath)
	if valueSet && value != "" && fileSet && filePath != "" {
		return "", fmt.Errorf("%s and %s_FILE cannot both be configured", name, name)
	}
	if filePath == "" {
		return value, nil
	}
	encoded, err := ReadProtectedFile(filePath)
	if err != nil {
		return "", fmt.Errorf("load %s_FILE: %w", name, err)
	}
	return trimLineEnding(string(encoded)), nil
}

func ReadProtectedFile(path string) ([]byte, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("secret file path must be absolute")
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat secret file: %w", err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return nil, fmt.Errorf("secret file must be a regular non-symlink file")
	}
	if entry.Mode().Perm()&0o027 != 0 {
		return nil, fmt.Errorf("secret file must not be group-writable or accessible by other users")
	}
	if entry.Size() < 1 || entry.Size() > maxSecretFileBytes {
		return nil, fmt.Errorf("secret file size is invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	if len(encoded) < 1 || len(encoded) > maxSecretFileBytes {
		clear(encoded)
		return nil, fmt.Errorf("secret file size changed while reading")
	}
	return encoded, nil
}

func trimLineEnding(value string) string {
	value = strings.TrimSuffix(value, "\n")
	return strings.TrimSuffix(value, "\r")
}
