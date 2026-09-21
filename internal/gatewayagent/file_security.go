package gatewayagent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxProtectedFileBytes = 1 << 20

func validateProtectedDirectory(directory, purpose string) error {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "." || !filepath.IsAbs(directory) {
		return fmt.Errorf("%s directory must be absolute: %w", purpose, ErrInvalidInput)
	}
	if err := rejectSymlinkComponents(directory, purpose); err != nil {
		return err
	}
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat %s directory: %w", purpose, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s directory must not be group or world writable: %w", purpose, ErrInvalidInput)
	}
	if info.Mode().Perm()&0o022 != 0 && !hasPrivateAncestor(directory) {
		return fmt.Errorf("%s directory must not be group or world writable: %w", purpose, ErrInvalidInput)
	}
	return nil
}

func rejectSymlinkComponents(path, purpose string) error {
	volume := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, volume)
	rooted := strings.HasPrefix(rest, string(filepath.Separator))
	parts := strings.Split(strings.TrimPrefix(rest, string(filepath.Separator)), string(filepath.Separator))
	current := volume
	if rooted {
		current += string(filepath.Separator)
	}
	if current == "" {
		current = "."
	}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		entry, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("lstat %s directory component: %w", purpose, err)
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s directory must not contain symlink components: %w", purpose, ErrInvalidInput)
		}
	}
	return nil
}

// openRegularFile opens a file only after checking the directory entry itself.
// os.Stat follows a final symlink, which would let a pre-created link redirect
// an otherwise trusted path to an unrelated file. Comparing the lstat result
// with the descriptor's fstat result also detects a simple replacement race
// between the checks and the open.
func openRegularFile(path, purpose string) (*os.File, os.FileInfo, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("lstat %s: %w", purpose, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s must be a regular file and not a symlink: %w", purpose, ErrInvalidInput)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", purpose, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat %s: %w", purpose, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(entry, info) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed while opening: %w", purpose, ErrInvalidInput)
	}
	return file, info, nil
}

// readProtectedFile applies the same file identity and permission checks to
// configuration material such as TLS certificates and keys.  In particular,
// it never follows a final symlink and bounds the amount of data read.
func readProtectedFile(path, purpose string, limit int64) ([]byte, os.FileInfo, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, nil, fmt.Errorf("%s path must be absolute: %w", purpose, ErrInvalidInput)
	}
	if err := validateProtectedDirectory(filepath.Dir(path), purpose); err != nil {
		return nil, nil, err
	}
	if limit <= 0 || limit > maxProtectedFileBytes {
		limit = maxProtectedFileBytes
	}
	file, info, err := openRegularFile(path, purpose)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	if info.Mode().Perm()&0o022 != 0 {
		return nil, nil, fmt.Errorf("%s must not be group or world writable: %w", purpose, ErrInvalidInput)
	}
	if info.Size() > limit {
		return nil, nil, fmt.Errorf("%s exceeds %d bytes: %w", purpose, limit, ErrInvalidInput)
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", purpose, err)
	}
	if int64(len(value)) > limit {
		return nil, nil, fmt.Errorf("%s exceeds %d bytes: %w", purpose, limit, ErrInvalidInput)
	}
	return value, info, nil
}

// A writable leaf is acceptable only when a private ancestor prevents another
// OS user from traversing to it. Ordinary shared paths such as /tmp and /var
// remain rejected because their write bits expand the trust boundary.
func hasPrivateAncestor(path string) bool {
	for parent := filepath.Dir(path); ; {
		info, err := os.Lstat(parent)
		if err == nil && info.IsDir() && info.Mode().Perm()&0o077 == 0 {
			return true
		}
		next := filepath.Dir(parent)
		if next == parent {
			return false
		}
		parent = next
	}
}
