package gatewayagent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type StateLock struct {
	file *os.File
}

func AcquireStateLock(stateFile string) (*StateLock, error) {
	stateFile = filepath.Clean(strings.TrimSpace(stateFile))
	if stateFile == "." || !filepath.IsAbs(stateFile) {
		return nil, fmt.Errorf("gateway state lock path must be absolute: %w", ErrInvalidInput)
	}
	directory := filepath.Dir(stateFile)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create gateway state directory for lock: %w", err)
	}
	if err := validateProtectedDirectory(directory, "gateway state"); err != nil {
		return nil, err
	}
	lockPath := stateFile + ".lock"
	entry, lstatErr := os.Lstat(lockPath)
	if lstatErr != nil && !os.IsNotExist(lstatErr) {
		return nil, fmt.Errorf("lstat gateway state lock: %w", lstatErr)
	}
	if lstatErr == nil && entry.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("gateway state lock must not be a symlink: %w", ErrInvalidInput)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open gateway state lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat gateway state lock: %w", err)
	}
	openedEntry, err := os.Lstat(lockPath)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lstat gateway state lock after open: %w", err)
	}
	if openedEntry.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !os.SameFile(openedEntry, info) || (entry != nil && !os.SameFile(entry, info)) {
		_ = file.Close()
		return nil, fmt.Errorf("gateway state lock permissions are unsafe: %w", ErrInvalidInput)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire gateway state lock: %w", err)
	}
	return &StateLock{file: file}, nil
}

func (l *StateLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("release gateway state lock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close gateway state lock: %w", closeErr)
	}
	return nil
}
