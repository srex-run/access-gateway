package gatewayagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The active-session ceiling is 100,000. Keep the decoder bounded while still
// allowing that worst-case active set plus the bounded terminal tombstones.
const maxStateFileBytes = 128 << 20

type StateStore interface {
	Load(ctx context.Context) ([]SessionRecord, error)
	Save(ctx context.Context, sessions []SessionRecord) error
}

type FileStateStore struct {
	path string
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("gateway state file path must be absolute: %w", ErrInvalidInput)
	}
	return &FileStateStore{path: path}, nil
}

func (s *FileStateStore) Load(ctx context.Context) ([]SessionRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("load gateway state: %w", err)
	}
	directory := filepath.Dir(s.path)
	if err := validateProtectedDirectory(directory, "gateway state"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, info, err := openRegularFile(s.path, "gateway state")
	if errors.Is(err, os.ErrNotExist) {
		return []SessionRecord{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway state: %w", err)
	}
	defer file.Close()
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("gateway state must have 0600 permissions: %w", ErrInvalidInput)
	}
	if info.Size() > maxStateFileBytes {
		return nil, fmt.Errorf("gateway state exceeds %d bytes", maxStateFileBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxStateFileBytes+1))
	decoder.DisallowUnknownFields()
	var state persistedState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode gateway state: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode gateway state: %w", err)
	}
	if state.Version != 1 {
		return nil, fmt.Errorf("unsupported gateway state version %d", state.Version)
	}
	if state.Sessions == nil {
		state.Sessions = []SessionRecord{}
	}
	return state.Sessions, nil
}

func (s *FileStateStore) Save(ctx context.Context, sessions []SessionRecord) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("save gateway state: %w", err)
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create gateway state directory: %w", err)
	}
	if err := validateProtectedDirectory(directory, "gateway state"); err != nil {
		return err
	}
	if entry, err := os.Lstat(s.path); err == nil && entry.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("gateway state must not be a symlink: %w", ErrInvalidInput)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat gateway state: %w", err)
	}
	copyOfSessions := append([]SessionRecord(nil), sessions...)
	sort.Slice(copyOfSessions, func(left, right int) bool { return copyOfSessions[left].SessionID < copyOfSessions[right].SessionID })
	encoded, err := json.Marshal(persistedState{Version: 1, Sessions: copyOfSessions})
	if err != nil {
		return fmt.Errorf("encode gateway state: %w", err)
	}
	if len(encoded) > maxStateFileBytes {
		return fmt.Errorf("gateway state exceeds %d bytes", maxStateFileBytes)
	}
	temporary, err := os.CreateTemp(directory, ".sessions-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary gateway state: %w", err)
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect temporary gateway state: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		cleanup()
		return fmt.Errorf("write temporary gateway state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary gateway state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("close temporary gateway state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("save gateway state: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("replace gateway state: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open gateway state directory: %w", err)
	}
	if err := directoryHandle.Sync(); err != nil {
		_ = directoryHandle.Close()
		return fmt.Errorf("sync gateway state directory: %w", err)
	}
	if err := directoryHandle.Close(); err != nil {
		return fmt.Errorf("close gateway state directory: %w", err)
	}
	return nil
}

type persistedState struct {
	Version  int             `json:"version"`
	Sessions []SessionRecord `json:"sessions"`
}
