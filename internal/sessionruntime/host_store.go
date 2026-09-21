package sessionruntime

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/id"
)

type hostStore struct {
	root *os.Root
	path string
	lock *gatewayagent.StateLock
}

func openHostStore(path string) (*hostStore, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("session state directory must be absolute")
	}
	lock, err := gatewayagent.AcquireStateLock(filepath.Join(path, "controller"))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		_ = lock.Close()
		return nil, fmt.Errorf("session state directory must have permissions 0700")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	s := &hostStore{root: root, path: path, lock: lock}
	for _, name := range []string{"records", "grants", "agents"} {
		if err := root.MkdirAll(name, 0o700); err != nil {
			_ = s.Close()
			return nil, err
		}
		info, err := root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			_ = s.Close()
			return nil, fmt.Errorf("session state subdirectory is not private")
		}
	}
	return s, nil
}

func (s *hostStore) Close() error {
	err := s.root.Close()
	lockErr := s.lock.Close()
	if err != nil {
		return err
	}
	return lockErr
}

func (s *hostStore) read(name string, result any) error {
	file, err := s.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o177 != 0 || info.Size() > 1<<20 {
		return fmt.Errorf("session record is not a protected regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("invalid session record: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("session record has trailing data")
	}
	return nil
}

func (s *hostStore) write(name string, value any, mode os.FileMode) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	temporary := filepath.Join(filepath.Dir(name), ".pending-"+id.New())
	file, err := s.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer s.root.Remove(temporary)
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	for _, err := range []error{writeErr, syncErr, closeErr} {
		if err != nil {
			return err
		}
	}
	if err := s.root.Rename(temporary, name); err != nil {
		return err
	}
	directory, err := s.root.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *hostStore) save(record *hostRecord) error {
	return s.write(filepath.Join("records", record.SessionID+".json"), record, 0o600)
}

func (s *hostStore) grantPath(sessionID string) string {
	return filepath.Join(s.path, "grants", sessionID+".json")
}

func (s *hostStore) agentPath(sessionID string) string {
	return filepath.Join(s.path, "agents", sessionID)
}
