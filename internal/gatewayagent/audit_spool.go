package gatewayagent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
)

const (
	maxAuditSpoolBytes  = 256 << 20
	maxAuditSpoolEvents = 100000
)

type ConnectionEventSink interface {
	Append(ctx context.Context, event gateway.ConnectionEvent) error
}

type FileEventSpool struct {
	mu     sync.Mutex
	path   string
	events []gateway.ConnectionEvent
	ids    map[string]struct{}
}

func NewFileEventSpool(path string) (*FileEventSpool, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("gateway audit spool path must be absolute: %w", ErrInvalidInput)
	}
	spool := &FileEventSpool{path: path, ids: make(map[string]struct{})}
	if err := spool.load(); err != nil {
		return nil, err
	}
	return spool, nil
}

func (s *FileEventSpool) Append(ctx context.Context, event gateway.ConnectionEvent) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("append gateway audit event: %w", err)
	}
	if err := validateConnectionEvent(event); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode gateway audit event: %w", err)
	}
	encoded = append(encoded, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.ids[event.EventID]; exists {
		return nil
	}
	if len(s.events) >= maxAuditSpoolEvents {
		return fmt.Errorf("gateway audit spool reached its event limit")
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create gateway audit spool directory: %w", err)
	}
	if err := validateProtectedDirectory(directory, "gateway audit spool"); err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open gateway audit spool: %w", err)
	}
	closeWithError := func(current error) error {
		if closeErr := file.Close(); closeErr != nil {
			return errors.Join(current, fmt.Errorf("close gateway audit spool: %w", closeErr))
		}
		return current
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("stat gateway audit spool: %w", err))
	}
	entry, err := os.Lstat(s.path)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() || !os.SameFile(entry, info) || info.Mode().Perm() != 0o600 {
		return closeWithError(fmt.Errorf("gateway audit spool must be an unchanged 0600 regular file: %w", ErrInvalidInput))
	}
	if info.Size()+int64(len(encoded)) > maxAuditSpoolBytes {
		return closeWithError(fmt.Errorf("gateway audit spool reached its byte limit"))
	}
	if _, err := file.Write(encoded); err != nil {
		return closeWithError(fmt.Errorf("write gateway audit spool: %w", err))
	}
	if err := file.Sync(); err != nil {
		return closeWithError(fmt.Errorf("sync gateway audit spool: %w", err))
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close gateway audit spool: %w", err)
	}
	s.events = append(s.events, event)
	s.ids[event.EventID] = struct{}{}
	return nil
}

func (s *FileEventSpool) Pending(limit int) []gateway.ConnectionEvent {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit > len(s.events) {
		limit = len(s.events)
	}
	return append([]gateway.ConnectionEvent(nil), s.events[:limit]...)
}

func (s *FileEventSpool) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *FileEventSpool) Ack(ctx context.Context, eventIDs []string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("acknowledge gateway audit events: %w", err)
	}
	if len(eventIDs) == 0 {
		return nil
	}
	acknowledged := make(map[string]struct{}, len(eventIDs))
	for _, eventID := range eventIDs {
		if !id.IsUUID(eventID) {
			return fmt.Errorf("gateway audit acknowledgement contains an invalid event ID")
		}
		acknowledged[eventID] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := make([]gateway.ConnectionEvent, 0, len(s.events))
	for _, event := range s.events {
		if _, remove := acknowledged[event.EventID]; remove {
			continue
		}
		remaining = append(remaining, event)
	}
	if len(remaining) == len(s.events) {
		return nil
	}
	if err := s.replace(ctx, remaining); err != nil {
		return err
	}
	s.events = remaining
	s.ids = make(map[string]struct{}, len(remaining))
	for _, event := range remaining {
		s.ids[event.EventID] = struct{}{}
	}
	return nil
}

func (s *FileEventSpool) load() error {
	directory := filepath.Dir(s.path)
	if err := validateProtectedDirectory(directory, "gateway audit spool"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, info, err := openRegularFile(s.path, "gateway audit spool")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if info.Mode().Perm() != 0o600 || info.Size() > maxAuditSpoolBytes {
		return fmt.Errorf("gateway audit spool permissions or size are invalid: %w", ErrInvalidInput)
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxAuditSpoolBytes+1))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var event gateway.ConnectionEvent
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return fmt.Errorf("decode gateway audit spool: %w", err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return fmt.Errorf("decode gateway audit spool: %w", err)
		}
		if err := validateConnectionEvent(event); err != nil {
			return fmt.Errorf("validate gateway audit spool: %w", err)
		}
		if _, exists := s.ids[event.EventID]; exists {
			return fmt.Errorf("gateway audit spool contains duplicate event ID: %w", ErrInvalidInput)
		}
		s.events = append(s.events, event)
		s.ids[event.EventID] = struct{}{}
		if len(s.events) > maxAuditSpoolEvents {
			return fmt.Errorf("gateway audit spool contains too many events: %w", ErrInvalidInput)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read gateway audit spool: %w", err)
	}
	return nil
}

func (s *FileEventSpool) replace(ctx context.Context, events []gateway.ConnectionEvent) error {
	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".audit-spool-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary gateway audit spool: %w", err)
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect temporary gateway audit spool: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			cleanup()
			return fmt.Errorf("write temporary gateway audit spool: %w", err)
		}
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary gateway audit spool: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("close temporary gateway audit spool: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("replace gateway audit spool: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		_ = os.Remove(temporaryName)
		return fmt.Errorf("replace gateway audit spool: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open gateway audit spool directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync gateway audit spool directory: %w", err)
	}
	return nil
}

func validateConnectionEvent(event gateway.ConnectionEvent) error {
	if !id.IsUUID(event.EventID) || !id.IsUUID(event.GatewayID) || !id.IsUUID(event.ConnectionID) || !id.IsUUID(event.SessionID) || event.OccurredAt.IsZero() {
		return fmt.Errorf("gateway connection event identity is invalid: %w", ErrInvalidInput)
	}
	allowed := map[string]struct{}{
		"connect_attempt": {}, "source_rejected": {}, "capacity_rejected": {}, "auth_rejected": {},
		"backend_connected": {}, "backend_failed": {}, "disconnected": {},
	}
	if _, exists := allowed[event.EventType]; !exists {
		return fmt.Errorf("gateway connection event type is invalid: %w", ErrInvalidInput)
	}
	for _, value := range []string{event.SourceIP, event.BackendSourceIP} {
		if value != "" && netParseIP(value) == "" {
			return fmt.Errorf("gateway connection event IP is invalid: %w", ErrInvalidInput)
		}
	}
	if event.BackendSourcePort < 0 || event.BackendSourcePort > 65535 || len(event.Result) > 32 || len(event.Reason) > 256 {
		return fmt.Errorf("gateway connection event details are invalid: %w", ErrInvalidInput)
	}
	for _, value := range []*int64{event.BytesUp, event.BytesDown, event.DurationMS} {
		if value != nil && *value < 0 {
			return fmt.Errorf("gateway connection event counters are invalid: %w", ErrInvalidInput)
		}
	}
	return nil
}

func netParseIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil || address.IsUnspecified() || address.IsMulticast() {
		return ""
	}
	return address.Unmap().String()
}

func sortedEventIDs(events []gateway.ConnectionEvent) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	sort.Strings(ids)
	return ids
}
