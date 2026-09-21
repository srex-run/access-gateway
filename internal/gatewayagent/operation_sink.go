package gatewayagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/operationaudit"
)

// Each redacted event is fsynced before delivery. Removal requires an exact
// durable acknowledgement. Recovery forwards evidence, never client commands.
type operationSink struct {
	mu        sync.Mutex
	directory string
	reporter  *AuditReporter
}

func newOperationSink(directory string, reporter *AuditReporter) (*operationSink, error) {
	directory = filepath.Join(directory, "operations")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("operation spool must be a private directory")
	}
	return &operationSink{directory: directory, reporter: reporter}, nil
}

func (s *operationSink) AppendOperation(ctx context.Context, event operationaudit.SessionEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.directory)
	if err != nil || len(entries) >= 4096 {
		return fmt.Errorf("operation audit spool is full or unavailable")
	}
	data, err := json.Marshal(event)
	if err != nil || len(data) > 64<<10 {
		return fmt.Errorf("operation audit event exceeds spool limit")
	}
	f, err := os.CreateTemp(s.directory, ".pending-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	name := event.OccurredAt.UTC().Format("20060102T150405.000000000") + "-" + event.EventID + ".json"
	if err = os.Rename(tmp, filepath.Join(s.directory, name)); err != nil {
		return err
	}
	if err = syncOperationDir(s.directory); err != nil {
		return err
	}
	return s.flushLocked(ctx)
}

func syncOperationDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *operationSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked(ctx)
}
func (s *operationSink) flushLocked(ctx context.Context) error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.directory, entry.Name())
		data, _, err := readProtectedFile(path, "operation audit spool", 64<<10)
		if err != nil {
			return err
		}
		var event operationaudit.SessionEvent
		if json.Unmarshal(data, &event) != nil {
			return fmt.Errorf("invalid operation audit spool")
		}
		payload, _ := json.Marshal(operationaudit.SessionBatch{Events: []operationaudit.SessionEvent{event}})
		r := s.reporter
		endpoint := strings.TrimSuffix(r.endpoint, "/events/batch") + "/operations/batch"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(gatewayauth.SessionIDHeader, r.sessionID)
		req.Header.Set(gateway.AuditGatewayIDHeader, r.gatewayID)
		req.Header.Set(gateway.AuditSecretHeader, r.secret)
		resp, err := r.client.Do(req)
		if err != nil {
			return fmt.Errorf("operation audit control plane unavailable")
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return fmt.Errorf("operation audit acknowledgement returned HTTP %d", resp.StatusCode)
		}
		err = validateAuditAcknowledgement(resp.Body, []gateway.ConnectionEvent{{EventID: event.EventID}})
		resp.Body.Close()
		if err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err = syncOperationDir(s.directory); err != nil {
			return err
		}
	}
	return nil
}
