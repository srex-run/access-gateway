package gatewayagent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
)

type operationRoundTrip func(*http.Request) (*http.Response, error)

func (f operationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOperationSpoolRecoveryRequiresExactAcknowledgement(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offline, wrongAck := true, false
	eventID := id.New()
	sends := 0
	reporter := &AuditReporter{endpoint: "https://control.example/api/v1/internal/gateways/gateway/sessions/session/events/batch", sessionID: "session", gatewayID: "gateway", secret: "session-scoped-test-token"}
	reporter.client = &http.Client{Transport: operationRoundTrip(func(r *http.Request) (*http.Response, error) {
		sends++
		if !strings.HasSuffix(r.URL.Path, "/operations/batch") || r.Header.Get(gatewayauth.SessionIDHeader) != "session" || r.Header.Get(gateway.AuditSecretHeader) != reporter.secret {
			t.Fatal("operation delivery lost session scope")
		}
		var batch operationaudit.SessionBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil || len(batch.Events) != 1 || batch.Events[0].EventID != eventID {
			t.Fatalf("recovery changed operation identity: %v", err)
		}
		status := http.StatusOK
		if offline {
			status = http.StatusServiceUnavailable
		}
		accepted := eventID
		if wrongAck {
			accepted = id.New()
		}
		body, _ := json.Marshal(gateway.ConnectionEventBatchResponse{Version: gateway.ConnectionEventBatchResponseVersion, AcceptedEventIDs: []string{accepted}})
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}
	sink, err := newOperationSink(directory, reporter)
	if err != nil {
		t.Fatal(err)
	}
	event := operationaudit.SessionEvent{ConnectionID: id.New(), OperationID: id.New(), Phase: "started", Event: operationaudit.Event{EventID: eventID, Protocol: "ssh", OccurredAt: time.Now().UTC()}}
	if err := sink.AppendOperation(context.Background(), event); err == nil {
		t.Fatal("offline audit accepted")
	}
	assertPending := func(want int) {
		t.Helper()
		files, err := os.ReadDir(filepath.Join(directory, "operations"))
		if err != nil || len(files) != want {
			t.Fatalf("pending spool files: %d %v", len(files), err)
		}
		for _, f := range files {
			info, _ := f.Info()
			if info.Mode().Perm() != 0600 {
				t.Fatal("operation evidence is not private")
			}
		}
	}
	assertPending(1)
	// Simulate a fresh reporter after the session agent has exited. Only evidence
	// is resubmitted, using the original ID; no connection or command is replayed.
	recovered, err := newOperationSink(directory, reporter)
	if err != nil {
		t.Fatal(err)
	}
	offline, wrongAck = false, true
	if err = recovered.Flush(context.Background()); err == nil {
		t.Fatal("foreign acknowledgement accepted")
	}
	assertPending(1)
	wrongAck = false
	if err = recovered.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertPending(0)
	if sends != 3 {
		t.Fatalf("unexpected delivery count: %d", sends)
	}
}
