package gatewayagent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
)

func TestFileEventSpoolPersistsDeduplicatesAndCompacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection-events.jsonl")
	spool, err := NewFileEventSpool(path)
	if err != nil {
		t.Fatalf("NewFileEventSpool: %v", err)
	}
	first := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
	second := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2")
	if err := spool.Append(context.Background(), first); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if err := spool.Append(context.Background(), first); err != nil {
		t.Fatalf("Append duplicate: %v", err)
	}
	if err := spool.Append(context.Background(), second); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	if pending := spool.Pending(100); len(pending) != 2 || pending[0].EventID != first.EventID || pending[1].EventID != second.EventID {
		t.Fatalf("pending events = %+v", pending)
	}
	reopened, err := NewFileEventSpool(path)
	if err != nil {
		t.Fatalf("reopen spool: %v", err)
	}
	if err := reopened.Ack(context.Background(), []string{first.EventID}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if pending := reopened.Pending(100); len(pending) != 1 || pending[0].EventID != second.EventID {
		t.Fatalf("compacted events = %+v", pending)
	}
	final, err := NewFileEventSpool(path)
	if err != nil {
		t.Fatalf("reopen compacted spool: %v", err)
	}
	if pending := final.Pending(100); len(pending) != 1 || pending[0].EventID != second.EventID {
		t.Fatalf("persisted compacted events = %+v", pending)
	}
}

func TestFileEventSpoolRejectsCorruptionAndUnsafePermissions(t *testing.T) {
	directory := t.TempDir()
	corruptPath := filepath.Join(directory, "corrupt.jsonl")
	if err := os.WriteFile(corruptPath, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("write corrupt spool: %v", err)
	}
	if _, err := NewFileEventSpool(corruptPath); err == nil {
		t.Fatal("corrupt spool was accepted")
	}
	event, err := json.Marshal(validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"))
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	unsafePath := filepath.Join(directory, "unsafe.jsonl")
	if err := os.WriteFile(unsafePath, append(event, '\n'), 0o644); err != nil {
		t.Fatalf("write unsafe spool: %v", err)
	}
	if _, err := NewFileEventSpool(unsafePath); err == nil {
		t.Fatal("world-readable spool was accepted")
	}
}

func TestAuditReporterRetriesWithoutLosingEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connection-events.jsonl")
	spool, err := NewFileEventSpool(path)
	if err != nil {
		t.Fatalf("NewFileEventSpool: %v", err)
	}
	event := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4")
	if err := spool.Append(context.Background(), event); err != nil {
		t.Fatalf("Append: %v", err)
	}
	var calls atomic.Int32
	client := &http.Client{Transport: auditRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/internal/gateway/events/batch" || request.Header.Get(gateway.AuditGatewayIDHeader) != event.GatewayID || request.Header.Get(gateway.AuditSecretHeader) != testGatewaySecret || request.Header.Get(gateway.InternalSecretHeader) != "" {
			t.Errorf("unexpected audit request %s headers=%v", request.URL.Path, request.Header)
			return auditResponse(http.StatusBadRequest, ""), nil
		}
		var batch gateway.ConnectionEventBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil || len(batch.Events) != 1 || batch.Events[0].EventID != event.EventID {
			t.Errorf("audit batch = %+v, %v", batch, err)
			return auditResponse(http.StatusBadRequest, ""), nil
		}
		if calls.Add(1) == 1 {
			return auditResponse(http.StatusServiceUnavailable, ""), nil
		}
		encoded, err := json.Marshal(gateway.ConnectionEventBatchResponse{
			Version:          gateway.ConnectionEventBatchResponseVersion,
			AcceptedEventIDs: []string{event.EventID},
		})
		if err != nil {
			t.Fatalf("marshal acknowledgement: %v", err)
		}
		return auditResponse(http.StatusOK, string(encoded)), nil
	})}
	reporter, err := NewAuditReporter(spool, AuditReporterOptions{
		ControlPlaneURL: "https://control-plane.test", GatewayID: event.GatewayID, AuditSecret: testGatewaySecret,
		HTTPClient: client, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("NewAuditReporter: %v", err)
	}
	if count, err := reporter.Flush(context.Background()); err == nil || count != 0 || len(spool.Pending(100)) != 1 {
		t.Fatalf("failed Flush count=%d err=%v pending=%d", count, err, len(spool.Pending(100)))
	}
	if count, err := reporter.Flush(context.Background()); err != nil || count != 1 || len(spool.Pending(100)) != 0 {
		t.Fatalf("retried Flush count=%d err=%v pending=%d", count, err, len(spool.Pending(100)))
	}
}

func TestAuditReporterRetainsEventsUntilExactAcknowledgement(t *testing.T) {
	event := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5")
	valid := `{"version":1,"accepted_event_ids":["` + event.EventID + `"]}`
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "no content", status: http.StatusNoContent, body: valid},
		{name: "empty response", status: http.StatusOK},
		{name: "wrong version", status: http.StatusOK, body: `{"version":2,"accepted_event_ids":["` + event.EventID + `"]}`},
		{name: "missing event", status: http.StatusOK, body: `{"version":1,"accepted_event_ids":[]}`},
		{name: "wrong event", status: http.StatusOK, body: `{"version":1,"accepted_event_ids":["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6"]}`},
		{name: "unknown field", status: http.StatusOK, body: strings.TrimSuffix(valid, "}") + `,"unexpected":true}`},
		{name: "trailing document", status: http.StatusOK, body: valid + `{}`},
		{name: "oversized response", status: http.StatusOK, body: strings.Repeat(" ", maxAuditAcknowledgementBytes+1) + valid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spool, err := NewFileEventSpool(filepath.Join(t.TempDir(), "connection-events.jsonl"))
			if err != nil {
				t.Fatalf("NewFileEventSpool: %v", err)
			}
			if err := spool.Append(context.Background(), event); err != nil {
				t.Fatalf("Append: %v", err)
			}
			client := &http.Client{Transport: auditRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}
			reporter, err := NewAuditReporter(spool, AuditReporterOptions{
				ControlPlaneURL: "https://control-plane.test", GatewayID: event.GatewayID, InternalSecret: testGatewaySecret,
				HTTPClient: client, Logger: zerolog.Nop(),
			})
			if err != nil {
				t.Fatalf("NewAuditReporter: %v", err)
			}
			if count, flushErr := reporter.Flush(context.Background()); flushErr == nil || count != 0 || spool.PendingCount() != 1 {
				t.Fatalf("Flush count=%d err=%v pending=%d", count, flushErr, spool.PendingCount())
			}
		})
	}
}

func TestAuditReporterRejectsEventsFromAnotherGateway(t *testing.T) {
	spool, err := NewFileEventSpool(filepath.Join(t.TempDir(), "connection-events.jsonl"))
	if err != nil {
		t.Fatalf("NewFileEventSpool: %v", err)
	}
	event := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7")
	if err := spool.Append(context.Background(), event); err != nil {
		t.Fatalf("Append: %v", err)
	}
	clientCalls := 0
	reporter, err := NewAuditReporter(spool, AuditReporterOptions{
		ControlPlaneURL: "https://control-plane.test",
		GatewayID:       "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		AuditSecret:     testGatewaySecret,
		HTTPClient: &http.Client{Transport: auditRoundTripFunc(func(*http.Request) (*http.Response, error) {
			clientCalls++
			return auditResponse(http.StatusOK, "{}"), nil
		})},
		Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("NewAuditReporter: %v", err)
	}
	if count, flushErr := reporter.Flush(context.Background()); flushErr == nil || count != 0 || clientCalls != 0 || spool.PendingCount() != 1 {
		t.Fatalf("Flush count=%d err=%v calls=%d pending=%d", count, flushErr, clientCalls, spool.PendingCount())
	}
}

func TestAuditReporterRejectsReusedManagementCredential(t *testing.T) {
	event := validSpoolEvent("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa8")
	spool, err := NewFileEventSpool(filepath.Join(t.TempDir(), "connection-events.jsonl"))
	if err != nil {
		t.Fatalf("NewFileEventSpool: %v", err)
	}
	if _, err := NewAuditReporter(spool, AuditReporterOptions{
		ControlPlaneURL: "https://control-plane.test",
		GatewayID:       event.GatewayID,
		AuditSecret:     testGatewaySecret,
		InternalSecret:  testGatewaySecret,
	}); err == nil {
		t.Fatal("audit reporter accepted a reused management credential")
	}
}

type auditRoundTripFunc func(*http.Request) (*http.Response, error)

func (f auditRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func auditResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func validSpoolEvent(eventID string) gateway.ConnectionEvent {
	return gateway.ConnectionEvent{
		EventID: eventID, GatewayID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		ConnectionID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		SessionID:    testGatewaySessionID, EventType: "connect_attempt",
		SourceIP: "127.0.0.1", Result: "received", OccurredAt: time.Now().UTC(),
	}
}
