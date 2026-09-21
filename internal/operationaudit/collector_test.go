package operationaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/id"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCollectorAcknowledgementAndReplay(t *testing.T) {
	const secret = "01234567890123456789012345678901"
	c, err := NewCollector("https://control.example", secret, false)
	if err != nil {
		t.Fatal(err)
	}
	event := Event{EventID: id.New(), AssetID: id.New(), SourceRecordID: "auditd:1", OccurredAt: time.Now(), Protocol: "ssh"}
	encoded, _ := json.Marshal(event)
	received := []string{}
	c.client.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/internal/audit/operations/batch" || req.Header.Get("X-Audit-Collector-Secret") != secret {
			t.Fatal("wrong collector destination/authentication")
		}
		var batch struct {
			Events []Event `json:"events"`
		}
		if err := json.NewDecoder(req.Body).Decode(&batch); err != nil {
			t.Fatal(err)
		}
		received = append(received, batch.Events[0].EventID)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"recorded","received":1,"inserted":0}`)), Header: make(http.Header)}, nil
	})
	for range 2 {
		count, err := c.Forward(context.Background(), strings.NewReader(string(encoded)+"\n"))
		if err != nil || count != 1 {
			t.Fatalf("forward: %d %v", count, err)
		}
	}
	if received[0] != received[1] {
		t.Fatal("replay changed event identity")
	}
	c.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(secret))}, nil
	})
	count, err := c.Forward(context.Background(), strings.NewReader(string(encoded)))
	if count != 0 || err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("failure acknowledgement or secret leak: %d %v", count, err)
	}
}

func TestCollectorRejectsUnsafeOriginsAndUnstableRecords(t *testing.T) {
	for _, endpoint := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test?token=secret", "https://example.test/redirect"} {
		if _, err := NewCollector(endpoint, strings.Repeat("a", 32), true); err == nil {
			t.Fatalf("unsafe origin: %s", endpoint)
		}
	}
	c, err := NewCollector("http://127.0.0.1:8080", strings.Repeat("a", 32), true)
	if err != nil {
		t.Fatal(err)
	}
	c.client.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid event reached network")
		return nil, fmt.Errorf("unexpected")
	})
	if _, err := c.Forward(context.Background(), strings.NewReader(`{"protocol":"ssh"}`)); err == nil {
		t.Fatal("missing stable event ID accepted")
	}
}
