package worker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type recordingHandler struct {
	mu          sync.Mutex
	provisioned []string
	revoked     []string
	outboxCalls int
	healthCalls int
	health      []service.GatewayHealthResult
	healthErr   error
	statsCalls  int
}

func (h *recordingHandler) GetOperationalStats(context.Context) (service.OperationalStats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statsCalls++
	return service.OperationalStats{OutboxPending: 2, DatabaseMaxOpen: 10, DatabaseOpen: 2, DatabaseInUse: 1, DatabaseIdle: 1}, nil
}

func (h *recordingHandler) ProvisionSession(_ context.Context, id string) (domain.Session, error) {
	h.mu.Lock()
	h.provisioned = append(h.provisioned, id)
	h.mu.Unlock()
	return domain.Session{ID: id}, nil
}

func (h *recordingHandler) RevokeSession(_ context.Context, id, _ string) (domain.Session, error) {
	h.mu.Lock()
	h.revoked = append(h.revoked, id)
	h.mu.Unlock()
	return domain.Session{ID: id}, nil
}

func (h *recordingHandler) ReapExpired(context.Context, int) (int, error) { return 0, nil }

func (h *recordingHandler) ProcessOutbox(context.Context, int) (int, error) {
	h.mu.Lock()
	h.outboxCalls++
	h.mu.Unlock()
	return 0, nil
}

func (h *recordingHandler) ProbeGateways(context.Context) ([]service.GatewayHealthResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healthCalls++
	return append([]service.GatewayHealthResult(nil), h.health...), h.healthErr
}

func TestQueueAndRunnerDispatchTasks(t *testing.T) {
	queue := NewQueue(2)
	handler := &recordingHandler{}
	runner, err := NewRunner(queue, handler, zerolog.Nop(), time.Hour)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = runner.Run(ctx)
		close(done)
	}()
	if err := queue.Enqueue(context.Background(), service.Task{Kind: service.TaskProvision, SessionID: "s1"}); err != nil {
		t.Fatalf("enqueue provision: %v", err)
	}
	if err := queue.Enqueue(context.Background(), service.Task{Kind: service.TaskRevoke, SessionID: "s2", Reason: "expired"}); err != nil {
		t.Fatalf("enqueue revoke: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		handler.mu.Lock()
		complete := len(handler.provisioned) == 1 && len(handler.revoked) == 1 && handler.outboxCalls > 0 && handler.healthCalls > 0
		handler.mu.Unlock()
		if complete {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner did not stop")
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.provisioned) != 1 || handler.provisioned[0] != "s1" || len(handler.revoked) != 1 || handler.revoked[0] != "s2" || handler.outboxCalls == 0 || handler.healthCalls == 0 {
		t.Fatalf("dispatch results: provisioned=%v revoked=%v outbox_calls=%d health_calls=%d", handler.provisioned, handler.revoked, handler.outboxCalls, handler.healthCalls)
	}
}

func TestGatewayHealthFailuresAlertAndRecover(t *testing.T) {
	var logs bytes.Buffer
	handler := &recordingHandler{health: []service.GatewayHealthResult{{GatewayID: "gateway-1", Err: errors.New("unavailable")}}}
	runner, err := NewRunnerWithOptions(NewQueue(1), handler, zerolog.New(&logs), RunnerOptions{
		GatewayHealthFailureThreshold: 3,
	})
	if err != nil {
		t.Fatalf("NewRunnerWithOptions: %v", err)
	}
	failures := make(map[string]int)
	for attempt := 0; attempt < 3; attempt++ {
		runner.checkGatewayHealth(context.Background(), failures)
	}
	if failures["gateway-1"] != 3 {
		t.Fatalf("consecutive failures = %d", failures["gateway-1"])
	}
	if output := logs.String(); !strings.Contains(output, `"alert":true`) || !strings.Contains(output, `"severity":"critical"`) || !strings.Contains(output, `"consecutive_failures":3`) {
		t.Fatalf("critical gateway alert was not logged: %s", output)
	}

	handler.mu.Lock()
	handler.health = []service.GatewayHealthResult{{GatewayID: "gateway-1"}}
	handler.mu.Unlock()
	runner.checkGatewayHealth(context.Background(), failures)
	if len(failures) != 0 || !strings.Contains(logs.String(), "gateway readiness recovered") {
		t.Fatalf("gateway recovery was not recorded: failures=%v logs=%s", failures, logs.String())
	}
}
