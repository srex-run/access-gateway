package worker

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type blockingCloudHandler struct {
	recordingHandler
	started chan struct{}
	revoked chan struct{}
}

func (h *blockingCloudHandler) ProcessCloudSync(ctx context.Context) error {
	close(h.started)
	<-ctx.Done()
	return ctx.Err()
}

func (h *blockingCloudHandler) RevokeSession(context.Context, string, string) (domain.Session, error) {
	close(h.revoked)
	return domain.Session{}, nil
}

func TestCloudSyncDoesNotBlockSessionRevocation(t *testing.T) {
	handler := &blockingCloudHandler{started: make(chan struct{}), revoked: make(chan struct{})}
	queue := NewQueue(1)
	runner, err := NewRunner(queue, handler, zerolog.Nop(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("cloud worker did not start")
	}
	if err := queue.Enqueue(ctx, service.Task{Kind: service.TaskRevoke, SessionID: "expired-session"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.revoked:
	case <-time.After(time.Second):
		t.Fatal("slow cloud request blocked session revocation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cloud worker did not stop with the runner")
	}
}
