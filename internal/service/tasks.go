package service

import "context"

type TaskKind string

const (
	TaskProvision TaskKind = "provision"
	TaskRevoke    TaskKind = "revoke"

	outboxSessionProvision    = "session.provision"
	outboxSessionRevoke       = "session.revoke"
	outboxNotifyApproval      = "notification.approval_requested"
	outboxNotifyRequestResult = "notification.request_result"
	outboxNotifySessionReady  = "notification.session_ready"
	outboxNotifySessionClosed = "notification.session_closed"
)

type Task struct {
	Kind      TaskKind
	SessionID string
	Reason    string
}

type TaskEnqueuer interface {
	Enqueue(ctx context.Context, task Task) error
}

type NoopTaskEnqueuer struct{}

func (NoopTaskEnqueuer) Enqueue(context.Context, Task) error { return nil }
