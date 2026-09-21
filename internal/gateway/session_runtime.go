package gateway

import (
	"context"
	"github.com/gorilla/websocket"
)

type TerminalClient interface {
	OpenTerminal(context.Context, string, string) (*websocket.Conn, error)
}

// ApprovedSessionClient receives a target resolved from the approved asset in
// the service layer. Target addresses never enter the public request protocol.
type ApprovedSessionClient interface {
	CreateApprovedSession(context.Context, string, CreateSessionRequest, string) (CreateSessionResponse, error)
	PublicHost() string
	RuntimeMode() string
}

type SessionResourceReconciler interface {
	Reconcile(context.Context) ([]string, error)
	AcknowledgeClosure(context.Context, string) error
}
