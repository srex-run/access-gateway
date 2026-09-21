package gatewayagent

import (
	"context"

	"github.com/srex-run/access-gateway/internal/gateway"
)

// Controller owns the lifecycle of one direct TCP listener per approved
// session. Implementations must enforce the target, source IP, TTL, and
// connection limit carried by the request.
type Controller interface {
	Start(ctx context.Context, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error)
	Stop(ctx context.Context, sessionID string) (gateway.CloseSessionResponse, error)
	Status(ctx context.Context, sessionID string) (gateway.SessionStatusResponse, error)
}
