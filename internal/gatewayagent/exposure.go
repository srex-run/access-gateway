package gatewayagent

import (
	"context"
	"fmt"
	"time"
)

type Exposure struct {
	Mode         string
	Reference    string
	ExternalPort int
}

type ExposureRequest struct {
	SessionID           string
	ListenerPort        int
	DesiredExternalPort int
	ExpiresAt           time.Time
}

type ExposureProvider interface {
	Ensure(ctx context.Context, request ExposureRequest) (Exposure, error)
	Remove(ctx context.Context, sessionID, reference string) error
}

type DirectExposureProvider struct{}

func (DirectExposureProvider) Ensure(_ context.Context, request ExposureRequest) (Exposure, error) {
	if request.ListenerPort < 1 || request.ListenerPort > 65535 {
		return Exposure{}, fmt.Errorf("direct exposure listener port is invalid: %w", ErrInvalidInput)
	}
	if request.DesiredExternalPort != 0 && request.DesiredExternalPort != request.ListenerPort {
		return Exposure{}, fmt.Errorf("direct exposure port changed during recovery: %w", ErrSessionConflict)
	}
	return Exposure{
		Mode: "direct", Reference: fmt.Sprintf("direct/%d", request.ListenerPort), ExternalPort: request.ListenerPort,
	}, nil
}

func (DirectExposureProvider) Remove(context.Context, string, string) error {
	return nil
}
