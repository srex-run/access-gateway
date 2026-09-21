package gatewayagent

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid gateway request")
	ErrRecoveryIncomplete = errors.New("gateway recovery incomplete")
	ErrTargetNotAllowed   = errors.New("gateway target is not allowed")
	ErrSessionConflict    = errors.New("gateway session conflict")
	ErrSessionInProgress  = errors.New("gateway session operation in progress")
	ErrSessionNotFound    = errors.New("gateway session not found")
	ErrCapacityExhausted  = errors.New("gateway session capacity exhausted")
)
