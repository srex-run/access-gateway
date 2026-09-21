package terminal

import "errors"

var (
	ErrTerminalClosed = errors.New("terminal closed by browser")
	ErrSessionClosed  = errors.New("session ended")
	ErrSessionExpired = errors.New("session expired")
	ErrAgentStopped   = errors.New("session agent stopped")
)

// CloseReason accepts only a deliberate close, possibly wrapped/joined with
// other deliberate closes. A real error joined to a close must remain a failure.
func CloseReason(err error) string {
	switch err {
	case nil:
		return ""
	case ErrTerminalClosed:
		return "terminal_closed"
	case ErrSessionClosed:
		return "session_closed"
	case ErrSessionExpired:
		return "expired"
	case ErrAgentStopped:
		return "agent_stopped"
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var reason string
		for _, child := range joined.Unwrap() {
			if child == nil {
				continue
			}
			reason = CloseReason(child)
			if reason == "" {
				return ""
			}
		}
		return reason
	}
	return CloseReason(errors.Unwrap(err))
}
