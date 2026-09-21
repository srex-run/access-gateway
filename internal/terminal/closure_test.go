package terminal

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestCloseReasonDoesNotHideJoinedFailures(t *testing.T) {
	for _, expected := range []error{ErrTerminalClosed, ErrSessionClosed, ErrSessionExpired, ErrAgentStopped} {
		if CloseReason(errors.Join(fmt.Errorf("wrapped: %w", expected))) == "" {
			t.Fatal("deliberate close was lost")
		}
		if CloseReason(errors.Join(expected, errors.New("audit failed"))) != "" {
			t.Fatal("a real failure was hidden by a close")
		}
	}
	if CloseReason(context.Canceled) != "" || CloseReason(nil) != "" {
		t.Fatal("unclassified cancellation was treated as a deliberate close")
	}
}
