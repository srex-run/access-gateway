package sessionproxy

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

func TestSSHTerminalClosurePreservesRealFailures(t *testing.T) {
	for _, sample := range []struct {
		name                string
		wait, output, input error
		closed              bool
	}{
		{"browser close", &ssh.ExitMissingError{}, net.ErrClosed, nil, true},
		{"close acknowledgement", &ssh.ExitMissingError{}, websocket.ErrCloseSent, io.ErrClosedPipe, true},
		{"audit failure", &ssh.ExitMissingError{}, errors.Join(ErrAudit, net.ErrClosed), nil, false},
		{"shell failure", &ssh.ExitError{}, nil, nil, false},
		{"broken transport", &ssh.ExitMissingError{}, nil, &websocket.CloseError{Code: 1006}, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			for _, cause := range []error{terminal.ErrTerminalClosed, terminal.ErrSessionClosed, terminal.ErrSessionExpired} {
				err := sshTerminalResult(sample.wait, sample.output, sample.input, cause)
				if (terminal.CloseReason(err) != "") != sample.closed {
					t.Fatalf("cause %v: %v", cause, err)
				}
				if errors.Is(sample.output, ErrAudit) && DiagnoseTerminalFailure(err).Reason != "operation_audit_unavailable" {
					t.Fatal("audit failure was hidden by shutdown")
				}
			}
		})
	}
}

func TestSSHTerminalTransportDiagnosticDoesNotExposeCloseText(t *testing.T) {
	err := sshTerminalResult(&ssh.ExitMissingError{}, nil, &websocket.CloseError{Code: 1006, Text: "must-not-expose-terminal-data"}, nil)
	diagnostic := DiagnoseTerminalFailure(err)
	if diagnostic.Reason != "ssh_terminal_input_failed" || !strings.Contains(diagnostic.Detail, "1006") || strings.Contains(diagnostic.Detail, "must-not-expose") {
		t.Fatalf("unsafe or missing transport diagnostic: %+v", diagnostic)
	}
}
