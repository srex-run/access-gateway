//go:build !linux && !darwin

package terminalclient

import (
	"context"
	"os/exec"
)

func prepareCommand(context.Context, *exec.Cmd, *launchSpec, Bridge, context.CancelFunc) (func(), error) {
	return nil, ErrUnavailable
}
func isolate(launchSpec) error { return ErrUnavailable }
