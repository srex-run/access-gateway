package sessionproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// Keep the original error for classification without exposing target-supplied
// messages, shell output, or authentication material in diagnostics.
type sshTerminalError struct {
	stage string
	cause error
}

func (e *sshTerminalError) Error() string { return e.stage + " failed" }
func (e *sshTerminalError) Unwrap() error { return e.cause }

func sshTerminalFailure(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &sshTerminalError{stage: stage, cause: err}
}

func (e *sshTerminalError) diagnostic() TerminalDiagnostic {
	d := TerminalDiagnostic{Stage: e.stage, Reason: e.stage + "_failed"}
	switch e.stage {
	case "ssh_handshake":
		d.Detail = "SSH 握手或目标账号认证失败"
	case "ssh_session":
		d.Detail = "无法创建 SSH 会话"
	case "ssh_pty":
		d.Detail = "目标 SSH 服务未能分配交互终端"
	case "ssh_shell":
		d.Detail = "SSH 认证已通过，但远端 shell 启动失败"
	case "ssh_terminal_ready":
		d.Detail = "SSH 已就绪，但无法通知浏览器"
	case "ssh_terminal_input":
		d.Detail = "SSH 终端输入或窗口尺寸转发失败"
	case "ssh_terminal_output":
		d.Detail = "SSH 终端输出转发失败"
	case "ssh_shell_wait":
		d.Detail = "SSH 远端 shell 异常结束"
		var exit *ssh.ExitError
		var missing *ssh.ExitMissingError
		if errors.As(e.cause, &exit) {
			d.Reason = "ssh_shell_exited"
			d.Detail = fmt.Sprintf("SSH 远端 shell 已退出（退出码 %d）", exit.ExitStatus())
		} else if errors.As(e.cause, &missing) {
			d.Reason = "ssh_connection_closed"
			d.Detail = "SSH 连接提前关闭，目标未返回退出状态"
		}
	}
	return d
}

// Socket/pipe errors caused by our own shutdown do not turn a deliberate close
// into a failed operation. Real audit, transport, or shell errors still win.
func sshTerminalShutdownError(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !sshTerminalShutdownError(child) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return sshTerminalShutdownError(wrapped)
	}
	_, missing := err.(*ssh.ExitMissingError)
	return missing || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, websocket.ErrCloseSent)
}

func sshTerminalResult(waitErr, outputErr, inputErr, cause error) error {
	if terminal.CloseReason(cause) != "" && sshTerminalShutdownError(waitErr) && sshTerminalShutdownError(outputErr) && sshTerminalShutdownError(inputErr) {
		return cause
	}
	return errors.Join(sshTerminalFailure("ssh_terminal_input", inputErr),
		sshTerminalFailure("ssh_terminal_output", outputErr), sshTerminalFailure("ssh_shell_wait", waitErr), cause)
}
