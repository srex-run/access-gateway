package sessionproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// ServeSSHTerminal runs the browser's SSH client inside the approved worker.
// It shares target pinning and the durable audit recorder with TCP SSH access.
func ServeSSHTerminal(ctx context.Context, cfg Config, backend net.Conn, binding Binding, sink Sink, start terminal.Message, channel terminal.Stream) (resultErr error) {
	if cfg.Protocol != "ssh" || sink == nil || binding.Account == "" || !start.ValidFor("ssh") {
		return ErrProtocol
	}
	var auth ssh.AuthMethod
	if start.PrivateKey != "" {
		key, err := terminalSSHSigner(start.PrivateKey, start.Passphrase)
		if err != nil {
			return err
		}
		auth = ssh.PublicKeys(key)
	} else {
		auth = ssh.Password(start.Password)
	}
	start.Password, start.PrivateKey, start.Passphrase = "", "", ""
	stop := context.AfterFunc(ctx, func() { _ = backend.Close(); _ = channel.Close() })
	defer stop()
	_ = backend.SetDeadline(time.Now().Add(20 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(backend, backend.RemoteAddr().String(), &ssh.ClientConfig{
		User: binding.Account, Auth: []ssh.AuthMethod{auth}, Timeout: 20 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, value := range cfg.TargetHostKeys {
				p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(value))
				if e == nil && subtle.ConstantTimeCompare(p.Marshal(), key.Marshal()) == 1 {
					return nil
				}
			}
			return errors.Join(ErrIdentity, ErrSSHHostKey)
		},
	})
	if err != nil {
		return sshTerminalFailure("ssh_handshake", err)
	}
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	shell, err := client.NewSession()
	if err != nil {
		return sshTerminalFailure("ssh_session", err)
	}
	defer shell.Close()
	input, err := shell.StdinPipe()
	if err != nil {
		return sshTerminalFailure("ssh_session", err)
	}
	stdout, err := shell.StdoutPipe()
	if err != nil {
		return sshTerminalFailure("ssh_session", err)
	}
	stderr, err := shell.StderrPipe()
	if err != nil {
		return sshTerminalFailure("ssh_session", err)
	}
	if err := shell.RequestPty("xterm-256color", start.Rows, start.Cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		return sshTerminalFailure("ssh_pty", err)
	}
	r := &recorder{ctx: ctx, binding: binding, protocol: "ssh", sink: sink}
	op, err := r.begin(binding.Account, "shell", "interactive shell", "", map[string]any{"entry": "web"})
	if err != nil {
		return err
	}
	result := "failure"
	defer func() { resultErr = errors.Join(resultErr, op.end(result)) }()
	if err := shell.Shell(); err != nil {
		return sshTerminalFailure("ssh_shell", err)
	}
	_ = backend.SetDeadline(time.Time{})
	channel.SetResize(shell.WindowChange)
	if err = channel.Send(terminal.Message{Type: "ready"}); err != nil {
		return sshTerminalFailure("ssh_terminal_ready", err)
	}
	// A failed audit/output write closes the SSH client immediately. Input is
	// never recorded: passwords entered into the shell must remain hidden.
	output := make(chan error, 2)
	for name, source := range map[string]io.Reader{"stdout": stdout, "stderr": stderr} {
		go func() {
			err := copySSHTerminal(channel, source, r, op, name)
			if err != nil && !errors.Is(err, websocket.ErrCloseSent) {
				_ = client.Close()
			}
			output <- err
		}()
	}
	inputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(input, channel)
		// Publish the cause before closing SSH; Wait otherwise reports only
		// a missing exit status and hides the original WebSocket/input error.
		inputDone <- err
		_ = client.Close()
	}()
	waitErr := shell.Wait()
	outputErr := errors.Join(<-output, <-output)
	var inputErr error
	inputFinished := false
	cause := context.Cause(ctx)
	select {
	case inputErr = <-inputDone:
		inputFinished = true
		if inputErr == nil && cause == nil {
			cause = terminal.ErrTerminalClosed
		}
	default:
	}
	err = sshTerminalResult(waitErr, outputErr, inputErr, cause)
	if err == nil || terminal.CloseReason(err) != "" {
		result = "success"
	}
	// Record the completion before reporting the result to the browser.
	if auditErr := op.end(result); auditErr != nil {
		err = errors.Join(err, auditErr)
	}
	if err == nil {
		_ = channel.Send(terminal.Message{Type: "exit"})
	} else if ctx.Err() == nil && terminal.CloseReason(err) == "" {
		diagnostic := DiagnoseTerminalFailure(err)
		_ = channel.Send(terminal.Message{Type: "error", Data: diagnostic.Detail + " (" + diagnostic.Reason + ")"})
	}
	_ = channel.Close()
	if !inputFinished {
		<-inputDone
	}
	return err
}
