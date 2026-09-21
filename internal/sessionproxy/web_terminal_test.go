package sessionproxy

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

type browserTerminal struct {
	input    *io.PipeReader
	mu       sync.Mutex
	output   bytes.Buffer
	wrote    chan struct{}
	ready    chan struct{}
	resize   func(int, int) error
	messages []terminal.Message
	closed   bool
}

func (b *browserTerminal) Read(p []byte) (int, error) { return b.input.Read(p) }
func (b *browserTerminal) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.output.Write(p)
	select {
	case b.wrote <- struct{}{}:
	default:
	}
	return n, err
}
func (b *browserTerminal) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	if b.input != nil {
		return b.input.Close()
	}
	return nil
}
func (b *browserTerminal) Send(m terminal.Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return io.ErrClosedPipe
	}
	b.messages = append(b.messages, m)
	if m.Type == "ready" {
		close(b.ready)
	}
	return nil
}
func (b *browserTerminal) SetResize(f func(int, int) error) { b.resize = f }

type terminalAuditSinkFunc func(context.Context, operationaudit.SessionEvent) error

func (f terminalAuditSinkFunc) AppendOperation(ctx context.Context, event operationaudit.SessionEvent) error {
	return f(ctx, event)
}

func TestWebTerminalSSHUsesApprovedIdentityAndAuditsOutput(t *testing.T) {
	for _, test := range []struct {
		name                                    string
		pinMismatch, auditFailure, cancel       bool
		privateKey, encryptedKey                bool
		browserClose, inputFailure, targetClose bool
		rejectSession, rejectPTY, rejectShell   bool
		auditSetupFailure                       bool
		exitStatus                              uint32
	}{
		{name: "interactive"}, {name: "wrong target pin", pinMismatch: true}, {name: "audit unavailable", auditFailure: true}, {name: "revoked", cancel: true},
		{name: "private key", privateKey: true}, {name: "encrypted private key", privateKey: true, encryptedKey: true},
		{name: "browser closes", browserClose: true}, {name: "input fails", inputFailure: true},
		{name: "target closes before prompt", targetClose: true}, {name: "shell exits unsuccessfully", exitStatus: 7},
		{name: "PTY rejected", rejectPTY: true}, {name: "shell rejected", rejectShell: true},
		{name: "session rejected", rejectSession: true}, {name: "shell audit unavailable", auditSetupFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputFailure := errors.New("must-not-expose-input-or-credentials")
			host, _ := sshTestIdentity(t)
			loginKey, privateKey := sshTestIdentity(t)
			start := terminal.Message{Type: "start", Password: "ephemeral-secret", Cols: 100, Rows: 30}
			if test.privateKey {
				start.Password, start.PrivateKey, start.Passphrase = "", privateKey, "optional-passphrase"
				if test.encryptedKey {
					raw, err := ssh.ParseRawPrivateKey([]byte(privateKey))
					if err != nil {
						t.Fatal(err)
					}
					block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, "test", []byte(start.Passphrase))
					if err != nil {
						t.Fatal(err)
					}
					start.PrivateKey = string(pem.EncodeToMemory(block))
				}
			}
			pin := host.PublicKey()
			if test.pinMismatch {
				other, _ := sshTestIdentity(t)
				pin = other.PublicKey()
			}
			back, target := sshTestPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				server := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
					if meta.User() != "reader" || string(password) != "ephemeral-secret" {
						return nil, ErrIdentity
					}
					return nil, nil
				}}
				if test.privateKey {
					server.PasswordCallback = nil
					server.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
						if meta.User() != "reader" || !bytes.Equal(key.Marshal(), loginKey.PublicKey().Marshal()) {
							return nil, ErrIdentity
						}
						return nil, nil
					}
				}
				server.AddHostKey(host)
				conn, channels, reqs, err := ssh.NewServerConn(target, server)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for next := range channels {
					if test.rejectSession {
						_ = next.Reject(ssh.Prohibited, "session unavailable")
						return
					}
					channel, requests, err := next.Accept()
					if err != nil {
						return
					}
					defer channel.Close()
					for req := range requests {
						if req.Type == "pty-req" {
							_ = req.Reply(!test.rejectPTY, nil)
							if test.rejectPTY {
								return
							}
							continue
						}
						if req.Type != "shell" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(!test.rejectShell, nil)
						if test.rejectShell || test.targetClose {
							return
						}
						if test.cancel {
							<-ctx.Done()
							return
						}
						_, _ = channel.Write([]byte("browser-terminal-output\r\nreader@target:~$ "))
						if !test.auditFailure && test.exitStatus == 0 {
							input := make([]byte, 5)
							if _, err := io.ReadFull(channel, input); err != nil || string(input) != "exit\n" {
								return
							}
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{test.exitStatus}))
						return
					}
				}
			}()
			reader, writer := io.Pipe()
			defer writer.Close()
			channel := &browserTerminal{input: reader, wrote: make(chan struct{}, 1), ready: make(chan struct{})}
			sink := &recordingSink{}
			var audit Sink = sink
			if test.auditFailure {
				audit = &failingTerminalSink{}
			}
			if test.auditSetupFailure {
				audit = terminalAuditSinkFunc(func(context.Context, operationaudit.SessionEvent) error { return errors.New("audit offline") })
			}
			result := make(chan error, 1)
			go func() {
				result <- ServeSSHTerminal(ctx, Config{Protocol: "ssh", TargetHostKeys: []string{string(ssh.MarshalAuthorizedKey(pin))}}, back, Binding{Account: "reader"}, audit, start, channel)
			}()
			if !test.pinMismatch && !test.rejectSession && !test.rejectPTY && !test.rejectShell && !test.auditSetupFailure {
				select {
				case <-channel.ready:
				case <-ctx.Done():
					t.Fatal("terminal never became ready")
				}
				if test.cancel {
					cancel()
				} else if !test.auditFailure && !test.targetClose {
					// The shell prompt must stream before any input or disconnect.
					select {
					case <-channel.wrote:
						channel.mu.Lock()
						prompt := channel.output.String()
						channel.mu.Unlock()
						if !strings.Contains(prompt, "reader@target:~$ ") {
							t.Fatalf("missing initial shell prompt: %q", prompt)
						}
					case <-ctx.Done():
						t.Fatal("terminal became ready without streaming its initial prompt")
					}
					if test.browserClose {
						_ = writer.Close()
					} else if test.inputFailure {
						_ = writer.CloseWithError(inputFailure)
					} else if test.exitStatus == 0 {
						if _, err := writer.Write([]byte("exit\n")); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(6 * time.Second):
				t.Fatal("terminal did not stop")
			}
			var wasReady bool
			for _, message := range channel.messages {
				wasReady = wasReady || message.Type == "ready"
			}
			wantReady := !test.pinMismatch && !test.rejectSession && !test.rejectPTY && !test.rejectShell && !test.auditSetupFailure
			if wasReady != wantReady {
				t.Fatalf("SSH readiness=%v want=%v", wasReady, wantReady)
			}
			if test.pinMismatch {
				if !errors.Is(err, ErrIdentity) {
					t.Fatalf("pin mismatch: %v", err)
				}
				return
			}
			if test.auditFailure || test.auditSetupFailure {
				if !errors.Is(err, ErrAudit) || channel.output.Len() != 0 {
					t.Fatalf("unaudited output: %v", err)
				}
				if test.auditFailure && (channel.messages[len(channel.messages)-1].Type != "error" || !strings.Contains(channel.messages[len(channel.messages)-1].Data, "operation_audit_unavailable")) {
					t.Fatal("output audit failure was not reported before closing the terminal")
				}
				return
			}
			if test.cancel {
				if err == nil {
					t.Fatal("revoked terminal succeeded")
				}
				return
			}
			wantReason := ""
			switch {
			case test.rejectSession:
				wantReason = "ssh_session_failed"
			case test.rejectPTY:
				wantReason = "ssh_pty_failed"
			case test.rejectShell:
				wantReason = "ssh_shell_failed"
			case test.targetClose:
				wantReason = "ssh_connection_closed"
			case test.exitStatus != 0:
				wantReason = "ssh_shell_exited"
			case test.inputFailure:
				wantReason = "ssh_terminal_input_failed"
				if !errors.Is(err, inputFailure) {
					t.Fatal("original input failure was discarded")
				}
			}
			if wantReason != "" {
				diagnostic := DiagnoseTerminalFailure(err)
				if diagnostic.Reason != wantReason {
					t.Fatalf("diagnostic=%+v, want %s: %v", diagnostic, wantReason, err)
				}
				if strings.Contains(err.Error()+diagnostic.Detail, "must-not-expose") {
					t.Fatal("diagnostic exposed input or credentials")
				}
				if !test.rejectSession && !test.rejectPTY && !test.rejectShell {
					if len(channel.messages) == 0 || channel.messages[len(channel.messages)-1].Type != "error" || !strings.Contains(channel.messages[len(channel.messages)-1].Data, wantReason) {
						t.Fatalf("failure was not sent before closing the terminal: %+v", channel.messages)
					}
				}
				return
			}
			if test.browserClose && terminal.CloseReason(err) != "terminal_closed" {
				t.Fatalf("browser close reported as failure: %v", err)
			}
			if (err != nil && terminal.CloseReason(err) == "") || !strings.Contains(channel.output.String(), "browser-terminal-output") {
				t.Fatalf("terminal: %v output=%q", err, channel.output.String())
			}
			var shell, output bool
			for _, event := range sink.events {
				if event.OperationType == "shell" && event.Phase == "completed" && event.Result == "success" {
					shell = true
				}
				if event.OperationType == "terminal_output" {
					output = true
				}
				if event.NormalizedOperation != nil && (strings.Contains(*event.NormalizedOperation, "ephemeral-secret") || strings.Contains(*event.NormalizedOperation, "exit\n")) {
					t.Fatal("credential/input was recorded")
				}
			}
			if !shell || !output {
				t.Fatal("terminal evidence missing")
			}
		})
	}
}
