//go:build linux || darwin

package sessionproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

type interactiveSSHResponse struct {
	net.Conn
	header http.Header
}

func (w interactiveSSHResponse) Header() http.Header { return w.header }
func (w interactiveSSHResponse) WriteHeader(int)     {}
func (w interactiveSSHResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Conn, bufio.NewReadWriter(bufio.NewReader(w.Conn), bufio.NewWriter(w.Conn)), nil
}

// Exercise the real browser/worker frame contract, SSH authentication and PTY
// requests against an actual interactive bash process. No prompts or command
// responses are manufactured by the fixture, and no listening port is needed.
func TestWebTerminalSSHRealInteractiveShell(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hostKey, _ := sshTestIdentity(t)
	loginKey, privateKey := sshTestIdentity(t)
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "colored-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ordinary-file"), []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "colored-executable"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ordinary-file", filepath.Join(directory, "colored-link")); err != nil {
		t.Fatal(err)
	}
	backend, target := sshTestPair(t)
	targetDone := make(chan error, 1)
	resized := make(chan struct{}, 1)
	go func() {
		targetDone <- serveInteractiveSSHTarget(ctx, target, hostKey, loginKey.PublicKey(), directory, resized)
	}()
	browserSide, workerSide := net.Pipe()
	defer browserSide.Close()
	defer workerSide.Close()
	audit := &recordingSink{}
	workerDone := make(chan error, 1)
	go func() {
		defer workerSide.Close()
		request, err := http.ReadRequest(bufio.NewReader(workerSide))
		if err != nil {
			workerDone <- err
			return
		}
		upgrader := websocket.Upgrader{}
		socket, err := upgrader.Upgrade(interactiveSSHResponse{Conn: workerSide, header: make(http.Header)}, request, nil)
		if err != nil {
			workerDone <- err
			return
		}
		defer socket.Close()
		_ = socket.SetReadDeadline(time.Now().Add(15 * time.Second))
		var start terminal.Message
		if err := socket.ReadJSON(&start); err != nil {
			workerDone <- err
			return
		}
		channel := &terminal.Channel{Socket: socket}
		err = ServeSSHTerminal(ctx, Config{Protocol: "ssh", TargetHostKeys: []string{string(ssh.MarshalAuthorizedKey(hostKey.PublicKey()))}}, backend, Binding{Account: "reader"}, audit, start, channel)
		if err != nil {
			diagnostic := DiagnoseTerminalFailure(err)
			_ = channel.Send(terminal.Message{Type: "error", Data: diagnostic.Detail})
		}
		workerDone <- err
	}()
	browser, _, err := websocket.NewClient(browserSide, &url.URL{Scheme: "ws", Host: "terminal.test"}, nil, 1024, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	_ = browser.SetReadDeadline(time.Now().Add(12 * time.Second))
	if err := browser.WriteJSON(terminal.Message{Type: "start", PrivateKey: privateKey, Cols: 100, Rows: 30}); err != nil {
		t.Fatal(err)
	}
	var ready terminal.Message
	if err := browser.ReadJSON(&ready); err != nil || ready.Type != "ready" {
		select {
		case targetErr := <-targetDone:
			t.Fatalf("real shell did not start: message=%+v read=%v target=%v", ready, err, targetErr)
		default:
			t.Fatalf("SSH was not ready: message=%+v read=%v", ready, err)
		}
	}
	var pending string
	readUntil := func(want string) string {
		t.Helper()
		for {
			if end := strings.Index(pending, want); end >= 0 {
				end += len(want)
				response := pending[:end]
				pending = pending[end:]
				return response
			}
			kind, data, err := browser.ReadMessage()
			if err != nil {
				t.Fatalf("terminal output: %v; received %q", err, pending)
			}
			if kind != websocket.BinaryMessage {
				t.Fatalf("expected shell bytes, received %s", data)
			}
			pending += string(data)
		}
	}
	input := func(data string) {
		t.Helper()
		if err := browser.WriteJSON(terminal.Message{Type: "input", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	// The first prompt must be generated before the user has typed anything.
	readUntil("SSH_TEST> ")
	input("if test -t 0 && test -t 1; then tty_result=yes; else tty_result=no; fi; printf '\\nTTY:%s\\n' \"$tty_result\"; case $- in *i*) printf 'INTER%s\\n' ACTIVE;; esac\r")
	response := readUntil("SSH_TEST> ")
	if !strings.Contains(response, "\r\nTTY:yes\r\n") || !strings.Contains(response, "\r\nINTERACTIVE\r\n") {
		t.Fatalf("shell did not have interactive mode and a PTY: %q", response)
	}
	// Colors originate in the real target program. Verify file-type colors
	// survive SSH, audited output and binary WebSocket frames without guessing
	// types from printed names or manufacturing ANSI responses in the fixture.
	listing := "LS_COLORS='di=34:ln=36:ex=32' command ls --color=auto -1d"
	if runtime.GOOS == "darwin" {
		listing = "CLICOLOR=1 LSCOLORS=exgxfxdxcxegedabagacad command ls -G1d"
	}
	input(listing + " colored-dir colored-link colored-executable ordinary-file\r")
	response = readUntil("SSH_TEST> ")
	for name, color := range map[string]string{"colored-dir": "34", "colored-link": "36", "colored-executable": "32"} {
		pattern := regexp.MustCompile(`\x1b\[(?:[0-9]+;)*` + color + `m` + name + `\x1b\[(?:0|39(?:;49)?)?m`)
		if !pattern.MatchString(response) {
			t.Fatalf("real ls color for %s was not preserved: %q", name, response)
		}
	}
	if !strings.Contains(response, "\r\nordinary-file\r\n") {
		t.Fatalf("plain file did not retain the terminal's default foreground: %q", response)
	}
	if err := browser.WriteJSON(terminal.Message{Type: "resize", Cols: 117, Rows: 42}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resized:
	case <-ctx.Done():
		t.Fatal("SSH window-change was not received")
	}
	input("stty size\r")
	// SIGWINCH can repaint the prompt before the command produces its output.
	readUntil("\r\n42 117\r\n")
	readUntil("SSH_TEST> ")
	input("printf '\\nWAIT%s\\n' ING; read value\r")
	readUntil("\r\nWAITING\r\n")
	input("\x03")
	readUntil("SSH_TEST> ")
	input("exit 0\r")
	for {
		kind, data, err := browser.ReadMessage()
		if err != nil {
			t.Fatalf("shell exit was not delivered: %v", err)
		}
		if kind == websocket.TextMessage {
			if string(data) != "{\"type\":\"exit\"}\n" {
				t.Fatalf("shell did not exit successfully: %s", data)
			}
			break
		}
	}
	if err := <-workerDone; err != nil {
		t.Fatalf("worker: %v", err)
	}
	if err := <-targetDone; err != nil {
		t.Fatalf("target: %v", err)
	}
	var recorded bool
	for _, event := range audit.events {
		if event.OperationType == "terminal_output" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("interactive output was not audited")
	}
}

func serveInteractiveSSHTarget(ctx context.Context, connection net.Conn, hostKey ssh.Signer, loginKey ssh.PublicKey, directory string, resized chan<- struct{}) error {
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "reader" || !bytes.Equal(key.Marshal(), loginKey.Marshal()) {
			return nil, errors.New("test SSH identity rejected")
		}
		return nil, nil
	}}
	config.AddHostKey(hostKey)
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return err
	}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	go ssh.DiscardRequests(requests)
	for next := range channels {
		if next.ChannelType() != "session" {
			_ = next.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, requests, err := next.Accept()
		if err != nil {
			return err
		}
		defer channel.Close()
		var size pty.Winsize
		var ptmx *os.File
		var processDone chan error
		var inputDone chan struct{}
		for request := range requests {
			switch request.Type {
			case "pty-req":
				var dimensions struct {
					Term                      string
					Cols, Rows, Width, Height uint32
					Modes                     string
				}
				if err := ssh.Unmarshal(request.Payload, &dimensions); err != nil || dimensions.Term != "xterm-256color" || dimensions.Rows != 30 || dimensions.Cols != 100 {
					_ = request.Reply(false, nil)
					return errors.New("invalid initial SSH PTY request")
				}
				size = pty.Winsize{Rows: uint16(dimensions.Rows), Cols: uint16(dimensions.Cols)}
				_ = request.Reply(true, nil)
			case "shell":
				if size.Rows == 0 || ptmx != nil || len(request.Payload) != 0 {
					_ = request.Reply(false, nil)
					return errors.New("shell requested without a PTY")
				}
				// Bash must infer interactive mode from the PTY, as a normal
				// SSH login shell does; do not force it with the -i flag.
				command := exec.CommandContext(ctx, "/bin/bash", "--noprofile", "--norc")
				command.Dir = directory
				command.Env = []string{"PATH=/usr/bin:/bin", "TERM=xterm-256color", "PS1=SSH_TEST> ", "PS2=CONTINUE> ", "HISTFILE="}
				ptmx, err = pty.StartWithSize(command, &size)
				if err != nil {
					_ = request.Reply(false, nil)
					return fmt.Errorf("start actual shell PTY: %w", err)
				}
				defer ptmx.Close()
				processDone = make(chan error, 1)
				inputDone = make(chan struct{})
				outputDone := make(chan error, 1)
				go func() { _, err := io.Copy(channel, ptmx); outputDone <- err }()
				go func() { defer close(inputDone); _, _ = io.Copy(ptmx, channel) }()
				go func() {
					err := command.Wait()
					outputErr := <-outputDone
					if outputErr != nil && !errors.Is(outputErr, syscall.EIO) {
						err = errors.Join(err, outputErr)
					}
					status := uint32(0)
					if err != nil {
						status = 1
					}
					_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
					_ = channel.Close()
					processDone <- err
				}()
				_ = request.Reply(true, nil)
			case "window-change":
				var dimensions struct{ Cols, Rows, Width, Height uint32 }
				if err := ssh.Unmarshal(request.Payload, &dimensions); err != nil || ptmx == nil {
					return errors.New("invalid resize request")
				}
				if err := pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(dimensions.Rows), Cols: uint16(dimensions.Cols)}); err != nil {
					return err
				}
				resized <- struct{}{}
			default:
				_ = request.Reply(false, nil)
			}
		}
		if processDone != nil {
			err := <-processDone
			<-inputDone
			return err
		}
		return errors.New("SSH channel closed before starting a shell")
	}
	return errors.New("SSH session channel was not created")
}
