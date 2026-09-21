package sessionproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/operationaudit"
	"golang.org/x/crypto/ssh"
)

func sshTestIdentity(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(pem.EncodeToMemory(block))
}

// A bounded in-memory socket buffer avoids net.Pipe's simultaneous SSH
// version-write deadlock and needs no OS listener or network permission.
type sshBufferedConn struct {
	net.Conn
	writes  chan []byte
	done    chan struct{}
	mu      sync.Mutex
	closing bool
	once    sync.Once
}

func (c *sshBufferedConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return 0, net.ErrClosed
	}
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	copy := append([]byte(nil), data...)
	select {
	case c.writes <- copy:
		return len(data), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *sshBufferedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closing {
		c.closing = true
		close(c.writes)
	}
	// Like a socket, already accepted writes reach the reader before EOF.
	return nil
}
func (c *sshBufferedConn) abort() {
	c.once.Do(func() { close(c.done); c.Conn.Close() })
}
func sshBuffered(c net.Conn) *sshBufferedConn {
	conn := &sshBufferedConn{Conn: c, writes: make(chan []byte, 16), done: make(chan struct{})}
	go func() {
		defer conn.abort()
		for {
			select {
			case data, ok := <-conn.writes:
				if !ok {
					return
				}
				if err := writeAll(c, data); err != nil {
					return
				}
			case <-conn.done:
				return
			}
		}
	}()
	return conn
}
func sshTestPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	c, s := sshBuffered(left), sshBuffered(right)
	t.Cleanup(func() { c.abort(); s.abort() })
	return c, s
}

type sshFixture struct {
	client     *ssh.Client
	done       <-chan error
	targetDone <-chan error
	cancel     context.CancelFunc
}

func startSSHFixture(t *testing.T, sink Sink, target func(ssh.Channel, <-chan *ssh.Request) error, mismatch bool) (*sshFixture, error) {
	t.Helper()
	host, key := sshTestIdentity(t)
	targetHost, _ := sshTestIdentity(t)
	pin := targetHost.PublicKey()
	if mismatch {
		pin = host.PublicKey()
	}
	cfg := Config{Protocol: "ssh", SSHHostKey: key, TargetHostKeys: []string{string(ssh.MarshalAuthorizedKey(pin))}}
	visitor, front := sshTestPair(t)
	back, asset := sshTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	stop := context.AfterFunc(ctx, func() {
		for _, conn := range []net.Conn{visitor, front, back, asset} {
			conn.(*sshBufferedConn).abort()
		}
	})
	t.Cleanup(func() { stop() })
	targetDone := make(chan error, 1)
	go func() {
		defer asset.Close()
		server := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() != "reader" || string(password) != "login-secret" {
				return nil, ErrIdentity
			}
			return nil, nil
		}}
		server.AddHostKey(targetHost)
		conn, channels, requests, err := ssh.NewServerConn(asset, server)
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		for next := range channels {
			channel, requests, err := next.Accept()
			if err != nil {
				targetDone <- err
				return
			}
			err = target(channel, requests)
			channel.Close()
			targetDone <- err
			return
		}
		targetDone <- nil
	}()
	done := make(chan error, 1)
	go func() {
		defer front.Close()
		defer back.Close()
		_, _, err := Serve(ctx, cfg, front, back, Binding{Account: "reader"}, sink)
		done <- err
	}()
	conn, channels, requests, err := ssh.NewClientConn(visitor, "agent", &ssh.ClientConfig{User: "reader", Auth: []ssh.AuthMethod{ssh.Password("login-secret")}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())})
	fixture := &sshFixture{done: done, targetDone: targetDone, cancel: cancel}
	if err != nil {
		return fixture, err
	}
	fixture.client = ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { fixture.client.Close() })
	return fixture, nil
}

func waitSSH(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(6 * time.Second):
		t.Fatal("SSH lifecycle did not terminate")
		return nil
	}
}

func TestSSHAuditInteractivePTYAndTerminalOutput(t *testing.T) {
	sink := &recordingSink{}
	resized := make(chan struct{})
	fixture, err := startSSHFixture(t, sink, func(ch ssh.Channel, requests <-chan *ssh.Request) error {
		for req := range requests {
			req.Reply(true, nil)
			switch req.Type {
			case "window-change":
				close(resized)
			case "shell":
				go func() {
					in := bufio.NewReader(ch)
					line, _ := in.ReadString('\n')
					hidden, _ := in.ReadString('\n')
					if line != "whoami\n" || hidden != "hidden-password\n" {
						ch.Close()
						return
					}
					io.WriteString(ch, "reader$ whoami\r\nreader\r\n")
					io.WriteString(ch.Stderr(), "visible diagnostic\r\n")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					ch.Close()
				}()
			}
		}
		return nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	session, err := fixture.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = session.Setenv("BASH_ENV", "startup-hook"); err == nil {
		t.Fatal("unsafe environment forwarded")
	}
	if err = session.Setenv("LANG", "C.UTF-8"); err != nil {
		t.Fatal(err)
	}
	if err = session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := session.StdinPipe()
	var stdout, stderr bytes.Buffer
	session.Stdout, session.Stderr = &stdout, &stderr
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	if err = session.WindowChange(32, 100); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resized:
	case <-time.After(time.Second):
		t.Fatal("resize was not forwarded")
	}
	io.WriteString(stdin, "whoami\nhidden-password\n")
	if err = session.Wait(); err != nil {
		t.Fatal(err)
	}
	fixture.client.Close()
	if err := waitSSH(t, fixture.done); err != nil {
		t.Fatal(err)
	}
	if err := waitSSH(t, fixture.targetDone); err != nil {
		t.Fatal(err)
	}
	transcripts := map[string]string{}
	var shellStarted, shellCompleted bool
	for _, event := range sink.events {
		if event.OperationType == "shell" {
			shellStarted = shellStarted || event.Phase == "started"
			shellCompleted = shellCompleted || event.Phase == "completed" && event.Result == "success"
		}
		if event.OperationType != "terminal_output" || event.Phase != "started" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(event.Metadata["data"].(string))
		if err != nil {
			t.Fatal(err)
		}
		transcripts[event.Metadata["stream"].(string)] += string(data)
		if event.Result != "unknown" || event.Metadata["evidence"] != "terminal_output" || event.Metadata["channel_id"] == "" {
			t.Fatal("terminal bytes falsely labelled as execution")
		}
	}
	if !shellStarted || !shellCompleted || transcripts["stdout"] != stdout.String() || transcripts["stderr"] != stderr.String() || !strings.Contains(stdout.String(), "whoami") {
		t.Fatalf("missing terminal evidence: %#v", transcripts)
	}
	for _, event := range sink.events {
		if strings.Contains(fmt.Sprint(event), "hidden-password") || strings.Contains(fmt.Sprint(event), "login-secret") {
			t.Fatal("password input persisted")
		}
	}
}

func TestSSHAuditExecExitAndRedaction(t *testing.T) {
	sink := &recordingSink{}
	fixture, err := startSSHFixture(t, sink, func(ch ssh.Channel, requests <-chan *ssh.Request) error {
		req := <-requests
		var command struct{ Command string }
		if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "echo sensitive-argument" {
			return ErrProtocol
		}
		req.Reply(true, nil)
		io.WriteString(ch, "output")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
		return nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	session, err := fixture.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("echo sensitive-argument")
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 7 || string(output) != "output" {
		t.Fatalf("exec result: %q %v", output, err)
	}
	fixture.client.Close()
	if err = waitSSH(t, fixture.done); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 || sink.events[1].Result != "failure" || *sink.events[0].NormalizedOperation != "echo [arguments redacted]" {
		t.Fatalf("exec audit: %+v", sink.events)
	}
}

type failingTerminalSink struct{ recordingSink }

func (s *failingTerminalSink) AppendOperation(ctx context.Context, event operationaudit.SessionEvent) error {
	if event.OperationType == "terminal_output" {
		return errors.New("audit offline")
	}
	return s.recordingSink.AppendOperation(ctx, event)
}

func TestSSHAuditFailureClosesTerminalBeforeUnrecordedOutput(t *testing.T) {
	fixture, err := startSSHFixture(t, &failingTerminalSink{}, func(ch ssh.Channel, requests <-chan *ssh.Request) error {
		req := <-requests
		req.Reply(true, nil)
		io.WriteString(ch, "must not reach client")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	session, _ := fixture.client.NewSession()
	var output bytes.Buffer
	session.Stdout = &output
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	session.Wait()
	fixture.client.Close()
	if err = waitSSH(t, fixture.done); !errors.Is(err, ErrAudit) {
		t.Fatalf("audit failure not propagated: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("unrecorded output reached client")
	}
}

func TestSSHAuditHostPinAndCancellation(t *testing.T) {
	t.Run("host key mismatch", func(t *testing.T) {
		fixture, err := startSSHFixture(t, &recordingSink{}, func(ssh.Channel, <-chan *ssh.Request) error { return errors.New("should not authenticate") }, true)
		if err == nil {
			t.Fatal("wrong target host accepted")
		}
		if err = waitSSH(t, fixture.done); !errors.Is(err, ErrIdentity) {
			t.Fatalf("identity failure missing: %v", err)
		}
	})
	t.Run("active shell cancellation", func(t *testing.T) {
		sink := &recordingSink{}
		fixture, err := startSSHFixture(t, sink, func(ch ssh.Channel, requests <-chan *ssh.Request) error {
			req := <-requests
			req.Reply(true, nil)
			_, err := io.Copy(io.Discard, ch)
			return err
		}, false)
		if err != nil {
			t.Fatal(err)
		}
		session, _ := fixture.client.NewSession()
		if err = session.Shell(); err != nil {
			t.Fatal(err)
		}
		fixture.cancel()
		session.Wait()
		waitSSH(t, fixture.done)
		if len(sink.events) != 2 || sink.events[1].Phase != "completed" || sink.events[1].Result != "unknown" {
			t.Fatal("interrupted shell not recorded as unknown")
		}
	})
}

func TestSSHAuditExecWithPTYAlsoRecordsTerminal(t *testing.T) {
	sink := &recordingSink{}
	fixture, err := startSSHFixture(t, sink, func(ch ssh.Channel, requests <-chan *ssh.Request) error {
		pty := <-requests
		if pty.Type != "pty-req" {
			return ErrProtocol
		}
		pty.Reply(true, nil)
		exec := <-requests
		if exec.Type != "exec" {
			return ErrProtocol
		}
		exec.Reply(true, nil)
		io.WriteString(ch, "reader$ whoami\r\nreader\r\n")
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	session, err := fixture.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = session.Output("bash"); err != nil {
		t.Fatal(err)
	}
	fixture.client.Close()
	if err = waitSSH(t, fixture.done); err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, event := range sink.events {
		if event.OperationType == "terminal_output" && event.Phase == "completed" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("exec with PTY bypassed terminal recording")
	}
}
