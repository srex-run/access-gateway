package sessionproxy

import (
	"bytes"
	"crypto/subtle"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func serveSSH(cfg Config, client, backend net.Conn, r *recorder) error {
	host, e := ssh.ParsePrivateKey([]byte(cfg.SSHHostKey))
	if e != nil {
		return ErrProtocol
	}
	var upstream *ssh.Client
	connect := func(user string, method ssh.AuthMethod) error {
		if upstream != nil {
			return ErrProtocol
		}
		config := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{method}, Timeout: 30 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, value := range cfg.TargetHostKeys {
				p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(value))
				if e == nil && subtle.ConstantTimeCompare(p.Marshal(), key.Marshal()) == 1 {
					return nil
				}
			}
			return ErrIdentity
		}}
		conn, channels, requests, e := ssh.NewClientConn(backend, backend.RemoteAddr().String(), config)
		if e != nil {
			return ErrIdentity
		}
		upstream = ssh.NewClient(conn, channels, requests)
		return nil
	}
	sc := &ssh.ServerConfig{MaxAuthTries: 1, PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != r.binding.Account {
			return nil, ErrIdentity
		}
		if e := connect(meta.User(), ssh.Password(string(password))); e != nil {
			return nil, e
		}
		return &ssh.Permissions{Extensions: map[string]string{"method": "password"}}, nil
	}}
	if len(cfg.AuthorizedKeys) > 0 {
		sc.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() != r.binding.Account {
				return nil, ErrIdentity
			}
			for _, value := range cfg.AuthorizedKeys {
				p, _, _, _, e := ssh.ParseAuthorizedKey([]byte(value))
				if e == nil && bytes.Equal(p.Marshal(), key.Marshal()) {
					return &ssh.Permissions{Extensions: map[string]string{"method": "publickey"}}, nil
				}
			}
			return nil, ErrIdentity
		}
	}
	sc.AddHostKey(host)
	conn, channels, requests, e := ssh.NewServerConn(client, sc)
	if e != nil {
		if upstream != nil {
			upstream.Close()
		}
		return ErrIdentity
	}
	defer conn.Close()
	if upstream == nil {
		key, e := ssh.ParsePrivateKey([]byte(cfg.TargetSSHKey))
		if e != nil {
			return ErrIdentity
		}
		if e = connect(conn.User(), ssh.PublicKeys(key)); e != nil {
			return e
		}
	}
	defer upstream.Close()
	go func() { _ = conn.Wait(); _ = upstream.Close() }()
	client.SetDeadline(time.Time{})
	backend.SetDeadline(time.Time{})
	go ssh.DiscardRequests(requests)
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	failures := make(chan error, 8)
	for next := range channels {
		if next.ChannelType() != "session" {
			next.Reject(ssh.Prohibited, "only audited session channels are allowed")
			continue
		}
		select {
		case limit <- struct{}{}:
		default:
			next.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}
		dst, dr, e := upstream.OpenChannel("session", next.ExtraData())
		if e != nil {
			<-limit
			next.Reject(ssh.ConnectionFailed, "target session unavailable")
			continue
		}
		src, sr, e := next.Accept()
		if e != nil {
			dst.Close()
			<-limit
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			e := sshChannel(src, dst, sr, dr, r, conn.User())
			if e != nil {
				select {
				case failures <- e:
				default:
				}
				conn.Close()
				upstream.Close()
			}
		}()
	}
	wg.Wait()
	select {
	case e := <-failures:
		return e
	default:
		return nil
	}
}

func shellShape(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "[empty command]"
	}
	name := fields[0]
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._-", c)) {
			return "[shell command; arguments redacted]"
		}
	}
	if len(fields) > 1 {
		return clean(name, 256) + " [arguments redacted]"
	}
	return clean(name, 256)
}

// SSH session channels carry exec, shell or SFTP. Forwarding channels remain
// prohibited because their contents would bypass the selected protocol auditor.
func sshChannel(src, dst ssh.Channel, sr, dr <-chan *ssh.Request, r *recorder, account string) error {
	defer src.Close()
	defer dst.Close()
	var op *operation
	interactive, pty := false, false
	for req := range sr {
		switch req.Type {
		case "pty-req":
			if pty || !validSSHPTY(req.Payload) {
				req.Reply(false, nil)
				continue
			}
			ok, err := dst.SendRequest(req.Type, true, req.Payload)
			req.Reply(ok, nil)
			if err != nil {
				return err
			}
			pty = ok
			continue
		case "env":
			if !validSSHEnvironment(req.Payload) {
				req.Reply(false, nil)
				continue
			}
			ok, err := dst.SendRequest(req.Type, true, req.Payload)
			req.Reply(ok, nil)
			if err != nil {
				return err
			}
			continue
		case "exec":
			var body struct{ Command string }
			if ssh.Unmarshal(req.Payload, &body) != nil || len(body.Command) > 64<<10 {
				return ErrProtocol
			}
			// ssh -t host bash/top uses exec with a PTY, not a shell request.
			// It needs the same terminal recording and window changes.
			interactive = pty
			var err error
			op, err = r.begin(account, "exec", shellShape(body.Command), "", map[string]any{"evidence": "exec_request", "arguments_redacted": true, "pty": pty})
			if err != nil {
				return err
			}
		case "shell":
			if len(req.Payload) != 0 {
				return ErrProtocol
			}
			interactive = true
			var err error
			op, err = r.begin(account, "shell", "interactive shell", "", map[string]any{"evidence": "shell_session", "pty": pty, "recording": "output"})
			if err != nil {
				return err
			}
		case "subsystem":
			var body struct{ Name string }
			if ssh.Unmarshal(req.Payload, &body) != nil || body.Name != "sftp" {
				req.Reply(false, nil)
				continue
			}
		default:
			req.Reply(false, nil)
			continue
		}
		ok, err := dst.SendRequest(req.Type, true, req.Payload)
		if err != nil {
			if op != nil {
				_ = op.end("unknown")
			}
			return err
		}
		req.Reply(ok, nil)
		if !ok {
			if op != nil {
				return op.end("rejected")
			}
			return nil
		}
		if req.Type == "subsystem" {
			go ssh.DiscardRequests(sr)
			go ssh.DiscardRequests(dr)
			return serveSFTP(src, dst, r, account)
		}
		break
	}
	if op == nil {
		return nil
	}
	return relaySSHSession(src, dst, sr, dr, r, op, interactive)
}

func validSSHPTY(payload []byte) bool {
	var p struct {
		Term                         string
		Columns, Rows, Width, Height uint32
		Modes                        string
	}
	return len(payload) <= 4096 && ssh.Unmarshal(payload, &p) == nil && len(p.Term) <= 128 && len(p.Modes) <= 2048
}

func validSSHEnvironment(payload []byte) bool {
	var p struct{ Name, Value string }
	if len(payload) > 4096 || ssh.Unmarshal(payload, &p) != nil {
		return false
	}
	// Do not allow startup hooks or loader variables to bypass the shell request.
	return p.Name == "LANG" || p.Name == "TERM" || (strings.HasPrefix(p.Name, "LC_") && len(p.Name) <= 64)
}

func relaySSHSession(src, dst ssh.Channel, sr, dr <-chan *ssh.Request, r *recorder, op *operation, interactive bool) error {
	closeBoth := func() { src.Close(); dst.Close() }
	frontDone := make(chan struct{})
	go func() {
		defer close(frontDone)
		for req := range sr {
			valid := false
			switch req.Type {
			case "window-change":
				var size struct{ Columns, Rows, Width, Height uint32 }
				valid = interactive && ssh.Unmarshal(req.Payload, &size) == nil
			case "signal":
				var signal struct{ Name string }
				valid = len(req.Payload) <= 128 && ssh.Unmarshal(req.Payload, &signal) == nil
			}
			if !valid {
				req.Reply(false, nil)
				continue
			}
			ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			req.Reply(ok, nil)
			if err != nil {
				closeBoth()
				return
			}
		}
	}()
	resultCh := make(chan string, 1)
	go func() {
		result := "unknown"
		for req := range dr {
			switch req.Type {
			case "exit-status":
				var status struct{ Status uint32 }
				if ssh.Unmarshal(req.Payload, &status) != nil {
					closeBoth()
					continue
				}
				result = "failure"
				if status.Status == 0 {
					result = "success"
				}
			case "exit-signal":
				result = "failure"
			default:
				req.Reply(false, nil)
				continue
			}
			src.SendRequest(req.Type, false, req.Payload)
			req.Reply(true, nil)
		}
		resultCh <- result
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		// Never persist raw stdin: it also contains non-echoed password prompts.
		io.Copy(dst, src)
		dst.CloseWrite()
	}()
	outputDone := make(chan error, 2)
	copyOutput := func(out io.Writer, in io.Reader, stream string) {
		var err error
		if interactive {
			err = copySSHTerminal(out, in, r, op, stream)
		} else {
			_, err = io.Copy(out, in)
		}
		if err != nil {
			closeBoth()
		}
		outputDone <- err
	}
	go copyOutput(src, dst, "stdout")
	go copyOutput(src.Stderr(), dst.Stderr(), "stderr")
	first, second := <-outputDone, <-outputDone
	result := <-resultCh
	closeBoth()
	<-frontDone
	<-inputDone
	if err := op.end(result); err != nil {
		return err
	}
	return pumpResult(first, second)
}
