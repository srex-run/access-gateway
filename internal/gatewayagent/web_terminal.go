package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// Only the per-session mTLS management listener exposes this endpoint. Browser
// ownership/permission checks belong to the control plane; no public TCP
// connection can opt into this trusted path or supply its own target/account.
func (a *sessionAgent) terminal(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || a.config.Proxy == nil || !terminal.Supported(a.config.Proxy.Protocol) {
		http.Error(w, "terminal unavailable", http.StatusForbidden)
		return
	}
	source := net.ParseIP(req.Header.Get("X-Terminal-Source-IP"))
	if source == nil || source.IsUnspecified() || source.IsMulticast() {
		http.Error(w, "invalid terminal source", http.StatusBadRequest)
		return
	}
	c := a.controller
	c.mu.Lock()
	runtime := c.sessions[a.config.Request.SessionID]
	c.mu.Unlock()
	if runtime == nil {
		http.Error(w, "session unavailable", http.StatusConflict)
		return
	}
	// Serialize registration with stop/expiry, and count web + TCP connections
	// against the same approved limit.
	runtime.mu.Lock()
	if runtime.status != sessionRunning || !runtime.expiresAt.After(c.clock()) {
		runtime.mu.Unlock()
		http.Error(w, "session unavailable", http.StatusConflict)
		return
	}
	select {
	case runtime.semaphore <- struct{}{}:
	default:
		runtime.mu.Unlock()
		http.Error(w, "connection limit", http.StatusTooManyRequests)
		return
	}
	upgrader := websocket.Upgrader{HandshakeTimeout: 5 * time.Second, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}
	socket, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		<-runtime.semaphore
		runtime.mu.Unlock()
		return
	}
	connectionID := id.New()
	runtime.connections[connectionID] = []net.Conn{socket.UnderlyingConn()}
	runtime.connectionWG.Add(1)
	runtime.mu.Unlock()
	defer runtime.connectionWG.Done()
	defer func() { <-runtime.semaphore; runtime.removeConnection(connectionID); _ = socket.Close() }()
	parent := runtime.context
	if parent == nil {
		parent = req.Context()
	}
	ctx, cancel := context.WithDeadlineCause(parent, a.config.ExpiresAt, terminal.ErrSessionExpired)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	terminal.KeepAlive(ctx, socket)
	channel := &terminal.Channel{Socket: socket}
	startTimer := time.AfterFunc(15*time.Second, func() { _ = socket.Close() })
	defer startTimer.Stop()
	_ = socket.SetReadDeadline(time.Now().Add(15 * time.Second))
	var start terminal.Message
	if socket.ReadJSON(&start) != nil || !start.ValidFor(a.config.Proxy.Protocol) {
		return
	}
	startTimer.Stop()
	_ = socket.SetReadDeadline(time.Now().Add(45 * time.Second))
	base := gateway.ConnectionEvent{GatewayID: c.gatewayID, SessionID: runtime.request.SessionID, ConnectionID: connectionID, SourceIP: source.String()}
	if err = c.appendEvent(ctx, base, "connect_attempt", "received", "", c.clock(), nil, nil, nil); err != nil {
		c.auditFailure(runtime.request.SessionID, err)
		return
	}
	dialCtx, stopDial := context.WithTimeout(ctx, c.dialTimeout)
	backend, err := c.dial(dialCtx, "tcp", runtime.target)
	stopDial()
	if err != nil {
		if err = c.appendEvent(ctx, base, "backend_failed", "failure", "backend_unavailable", c.clock(), nil, nil, nil); err != nil {
			c.auditFailure(runtime.request.SessionID, err)
		}
		_ = channel.Send(terminal.Message{Type: "error", Data: "无法连接目标服务"})
		return
	}
	defer backend.Close()
	if !runtime.addConnection(connectionID, backend) {
		return
	}
	base.BackendSourceIP, base.BackendSourcePort = connectionLocalTuple(backend.LocalAddr())
	if base.BackendSourceIP == "" || base.BackendSourcePort == 0 {
		return
	}
	connectedAt := c.clock()
	if err = c.appendEvent(ctx, base, "backend_connected", "success", "", connectedAt, nil, nil, nil); err != nil {
		c.auditFailure(runtime.request.SessionID, err)
		return
	}
	host, _, _ := net.SplitHostPort(runtime.target)
	binding := sessionproxy.Binding{ConnectionID: connectionID, AssetID: runtime.request.TargetID, Account: runtime.request.TargetAccount, TargetHost: host, TargetPort: runtime.request.TargetPort, BackendSourceIP: base.BackendSourceIP, BackendSourcePort: base.BackendSourcePort}
	if c.proxy.Protocol == "ssh" {
		err = sessionproxy.ServeSSHTerminal(ctx, *c.proxy, backend, binding, c.operations, start, channel)
	} else {
		err = sessionproxy.ServeClientTerminal(ctx, *c.proxy, backend, binding, c.operations, start, channel, func(ctx context.Context, client net.Conn, cfg sessionproxy.Config) error {
			return c.extraTerminalConnection(ctx, runtime, source.String(), client, cfg)
		})
	}
	start = terminal.Message{}
	result, reason := "success", ""
	if closeReason := terminal.CloseReason(err); closeReason != "" {
		reason = closeReason
	} else if err != nil {
		result = "failure"
		reason = c.logTerminalFailure(runtime.request.SessionID, connectionID, *c.proxy, err)
		if errors.Is(err, sessionproxy.ErrAudit) {
			c.auditFailure(runtime.request.SessionID, err)
		}
		diagnostic := sessionproxy.DiagnoseTerminalFailure(err)
		_ = channel.Send(terminal.Message{Type: "error", Data: diagnostic.Detail + " (" + diagnostic.Reason + ")"})
	}
	duration := c.clock().Sub(connectedAt).Milliseconds()
	if err = c.appendEvent(ctx, base, "disconnected", result, reason, c.clock(), nil, nil, &duration); err != nil {
		c.auditFailure(runtime.request.SessionID, err)
	}
}

func (c *DirectController) extraTerminalConnection(ctx context.Context, runtime *directRuntime, source string, client net.Conn, cfg sessionproxy.Config) error {
	runtime.mu.Lock()
	if runtime.status != sessionRunning || !runtime.expiresAt.After(c.clock()) {
		runtime.mu.Unlock()
		return ErrInvalidInput
	}
	select {
	case runtime.semaphore <- struct{}{}:
	default:
		runtime.mu.Unlock()
		return ErrInvalidInput
	}
	connectionID := id.New()
	runtime.connections[connectionID] = []net.Conn{client}
	runtime.connectionWG.Add(1)
	runtime.mu.Unlock()
	defer runtime.connectionWG.Done()
	defer func() { <-runtime.semaphore; runtime.removeConnection(connectionID) }()
	base := gateway.ConnectionEvent{GatewayID: c.gatewayID, SessionID: runtime.request.SessionID, ConnectionID: connectionID, SourceIP: source}
	appendEvent := func(kind, result, reason string, at time.Time, duration *int64) error {
		err := c.appendEvent(ctx, base, kind, result, reason, at, nil, nil, duration)
		if err != nil {
			c.auditFailure(runtime.request.SessionID, err)
		}
		return err
	}
	if err := appendEvent("connect_attempt", "received", "", c.clock(), nil); err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	backend, err := c.dial(dialCtx, "tcp", runtime.target)
	cancel()
	if err != nil {
		return errors.Join(err, appendEvent("backend_failed", "failure", "backend_unavailable", c.clock(), nil))
	}
	defer backend.Close()
	if !runtime.addConnection(connectionID, backend) {
		return ErrInvalidInput
	}
	base.BackendSourceIP, base.BackendSourcePort = connectionLocalTuple(backend.LocalAddr())
	connectedAt := c.clock()
	if err = appendEvent("backend_connected", "success", "", connectedAt, nil); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(runtime.target)
	_, _, err = sessionproxy.Serve(ctx, cfg, client, backend, sessionproxy.Binding{ConnectionID: connectionID, AssetID: runtime.request.TargetID, Account: runtime.request.TargetAccount, TargetHost: host, TargetPort: runtime.request.TargetPort, BackendSourceIP: base.BackendSourceIP, BackendSourcePort: base.BackendSourcePort}, c.operations)
	result, reason := "success", ""
	if err != nil {
		result = "failure"
		reason = c.logTerminalFailure(runtime.request.SessionID, connectionID, cfg, err)
	}
	if errors.Is(err, sessionproxy.ErrAudit) {
		c.auditFailure(runtime.request.SessionID, err)
	}
	duration := c.clock().Sub(connectedAt).Milliseconds()
	return errors.Join(err, appendEvent("disconnected", result, reason, c.clock(), &duration))
}

func (c *DirectController) logTerminalFailure(sessionID, connectionID string, cfg sessionproxy.Config, err error) string {
	diagnostic := sessionproxy.DiagnoseTerminalFailure(err)
	event := c.logger.Warn().Str("session_id", sessionID).Str("connection_id", connectionID).
		Str("protocol", cfg.Protocol).Str("failure_stage", diagnostic.Stage).
		Str("reason", diagnostic.Reason).Str("error", diagnostic.Detail).
		Strs("error_types", terminalErrorTypes(err)).
		Bool("target_ca_configured", cfg.TargetCA != "").
		Bool("target_pin_configured", cfg.TargetCertificateSHA256 != "").
		Bool("ssh_host_keys_configured", len(cfg.TargetHostKeys) > 0).
		Bool("target_server_name_configured", cfg.TargetServerName != "")
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ProcessState != nil {
		event.Str("process_state", exitError.ProcessState.String())
	}
	var sshExit *ssh.ExitError
	if errors.As(err, &sshExit) {
		// The remote exit message/signal can contain arbitrary target text.
		// The numeric status alone is sufficient for safe startup diagnostics.
		event.Int("ssh_exit_status", sshExit.ExitStatus())
	}
	event.Msg("web terminal connection failed")
	return diagnostic.Reason
}

func terminalErrorTypes(err error) []string {
	var types []string
	var visit func(error)
	visit = func(err error) {
		if err == nil || len(types) >= 16 {
			return
		}
		types = append(types, fmt.Sprintf("%T", err))
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				visit(child)
			}
		} else {
			visit(errors.Unwrap(err))
		}
	}
	visit(err)
	return types
}
