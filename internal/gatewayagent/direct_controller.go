package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
	"github.com/srex-run/access-gateway/internal/terminal"
)

type DirectControllerOptions struct {
	Proxy       *sessionproxy.Config
	Operations  sessionproxy.Sink
	GatewayID   string
	BindHost    string
	PortStart   int
	PortEnd     int
	DialTimeout time.Duration
	Resolver    TargetResolver
	Exposure    ExposureProvider
	Events      ConnectionEventSink
	Logger      zerolog.Logger
	Clock       func() time.Time
}

type DirectController struct {
	proxy       *sessionproxy.Config
	operations  sessionproxy.Sink
	listen      func(context.Context, string, string) (net.Listener, error)
	dial        func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	gatewayID   string
	bindHost    string
	portStart   int
	portEnd     int
	nextPort    int
	dialTimeout time.Duration
	resolver    TargetResolver
	exposure    ExposureProvider
	events      ConnectionEventSink
	logger      zerolog.Logger
	clock       func() time.Time
	sessions    map[string]*directRuntime
}

type directRuntime struct {
	auditFailed  bool
	mu           sync.Mutex
	request      gateway.CreateSessionRequest
	target       string
	listener     net.Listener
	exposure     Exposure
	startedAt    time.Time
	expiresAt    time.Time
	status       string
	context      context.Context
	cancel       context.CancelCauseFunc
	done         chan struct{}
	connections  map[string][]net.Conn
	semaphore    chan struct{}
	connectionWG sync.WaitGroup
}

func NewDirectController(options DirectControllerOptions) (*DirectController, error) {
	options.GatewayID = strings.TrimSpace(options.GatewayID)
	options.BindHost = strings.TrimSpace(options.BindHost)
	if !id.IsUUID(options.GatewayID) {
		return nil, fmt.Errorf("direct controller gateway ID is invalid: %w", ErrInvalidInput)
	}
	if options.BindHost == "" {
		options.BindHost = "0.0.0.0"
	}
	if net.ParseIP(options.BindHost) == nil {
		return nil, fmt.Errorf("direct controller bind host must be an IP address: %w", ErrInvalidInput)
	}
	if options.PortStart < 1024 || options.PortStart > 65535 || options.PortEnd < options.PortStart || options.PortEnd > 65535 {
		return nil, fmt.Errorf("direct controller port range is invalid: %w", ErrInvalidInput)
	}
	if options.Resolver == nil || options.Exposure == nil || options.Events == nil {
		return nil, fmt.Errorf("direct controller resolver, exposure provider, and event sink are required")
	}
	if options.DialTimeout <= 0 {
		options.DialTimeout = 10 * time.Second
	}
	if options.DialTimeout > time.Minute {
		return nil, fmt.Errorf("direct controller dial timeout cannot exceed one minute: %w", ErrInvalidInput)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &DirectController{
		proxy: options.Proxy, operations: options.Operations,
		listen:    (&net.ListenConfig{}).Listen,
		dial:      (&net.Dialer{Timeout: options.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		gatewayID: options.GatewayID, bindHost: options.BindHost,
		portStart: options.PortStart, portEnd: options.PortEnd, nextPort: options.PortStart,
		dialTimeout: options.DialTimeout, resolver: options.Resolver, exposure: options.Exposure,
		events: options.Events, logger: options.Logger, clock: options.Clock,
		sessions: make(map[string]*directRuntime),
	}, nil
}

func (c *DirectController) Start(ctx context.Context, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	if err := gateway.ValidateCreateRequest(request); err != nil || !id.IsUUID(request.SessionID) || !id.IsUUID(request.TargetID) {
		return gateway.CreateSessionResponse{}, fmt.Errorf("validate direct gateway session: %w", ErrInvalidInput)
	}
	normalizedSource := netParseIP(request.SourceIP)
	if normalizedSource == "" && !request.WebOnly {
		return gateway.CreateSessionResponse{}, fmt.Errorf("validate direct gateway source: %w", ErrInvalidInput)
	}
	request.SourceIP = normalizedSource
	target, err := c.resolver.Resolve(request.TargetID, request.TargetPort)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	startedAt := c.clock()
	expiresAt := startedAt.Add(time.Duration(request.TTLSeconds) * time.Second)
	if request.ExpiresAt != nil {
		expiresAt = request.ExpiresAt.UTC()
	}
	if !expiresAt.After(startedAt) || expiresAt.After(startedAt.Add(time.Duration(request.TTLSeconds)*time.Second)) {
		return gateway.CreateSessionResponse{}, fmt.Errorf("session expiry is outside the approved validity: %w", ErrInvalidInput)
	}
	return c.startRuntime(ctx, request, target, 0, 0, "", "", startedAt, expiresAt)
}

func (c *DirectController) Restore(ctx context.Context, record SessionRecord) (gateway.CreateSessionResponse, error) {
	request := gateway.CreateSessionRequest{
		WebOnly:        record.WebOnly,
		ConnectionMode: record.ConnectionMode,
		SessionID:      record.SessionID, TargetID: record.TargetID, TargetPort: record.TargetPort,
		SourceIP: record.SourceIP, TargetAccount: record.TargetAccount,
		TTLSeconds: record.TTLSeconds, MaxConnections: record.MaxConnections,
		ExpiresAt:       record.RequestExpiresAt,
		ClientPublicKey: record.ClientPublicKey,
	}
	if c.proxy != nil {
		request.AuditPolicy = c.proxy.Policy()
	}
	if err := gateway.ValidateCreateRequest(request); err != nil || record.ListenerPort < 1 || record.ExternalPort < 1 || record.StartedAt == nil || record.ExpiresAt == nil {
		return gateway.CreateSessionResponse{}, fmt.Errorf("validate recovered direct session: %w", ErrInvalidInput)
	}
	if !record.ExpiresAt.After(c.clock()) {
		return gateway.CreateSessionResponse{}, fmt.Errorf("recovered direct session has expired: %w", ErrSessionConflict)
	}
	if record.ServerCertificate != "" {
		return gateway.CreateSessionResponse{}, fmt.Errorf("recovered direct session has a tunnel identity: %w", ErrSessionConflict)
	}
	target, err := c.resolver.Resolve(request.TargetID, request.TargetPort)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	return c.startRuntime(ctx, request, target, record.ListenerPort, record.ExternalPort, record.ExposureMode, record.ExposureRef, *record.StartedAt, *record.ExpiresAt)
}

func (c *DirectController) startRuntime(
	ctx context.Context,
	request gateway.CreateSessionRequest,
	target string,
	desiredListenerPort int,
	desiredExternalPort int,
	desiredMode string,
	desiredReference string,
	startedAt time.Time,
	expiresAt time.Time,
) (gateway.CreateSessionResponse, error) {
	if request.ConnectionMode == gateway.ConnectionModeAudit && (c.proxy == nil || c.operations == nil || c.proxy.Policy() != request.AuditPolicy) {
		return gateway.CreateSessionResponse{}, ErrInvalidInput
	}
	c.mu.Lock()
	if existing, exists := c.sessions[request.SessionID]; exists {
		if !gateway.SameCreateRequest(existing.request, request) {
			c.mu.Unlock()
			return gateway.CreateSessionResponse{}, ErrSessionConflict
		}
		response := existing.response()
		c.mu.Unlock()
		return response, nil
	}
	listener, listenerPort, err := c.listenLocked(ctx, desiredListenerPort)
	if err != nil {
		c.mu.Unlock()
		return gateway.CreateSessionResponse{}, err
	}
	c.mu.Unlock()

	exposure, err := c.exposure.Ensure(ctx, ExposureRequest{
		SessionID: request.SessionID, ListenerPort: listenerPort,
		DesiredExternalPort: desiredExternalPort, ExpiresAt: expiresAt,
	})
	if err != nil {
		_ = listener.Close()
		return gateway.CreateSessionResponse{}, fmt.Errorf("expose direct gateway listener: %w", err)
	}
	if desiredMode != "" && (exposure.Mode != desiredMode || exposure.Reference != desiredReference || exposure.ExternalPort != desiredExternalPort) {
		_ = listener.Close()
		_ = c.exposure.Remove(context.WithoutCancel(ctx), request.SessionID, exposure.Reference)
		return gateway.CreateSessionResponse{}, fmt.Errorf("direct gateway exposure changed during recovery: %w", ErrSessionConflict)
	}
	runtimeCtx, cancel := context.WithCancelCause(context.Background())
	runtime := &directRuntime{
		request: request, target: target, listener: listener, exposure: exposure,
		startedAt: startedAt, expiresAt: expiresAt, status: sessionRunning,
		context: runtimeCtx, cancel: cancel, done: make(chan struct{}), connections: make(map[string][]net.Conn),
		semaphore: make(chan struct{}, request.MaxConnections),
	}
	c.mu.Lock()
	if _, exists := c.sessions[request.SessionID]; exists {
		c.mu.Unlock()
		cancel(nil)
		_ = listener.Close()
		_ = c.exposure.Remove(context.WithoutCancel(ctx), request.SessionID, exposure.Reference)
		return gateway.CreateSessionResponse{}, ErrSessionConflict
	}
	c.sessions[request.SessionID] = runtime
	c.mu.Unlock()
	go c.serve(runtimeCtx, runtime)
	return runtime.response(), nil
}

func (c *DirectController) listenLocked(ctx context.Context, desiredPort int) (net.Listener, int, error) {
	if desiredPort != 0 {
		if desiredPort < c.portStart || desiredPort > c.portEnd {
			return nil, 0, fmt.Errorf("recovered listener port is outside the configured pool: %w", ErrInvalidInput)
		}
		listener, err := c.listen(ctx, "tcp", net.JoinHostPort(c.bindHost, strconv.Itoa(desiredPort)))
		if err != nil {
			return nil, 0, fmt.Errorf("restore direct gateway listener: %w", err)
		}
		return listener, desiredPort, nil
	}
	poolSize := c.portEnd - c.portStart + 1
	for attempt := 0; attempt < poolSize; attempt++ {
		port := c.nextPort
		c.nextPort++
		if c.nextPort > c.portEnd {
			c.nextPort = c.portStart
		}
		listener, err := c.listen(ctx, "tcp", net.JoinHostPort(c.bindHost, strconv.Itoa(port)))
		if err == nil {
			return listener, port, nil
		}
		if ctx.Err() != nil {
			return nil, 0, fmt.Errorf("allocate direct gateway listener: %w", ctx.Err())
		}
	}
	return nil, 0, ErrCapacityExhausted
}

func (c *DirectController) serve(ctx context.Context, runtime *directRuntime) {
	defer close(runtime.done)
	ttl := time.NewTimer(time.Until(runtime.expiresAt))
	defer ttl.Stop()
	expired := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-ttl.C:
			runtime.mu.Lock()
			if runtime.status == sessionRunning {
				runtime.status = sessionExpired
			}
			runtime.cancel(terminal.ErrSessionExpired)
			_ = runtime.listener.Close()
			for _, connections := range runtime.connections {
				for _, connection := range connections {
					_ = connection.Close()
				}
			}
			runtime.mu.Unlock()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := c.exposure.Remove(cleanupCtx, runtime.request.SessionID, runtime.exposure.Reference); err != nil {
				c.logger.Error().Err(err).Str("session_id", runtime.request.SessionID).Bool("alert", true).Msg("remove expired gateway exposure failed")
			}
			cancel()
		}
		close(expired)
	}()

	var delay time.Duration
	for {
		connection, err := runtime.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				<-expired
				return
			default:
			}
			runtime.mu.Lock()
			terminal := runtime.status != sessionRunning
			runtime.mu.Unlock()
			if terminal || errors.Is(err, net.ErrClosed) {
				<-expired
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
			}
			if delay > time.Second {
				delay = time.Second
			}
			select {
			case <-ctx.Done():
				<-expired
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		runtime.connectionWG.Add(1)
		go func() {
			defer runtime.connectionWG.Done()
			c.handleConnection(ctx, runtime, connection)
		}()
	}
}

func (c *DirectController) handleConnection(ctx context.Context, runtime *directRuntime, client net.Conn) {
	// Web-only grants are never usable through the TCP listener, even locally.
	if runtime.request.WebOnly {
		_ = client.Close()
		return
	}
	connectionID := id.New()
	startedAt := c.clock()
	sourceIP := connectionSourceIP(client.RemoteAddr())
	base := gateway.ConnectionEvent{
		GatewayID: c.gatewayID, ConnectionID: connectionID, SessionID: runtime.request.SessionID,
		SourceIP: sourceIP,
	}
	if err := c.appendEvent(ctx, base, "connect_attempt", "received", "", startedAt, nil, nil, nil); err != nil {
		_ = client.Close()
		c.auditFailure(runtime.request.SessionID, err)
		return
	}
	if sourceIP == "" || sourceIP != runtime.request.SourceIP {
		if err := c.appendEvent(ctx, base, "source_rejected", "rejected", "source_ip_mismatch", c.clock(), nil, nil, nil); err != nil {
			c.auditFailure(runtime.request.SessionID, err)
		}
		_ = client.Close()
		return
	}
	select {
	case runtime.semaphore <- struct{}{}:
		defer func() { <-runtime.semaphore }()
	default:
		if err := c.appendEvent(ctx, base, "capacity_rejected", "rejected", "session_connection_limit", c.clock(), nil, nil, nil); err != nil {
			c.auditFailure(runtime.request.SessionID, err)
		}
		_ = client.Close()
		return
	}
	if !runtime.addConnection(connectionID, client) {
		_ = client.Close()
		return
	}
	defer runtime.removeConnection(connectionID)
	defer client.Close()

	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	backend, err := c.dial(dialCtx, "tcp", runtime.target)
	cancel()
	if err != nil {
		if eventErr := c.appendEvent(ctx, base, "backend_failed", "failure", "backend_unavailable", c.clock(), nil, nil, nil); eventErr != nil {
			c.auditFailure(runtime.request.SessionID, eventErr)
		}
		_ = client.Close()
		return
	}
	if !runtime.addConnection(connectionID, backend) {
		_ = backend.Close()
		_ = client.Close()
		return
	}
	defer backend.Close()
	defer client.Close()
	backendSourceIP, backendSourcePort := connectionLocalTuple(backend.LocalAddr())
	base.BackendSourceIP = backendSourceIP
	base.BackendSourcePort = backendSourcePort
	if backendSourceIP == "" || backendSourcePort == 0 {
		c.auditFailure(runtime.request.SessionID, fmt.Errorf("backend source tuple is unavailable"))
		return
	}
	connectedAt := c.clock()
	if err := c.appendEvent(ctx, base, "backend_connected", "success", "", connectedAt, nil, nil, nil); err != nil {
		c.auditFailure(runtime.request.SessionID, err)
		return
	}
	var handshakeUp, handshakeDown int64
	if runtime.request.ConnectionMode == gateway.ConnectionModeAudit {
		host, _, _ := net.SplitHostPort(runtime.target)
		up, down, err := sessionproxy.Serve(ctx, *c.proxy, client, backend, sessionproxy.Binding{ConnectionID: connectionID, AssetID: runtime.request.TargetID, Account: runtime.request.TargetAccount, TargetHost: host, TargetPort: runtime.request.TargetPort, BackendSourceIP: backendSourceIP, BackendSourcePort: backendSourcePort}, c.operations)
		result, reason := "success", ""
		if err != nil {
			result, reason = "failure", "application_proxy_failed"
			if errors.Is(err, sessionproxy.ErrProtocol) {
				reason = "unsupported_application_protocol"
			}
			if errors.Is(err, sessionproxy.ErrIdentity) {
				reason = "application_identity_rejected"
			}
			if errors.Is(err, sessionproxy.ErrClientTLS) {
				reason = "client_tls_handshake_failed"
			}
			if errors.Is(err, sessionproxy.ErrTargetTLS) {
				reason = sessionproxy.TargetTLSFailureReason(err)
			}
			if errors.Is(err, sessionproxy.ErrTargetGreeting) {
				reason = "mysql_target_greeting_unavailable"
			}
			if errors.Is(err, sessionproxy.ErrAudit) {
				reason = "operation_audit_unavailable"
				c.auditFailure(runtime.request.SessionID, err)
			}
		}
		duration := c.clock().Sub(connectedAt).Milliseconds()
		if eventErr := c.appendEvent(context.WithoutCancel(ctx), base, "disconnected", result, reason, c.clock(), &up, &down, &duration); eventErr != nil {
			c.auditFailure(runtime.request.SessionID, eventErr)
		}
		return
	}
	if runtime.request.ConnectionMode == gateway.ConnectionModeNative {
		stream, err := negotiateNativeEncryption(client, backend)
		if err != nil {
			if eventErr := c.appendEvent(ctx, base, "auth_rejected", "rejected", nativeHandshakeReason(err), c.clock(), nil, nil, nil); eventErr != nil {
				c.auditFailure(runtime.request.SessionID, eventErr)
			}
			return
		}
		client, backend = stream.client, stream.backend
		handshakeUp, handshakeDown = stream.up, stream.down
	}

	type copyResult struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan copyResult, 2)
	go func() {
		count, copyErr := io.Copy(backend, client)
		if tcp, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		if copyErr != nil {
			_ = client.Close()
			_ = backend.Close()
		}
		results <- copyResult{direction: "up", bytes: count, err: copyErr}
	}()
	go func() {
		count, copyErr := io.Copy(client, backend)
		if tcp, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		if copyErr != nil {
			_ = client.Close()
			_ = backend.Close()
		}
		results <- copyResult{direction: "down", bytes: count, err: copyErr}
	}()
	bytesUp, bytesDown := handshakeUp, handshakeDown
	var encryptionRejected bool
	for count := 0; count < 2; count++ {
		result := <-results
		if result.direction == "up" {
			bytesUp += result.bytes
		} else {
			bytesDown += result.bytes
		}
		encryptionRejected = encryptionRejected || errors.Is(result.err, errNativeEncryption)
	}
	if encryptionRejected {
		if err := c.appendEvent(ctx, base, "auth_rejected", "rejected", "native_encryption_required", c.clock(), nil, nil, nil); err != nil {
			c.auditFailure(runtime.request.SessionID, err)
		}
	}
	duration := c.clock().Sub(connectedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	result, reason := "success", ""
	if encryptionRejected {
		result, reason = "failure", "native_encryption_required"
	}
	if err := c.appendEvent(context.WithoutCancel(ctx), base, "disconnected", result, reason, c.clock(), &bytesUp, &bytesDown, &duration); err != nil {
		c.auditFailure(runtime.request.SessionID, err)
	}
}

func (c *DirectController) appendEvent(ctx context.Context, base gateway.ConnectionEvent, eventType, result, reason string, occurredAt time.Time, bytesUp, bytesDown, durationMS *int64) error {
	event := base
	event.EventID = id.New()
	event.EventType = eventType
	event.Result = result
	event.Reason = reason
	event.OccurredAt = occurredAt
	event.BytesUp = bytesUp
	event.BytesDown = bytesDown
	event.DurationMS = durationMS
	if result == "rejected" || result == "failure" {
		c.logger.Warn().Str("session_id", event.SessionID).Str("connection_id", event.ConnectionID).
			Str("event_type", event.EventType).Str("source_ip", event.SourceIP).Str("reason", event.Reason).
			Msg("session connection failed")
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return c.events.Append(persistCtx, event)
}

func (c *DirectController) auditFailure(sessionID string, err error) {
	c.logger.Error().Err(err).Str("session_id", sessionID).Bool("alert", true).Msg("persist gateway connection audit event failed")
	c.mu.Lock()
	runtime := c.sessions[sessionID]
	c.mu.Unlock()
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	if runtime.auditFailed {
		runtime.mu.Unlock()
		return
	}
	runtime.auditFailed = true
	runtime.status = sessionStopping
	runtime.cancel(sessionproxy.ErrAudit)
	_ = runtime.listener.Close()
	for _, connections := range runtime.connections {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}
	runtime.mu.Unlock()
	// Stop waits for connection workers, so run cleanup outside the worker
	// that reported the failure. Further audit failures cannot spawn retries.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := c.Stop(ctx, sessionID); err != nil {
			c.logger.Error().Err(err).Str("session_id", sessionID).Bool("alert", true).Msg("close unauditable gateway session failed")
		}
	}()
}

func (c *DirectController) Stop(ctx context.Context, sessionID string) (gateway.CloseSessionResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.CloseSessionResponse{}, fmt.Errorf("validate direct gateway stop request: %w", ErrInvalidInput)
	}
	now := c.clock()
	c.mu.Lock()
	runtime, exists := c.sessions[sessionID]
	c.mu.Unlock()
	if !exists {
		if err := c.exposure.Remove(ctx, sessionID, ""); err != nil {
			return gateway.CloseSessionResponse{}, fmt.Errorf("remove orphaned gateway exposure: %w", err)
		}
		return gateway.CloseSessionResponse{SessionID: sessionID, Status: "not_found", ClosedAt: now}, nil
	}
	runtime.mu.Lock()
	wasExpired := runtime.status == sessionExpired
	if !wasExpired {
		runtime.status = sessionStopping
	}
	runtime.cancel(terminal.ErrSessionClosed)
	_ = runtime.listener.Close()
	for _, connections := range runtime.connections {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}
	runtime.mu.Unlock()
	select {
	case <-runtime.done:
	case <-ctx.Done():
		return gateway.CloseSessionResponse{}, fmt.Errorf("wait for direct gateway listener shutdown: %w", ctx.Err())
	}
	if err := waitForConnections(ctx, runtime); err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	if err := c.exposure.Remove(ctx, sessionID, runtime.exposure.Reference); err != nil {
		runtime.mu.Lock()
		runtime.status = sessionRevokeFailed
		runtime.mu.Unlock()
		return gateway.CloseSessionResponse{}, fmt.Errorf("remove direct gateway exposure: %w", err)
	}
	status := sessionClosed
	if wasExpired {
		status = sessionExpired
	}
	runtime.mu.Lock()
	runtime.status = status
	runtime.mu.Unlock()
	c.mu.Lock()
	if c.sessions[sessionID] == runtime {
		delete(c.sessions, sessionID)
	}
	c.mu.Unlock()
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: status, ClosedAt: c.clock()}, nil
}

func (c *DirectController) Status(_ context.Context, sessionID string) (gateway.SessionStatusResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.SessionStatusResponse{}, fmt.Errorf("validate direct gateway status request: %w", ErrInvalidInput)
	}
	c.mu.Lock()
	runtime, exists := c.sessions[sessionID]
	c.mu.Unlock()
	if !exists {
		return gateway.SessionStatusResponse{SessionID: sessionID, Status: "not_found"}, nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	expiresAt := runtime.expiresAt
	return gateway.SessionStatusResponse{
		ConnectionMode: runtime.request.ConnectionMode,
		SessionID:      sessionID, Status: runtime.status,
		ListenerPort: listenerPort(runtime.listener), ExternalPort: runtime.exposure.ExternalPort,
		ExposureMode: runtime.exposure.Mode, ExposureRef: runtime.exposure.Reference, ExpiresAt: &expiresAt,
	}, nil
}

func (c *DirectController) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	runtimes := make([]*directRuntime, 0, len(c.sessions))
	for _, runtime := range c.sessions {
		runtimes = append(runtimes, runtime)
	}
	c.mu.Unlock()
	for _, runtime := range runtimes {
		runtime.mu.Lock()
		runtime.cancel(terminal.ErrAgentStopped)
		_ = runtime.listener.Close()
		for _, connections := range runtime.connections {
			for _, connection := range connections {
				_ = connection.Close()
			}
		}
		runtime.mu.Unlock()
	}
	for _, runtime := range runtimes {
		select {
		case <-runtime.done:
		case <-ctx.Done():
			return fmt.Errorf("shutdown direct gateway sessions: %w", ctx.Err())
		}
		if err := waitForConnections(ctx, runtime); err != nil {
			return err
		}
	}
	return nil
}

func waitForConnections(ctx context.Context, runtime *directRuntime) error {
	done := make(chan struct{})
	go func() {
		runtime.connectionWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for direct gateway connections: %w", ctx.Err())
	}
}

func (r *directRuntime) response() gateway.CreateSessionResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	return gateway.CreateSessionResponse{
		ConnectionMode: r.request.ConnectionMode,
		SessionID:      r.request.SessionID, Status: r.status,
		ProcessID:    fmt.Sprintf("tcp-%d", listenerPort(r.listener)),
		ListenerPort: listenerPort(r.listener), ExternalPort: r.exposure.ExternalPort,
		ExposureMode: r.exposure.Mode, ExposureRef: r.exposure.Reference,
		StartedAt: r.startedAt, ExpiresAt: r.expiresAt,
	}
}

func (r *directRuntime) addConnection(connectionID string, connection net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status != sessionRunning {
		return false
	}
	r.connections[connectionID] = append(r.connections[connectionID], connection)
	return true
}

func (r *directRuntime) removeConnection(connectionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.connections, connectionID)
}

func listenerPort(listener net.Listener) int {
	if listener == nil {
		return 0
	}
	if address, ok := listener.Addr().(*net.TCPAddr); ok {
		return address.Port
	}
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(rawPort)
	return port
}

func connectionSourceIP(address net.Addr) string {
	if tcp, ok := address.(*net.TCPAddr); ok {
		parsed, ok := netip.AddrFromSlice(tcp.IP)
		if !ok {
			return ""
		}
		return parsed.Unmap().String()
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return ""
	}
	return netParseIP(host)
}

func connectionLocalTuple(address net.Addr) (string, int) {
	if tcp, ok := address.(*net.TCPAddr); ok {
		parsed, ok := netip.AddrFromSlice(tcp.IP)
		if !ok || tcp.Port < 1 || tcp.Port > 65535 {
			return "", 0
		}
		return parsed.Unmap().String(), tcp.Port
	}
	host, rawPort, err := net.SplitHostPort(address.String())
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return "", 0
	}
	return netParseIP(host), port
}
