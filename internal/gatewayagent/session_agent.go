package gatewayagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
)

type sessionAuditSink struct {
	mu       sync.Mutex
	spool    *FileEventSpool
	reporter *AuditReporter
}

// An ephemeral agent cannot carry unacknowledged audit events to a replacement.
// Require the collector to acknowledge connection events before forwarding.
func (s *sessionAuditSink) Append(ctx context.Context, event gateway.ConnectionEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.spool.Append(ctx, event); err != nil {
		return err
	}
	return s.flushLocked(ctx)
}

func (s *sessionAuditSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked(ctx)
}

func (s *sessionAuditSink) flushLocked(ctx context.Context) error {
	for s.spool.PendingCount() > 0 {
		if _, err := s.reporter.Flush(ctx); err != nil {
			return err
		}
	}
	return nil
}

type sessionAgent struct {
	operations *operationSink
	controller *DirectController
	audit      *sessionAuditSink
	config     SessionConfig
	response   gateway.CreateSessionResponse
	mu         sync.Mutex
	closed     bool
	done       chan struct{}
	once       sync.Once
}

func RunSessionAgent(ctx context.Context, cfg SessionConfig, stateDirectory string, logger zerolog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !cfg.ExpiresAt.After(time.Now()) || cfg.StartedAt.After(time.Now().Add(5*time.Second)) {
		return fmt.Errorf("session grant is expired or not yet valid: %w", ErrInvalidInput)
	}
	if err := sessionStopRequested(stateDirectory); err != nil {
		return err
	}
	resolver, err := NewStaticTargetResolver([]TargetMapEntry{{TargetID: cfg.Request.TargetID, Host: cfg.TargetHost, Ports: []int{cfg.Request.TargetPort}}})
	if err != nil {
		return err
	}
	spool, err := NewFileEventSpool(filepath.Join(stateDirectory, "events.jsonl"))
	if err != nil {
		return err
	}
	reporter, err := NewAuditReporter(spool, AuditReporterOptions{
		GatewayID: cfg.GatewayID, SessionID: cfg.Request.SessionID, AuditSecret: cfg.AuditToken,
		ControlPlaneURL: cfg.ControlPlaneURL, AllowHTTP: cfg.AuditAllowHTTP, Logger: logger,
	})
	if err != nil {
		return err
	}
	audit := &sessionAuditSink{spool: spool, reporter: reporter}
	operations, err := newOperationSink(stateDirectory, reporter)
	if err != nil {
		return err
	}
	bindHost, listenerPort := cfg.ListenerAddress()
	controller, err := NewDirectController(DirectControllerOptions{
		GatewayID: cfg.GatewayID, BindHost: bindHost, PortStart: listenerPort, PortEnd: listenerPort,
		Resolver: resolver, Exposure: DirectExposureProvider{}, Events: audit, Logger: logger,
		Proxy: cfg.Proxy, Operations: operations,
	})
	if err != nil {
		return err
	}
	response, err := controller.Restore(ctx, SessionRecord{
		WebOnly:   cfg.Request.WebOnly,
		SessionID: cfg.Request.SessionID, ConnectionMode: cfg.Request.ConnectionMode,
		TargetID: cfg.Request.TargetID, TargetPort: cfg.Request.TargetPort,
		SourceIP: cfg.Request.SourceIP, TargetAccount: cfg.Request.TargetAccount,
		TTLSeconds: cfg.Request.TTLSeconds, MaxConnections: cfg.Request.MaxConnections,
		ListenerPort: listenerPort, ExternalPort: listenerPort,
		ExposureMode: "direct", ExposureRef: fmt.Sprintf("direct/%d", listenerPort),
		StartedAt: &cfg.StartedAt, ExpiresAt: &cfg.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("start approved session listener: %w", err)
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := controller.Shutdown(shutdown); err != nil {
			logger.Error().Err(err).Bool("alert", true).Msg("session listener shutdown failed")
		}
	}()
	agent := &sessionAgent{controller: controller, audit: audit, operations: operations, config: cfg, response: response, done: make(chan struct{})}
	tlsConfig, err := cfg.ManagementTLS(true)
	if err != nil {
		return err
	}
	management, err := net.Listen("tcp", cfg.ManagementAddress())
	if err != nil {
		return fmt.Errorf("listen on session management port: %w", err)
	}
	defer management.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", agent.status)
	mux.HandleFunc("POST /stop", agent.stop)
	mux.HandleFunc("GET /terminal", agent.terminal)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		status, err := controller.Status(r.Context(), cfg.Request.SessionID)
		if err != nil || status.Status != sessionRunning {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	servers := []*http.Server{
		{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second},
		{Handler: healthMux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second},
	}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- servers[0].Serve(tls.NewListener(management, tlsConfig)) }()
	if cfg.Network == nil {
		health, err := net.Listen("tcp", fmt.Sprintf(":%d", SessionHealthPort))
		if err != nil {
			_ = servers[0].Close()
			return fmt.Errorf("listen on session health port: %w", err)
		}
		defer health.Close()
		go func() { errorsCh <- servers[1].Serve(health) }()
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(shutdown)
			_ = server.Close()
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := agent.close(shutdown)
			cancel()
			return err
		case <-agent.done:
			return nil
		case err := <-errorsCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return fmt.Errorf("serve session agent: %w", err)
		case <-ticker.C:
			if err := sessionStopRequested(stateDirectory); err != nil {
				stopCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				err = agent.close(stopCtx)
				cancel()
				if err == nil || cfg.Network != nil {
					return err
				}
				logger.Error().Err(err).Bool("alert", true).Msg("revoked session audit delivery still pending")
			}
			status, err := controller.Status(ctx, cfg.Request.SessionID)
			if err == nil && status.Status != sessionRunning {
				flushCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
				err = agent.close(flushCtx)
				cancel()
				// Host runtimes recover the durable spool after this process exits.
				if err == nil || cfg.Network != nil {
					return err
				}
				logger.Error().Err(err).Bool("alert", true).Msg("session stopped; audit delivery still pending")
			}
		}
	}
}

func sessionStopRequested(stateDirectory string) error {
	_, err := os.Lstat(filepath.Join(stateDirectory, "stop"))
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("session grant has been revoked or its state is unavailable")
}

// FlushSessionAudit is also used by the controller after an agent exits. The
// caller must hold the session process lock so no agent can mutate the spool.
func FlushSessionAudit(ctx context.Context, cfg SessionConfig, stateDirectory string, logger zerolog.Logger) error {
	spool, err := NewFileEventSpool(filepath.Join(stateDirectory, "events.jsonl"))
	if err != nil {
		return err
	}
	reporter, err := NewAuditReporter(spool, AuditReporterOptions{
		GatewayID: cfg.GatewayID, SessionID: cfg.Request.SessionID, AuditSecret: cfg.AuditToken,
		ControlPlaneURL: cfg.ControlPlaneURL, AllowHTTP: cfg.AuditAllowHTTP, Logger: logger,
	})
	if err != nil {
		return err
	}
	for spool.PendingCount() > 0 {
		if _, err := reporter.Flush(ctx); err != nil {
			return err
		}
	}
	operations, err := newOperationSink(stateDirectory, reporter)
	if err != nil {
		return err
	}
	return operations.Flush(ctx)
}

func (a *sessionAgent) status(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	response := a.response
	status, err := a.controller.Status(r.Context(), a.config.Request.SessionID)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	response.Status = status.Status
	if a.closed {
		response.Status = sessionClosed
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *sessionAgent) close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		if _, err := a.controller.Stop(ctx, a.config.Request.SessionID); err != nil {
			return err
		}
		a.closed = true
	}
	if err := a.audit.Flush(ctx); err != nil {
		return err
	}
	if a.operations != nil {
		return a.operations.Flush(ctx)
	}
	return nil
}

func (a *sessionAgent) stop(w http.ResponseWriter, r *http.Request) {
	if err := a.close(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(gateway.CloseSessionResponse{SessionID: a.config.Request.SessionID, Status: sessionClosed, ClosedAt: time.Now()})
	a.once.Do(func() { close(a.done) })
}
