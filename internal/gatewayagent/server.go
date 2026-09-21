package gatewayagent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/observability"
)

type Server struct {
	manager            *Manager
	secret             string
	logger             zerolog.Logger
	metrics            *observability.Metrics
	metricsEnabled     bool
	metricsBearerToken string
}

func NewServer(manager *Manager, internalSecret string, logger zerolog.Logger) (*Server, error) {
	return NewServerWithOptions(ServerOptions{Manager: manager, InternalSecret: internalSecret, Logger: logger})
}

type ServerOptions struct {
	Manager            *Manager
	InternalSecret     string
	Logger             zerolog.Logger
	Metrics            *observability.Metrics
	MetricsEnabled     bool
	MetricsBearerToken string
}

func NewServerWithOptions(options ServerOptions) (*Server, error) {
	manager := options.Manager
	internalSecret := options.InternalSecret
	if manager == nil || len([]byte(internalSecret)) < 32 {
		return nil, fmt.Errorf("gateway server requires manager and a 32-byte internal secret")
	}
	return &Server{
		manager: manager, secret: internalSecret, logger: options.Logger,
		metrics: options.Metrics, metricsEnabled: options.MetricsEnabled,
		metricsBearerToken: strings.TrimSpace(options.MetricsBearerToken),
	}, nil
}

func (s *Server) Container() *restful.Container {
	container := restful.NewContainer()
	container.Router(restful.CurlyRouter{})
	container.Filter(s.securityFilter)
	container.Filter(s.metricsFilter)
	internal := new(restful.WebService)
	internal.Path("/internal/gateway").Consumes(restful.MIME_JSON).Produces(restful.MIME_JSON)
	internal.Route(internal.POST("/sessions").To(s.createSession))
	internal.Route(internal.GET("/sessions/{session_id}").To(s.getSession))
	internal.Route(internal.DELETE("/sessions/{session_id}").To(s.closeSession))
	container.Add(internal)
	health := new(restful.WebService)
	health.Path("").Produces(restful.MIME_JSON)
	health.Route(health.GET("/healthz").To(func(_ *restful.Request, response *restful.Response) {
		_ = response.WriteEntity(map[string]string{"status": "ok"})
	}))
	health.Route(health.GET("/readyz").To(func(_ *restful.Request, response *restful.Response) {
		active, maximum := s.manager.Capacity()
		_ = response.WriteEntity(gateway.ReadinessReport{Status: "ready", ActiveSessions: &active, MaxSessions: &maximum})
	}))
	container.Add(health)
	if s.metricsEnabled && s.metrics != nil {
		container.Handle("/metrics", http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			s.syncSessionMetrics()
			s.metrics.Handler(s.metricsBearerToken).ServeHTTP(response, request)
		}))
	}
	return container
}

func (s *Server) metricsFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	startedAt := time.Now()
	chain.ProcessFilter(request, response)
	status := response.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	s.metrics.ObserveHTTP(request.Request.Method, request.SelectedRoutePath(), status, time.Since(startedAt))
	s.syncSessionMetrics()
}

func (s *Server) syncSessionMetrics() {
	for status, count := range s.manager.SessionCounts() {
		s.metrics.SetManagedSessions(status, count)
	}
	s.metrics.SetOverdueSessions(s.manager.OverdueSessionCount())
}

func (s *Server) securityFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Request.TLS != nil {
		response.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	path := request.Request.URL.Path
	if path != "/healthz" && path != "/readyz" {
		values := request.Request.Header.Values("X-Gateway-Internal-Secret")
		if len(values) != 1 || len(values[0]) != len(s.secret) || subtle.ConstantTimeCompare([]byte(values[0]), []byte(s.secret)) != 1 {
			_ = response.WriteHeaderAndEntity(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
	}
	request.Request.Body = http.MaxBytesReader(response.ResponseWriter, request.Request.Body, 1<<20)
	chain.ProcessFilter(request, response)
}

func (s *Server) createSession(request *restful.Request, response *restful.Response) {
	var body gateway.CreateSessionRequest
	decoder := json.NewDecoder(request.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway session: %w", ErrInvalidInput))
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		s.writeError(response, fmt.Errorf("decode gateway session: %w", ErrInvalidInput))
		return
	}
	if key := strings.TrimSpace(request.Request.Header.Get("Idempotency-Key")); key == "" || key != body.SessionID {
		s.writeError(response, fmt.Errorf("create idempotency key is invalid: %w", ErrInvalidInput))
		return
	}
	value, err := s.manager.Start(request.Request.Context(), body)
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Pragma", "no-cache")
	_ = response.WriteHeaderAndEntity(http.StatusCreated, value)
}

func (s *Server) getSession(request *restful.Request, response *restful.Response) {
	value, err := s.manager.Get(request.Request.Context(), request.PathParameter("session_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) closeSession(request *restful.Request, response *restful.Response) {
	sessionID := request.PathParameter("session_id")
	key := strings.TrimSpace(request.Request.Header.Get("Idempotency-Key"))
	if key != "revoke-"+sessionID && key != "compensate-"+sessionID {
		s.writeError(response, fmt.Errorf("close idempotency key is invalid: %w", ErrInvalidInput))
		return
	}
	value, err := s.manager.Stop(request.Request.Context(), sessionID, "requested")
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) writeError(response *restful.Response, err error) {
	status := http.StatusInternalServerError
	public := "internal server error"
	switch {
	case errors.Is(err, ErrInvalidInput):
		status, public = http.StatusBadRequest, "bad request"
	case errors.Is(err, ErrTargetNotAllowed):
		status, public = http.StatusForbidden, "target not allowed"
	case errors.Is(err, ErrSessionNotFound):
		status, public = http.StatusNotFound, "not found"
	case errors.Is(err, ErrSessionConflict), errors.Is(err, ErrSessionInProgress):
		status, public = http.StatusConflict, "conflict"
	case errors.Is(err, ErrCapacityExhausted):
		status, public = http.StatusServiceUnavailable, "capacity exhausted"
	}
	if status >= 500 {
		s.logger.Error().Err(err).Msg("gateway request failed")
	}
	encoded, marshalErr := json.Marshal(map[string]string{"error": public})
	if marshalErr != nil {
		response.WriteHeader(status)
		return
	}
	response.Header().Set("Content-Type", restful.MIME_JSON)
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}
