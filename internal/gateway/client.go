package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"

	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/terminal"
)

var ErrUnavailable = errors.New("gateway unavailable")

type CreateSessionRequest struct {
	WebOnly         bool                  `json:"web_only,omitempty"`
	AuditPolicy     operationaudit.Policy `json:"audit_policy,omitempty,omitzero"`
	ConnectionMode  string                `json:"connection_mode,omitempty"`
	SessionID       string                `json:"session_id"`
	TargetID        string                `json:"target_id"`
	TargetPort      int                   `json:"target_port"`
	SourceIP        string                `json:"source_ip"`
	TargetAccount   string                `json:"target_account"`
	TTLSeconds      int                   `json:"ttl_seconds"`
	ExpiresAt       *time.Time            `json:"expires_at,omitempty"`
	MaxConnections  int                   `json:"max_connections"`
	ClientPublicKey string                `json:"client_public_key"`
}

type CreateSessionResponse struct {
	ConnectionMode    string    `json:"connection_mode,omitempty"`
	ServerCertificate string    `json:"server_certificate"`
	SessionID         string    `json:"session_id"`
	Status            string    `json:"status"`
	ProcessID         string    `json:"process_id"`
	ListenerPort      int       `json:"listener_port"`
	ExternalPort      int       `json:"external_port"`
	ExposureMode      string    `json:"exposure_mode"`
	ExposureRef       string    `json:"exposure_ref"`
	StartedAt         time.Time `json:"started_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// SameCreateRequest compares the approved deadline by value across JSON round trips.
func SameCreateRequest(left, right CreateSessionRequest) bool {
	leftExpiry, rightExpiry := left.ExpiresAt, right.ExpiresAt
	left.ExpiresAt, right.ExpiresAt = nil, nil
	return left == right && ((leftExpiry == nil && rightExpiry == nil) ||
		(leftExpiry != nil && rightExpiry != nil && leftExpiry.Equal(*rightExpiry)))
}

type CloseSessionResponse struct {
	SessionID string    `json:"session_id"`
	Status    string    `json:"status"`
	ClosedAt  time.Time `json:"closed_at"`
}

type SessionStatusResponse struct {
	ConnectionMode string     `json:"connection_mode,omitempty"`
	SessionID      string     `json:"session_id"`
	Status         string     `json:"status"`
	ListenerPort   int        `json:"listener_port,omitempty"`
	ExternalPort   int        `json:"external_port,omitempty"`
	ExposureMode   string     `json:"exposure_mode,omitempty"`
	ExposureRef    string     `json:"exposure_ref,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

const MaxSessionConnections = 5

const (
	ConnectionModeNative = "native"
	ConnectionModeAudit  = "audit"
	ConnectionModeDirect = "direct"
	ConnectionModeTunnel = "tunnel"
)

// Missing modes identify historical tunnel records; validation rejects them.
func NormalizeConnectionMode(mode string) string {
	if mode == "" {
		return ConnectionModeTunnel
	}
	return mode
}

func ValidateConnectionIdentity(mode, publicKey string) error {
	switch NormalizeConnectionMode(mode) {
	case ConnectionModeNative, ConnectionModeAudit:
		if publicKey != "" {
			return fmt.Errorf("native encrypted connections must not include a tunnel identity")
		}
	default:
		return fmt.Errorf("unsupported connection_mode")
	}
	return nil
}

func ValidateConnectionResponse(mode string, response CreateSessionResponse) error {
	if NormalizeConnectionMode(response.ConnectionMode) != NormalizeConnectionMode(mode) {
		return fmt.Errorf("gateway connection mode does not match the session")
	}
	switch NormalizeConnectionMode(mode) {
	case ConnectionModeNative, ConnectionModeAudit:
		if response.ServerCertificate != "" {
			return fmt.Errorf("native encrypted connections must not include a tunnel certificate")
		}
		return nil
	default:
		return fmt.Errorf("unsupported connection_mode")
	}
}

const (
	InternalSecretHeader = "X-Gateway-Internal-Secret"
	AuditGatewayIDHeader = "X-Gateway-ID"
	AuditSecretHeader    = "X-Gateway-Audit-Secret"
)

type ConnectionEvent struct {
	EventID           string    `json:"event_id"`
	GatewayID         string    `json:"gateway_id"`
	ConnectionID      string    `json:"connection_id"`
	SessionID         string    `json:"session_id"`
	EventType         string    `json:"event_type"`
	SourceIP          string    `json:"source_ip,omitempty"`
	BackendSourceIP   string    `json:"backend_source_ip,omitempty"`
	BackendSourcePort int       `json:"backend_source_port,omitempty"`
	BytesUp           *int64    `json:"bytes_up,omitempty"`
	BytesDown         *int64    `json:"bytes_down,omitempty"`
	DurationMS        *int64    `json:"duration_ms,omitempty"`
	Result            string    `json:"result,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	OccurredAt        time.Time `json:"occurred_at"`
}

type ConnectionEventBatch struct {
	Events []ConnectionEvent `json:"events"`
}

const ConnectionEventBatchResponseVersion = 1

// ConnectionEventBatchResponse is the durable acknowledgement contract
// between the control plane and a Gateway Agent. Agents only remove events
// from their local spool after every ID is acknowledged in request order.
type ConnectionEventBatchResponse struct {
	Version          int      `json:"version"`
	AcceptedEventIDs []string `json:"accepted_event_ids"`
}

type Client interface {
	CreateSession(ctx context.Context, managementEndpoint string, request CreateSessionRequest) (CreateSessionResponse, error)
	CloseSession(ctx context.Context, managementEndpoint, sessionID, idempotencyKey string) (CloseSessionResponse, error)
	GetSession(ctx context.Context, managementEndpoint, sessionID string) (SessionStatusResponse, error)
}

// ReadinessChecker is implemented by transports that can verify a Gateway
// Agent before a session command is dispatched. It stays separate from Client
// so alternate transports can opt in without weakening the session contract.
type ReadinessChecker interface {
	CheckReady(ctx context.Context, managementEndpoint string) error
}

type ReadinessReport struct {
	Status         string `json:"status"`
	ActiveSessions *int   `json:"active_sessions,omitempty"`
	MaxSessions    *int   `json:"max_sessions,omitempty"`
}

type ReadinessReporter interface {
	GetReadiness(ctx context.Context, managementEndpoint string) (ReadinessReport, error)
}

type HTTPClient struct {
	baseURL        *url.URL
	client         *http.Client
	internalSecret string
	requireHTTPS   bool
}

type HTTPClientConfig struct {
	BaseURL        string
	Timeout        time.Duration
	InternalSecret string
	ClientCertFile string
	ClientKeyFile  string
	RootCAFile     string
	ServerName     string
	RequireHTTPS   bool
}

func NewHTTPClient(baseURL string, timeout time.Duration) (*HTTPClient, error) {
	return NewHTTPClientWithSecret(baseURL, timeout, "")
}

// NewHTTPClientWithSecret configures the control-plane to gateway transport.
// The secret is sent only on internal management requests and is never
// included in request paths, query parameters, or error messages.
func NewHTTPClientWithSecret(baseURL string, timeout time.Duration, internalSecret string) (*HTTPClient, error) {
	return NewHTTPClientWithConfig(HTTPClientConfig{
		BaseURL: baseURL, Timeout: timeout, InternalSecret: internalSecret, RequireHTTPS: true,
	})
}

func NewHTTPClientWithConfig(config HTTPClientConfig) (*HTTPClient, error) {
	var parsed *url.URL
	if strings.TrimSpace(config.BaseURL) != "" {
		var err error
		parsed, err = url.Parse(strings.TrimRight(config.BaseURL, "/"))
		if err != nil {
			return nil, fmt.Errorf("parse gateway URL: %w", err)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return nil, fmt.Errorf("gateway URL must use http or https")
		}
		if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
			return nil, fmt.Errorf("gateway URL is invalid")
		}
		if config.RequireHTTPS && parsed.Scheme != "https" {
			return nil, fmt.Errorf("gateway URL must use https")
		}
		if err := validateGatewayURLHost(parsed, false); err != nil {
			return nil, fmt.Errorf("gateway URL is invalid: %w", err)
		}
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	tlsConfig, err := gatewayTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return &HTTPClient{
		baseURL:        parsed,
		internalSecret: strings.TrimSpace(config.InternalSecret),
		requireHTTPS:   config.RequireHTTPS,
		client: &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig:    tlsConfig,
				DisableCompression: true,
				ForceAttemptHTTP2:  true,
			},
		},
	}, nil
}

func (c *HTTPClient) CreateSession(ctx context.Context, managementEndpoint string, request CreateSessionRequest) (CreateSessionResponse, error) {
	if err := ValidateCreateRequest(request); err != nil {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: %w", err)
	}
	var response CreateSessionResponse
	// A provisioning event is delivered at least once.  The session ID is the
	// durable operation identity, so replays of the create request must resolve
	// to the same gateway session instead of starting a second tunnel.
	err := c.doJSON(ctx, managementEndpoint, http.MethodPost, "/internal/gateway/sessions", request.SessionID, request, &response)
	if err != nil {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: %w", err)
	}
	if response.SessionID != request.SessionID || !validGatewayProcessID(response.ProcessID) ||
		response.ListenerPort < 1 || response.ListenerPort > 65535 ||
		response.ExternalPort < 1 || response.ExternalPort > 65535 ||
		!validExposure(response.ExposureMode, response.ExposureRef) {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: invalid gateway response")
	}
	if response.Status != "" && response.Status != "running" {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: gateway returned invalid status")
	}
	if !response.ExpiresAt.IsZero() && !response.StartedAt.IsZero() && !response.ExpiresAt.After(response.StartedAt) {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: invalid expiry")
	}
	if err := ValidateConnectionResponse(request.ConnectionMode, response); err != nil {
		return CreateSessionResponse{}, fmt.Errorf("create gateway session: %w", err)
	}
	return response, nil
}

func (c *HTTPClient) CloseSession(ctx context.Context, managementEndpoint, sessionID, idempotencyKey string) (CloseSessionResponse, error) {
	if !validGatewayReference(sessionID) {
		return CloseSessionResponse{}, fmt.Errorf("close gateway session: session_id is invalid")
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		idempotencyKey = "revoke-" + sessionID
	}
	var response CloseSessionResponse
	err := c.doJSON(ctx, managementEndpoint, http.MethodDelete, "/internal/gateway/sessions/"+url.PathEscape(sessionID), idempotencyKey, nil, &response)
	if err != nil {
		return CloseSessionResponse{}, fmt.Errorf("close gateway session: %w", err)
	}
	if response.SessionID != sessionID {
		return CloseSessionResponse{}, fmt.Errorf("close gateway session: invalid gateway response")
	}
	if response.Status != "closed" && response.Status != "expired" && response.Status != "not_found" {
		return CloseSessionResponse{}, fmt.Errorf("close gateway session: gateway returned invalid status")
	}
	return response, nil
}

func (c *HTTPClient) GetSession(ctx context.Context, managementEndpoint, sessionID string) (SessionStatusResponse, error) {
	if !validGatewayReference(sessionID) {
		return SessionStatusResponse{}, fmt.Errorf("get gateway session: session_id is invalid")
	}
	var response SessionStatusResponse
	err := c.doJSON(ctx, managementEndpoint, http.MethodGet, "/internal/gateway/sessions/"+url.PathEscape(sessionID), "", nil, &response)
	if err != nil {
		return SessionStatusResponse{}, fmt.Errorf("get gateway session: %w", err)
	}
	if response.SessionID != sessionID {
		return SessionStatusResponse{}, fmt.Errorf("get gateway session: invalid gateway response")
	}
	switch response.Status {
	case "starting", "running", "stopping", "revoke_failed", "closed", "expired", "failed", "not_found":
	default:
		return SessionStatusResponse{}, fmt.Errorf("get gateway session: gateway returned invalid status")
	}
	return response, nil
}

func (c *HTTPClient) CheckReady(ctx context.Context, managementEndpoint string) error {
	_, err := c.GetReadiness(ctx, managementEndpoint)
	return err
}

func (c *HTTPClient) GetReadiness(ctx context.Context, managementEndpoint string) (ReadinessReport, error) {
	var response ReadinessReport
	if err := c.doJSON(ctx, managementEndpoint, http.MethodGet, "/readyz", "", nil, &response); err != nil {
		return ReadinessReport{}, fmt.Errorf("check gateway readiness: %w", err)
	}
	if response.Status != "ready" {
		return ReadinessReport{}, fmt.Errorf("check gateway readiness: gateway returned invalid status")
	}
	if (response.ActiveSessions == nil) != (response.MaxSessions == nil) {
		return ReadinessReport{}, fmt.Errorf("check gateway readiness: gateway returned partial capacity")
	}
	if response.MaxSessions != nil && (*response.MaxSessions < 1 || *response.MaxSessions > 100000 || *response.ActiveSessions < 0 || *response.ActiveSessions > *response.MaxSessions) {
		return ReadinessReport{}, fmt.Errorf("check gateway readiness: gateway returned invalid capacity")
	}
	return response, nil
}

func (c *HTTPClient) doJSON(ctx context.Context, managementEndpoint, method, path, idempotencyKey string, request any, response any) error {
	ctx, span := otel.Tracer("github.com/srex-run/access-gateway/internal/gateway").Start(ctx, "gateway.request")
	span.SetAttributes(
		attribute.String("http.request.method", method),
		attribute.String("gateway.operation", gatewayOperation(method, path)),
	)
	defer span.End()
	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	endpoint, err := c.resolveEndpoint(managementEndpoint)
	if err != nil {
		return err
	}
	requestURL := *endpoint
	requestURL.Path = strings.TrimRight(endpoint.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if c.internalSecret != "" {
		req.Header.Set(InternalSecretHeader, c.internalSecret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		// net/http errors normally include the full management URL. Do not let a
		// private gateway address escape into application errors, audit rows, or
		// user-facing session failure details.
		span.RecordError(ErrUnavailable)
		span.SetStatus(codes.Error, "gateway unavailable")
		return fmt.Errorf("send gateway request: %w", ErrUnavailable)
	}
	defer resp.Body.Close()
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		span.SetStatus(codes.Error, "gateway returned non-success status")
		return fmt.Errorf("gateway returned HTTP status %d", resp.StatusCode)
	}
	if response == nil {
		return nil
	}
	if err := decodeGatewayResponse(resp.Body, response); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "gateway returned invalid response")
		return fmt.Errorf("gateway returned an invalid JSON response")
	}
	return nil
}

func gatewayOperation(method, path string) string {
	switch {
	case path == "/readyz":
		return "readiness"
	case method == http.MethodPost:
		return "session.create"
	case method == http.MethodDelete:
		return "session.close"
	case method == http.MethodGet:
		return "session.get"
	default:
		return "unknown"
	}
}

func decodeGatewayResponse(reader io.Reader, target any) error {
	const limit = int64(1 << 20)
	encoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	defer clear(encoded)
	if int64(len(encoded)) > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func (c *HTTPClient) resolveEndpoint(managementEndpoint string) (*url.URL, error) {
	managementEndpoint = strings.TrimSpace(managementEndpoint)
	if managementEndpoint == "" {
		if c.baseURL == nil {
			return nil, fmt.Errorf("gateway management endpoint is required")
		}
		copy := *c.baseURL
		return &copy, nil
	}
	parsed, err := url.Parse(strings.TrimRight(managementEndpoint, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("gateway management endpoint is invalid")
	}
	if c.requireHTTPS && parsed.Scheme != "https" {
		return nil, fmt.Errorf("gateway management endpoint must use https")
	}
	if err := validateGatewayURLHost(parsed, false); err != nil {
		return nil, fmt.Errorf("gateway management endpoint is invalid: %w", err)
	}
	return parsed, nil
}

func validateGatewayURLHost(parsed *url.URL, requirePort bool) error {
	host := parsed.Hostname()
	if host == "" || strings.IndexFunc(host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 || strings.Contains(parsed.Host, "%") {
		return fmt.Errorf("endpoint host is invalid")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
			return fmt.Errorf("endpoint host is invalid")
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("endpoint host is invalid")
			}
			for _, character := range label {
				if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
					continue
				}
				return fmt.Errorf("endpoint host is invalid")
			}
		}
	}
	port, explicit, err := gatewayURLPort(parsed.Host)
	if err != nil {
		return err
	}
	if requirePort && (!explicit || port == "") {
		return fmt.Errorf("endpoint port is required")
	}
	if explicit && port == "" {
		return fmt.Errorf("endpoint port is invalid")
	}
	if explicit {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return fmt.Errorf("endpoint port is invalid")
		}
	}
	return nil
}

func gatewayURLPort(authority string) (string, bool, error) {
	if strings.HasPrefix(authority, "[") {
		closing := strings.LastIndex(authority, "]")
		if closing < 0 {
			return "", false, fmt.Errorf("endpoint host is invalid")
		}
		if len(authority) == closing+1 {
			return "", false, nil
		}
		if authority[closing+1] != ':' {
			return "", false, fmt.Errorf("endpoint host is invalid")
		}
		return authority[closing+2:], true, nil
	}
	count := strings.Count(authority, ":")
	if count == 0 {
		return "", false, nil
	}
	if count != 1 {
		return "", false, fmt.Errorf("endpoint host is invalid")
	}
	return strings.SplitN(authority, ":", 2)[1], true, nil
}

func gatewayTLSConfig(config HTTPClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: strings.TrimSpace(config.ServerName)}
	tlsFileCount := 0
	for _, path := range []string{config.ClientCertFile, config.ClientKeyFile, config.RootCAFile} {
		if strings.TrimSpace(path) != "" {
			tlsFileCount++
		}
	}
	if tlsFileCount == 0 {
		return tlsConfig, nil
	}
	if tlsFileCount != 3 {
		return nil, fmt.Errorf("gateway client certificate, key, and root CA files must be configured together")
	}
	certificatePEM, err := readGatewayFile(config.ClientCertFile, "gateway client certificate", false)
	if err != nil {
		return nil, fmt.Errorf("read gateway client certificate: %w", err)
	}
	keyPEM, err := readGatewayFile(config.ClientKeyFile, "gateway client private key", true)
	if err != nil {
		return nil, fmt.Errorf("read gateway client private key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load gateway client TLS key pair: %w", err)
	}
	caPEM, err := readGatewayFile(config.RootCAFile, "gateway root CA", false)
	if err != nil {
		return nil, fmt.Errorf("read gateway root CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("gateway root CA contains no certificates")
	}
	tlsConfig.Certificates = []tls.Certificate{certificate}
	tlsConfig.RootCAs = roots
	return tlsConfig, nil
}

func readGatewayFile(path, purpose string, private bool) ([]byte, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s path must be absolute", purpose)
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", purpose, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file and not a symlink", purpose)
	}
	if entry.Mode().Perm()&0o022 != 0 || (private && entry.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("%s has unsafe permissions", purpose)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", purpose, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", purpose, err)
	}
	const limit = int64(1 << 20)
	if !info.Mode().IsRegular() || !os.SameFile(entry, info) || info.Size() > limit {
		return nil, fmt.Errorf("%s must be unchanged, regular, and no larger than %d bytes", purpose, limit)
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, fmt.Errorf("file must be no larger than %d bytes", limit)
	}
	return value, nil
}

func validGatewayProcessID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

type UnavailableClient struct{}

func (UnavailableClient) CreateSession(context.Context, string, CreateSessionRequest) (CreateSessionResponse, error) {
	return CreateSessionResponse{}, fmt.Errorf("gateway client is not configured: %w", ErrUnavailable)
}

func (UnavailableClient) CloseSession(context.Context, string, string, string) (CloseSessionResponse, error) {
	return CloseSessionResponse{}, fmt.Errorf("gateway client is not configured: %w", ErrUnavailable)
}

func (UnavailableClient) GetSession(context.Context, string, string) (SessionStatusResponse, error) {
	return SessionStatusResponse{}, fmt.Errorf("gateway client is not configured: %w", ErrUnavailable)
}

func ValidateCreateRequest(request CreateSessionRequest) error {
	if err := ValidateConnectionIdentity(request.ConnectionMode, request.ClientPublicKey); err != nil {
		return err
	}
	if !validGatewayReference(request.SessionID) || !validGatewayReference(request.TargetID) {
		return fmt.Errorf("session_id and target_id are required")
	}
	if request.TargetPort < 1 || request.TargetPort > 65535 {
		return fmt.Errorf("target_port must be between 1 and 65535")
	}
	if request.TTLSeconds < 1 || request.TTLSeconds > 5*60*60 {
		return fmt.Errorf("ttl_seconds must be between 1 and 18000 seconds")
	}
	parsedSource := net.ParseIP(request.SourceIP)
	if request.WebOnly && (request.SourceIP != "" || request.ConnectionMode != ConnectionModeAudit || !terminal.Supported(request.AuditPolicy.Protocol)) {
		return fmt.Errorf("web-only sessions require a supported audited client grant without a TCP source IP")
	}
	if !request.WebOnly && (parsedSource == nil || parsedSource.IsUnspecified() || parsedSource.IsMulticast() || strings.TrimSpace(request.SourceIP) != request.SourceIP) {
		return fmt.Errorf("source_ip must be one exact IPv4 or IPv6 address")
	}
	if !validTargetAccount(request.TargetAccount) {
		return fmt.Errorf("target_account is invalid")
	}
	if request.MaxConnections != MaxSessionConnections {
		return fmt.Errorf("max_connections must equal %d", MaxSessionConnections)
	}
	return nil
}

func validTargetAccount(value string) bool {
	if len([]byte(value)) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validExposure(mode, reference string) bool {
	if mode != "direct" && mode != "kubernetes_nodeport" {
		return false
	}
	if reference == "" || len(reference) > 253 || strings.TrimSpace(reference) != reference {
		return false
	}
	for _, character := range []byte(reference) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func validGatewayReference(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func FormatTTL(seconds int) string {
	return strconv.Itoa(seconds)
}
