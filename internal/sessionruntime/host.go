package sessionruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

type HostOptions struct {
	AuditProfiles        sessionproxy.ProfileSource
	Mode                 string
	StateDirectory       string
	AgentBinary          string
	DockerSocket         string
	DockerStateDirectory string
	Image                string
	BindHost             string
	PortStart            int
	PortEnd              int
	PublicAddress        string
	ControlPlaneURL      string
	AllowAuditHTTP       bool
	StartupTimeout       time.Duration
	PollInterval         time.Duration
	MaxSessions          int
	Credentials          *gatewayauth.SessionCredentials
	Logger               zerolog.Logger
}

type hostRecord struct {
	ConnectionMode string                      `json:"connection_mode,omitempty"`
	Version        int                         `json:"version"`
	SessionID      string                      `json:"session_id"`
	GatewayID      string                      `json:"gateway_id,omitempty"`
	Fingerprint    string                      `json:"fingerprint,omitempty"`
	State          string                      `json:"state"`
	ResourceID     string                      `json:"resource_id,omitempty"`
	StartedAt      time.Time                   `json:"started_at"`
	ExpiresAt      time.Time                   `json:"expires_at"`
	ClosedAt       time.Time                   `json:"closed_at"`
	Network        gatewayagent.SessionNetwork `json:"network"`
	Acknowledged   bool                        `json:"acknowledged"`
}

type hostResource struct {
	ID      string
	Exists  bool
	Running bool
}

type hostDriver interface {
	Ready(context.Context) error
	Start(context.Context, hostRecord) (string, error)
	Inspect(context.Context, hostRecord) (hostResource, error)
	Stop(context.Context, hostRecord) error
	Remove(context.Context, hostRecord) error
}

type HostClient struct {
	mu           sync.Mutex
	launches     sync.WaitGroup
	options      HostOptions
	store        *hostStore
	instanceID   string
	driver       hostDriver
	records      map[string]hostRecord
	operations   map[string]*sync.Mutex
	closed       bool
	callAgent    func(context.Context, string, gatewayagent.SessionConfig, string, any) error
	reservePorts func(bool) (gatewayagent.SessionNetwork, func(), error)
	flushAudit   func(context.Context, gatewayagent.SessionConfig, string, zerolog.Logger) error
}

func NewHostClient(options HostOptions) (*HostClient, error) {
	if options.Mode != "local" && options.Mode != "docker" {
		return nil, fmt.Errorf("host session runtime must be local or docker")
	}
	if options.Credentials == nil || (net.ParseIP(options.PublicAddress) == nil && len(validation.IsDNS1123Subdomain(options.PublicAddress)) != 0) {
		return nil, fmt.Errorf("session runtime requires an audit signer and public hostname or IP")
	}
	endpoint, err := url.Parse(options.ControlPlaneURL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.ForceQuery ||
		(endpoint.Scheme != "https" && !(options.AllowAuditHTTP && endpoint.Scheme == "http")) {
		return nil, fmt.Errorf("session audit control-plane URL must use HTTPS, or explicitly allow HTTP")
	}
	if options.BindHost == "" {
		options.BindHost = "0.0.0.0"
	}
	if options.PortStart == 0 && options.PortEnd == 0 {
		options.PortStart, options.PortEnd = 20000, 20999
	}
	if options.StartupTimeout == 0 {
		options.StartupTimeout = 90 * time.Second
	}
	if options.PollInterval == 0 {
		options.PollInterval = 250 * time.Millisecond
	}
	if options.MaxSessions == 0 {
		options.MaxSessions = 100
	}
	if net.ParseIP(options.BindHost) == nil || options.PortStart < 1024 || options.PortEnd > 65535 || options.PortEnd < options.PortStart ||
		options.StartupTimeout < time.Second || options.StartupTimeout > 90*time.Second || options.PollInterval <= 0 || options.MaxSessions < 1 || options.MaxSessions > options.PortEnd-options.PortStart+1 {
		return nil, fmt.Errorf("session listener range, timeout or capacity is invalid")
	}
	if options.Mode == "local" {
		binary, err := exec.LookPath(options.AgentBinary)
		if err != nil {
			return nil, fmt.Errorf("locate session agent binary: %w", err)
		}
		options.AgentBinary, err = filepath.Abs(binary)
		if err != nil {
			return nil, err
		}
	} else if err := validateDockerOptions(options); err != nil {
		return nil, err
	}
	store, err := openHostStore(options.StateDirectory)
	if err != nil {
		return nil, err
	}
	c := &HostClient{options: options, store: store, records: make(map[string]hostRecord), operations: make(map[string]*sync.Mutex)}
	if err := c.load(); err != nil {
		_ = store.Close()
		return nil, err
	}
	if options.Mode == "local" {
		c.driver = &processDriver{binary: options.AgentBinary, store: store, active: make(map[string]*os.Process)}
	} else {
		c.driver = newDockerDriver(options, c.instanceID)
	}
	c.callAgent, c.reservePorts = requestSessionAgent, c.allocatePorts
	c.flushAudit = gatewayagent.FlushSessionAudit
	return c, nil
}

func (c *HostClient) load() error {
	var identity struct {
		Version int    `json:"version"`
		ID      string `json:"id"`
		Mode    string `json:"mode"`
	}
	if err := c.store.read("controller.json", &identity); os.IsNotExist(err) {
		identity.Version, identity.ID, identity.Mode = 1, id.New(), c.options.Mode
		if err := c.store.write("controller.json", identity, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if identity.Version != 1 || !id.IsUUID(identity.ID) || identity.Mode != c.options.Mode {
		return fmt.Errorf("session state belongs to another runtime; use its original runtime to drain sessions")
	}
	c.instanceID = identity.ID
	directory, err := c.store.root.Open("records")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		sessionID := strings.TrimSuffix(entry.Name(), ".json")
		if !id.IsUUID(sessionID) || entry.Name() != sessionID+".json" {
			return fmt.Errorf("invalid session lifecycle record name")
		}
		var record hostRecord
		if err := c.store.read(filepath.Join("records", entry.Name()), &record); err != nil {
			return err
		}
		if record.Version != 1 || record.SessionID != sessionID ||
			(record.State != "starting" && record.State != "running" && record.State != "stopping" && record.State != "closed") {
			return fmt.Errorf("invalid session lifecycle record")
		}
		c.records[sessionID] = record
	}
	return nil
}

func (c *HostClient) RuntimeMode() string { return c.options.Mode }
func (c *HostClient) PublicHost() string  { return c.options.PublicAddress }

// Active agents keep their absolute TTL across a control-plane restart.
func (c *HostClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.launches.Wait()
	return c.store.Close()
}

func (c *HostClient) CreateSession(context.Context, string, gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	return gateway.CreateSessionResponse{}, fmt.Errorf("session agents require an approved asset target")
}

func (c *HostClient) CreateApprovedSession(ctx context.Context, gatewayID string, request gateway.CreateSessionRequest, target string) (gateway.CreateSessionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.options.StartupTimeout)
	defer cancel()
	started := time.Now().UTC().Truncate(time.Second)
	if request.ExpiresAt != nil {
		started = time.Now().UTC()
	}
	cfg := gatewayagent.SessionConfig{Version: 1, GatewayID: gatewayID, Request: request, TargetHost: target,
		StartedAt: started, ExpiresAt: sessionExpiry(started, request),
		ControlPlaneURL: c.options.ControlPlaneURL, AuditAllowHTTP: c.options.AllowAuditHTTP}
	proxy, err := sessionproxy.ResolveProfile(ctx, c.options.AuditProfiles, request.AuditPolicy)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	cfg.Proxy = proxy
	if err := cfg.Validate(); err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	encoded, err := json.Marshal(struct {
		GatewayID string
		Request   gateway.CreateSessionRequest
		Target    string
	}{gatewayID, request, target})
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	sum := sha256.Sum256(encoded)
	clear(encoded)
	fingerprint := hex.EncodeToString(sum[:])
	if err := c.ensureStarted(ctx, cfg, fingerprint); err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	var response gateway.CreateSessionResponse
	err = pollHost(ctx, c.options.PollInterval, func() (bool, error) {
		record, ok, err := c.snapshot(request.SessionID)
		if err != nil {
			return false, err
		}
		if !ok || (record.State != "starting" && record.State != "running") || !record.ExpiresAt.After(time.Now()) {
			return false, fmt.Errorf("session grant is closed or expired")
		}
		resource, err := c.driver.Inspect(ctx, record)
		if err != nil {
			return false, err
		}
		if !resource.Running {
			return false, fmt.Errorf("session agent exited or its launch did not complete; the grant will not be relaunched")
		}
		cfg, err := c.loadGrant(record)
		if err != nil {
			return false, err
		}
		if err := c.callAgent(ctx, cfg.ManagementAddress(), cfg, "/status", &response); err != nil {
			return false, nil
		}
		if err := validateHostResponse(record, response); err != nil {
			return false, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		current := c.records[record.SessionID]
		if c.closed || (current.State != "starting" && current.State != "running") || !current.ExpiresAt.After(time.Now()) {
			return false, fmt.Errorf("session grant was revoked while starting")
		}
		current.State, current.ResourceID = "running", resource.ID
		if err := c.save(current); err != nil {
			return false, err
		}
		response.ProcessID = c.options.Mode + ":" + resource.ID
		return true, nil
	})
	return response, err
}

func (c *HostClient) ensureStarted(ctx context.Context, cfg gatewayagent.SessionConfig, fingerprint string) error {
	operation := c.operation(cfg.Request.SessionID)
	operation.Lock()
	defer operation.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return gateway.ErrUnavailable
	}
	if record, exists := c.records[cfg.Request.SessionID]; exists {
		c.mu.Unlock()
		if record.Fingerprint != fingerprint || (record.State != "starting" && record.State != "running") || !record.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("session grant is closed, expired, or conflicts with an earlier grant")
		}
		return nil
	}
	c.mu.Unlock()
	if err := c.driver.Ready(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	if c.closed {
		return gateway.ErrUnavailable
	}
	if c.activeCount() >= c.options.MaxSessions {
		return fmt.Errorf("session runtime capacity exhausted")
	}
	network, release, err := c.reservePorts(cfg.Request.WebOnly)
	if err != nil {
		return err
	}
	defer release()
	cfg.Network = &network
	cfg.Certificate, cfg.PrivateKey, err = gatewayagent.NewSessionIdentity(cfg.ExpiresAt)
	if err != nil {
		return err
	}
	cfg.AuditToken = c.options.Credentials.Issue(cfg.GatewayID, cfg.Request.SessionID, cfg.ExpiresAt.Add(24*time.Hour))
	record := hostRecord{Version: 1, SessionID: cfg.Request.SessionID, GatewayID: cfg.GatewayID, Fingerprint: fingerprint,
		ConnectionMode: cfg.Request.ConnectionMode,
		State:          "starting", StartedAt: cfg.StartedAt, ExpiresAt: cfg.ExpiresAt, Network: network}
	// Persist the launch intent before either backend can start a workload. An
	// uncertain launch is inspected and closed, never replayed as a new workload.
	if err := c.save(record); err != nil {
		return err
	}
	if err := c.store.root.Mkdir(filepath.Join("agents", record.SessionID), 0o700); err != nil {
		return err
	}
	if err := c.store.write(filepath.Join("grants", record.SessionID+".json"), cfg, 0o400); err != nil {
		return err
	}
	c.launches.Add(1)
	defer c.launches.Done()
	c.mu.Unlock()
	locked = false
	release()
	resourceID, err := c.driver.Start(ctx, record)
	if err != nil {
		return err
	}
	record.ResourceID = resourceID
	c.mu.Lock()
	locked = true
	return c.save(record)
}

func (c *HostClient) CloseSession(ctx context.Context, _ string, sessionID, _ string) (gateway.CloseSessionResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.CloseSessionResponse{}, fmt.Errorf("invalid session ID")
	}
	operation := c.operation(sessionID)
	operation.Lock()
	defer operation.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return gateway.CloseSessionResponse{}, gateway.ErrUnavailable
	}
	c.launches.Add(1)
	defer c.launches.Done()
	record, exists := c.records[sessionID]
	if !exists {
		record = hostRecord{Version: 1, SessionID: sessionID, State: "stopping"}
	}
	if record.ClosedAt.IsZero() {
		record.ClosedAt = time.Now().UTC()
	}
	if record.State != "closed" {
		record.State = "stopping"
	}
	err := c.save(record)
	c.mu.Unlock()
	if err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	if err := c.cleanup(ctx, record); err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	c.mu.Lock()
	record = c.records[sessionID]
	record.State = "closed"
	err = c.save(record)
	c.mu.Unlock()
	if err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	status := "closed"
	if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now()) {
		status = "expired"
	}
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: status, ClosedAt: record.ClosedAt}, nil
}

func (c *HostClient) cleanup(ctx context.Context, record hostRecord) error {
	directory := filepath.Join("agents", record.SessionID)
	if err := c.store.root.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := c.store.write(filepath.Join(directory, "stop"), struct{}{}, 0o600); err != nil {
		return fmt.Errorf("persist session stop marker: %w", err)
	}
	resource, err := c.driver.Inspect(ctx, record)
	if err != nil {
		return err
	}
	cfg, grantErr := c.loadGrant(record)
	if resource.Running {
		if grantErr == nil {
			var response gateway.CloseSessionResponse
			_ = c.callAgent(ctx, cfg.ManagementAddress(), cfg, "/stop", &response)
		}
		if err := c.driver.Stop(ctx, record); err != nil {
			return fmt.Errorf("stop session workload: %w", err)
		}
	}
	resource, err = c.driver.Inspect(ctx, record)
	if err != nil || resource.Running {
		return fmt.Errorf("session workload termination is not confirmed: %w", errors.Join(err, gateway.ErrUnavailable))
	}
	if err := c.driver.Remove(ctx, record); err != nil {
		return err
	}
	lock, busy, err := processLock(c.store.agentPath(record.SessionID))
	if err != nil {
		return err
	}
	if busy {
		return fmt.Errorf("session agent still holds its process lock")
	}
	defer lock.Close()
	if grantErr != nil && !errors.Is(grantErr, os.ErrNotExist) {
		return grantErr
	}
	if grantErr == nil {
		// The controller can renew audit-only credentials to recover a durable
		// spool after downtime; this never renews the data-plane grant.
		cfg.AuditToken = c.options.Credentials.Issue(cfg.GatewayID, cfg.Request.SessionID, time.Now().Add(24*time.Hour))
		if err := c.flushAudit(ctx, cfg, c.store.agentPath(record.SessionID), c.options.Logger); err != nil {
			return fmt.Errorf("drain stopped session audit: %w", err)
		}
		if err := c.store.root.Remove(filepath.Join("grants", record.SessionID+".json")); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		spool, err := gatewayagent.NewFileEventSpool(filepath.Join(c.store.agentPath(record.SessionID), "events.jsonl"))
		if err != nil {
			return err
		}
		if spool.PendingCount() > 0 {
			return fmt.Errorf("session grant is missing while audit events still require delivery")
		}
	}
	return nil
}

func (c *HostClient) GetSession(ctx context.Context, _ string, sessionID string) (gateway.SessionStatusResponse, error) {
	response := gateway.SessionStatusResponse{SessionID: sessionID, ConnectionMode: gateway.ConnectionModeNative, Status: "not_found"}
	record, ok, err := c.snapshot(sessionID)
	if err != nil || !ok {
		return response, err
	}
	response.Status, response.ExpiresAt = record.State, &record.ExpiresAt
	if record.ConnectionMode != "" {
		response.ConnectionMode = record.ConnectionMode
	}
	if record.State == "closed" {
		if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(time.Now()) {
			response.Status = "expired"
		}
		return response, nil
	}
	if record.State == "stopping" || !record.ExpiresAt.After(time.Now()) {
		response.Status = "stopping"
		return response, nil
	}
	response.Status = "starting"
	resource, err := c.driver.Inspect(ctx, record)
	if err != nil || !resource.Running {
		return response, err
	}
	cfg, err := c.loadGrant(record)
	if err != nil {
		return response, err
	}
	var agent gateway.CreateSessionResponse
	if err := c.callAgent(ctx, cfg.ManagementAddress(), cfg, "/status", &agent); err != nil {
		return response, err
	}
	if err := validateHostResponse(record, agent); err != nil {
		response.Status = "stopping"
		return response, nil
	}
	response.Status = "running"
	response.ListenerPort, response.ExternalPort = agent.ListenerPort, agent.ExternalPort
	response.ExposureMode, response.ExposureRef = agent.ExposureMode, agent.ExposureRef
	return response, nil
}

func (c *HostClient) CheckReady(ctx context.Context, endpoint string) error {
	_, err := c.GetReadiness(ctx, endpoint)
	return err
}

func (c *HostClient) GetReadiness(ctx context.Context, _ string) (gateway.ReadinessReport, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return gateway.ReadinessReport{}, gateway.ErrUnavailable
	}
	active := c.activeCount()
	c.mu.Unlock()
	if err := c.driver.Ready(ctx); err != nil {
		return gateway.ReadinessReport{}, err
	}
	return gateway.ReadinessReport{Status: "ready", ActiveSessions: ptr(active), MaxSessions: ptr(c.options.MaxSessions)}, nil
}

func (c *HostClient) Reconcile(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	records := make([]hostRecord, 0, len(c.records))
	for _, record := range c.records {
		records = append(records, record)
	}
	c.mu.Unlock()
	var ended []string
	var failures []error
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return ended, errors.Join(append(failures, err)...)
		}
		stop := record.State == "stopping" || record.State == "closed" || !record.ExpiresAt.After(time.Now())
		if !stop && (record.State == "running" || time.Since(record.StartedAt) > c.options.StartupTimeout) {
			statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			status, err := c.GetSession(statusCtx, "", record.SessionID)
			cancel()
			stop = err != nil || status.Status != "running"
		}
		if !stop {
			continue
		}
		if !record.Acknowledged {
			ended = append(ended, record.SessionID)
		}
		if _, err := c.CloseSession(ctx, "", record.SessionID, "reconcile"); err != nil {
			failures = append(failures, fmt.Errorf("reconcile session %s: %w", record.SessionID, err))
			continue
		}
		if record.Acknowledged && time.Since(record.ClosedAt) > terminalRetention {
			if err := c.prune(record.SessionID); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return ended, errors.Join(failures...)
}

func (c *HostClient) AcknowledgeClosure(_ context.Context, sessionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.records[sessionID]
	if !ok || c.closed || record.State != "closed" {
		return fmt.Errorf("session closure has not completed")
	}
	record.Acknowledged = true
	return c.save(record)
}

func (c *HostClient) prune(sessionID string) error {
	operation := c.operation(sessionID)
	operation.Lock()
	defer operation.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	record := c.records[sessionID]
	if record.State != "closed" || !record.Acknowledged || time.Since(record.ClosedAt) <= terminalRetention {
		return nil
	}
	if err := c.store.root.RemoveAll(filepath.Join("agents", sessionID)); err != nil {
		return err
	}
	if err := c.store.root.Remove(filepath.Join("records", sessionID+".json")); err != nil {
		return err
	}
	delete(c.records, sessionID)
	return nil
}

func (c *HostClient) operation(sessionID string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	operation := c.operations[sessionID]
	if operation == nil {
		operation = &sync.Mutex{}
		c.operations[sessionID] = operation
	}
	return operation
}

func (c *HostClient) snapshot(sessionID string) (hostRecord, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !id.IsUUID(sessionID) {
		return hostRecord{}, false, fmt.Errorf("invalid session ID")
	}
	if c.closed {
		return hostRecord{}, false, gateway.ErrUnavailable
	}
	record, ok := c.records[sessionID]
	return record, ok, nil
}

func (c *HostClient) save(record hostRecord) error {
	// A partially persisted transition must still block another launch in this
	// process. Reconciliation retries the write and completes resource cleanup.
	c.records[record.SessionID] = record
	return c.store.save(&record)
}

func (c *HostClient) activeCount() int {
	count := 0
	for _, record := range c.records {
		if record.State != "closed" {
			count++
		}
	}
	return count
}

func (c *HostClient) loadGrant(record hostRecord) (gatewayagent.SessionConfig, error) {
	cfg, err := gatewayagent.LoadSessionConfig(c.store.grantPath(record.SessionID))
	if err != nil {
		return cfg, err
	}
	if cfg.Request.SessionID != record.SessionID || cfg.GatewayID != record.GatewayID || cfg.Network == nil || !reflect.DeepEqual(*cfg.Network, record.Network) ||
		(record.ConnectionMode != "" && cfg.Request.ConnectionMode != record.ConnectionMode) ||
		!cfg.StartedAt.Equal(record.StartedAt) || !cfg.ExpiresAt.Equal(record.ExpiresAt) {
		return gatewayagent.SessionConfig{}, fmt.Errorf("session grant does not match its lifecycle record")
	}
	return cfg, nil
}

func (c *HostClient) allocatePorts(webOnly bool) (gatewayagent.SessionNetwork, func(), error) {
	bindHost := c.options.BindHost
	if webOnly {
		bindHost = "127.0.0.1"
	}
	used := make(map[int]bool)
	for _, record := range c.records {
		if record.State != "closed" {
			used[record.Network.ListenerPort], used[record.Network.ManagementPort] = true, true
		}
	}
	for port := c.options.PortStart; port <= c.options.PortEnd; port++ {
		if used[port] {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(bindHost, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		management, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			_ = listener.Close()
			return gatewayagent.SessionNetwork{}, nil, err
		}
		managementPort := management.Addr().(*net.TCPAddr).Port
		if used[managementPort] || managementPort == port {
			_ = listener.Close()
			_ = management.Close()
			continue
		}
		var once sync.Once
		release := func() { once.Do(func() { _ = listener.Close(); _ = management.Close() }) }
		return gatewayagent.SessionNetwork{ListenerHost: bindHost, ListenerPort: port, ManagementPort: managementPort}, release, nil
	}
	return gatewayagent.SessionNetwork{}, nil, fmt.Errorf("no available temporary session port")
}

func validateHostResponse(record hostRecord, response gateway.CreateSessionResponse) error {
	mode := record.ConnectionMode
	if mode == "" {
		mode = gateway.ConnectionModeNative
	}
	if response.SessionID != record.SessionID || response.Status != "running" || response.ConnectionMode != mode || response.ServerCertificate != "" ||
		response.ListenerPort != record.Network.ListenerPort || response.ExternalPort != record.Network.ListenerPort || response.ExposureMode != "direct" ||
		response.ExposureRef != "direct/"+strconv.Itoa(record.Network.ListenerPort) || !response.StartedAt.Equal(record.StartedAt) || !response.ExpiresAt.Equal(record.ExpiresAt) {
		return fmt.Errorf("session agent returned an inconsistent grant")
	}
	return nil
}

func pollHost(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := check()
		if err != nil || done {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
