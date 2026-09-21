package sessionruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/id"
)

type fakeHostDriver struct {
	mu        sync.Mutex
	resources map[string]hostResource
	starts    int
	startErr  error
	stopErr   error
}

func (*fakeHostDriver) Ready(context.Context) error { return nil }
func (d *fakeHostDriver) Start(_ context.Context, r hostRecord) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.starts++
	d.resources[r.SessionID] = hostResource{ID: r.SessionID, Exists: true, Running: true}
	return r.SessionID, d.startErr
}
func (d *fakeHostDriver) Inspect(_ context.Context, r hostRecord) (hostResource, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.resources[r.SessionID], nil
}
func (d *fakeHostDriver) Stop(_ context.Context, r hostRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopErr != nil {
		return d.stopErr
	}
	resource := d.resources[r.SessionID]
	resource.Running = false
	d.resources[r.SessionID] = resource
	return nil
}
func (d *fakeHostDriver) Remove(_ context.Context, r hostRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.resources, r.SessionID)
	return nil
}

func hostTestOptions(t *testing.T) HostOptions {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	credentials, _ := gatewayauth.NewSessionCredentials(make([]byte, 32))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return HostOptions{Mode: "local", StateDirectory: directory, AgentBinary: binary,
		PublicAddress: "sessions.example.test", ControlPlaneURL: "https://audit.example.test",
		Credentials: credentials, PollInterval: time.Millisecond, StartupTimeout: time.Second,
		MaxSessions: 3, PortStart: 21000, PortEnd: 21010, Logger: zerolog.Nop()}
}

func configureHostFake(c *HostClient, driver hostDriver) {
	c.driver = driver
	c.reservePorts = func(bool) (gatewayagent.SessionNetwork, func(), error) {
		port := 21000 + 2*len(c.records)
		return gatewayagent.SessionNetwork{ListenerHost: "0.0.0.0", ListenerPort: port, ManagementPort: port + 1}, func() {}, nil
	}
	c.callAgent = func(_ context.Context, _ string, cfg gatewayagent.SessionConfig, path string, result any) error {
		if path == "/stop" {
			*result.(*gateway.CloseSessionResponse) = gateway.CloseSessionResponse{SessionID: cfg.Request.SessionID, Status: "closed", ClosedAt: time.Now()}
			return nil
		}
		*result.(*gateway.CreateSessionResponse) = hostAgentResponse(cfg)
		return nil
	}
}

func hostAgentResponse(cfg gatewayagent.SessionConfig) gateway.CreateSessionResponse {
	return gateway.CreateSessionResponse{SessionID: cfg.Request.SessionID, ConnectionMode: "native", Status: "running",
		StartedAt: cfg.StartedAt, ExpiresAt: cfg.ExpiresAt, ListenerPort: cfg.Network.ListenerPort,
		ExternalPort: cfg.Network.ListenerPort, ExposureMode: "direct", ExposureRef: "direct/" + strconv.Itoa(cfg.Network.ListenerPort)}
}

func hostTestRequest() gateway.CreateSessionRequest {
	return gateway.CreateSessionRequest{SessionID: id.New(), TargetID: id.New(), TargetPort: 443, SourceIP: "192.0.2.10",
		TargetAccount: "operator", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections, ConnectionMode: "native"}
}

func newHostTestClient(t *testing.T) (*HostClient, *fakeHostDriver) {
	t.Helper()
	c, err := NewHostClient(hostTestOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	driver := &fakeHostDriver{resources: make(map[string]hostResource)}
	configureHostFake(c, driver)
	return c, driver
}

func TestHostRuntimeIsolationIdempotencyAndClosure(t *testing.T) {
	c, driver := newHostTestClient(t)
	ctx := context.Background()
	route := id.New()
	first, second := hostTestRequest(), hostTestRequest()
	one, err := c.CreateApprovedSession(ctx, route, first, "one.internal")
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.CreateApprovedSession(ctx, route, second, "two.internal")
	if err != nil || one.ExternalPort == two.ExternalPort || one.ProcessID == two.ProcessID || driver.starts != 2 {
		t.Fatalf("independent sessions: one=%+v two=%+v starts=%d err=%v", one, two, driver.starts, err)
	}
	firstGrant, err := gatewayagent.LoadSessionConfig(c.store.grantPath(first.SessionID))
	if err != nil || firstGrant.TargetHost != "one.internal" || firstGrant.Request != first || firstGrant.GatewayID != route {
		t.Fatalf("grant scope mismatch: %v", err)
	}
	secondGrant, err := gatewayagent.LoadSessionConfig(c.store.grantPath(second.SessionID))
	if err != nil || firstGrant.Certificate == secondGrant.Certificate || firstGrant.AuditToken == secondGrant.AuditToken {
		t.Fatalf("session identities were not isolated: %v", err)
	}
	replay, err := c.CreateApprovedSession(ctx, route, first, "one.internal")
	if err != nil || !reflect.DeepEqual(one, replay) || driver.starts != 2 {
		t.Fatalf("replay changed workload or TTL: %v", err)
	}
	if _, err := c.CreateApprovedSession(ctx, route, first, "two.internal"); err == nil {
		t.Fatal("changed approved target accepted")
	}
	if _, err := c.CloseSession(ctx, "", first.SessionID, "close"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.store.grantPath(first.SessionID)); !os.IsNotExist(err) {
		t.Fatalf("closed session grant remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.store.agentPath(first.SessionID), "stop")); err != nil {
		t.Fatal("durable revocation marker was lost")
	}
	if _, err := c.CreateApprovedSession(ctx, route, first, "one.internal"); err == nil {
		t.Fatal("closed grant relaunched")
	}
	status, err := c.GetSession(ctx, "", second.SessionID)
	if err != nil || status.Status != "running" {
		t.Fatalf("closing one session affected another: %+v %v", status, err)
	}
}

func TestHostRuntimeConcurrentDuplicateAndCapacity(t *testing.T) {
	c, driver := newHostTestClient(t)
	c.options.MaxSessions = 1
	route, request := id.New(), hostTestRequest()
	var workers sync.WaitGroup
	errorsCh := make(chan error, 16)
	for range 16 {
		workers.Go(func() {
			_, err := c.CreateApprovedSession(context.Background(), route, request, "approved.internal")
			errorsCh <- err
		})
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if driver.starts != 1 {
		t.Fatalf("duplicate requests launched %d workloads", driver.starts)
	}
	if _, err := c.CreateApprovedSession(context.Background(), id.New(), hostTestRequest(), "another.internal"); err == nil {
		t.Fatal("a second logical gateway bypassed shared runtime capacity")
	}
}

func TestHostRuntimeRestartRecoversIdentityAndNeverRecreatesExitedAgent(t *testing.T) {
	c, driver := newHostTestClient(t)
	route, request := id.New(), hostTestRequest()
	one, err := c.CreateApprovedSession(context.Background(), route, request, "approved.internal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHostClient(c.options); err == nil {
		t.Fatal("two controllers acquired the same state directory")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewHostClient(c.options)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	configureHostFake(recovered, driver)
	two, err := recovered.CreateApprovedSession(context.Background(), route, request, "approved.internal")
	if err != nil || !reflect.DeepEqual(one, two) || c.instanceID != recovered.instanceID || driver.starts != 1 {
		t.Fatalf("restart changed running grant: %v", err)
	}
	delete(driver.resources, request.SessionID)
	if _, err := recovered.CreateApprovedSession(context.Background(), route, request, "approved.internal"); err == nil || driver.starts != 1 {
		t.Fatal("an exited agent was relaunched")
	}
	ended, err := recovered.Reconcile(context.Background())
	if err != nil || !reflect.DeepEqual(ended, []string{request.SessionID}) {
		t.Fatalf("exited session was not reconciled: %v %v", ended, err)
	}
	if err := recovered.AcknowledgeClosure(context.Background(), request.SessionID); err != nil {
		t.Fatal(err)
	}
}

func TestHostRuntimeUncertainLaunchIsInspectedWithoutReplay(t *testing.T) {
	c, driver := newHostTestClient(t)
	driver.startErr = errors.New("launch response lost")
	route, request := id.New(), hostTestRequest()
	if _, err := c.CreateApprovedSession(context.Background(), route, request, "approved.internal"); err == nil {
		t.Fatal("expected uncertain launch")
	}
	if _, err := c.CreateApprovedSession(context.Background(), route, request, "approved.internal"); err != nil || driver.starts != 1 {
		t.Fatalf("uncertain launch was not recovered: %v", err)
	}
}

func TestHostRuntimeCloseBeforeCreateAndAuditRecovery(t *testing.T) {
	c, _ := newHostTestClient(t)
	ctx := context.Background()
	route, neverStarted := id.New(), hostTestRequest()
	if _, err := c.CloseSession(ctx, "", neverStarted.SessionID, "cancel"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateApprovedSession(ctx, route, neverStarted, "approved.internal"); err == nil {
		t.Fatal("late create bypassed a preexisting revocation")
	}
	request := hostTestRequest()
	if _, err := c.CreateApprovedSession(ctx, route, request, "approved.internal"); err != nil {
		t.Fatal(err)
	}
	c.flushAudit = func(context.Context, gatewayagent.SessionConfig, string, zerolog.Logger) error {
		return errors.New("collector unavailable")
	}
	if _, err := c.CloseSession(ctx, "", request.SessionID, "close"); err == nil {
		t.Fatal("audit failure was acknowledged as fully closed")
	}
	if err := c.AcknowledgeClosure(ctx, request.SessionID); err == nil {
		t.Fatal("incomplete cleanup was acknowledged")
	}
	if _, err := os.Stat(c.store.grantPath(request.SessionID)); err != nil {
		t.Fatal("audit recovery material was deleted")
	}
	status, err := c.GetSession(ctx, "", request.SessionID)
	if err != nil || status.Status != "stopping" {
		t.Fatalf("revocation state: %+v %v", status, err)
	}
	c.flushAudit = gatewayagent.FlushSessionAudit
	if _, err := c.CloseSession(ctx, "", request.SessionID, "retry"); err != nil {
		t.Fatal(err)
	}
}

func TestHostRuntimeRevocationDuringReadinessCannotReturnRunning(t *testing.T) {
	c, _ := newHostTestClient(t)
	request := hostTestRequest()
	entered, release := make(chan struct{}), make(chan struct{})
	original := c.callAgent
	c.callAgent = func(ctx context.Context, address string, cfg gatewayagent.SessionConfig, path string, result any) error {
		if path == "/status" {
			close(entered)
			<-release
		}
		return original(ctx, address, cfg, path, result)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.CreateApprovedSession(context.Background(), id.New(), request, "approved.internal")
		done <- err
	}()
	<-entered
	_, err := c.CloseSession(context.Background(), "", request.SessionID, "revoke")
	close(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("readiness acknowledged a revoked grant")
	}
}

func TestHostRuntimeExpiredGrantIsReconciledWithoutExtendingTTL(t *testing.T) {
	c, _ := newHostTestClient(t)
	request := hostTestRequest()
	if _, err := c.CreateApprovedSession(context.Background(), id.New(), request, "approved.internal"); err != nil {
		t.Fatal(err)
	}
	record := c.records[request.SessionID]
	cfg, err := c.loadGrant(record)
	if err != nil {
		t.Fatal(err)
	}
	record.StartedAt = record.StartedAt.Add(-2 * time.Minute)
	record.ExpiresAt = record.ExpiresAt.Add(-2 * time.Minute)
	cfg.StartedAt, cfg.ExpiresAt = record.StartedAt, record.ExpiresAt
	if err := c.store.write(filepath.Join("grants", request.SessionID+".json"), cfg, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := c.save(record); err != nil {
		t.Fatal(err)
	}
	ended, err := c.Reconcile(context.Background())
	if err != nil || !reflect.DeepEqual(ended, []string{request.SessionID}) {
		t.Fatalf("expiry cleanup: %v %v", ended, err)
	}
	status, err := c.GetSession(context.Background(), "", request.SessionID)
	if err != nil || status.Status != "expired" || !status.ExpiresAt.Equal(record.ExpiresAt) {
		t.Fatalf("expiry state changed: %+v %v", status, err)
	}
}
