package gatewayagent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
)

const (
	testGatewaySessionID = "11111111-1111-4111-8111-111111111111"
	testGatewayTargetID  = "22222222-2222-4222-8222-222222222222"
	testOtherTargetID    = "33333333-3333-4333-8333-333333333333"
	testOtherSessionID   = "44444444-4444-4444-8444-444444444444"
)

type controllerStub struct {
	mu             sync.Mutex
	startResponse  gateway.CreateSessionResponse
	startErr       error
	stopResponse   gateway.CloseSessionResponse
	stopErrors     []error
	statusResponse gateway.SessionStatusResponse
	statusErr      error
	stopHook       func()
	startCalls     int
	stopCalls      int
	statusCalls    int
}

func (s *controllerStub) Start(_ context.Context, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startCalls++
	response := s.startResponse
	if response.SessionID == "" {
		response.SessionID = request.SessionID
	}
	if response.ProcessID == "" {
		response.ProcessID = "tcp-20000"
	}
	if response.ListenerPort == 0 {
		response.ListenerPort = 20000
	}
	if response.ExternalPort == 0 {
		response.ExternalPort = response.ListenerPort
	}
	if response.ExposureMode == "" {
		response.ExposureMode = "direct"
	}
	if response.ExposureRef == "" {
		response.ExposureRef = "direct/20000"
	}
	if response.ConnectionMode == "" {
		response.ConnectionMode = request.ConnectionMode
	}
	return response, s.startErr
}

func (s *controllerStub) Stop(_ context.Context, sessionID string) (gateway.CloseSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopCalls++
	if s.stopHook != nil {
		s.stopHook()
	}
	if len(s.stopErrors) > 0 {
		err := s.stopErrors[0]
		s.stopErrors = s.stopErrors[1:]
		if err != nil {
			return gateway.CloseSessionResponse{}, err
		}
	}
	response := s.stopResponse
	if response.SessionID == "" {
		response.SessionID = sessionID
	}
	if response.Status == "" {
		response.Status = sessionClosed
	}
	return response, nil
}

func (s *controllerStub) Status(_ context.Context, sessionID string) (gateway.SessionStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statusCalls++
	response := s.statusResponse
	if response.SessionID == "" {
		response.SessionID = sessionID
	}
	if response.Status == "" {
		response.Status = sessionRunning
	}
	if response.ConnectionMode == "" {
		response.ConnectionMode = gateway.ConnectionModeNative
	}
	return response, s.statusErr
}

type memoryStateStore struct {
	mu         sync.Mutex
	sessions   []SessionRecord
	saveErr    error
	saveErrors []error
	saves      int
}

func (s *memoryStateStore) Load(context.Context) ([]SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSessionRecords(s.sessions), nil
}

func (s *memoryStateStore) Save(_ context.Context, sessions []SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if len(s.saveErrors) > 0 {
		err := s.saveErrors[0]
		s.saveErrors = s.saveErrors[1:]
		if err != nil {
			return err
		}
	}
	if s.saveErr != nil {
		return s.saveErr
	}
	s.sessions = cloneSessionRecords(sessions)
	return nil
}

func cloneSessionRecords(records []SessionRecord) []SessionRecord {
	result := append([]SessionRecord(nil), records...)
	for index := range result {
		if result[index].StartedAt != nil {
			value := *result[index].StartedAt
			result[index].StartedAt = &value
		}
		if result[index].ExpiresAt != nil {
			value := *result[index].ExpiresAt
			result[index].ExpiresAt = &value
		}
		if result[index].ClosedAt != nil {
			value := *result[index].ClosedAt
			result[index].ClosedAt = &value
		}
	}
	return result
}

func newTestManager(t *testing.T, controller *controllerStub, store *memoryStateStore, entries []AssetCatalogEntry, now *time.Time) *Manager {
	t.Helper()
	catalog, err := NewAssetCatalog(entries)
	if err != nil {
		t.Fatalf("NewAssetCatalog: %v", err)
	}
	manager, err := NewManager(controller, store, catalog, time.Hour, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	manager.clock = func() time.Time { return *now }
	return manager
}

func validGatewayRequest() gateway.CreateSessionRequest {
	return gateway.CreateSessionRequest{
		ConnectionMode: gateway.ConnectionModeNative,
		SessionID:      testGatewaySessionID, TargetID: testGatewayTargetID,
		TargetPort: 5432, SourceIP: "127.0.0.1", TargetAccount: "readonly",
		TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections,
	}
}

func TestManagerStartEnforcesCatalogAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{
		ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	store := &memoryStateStore{}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)

	unauthorized := validGatewayRequest()
	unauthorized.TargetPort = 22
	if _, err := manager.Start(context.Background(), unauthorized); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("unauthorized Start error = %v", err)
	}
	if controller.startCalls != 0 {
		t.Fatalf("controller start calls after rejected target = %d", controller.startCalls)
	}

	created, err := manager.Start(context.Background(), validGatewayRequest())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if created.Status != sessionRunning || created.ListenerPort != 20000 || created.ExternalPort != 20000 {
		t.Fatalf("created response = %+v", created)
	}
	replayed, err := manager.Start(context.Background(), validGatewayRequest())
	if err != nil || replayed.ListenerPort != created.ListenerPort || replayed.ExposureRef != created.ExposureRef {
		t.Fatalf("duplicate Start response = %+v, %v", replayed, err)
	}
	if controller.startCalls != 1 {
		t.Fatalf("controller start calls = %d", controller.startCalls)
	}
	for _, record := range store.sessions {
		if record.SessionID == testGatewaySessionID && record.ProcessID != "tcp-20000" {
			t.Fatalf("persisted record = %+v", record)
		}
	}
}

func TestManagerKeepsExplicitDeadlineOnRetry(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(30 * time.Second)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: deadline}}
	manager := newTestManager(t, controller, &memoryStateStore{}, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	request := validGatewayRequest()
	request.ExpiresAt = &deadline
	first, err := manager.Start(context.Background(), request)
	if err != nil || !first.ExpiresAt.Equal(deadline) {
		t.Fatalf("create deadline: %+v %v", first, err)
	}
	now = now.Add(10 * time.Second)
	retried, err := manager.Start(context.Background(), request)
	if err != nil || !retried.ExpiresAt.Equal(deadline) || controller.startCalls != 1 {
		t.Fatalf("retry extended grant: %+v %v", retried, err)
	}
	replacement := deadline.Add(time.Second)
	request.ExpiresAt = &replacement
	if _, err := manager.Start(context.Background(), request); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("changed deadline accepted: %v", err)
	}
}

func TestManagerEnforcesAndReportsCapacity(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{
		ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}})
	if err != nil {
		t.Fatalf("NewAssetCatalog: %v", err)
	}
	manager, err := NewManagerWithOptions(controller, &memoryStateStore{}, catalog, ManagerOptions{MaxTTL: time.Hour, MaxSessions: 1}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewManagerWithOptions: %v", err)
	}
	manager.clock = func() time.Time { return now }
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if active, maximum := manager.Capacity(); active != 1 || maximum != 1 {
		t.Fatalf("capacity active=%d maximum=%d", active, maximum)
	}
	second := validGatewayRequest()
	second.SessionID = "44444444-4444-4444-8444-444444444444"
	if _, err := manager.Start(context.Background(), second); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("full gateway Start error=%v", err)
	}
	if _, err := manager.Stop(context.Background(), testGatewaySessionID, "requested"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if active, maximum := manager.Capacity(); active != 0 || maximum != 1 {
		t.Fatalf("released capacity active=%d maximum=%d", active, maximum)
	}
}

func TestManagerCompactsTerminalTombstonesOnRecovery(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	startedAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Minute)
	oldClosedAt := now.Add(-25 * time.Hour)
	recentClosedAt := now.Add(-time.Hour)
	newestClosedAt := now.Add(-time.Minute)
	store := &memoryStateStore{sessions: []SessionRecord{
		{SessionID: "44444444-4444-4444-8444-444444444444", Status: sessionClosed, ClosedAt: &oldClosedAt},
		{SessionID: "55555555-5555-4555-8555-555555555555", Status: sessionClosed, ClosedAt: &recentClosedAt},
		{SessionID: "66666666-6666-4666-8666-666666666666", Status: sessionExpired, ClosedAt: &newestClosedAt},
		{SessionID: testGatewaySessionID, TargetID: testGatewayTargetID, TargetPort: 5432,
			ConnectionMode: gateway.ConnectionModeNative,
			SourceIP:       "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 120, MaxConnections: gateway.MaxSessionConnections,
			ProcessID: "tcp-20000", ListenerPort: 20000, ExternalPort: 20000, ExposureMode: "direct", ExposureRef: "direct/20000",
			Status: sessionRunning, StartedAt: &startedAt, ExpiresAt: &expiresAt},
	}}
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}})
	if err != nil {
		t.Fatalf("NewAssetCatalog: %v", err)
	}
	manager, err := NewManagerWithOptions(&controllerStub{}, store, catalog, ManagerOptions{
		MaxTTL: time.Hour, MaxSessions: 10, TerminalRetention: 24 * time.Hour, MaxTerminalRecords: 1,
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewManagerWithOptions: %v", err)
	}
	manager.clock = func() time.Time { return now }
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(store.sessions) != 2 {
		t.Fatalf("persisted sessions after compaction = %+v", store.sessions)
	}
	if _, err := manager.Get(context.Background(), "44444444-4444-4444-8444-444444444444"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expired tombstone lookup error = %v", err)
	}
	if _, err := manager.Get(context.Background(), "55555555-5555-4555-8555-555555555555"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("overflow tombstone lookup error = %v", err)
	}
	if status, err := manager.Get(context.Background(), "66666666-6666-4666-8666-666666666666"); err != nil || status.Status != sessionExpired {
		t.Fatalf("retained tombstone = %+v, %v", status, err)
	}
	if status, err := manager.Get(context.Background(), testGatewaySessionID); err != nil || status.Status != sessionRunning {
		t.Fatalf("active session after compaction = %+v, %v", status, err)
	}
}

func TestManagerRejectsUnsafeTerminalRetention(t *testing.T) {
	catalog, err := NewAssetCatalog([]AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}})
	if err != nil {
		t.Fatalf("NewAssetCatalog: %v", err)
	}
	_, err = NewManagerWithOptions(&controllerStub{}, &memoryStateStore{}, catalog, ManagerOptions{
		MaxTTL: time.Hour, MaxSessions: 1, TerminalRetention: 30 * time.Minute, MaxTerminalRecords: 10,
	}, zerolog.Nop())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short terminal retention error = %v", err)
	}
}

func TestManagerReapsExpiredSessionAndRetriesFailedStop(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{
		startResponse: gateway.CreateSessionResponse{ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute)},
		stopErrors:    []error{errors.New("temporary stop failure"), nil},
	}
	store := &memoryStateStore{}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := manager.ReapExpired(context.Background()); err == nil {
		t.Fatal("first ReapExpired unexpectedly succeeded")
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionRevokeFailed {
		t.Fatalf("status after failed revoke = %+v, %v", status, err)
	}
	if err := manager.ReapExpired(context.Background()); err != nil {
		t.Fatalf("second ReapExpired: %v", err)
	}
	status, err = manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionExpired {
		t.Fatalf("status after retry = %+v, %v", status, err)
	}
	if controller.stopCalls != 2 {
		t.Fatalf("controller stop calls = %d", controller.stopCalls)
	}
}

func TestManagerRecoversTransientStatesByStoppingThem(t *testing.T) {
	for _, state := range []string{sessionStarting, sessionStopping, sessionRevokeFailed} {
		t.Run(state, func(t *testing.T) {
			now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			startedAt := now.Add(-time.Minute)
			expiresAt := now.Add(time.Minute)
			store := &memoryStateStore{sessions: []SessionRecord{{
				SessionID: testGatewaySessionID, TargetID: testGatewayTargetID, TargetPort: 5432,
				SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 120,
				MaxConnections: gateway.MaxSessionConnections, Status: state, StartedAt: &startedAt, ExpiresAt: &expiresAt,
			}}}
			controller := &controllerStub{stopResponse: gateway.CloseSessionResponse{ClosedAt: now}}
			manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
			if err := manager.Recover(context.Background()); err != nil {
				t.Fatalf("Recover: %v", err)
			}
			status, err := manager.Get(context.Background(), testGatewaySessionID)
			if err != nil || status.Status != sessionClosed || controller.stopCalls != 1 {
				t.Fatalf("recovered status=%+v err=%v stop_calls=%d", status, err, controller.stopCalls)
			}
		})
	}
}

func TestManagerCountsSessionsPastLocalExpiry(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-time.Second)
	future := now.Add(time.Minute)
	store := &memoryStateStore{sessions: []SessionRecord{
		{SessionID: testGatewaySessionID, TargetID: testGatewayTargetID, TargetPort: 5432, SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections, ProcessID: "tcp-20000", ListenerPort: 20000, ExternalPort: 20000, ExposureMode: "direct", ExposureRef: "direct/20000", Status: sessionRunning, StartedAt: &now, ExpiresAt: &expiredAt},
		{SessionID: testOtherSessionID, TargetID: testGatewayTargetID, TargetPort: 5432, SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 60, MaxConnections: gateway.MaxSessionConnections, ProcessID: "tcp-20001", ListenerPort: 20001, ExternalPort: 20001, ExposureMode: "direct", ExposureRef: "direct/20001", Status: sessionRunning, StartedAt: &now, ExpiresAt: &future},
	}}
	manager := newTestManager(t, &controllerStub{}, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	manager.sessions = map[string]SessionRecord{store.sessions[0].SessionID: store.sessions[0], store.sessions[1].SessionID: store.sessions[1]}
	if count := manager.OverdueSessionCount(); count != 1 {
		t.Fatalf("OverdueSessionCount = %d, want 1", count)
	}
}

func TestManagerFailedStartRemainsRetryableUntilStopSucceeds(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{
		startErr:   errors.New("start response lost"),
		stopErrors: []error{errors.New("gateway unavailable"), nil},
	}
	store := &memoryStateStore{}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err == nil {
		t.Fatal("Start unexpectedly succeeded")
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionRevokeFailed {
		t.Fatalf("status after failed compensation = %+v, %v", status, err)
	}
	if err := manager.ReapExpired(context.Background()); err != nil {
		t.Fatalf("retry compensation: %v", err)
	}
	status, err = manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed {
		t.Fatalf("status after compensation retry = %+v, %v", status, err)
	}
}

func TestManagerRecoveryRevokesRunningTargetRemovedFromCatalog(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	startedAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Minute)
	store := &memoryStateStore{sessions: []SessionRecord{{
		SessionID: testGatewaySessionID, TargetID: testGatewayTargetID, TargetPort: 5432,
		SourceIP: "127.0.0.1", TargetAccount: "readonly", TTLSeconds: 120, MaxConnections: gateway.MaxSessionConnections,
		ProcessID: "tcp-20000", ListenerPort: 20000, ExternalPort: 20000, ExposureMode: "direct", ExposureRef: "direct/20000",
		Status: sessionRunning, StartedAt: &startedAt, ExpiresAt: &expiresAt,
	}}}
	controller := &controllerStub{}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testOtherTargetID, Ports: []int{5432}}}, &now)
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed || controller.stopCalls != 1 {
		t.Fatalf("policy-change recovery status=%+v err=%v stop_calls=%d", status, err, controller.stopCalls)
	}
}

func TestManagerGetReconcilesControllerTerminalStatus(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{
		startResponse:  gateway.CreateSessionResponse{ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute)},
		statusResponse: gateway.SessionStatusResponse{Status: "not_found"},
	}
	store := &memoryStateStore{}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed {
		t.Fatalf("reconciled status = %+v, %v", status, err)
	}
	if controller.statusCalls != 1 || controller.stopCalls != 0 {
		t.Fatalf("controller calls: status=%d stop=%d", controller.statusCalls, controller.stopCalls)
	}
	status, err = manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed || controller.statusCalls != 1 {
		t.Fatalf("cached terminal status = %+v err=%v status_calls=%d", status, err, controller.statusCalls)
	}
}

func TestManagerRetriesWhenPersistingConfirmedStopFails(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{
		ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	store := &memoryStateStore{saveErrors: []error{
		nil, nil, nil, errors.New("state disk unavailable"), nil, nil,
	}}
	manager := newTestManager(t, controller, store, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := manager.Stop(context.Background(), testGatewaySessionID, "requested"); err == nil {
		t.Fatal("Stop unexpectedly hid terminal persistence failure")
	}
	status, err := manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionRevokeFailed {
		t.Fatalf("status after persistence failure = %+v, %v", status, err)
	}
	if err := manager.ReapExpired(context.Background()); err != nil {
		t.Fatalf("retry terminal persistence: %v", err)
	}
	status, err = manager.Get(context.Background(), testGatewaySessionID)
	if err != nil || status.Status != sessionClosed || controller.stopCalls != 2 {
		t.Fatalf("status after retry=%+v err=%v stop_calls=%d", status, err, controller.stopCalls)
	}
}

func TestManagerValidatesCloseTimeAgainstControllerCompletion(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	closedAt := now.Add(8 * time.Second)
	controller := &controllerStub{
		startResponse: gateway.CreateSessionResponse{
			ProcessID: "tcp-20000", StartedAt: now, ExpiresAt: now.Add(time.Minute),
		},
		stopResponse: gateway.CloseSessionResponse{ClosedAt: closedAt},
		stopHook:     func() { now = closedAt },
	}
	manager := newTestManager(t, controller, &memoryStateStore{}, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	closed, err := manager.Stop(context.Background(), testGatewaySessionID, "requested")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if closed.Status != sessionClosed || !closed.ClosedAt.Equal(closedAt) {
		t.Fatalf("closed response = %+v", closed)
	}
}

func TestManagerRejectsInvalidControllerExposure(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	controller := &controllerStub{startResponse: gateway.CreateSessionResponse{
		ProcessID: "tcp-20000", ExposureRef: "direct/20000\nforged", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}}
	manager := newTestManager(t, controller, &memoryStateStore{}, []AssetCatalogEntry{{TargetID: testGatewayTargetID, Ports: []int{5432}}}, &now)
	if _, err := manager.Start(context.Background(), validGatewayRequest()); err == nil {
		t.Fatal("invalid controller exposure was accepted")
	}
}
