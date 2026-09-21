package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/id"
)

const (
	sessionStarting     = "starting"
	sessionRunning      = "running"
	sessionStopping     = "stopping"
	sessionRevokeFailed = "revoke_failed"
	sessionClosed       = "closed"
	sessionExpired      = "expired"
	sessionFailed       = "failed"

	controllerClockSkew = 5 * time.Second
	maxProcessIDBytes   = 128

	defaultTerminalRetention  = 7 * 24 * time.Hour
	defaultMaxTerminalRecords = 10000
)

type SessionRecord struct {
	WebOnly           bool       `json:"web_only,omitempty"`
	ConnectionMode    string     `json:"connection_mode,omitempty"`
	ClientPublicKey   string     `json:"client_public_key,omitempty"`
	ServerCertificate string     `json:"server_certificate,omitempty"`
	SessionID         string     `json:"session_id"`
	TargetID          string     `json:"target_id,omitempty"`
	TargetPort        int        `json:"target_port,omitempty"`
	SourceIP          string     `json:"source_ip,omitempty"`
	TargetAccount     string     `json:"target_account,omitempty"`
	TTLSeconds        int        `json:"ttl_seconds,omitempty"`
	RequestExpiresAt  *time.Time `json:"request_expires_at,omitempty"`
	MaxConnections    int        `json:"max_connections,omitempty"`
	ProcessID         string     `json:"process_id,omitempty"`
	ListenerPort      int        `json:"listener_port,omitempty"`
	ExternalPort      int        `json:"external_port,omitempty"`
	ExposureMode      string     `json:"exposure_mode,omitempty"`
	ExposureRef       string     `json:"exposure_ref,omitempty"`
	Status            string     `json:"status"`
	CloseReason       string     `json:"close_reason,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	ClosedAt          *time.Time `json:"closed_at,omitempty"`
}

type sessionRestorer interface {
	Restore(ctx context.Context, record SessionRecord) (gateway.CreateSessionResponse, error)
}

type Manager struct {
	mu                 sync.Mutex
	controller         Controller
	store              StateStore
	catalog            TargetCatalog
	maxTTL             time.Duration
	maxSessions        int
	terminalRetention  time.Duration
	maxTerminalRecords int
	clock              func() time.Time
	logger             zerolog.Logger
	sessions           map[string]SessionRecord
}

func (m *Manager) SessionCounts() map[string]int {
	counts := map[string]int{
		sessionStarting: 0, sessionRunning: 0, sessionStopping: 0,
		sessionRevokeFailed: 0, sessionClosed: 0, sessionExpired: 0, sessionFailed: 0,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, record := range m.sessions {
		counts[record.Status]++
	}
	return counts
}

func (m *Manager) OverdueSessionCount() int {
	if m == nil {
		return 0
	}
	now := m.clock()
	count := 0
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, record := range m.sessions {
		if record.ExpiresAt == nil || record.ExpiresAt.After(now) {
			continue
		}
		switch record.Status {
		case sessionStarting, sessionRunning, sessionStopping, sessionRevokeFailed:
			count++
		}
	}
	return count
}

func (m *Manager) Capacity() (active, maximum int) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeSessionsLocked(), m.maxSessions
}

type ManagerOptions struct {
	MaxTTL             time.Duration
	MaxSessions        int
	TerminalRetention  time.Duration
	MaxTerminalRecords int
}

func NewManager(controller Controller, store StateStore, catalog TargetCatalog, maxTTL time.Duration, logger zerolog.Logger) (*Manager, error) {
	return NewManagerWithOptions(controller, store, catalog, ManagerOptions{
		MaxTTL: maxTTL, MaxSessions: 100,
		TerminalRetention: defaultTerminalRetention, MaxTerminalRecords: defaultMaxTerminalRecords,
	}, logger)
}

func NewManagerWithOptions(controller Controller, store StateStore, catalog TargetCatalog, options ManagerOptions, logger zerolog.Logger) (*Manager, error) {
	if controller == nil || store == nil || catalog == nil {
		return nil, fmt.Errorf("gateway manager requires controller, state store, and asset catalog")
	}
	if options.MaxTTL <= 0 || options.MaxTTL > 5*time.Hour {
		return nil, fmt.Errorf("gateway maximum TTL is invalid: %w", ErrInvalidInput)
	}
	if options.MaxSessions < 1 || options.MaxSessions > 100000 {
		return nil, fmt.Errorf("gateway maximum sessions is invalid: %w", ErrInvalidInput)
	}
	if options.TerminalRetention == 0 {
		options.TerminalRetention = defaultTerminalRetention
	}
	if options.MaxTerminalRecords == 0 {
		options.MaxTerminalRecords = defaultMaxTerminalRecords
	}
	if options.TerminalRetention < options.MaxTTL || options.TerminalRetention > 90*24*time.Hour {
		return nil, fmt.Errorf("gateway terminal retention must be between the maximum TTL and 90 days: %w", ErrInvalidInput)
	}
	if options.MaxTerminalRecords < 1 || options.MaxTerminalRecords > 50000 {
		return nil, fmt.Errorf("gateway terminal record limit is invalid: %w", ErrInvalidInput)
	}
	return &Manager{
		controller:         controller,
		store:              store,
		catalog:            catalog,
		maxTTL:             options.MaxTTL,
		maxSessions:        options.MaxSessions,
		terminalRetention:  options.TerminalRetention,
		maxTerminalRecords: options.MaxTerminalRecords,
		clock:              time.Now,
		logger:             logger,
		sessions:           make(map[string]SessionRecord),
	}, nil
}

func (m *Manager) Recover(ctx context.Context) error {
	records, err := m.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("recover gateway sessions: %w", err)
	}
	recovered := make(map[string]SessionRecord, len(records))
	for _, record := range records {
		if err := m.validateRecord(record); err != nil {
			return fmt.Errorf("recover gateway session %q: %w", record.SessionID, err)
		}
		if _, exists := recovered[record.SessionID]; exists {
			return fmt.Errorf("duplicate gateway session %q in state", record.SessionID)
		}
		recovered[record.SessionID] = record
	}

	m.mu.Lock()
	m.sessions = recovered
	if err := m.saveLocked(ctx); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("compact recovered gateway sessions: %w", err)
	}
	m.mu.Unlock()

	now := m.clock()
	var recoveryErrors []error
	for _, original := range records {
		record := original
		reason := record.CloseReason
		mustStop := false
		switch record.Status {
		case sessionStarting, sessionStopping, sessionRevokeFailed:
			mustStop = true
			if reason == "" {
				reason = "recovery"
			}
			m.prepareRecoveredRetry(record.SessionID, reason)
		case sessionRunning:
			if record.ExpiresAt != nil && !record.ExpiresAt.After(now) {
				mustStop = true
				reason = "ttl_expired"
			} else if !m.recordWithinCurrentPolicy(record) {
				mustStop = true
				reason = "catalog_or_policy_changed"
				m.prepareRecoveredRetry(record.SessionID, reason)
			} else if restorer, ok := m.controller.(sessionRestorer); ok {
				response, restoreErr := restorer.Restore(ctx, record)
				if restoreErr != nil || !sameRecoveredExposure(record, response) {
					mustStop = true
					reason = "runtime_restore_failed"
					m.prepareRecoveredRetry(record.SessionID, reason)
					if restoreErr != nil {
						recoveryErrors = append(recoveryErrors, fmt.Errorf("restore session %s: %w", record.SessionID, restoreErr))
					} else {
						recoveryErrors = append(recoveryErrors, fmt.Errorf("restore session %s: exposure metadata changed", record.SessionID))
					}
				}
			}
		}
		if !mustStop {
			continue
		}
		if _, stopErr := m.Stop(ctx, record.SessionID, reason); stopErr != nil {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("recover session %s: %w", record.SessionID, stopErr))
		}
	}
	if err := errors.Join(recoveryErrors...); err != nil {
		return fmt.Errorf("%w: %w", ErrRecoveryIncomplete, err)
	}
	return nil
}

func (m *Manager) Start(ctx context.Context, request gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	if err := m.validateCreateRequest(request); err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	acceptedAt := m.clock()
	provisionalExpiry := acceptedAt.Add(time.Duration(request.TTLSeconds) * time.Second)
	if request.ExpiresAt != nil {
		provisionalExpiry = request.ExpiresAt.UTC()
	}
	record := SessionRecord{
		WebOnly:         request.WebOnly,
		ConnectionMode:  request.ConnectionMode,
		ClientPublicKey: request.ClientPublicKey,
		SessionID:       request.SessionID, TargetID: request.TargetID, TargetPort: request.TargetPort,
		SourceIP: request.SourceIP, TargetAccount: request.TargetAccount,
		TTLSeconds: request.TTLSeconds, MaxConnections: request.MaxConnections, Status: sessionStarting,
		RequestExpiresAt: request.ExpiresAt,
		StartedAt:        &acceptedAt, ExpiresAt: &provisionalExpiry,
	}

	m.mu.Lock()
	if existing, exists := m.sessions[request.SessionID]; exists {
		m.mu.Unlock()
		if !sameSessionParameters(existing, record) {
			return gateway.CreateSessionResponse{}, fmt.Errorf("session ID is bound to different parameters: %w", ErrSessionConflict)
		}
		switch existing.Status {
		case sessionStarting, sessionStopping, sessionRevokeFailed:
			return gateway.CreateSessionResponse{}, ErrSessionInProgress
		case sessionRunning:
			return responseFromRecord(existing), nil
		default:
			return gateway.CreateSessionResponse{}, ErrSessionConflict
		}
	}
	if m.activeSessionsLocked() >= m.maxSessions {
		m.mu.Unlock()
		return gateway.CreateSessionResponse{}, ErrCapacityExhausted
	}
	m.sessions[request.SessionID] = record
	if err := m.saveLocked(ctx); err != nil {
		delete(m.sessions, request.SessionID)
		m.mu.Unlock()
		return gateway.CreateSessionResponse{}, fmt.Errorf("persist starting gateway session: %w", err)
	}
	m.mu.Unlock()

	response, err := m.controller.Start(ctx, request)
	if err != nil {
		cleanupErr := m.finishFailedStart(ctx, request.SessionID, "controller_start_failed")
		return gateway.CreateSessionResponse{}, fmt.Errorf("create direct session: %w", errors.Join(err, cleanupErr))
	}
	completedAt := m.clock()
	startedAt, expiresAt, err := validateCreateResponse(request, response, acceptedAt, completedAt)
	if err != nil {
		cleanupErr := m.finishFailedStart(ctx, request.SessionID, "invalid_controller_response")
		return gateway.CreateSessionResponse{}, fmt.Errorf("create direct session: %w", errors.Join(err, cleanupErr))
	}
	response.Status = sessionRunning
	response.StartedAt = startedAt
	response.ExpiresAt = expiresAt

	m.mu.Lock()
	current, exists := m.sessions[request.SessionID]
	if !exists || current.Status != sessionStarting {
		m.mu.Unlock()
		cleanupErr := m.finishFailedStart(ctx, request.SessionID, "state_conflict_after_start")
		return gateway.CreateSessionResponse{}, errors.Join(ErrSessionConflict, cleanupErr)
	}
	current.Status = sessionRunning
	current.ServerCertificate = response.ServerCertificate
	current.ProcessID = response.ProcessID
	current.ListenerPort = response.ListenerPort
	current.ExternalPort = response.ExternalPort
	current.ExposureMode = response.ExposureMode
	current.ExposureRef = response.ExposureRef
	current.StartedAt = &startedAt
	current.ExpiresAt = &expiresAt
	m.sessions[request.SessionID] = current
	if err := m.saveLocked(ctx); err != nil {
		m.mu.Unlock()
		cleanupErr := m.finishFailedStart(ctx, request.SessionID, "persist_running_failed")
		return gateway.CreateSessionResponse{}, fmt.Errorf("persist running gateway session: %w", errors.Join(err, cleanupErr))
	}
	m.mu.Unlock()
	return response, nil
}

func (m *Manager) activeSessionsLocked() int {
	count := 0
	for _, record := range m.sessions {
		switch record.Status {
		case sessionStarting, sessionRunning, sessionStopping, sessionRevokeFailed:
			count++
		}
	}
	return count
}

func (m *Manager) Stop(ctx context.Context, sessionID, reason string) (gateway.CloseSessionResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.CloseSessionResponse{}, fmt.Errorf("session ID is invalid: %w", ErrInvalidInput)
	}
	now := m.clock()
	reason = normalizeCloseReason(reason)

	m.mu.Lock()
	record, exists := m.sessions[sessionID]
	if exists {
		switch record.Status {
		case sessionClosed, sessionExpired, sessionFailed:
			m.mu.Unlock()
			closedAt := now
			if record.ClosedAt != nil {
				closedAt = *record.ClosedAt
			}
			return gateway.CloseSessionResponse{SessionID: sessionID, Status: record.Status, ClosedAt: closedAt}, nil
		case sessionStarting, sessionStopping:
			m.mu.Unlock()
			return gateway.CloseSessionResponse{}, ErrSessionInProgress
		}
		if record.CloseReason != "" && record.Status == sessionRevokeFailed && reason != "ttl_expired" && reason != "expired" {
			reason = record.CloseReason
		}
	} else {
		record = SessionRecord{SessionID: sessionID}
	}
	previous := record
	record.Status = sessionStopping
	record.CloseReason = reason
	m.sessions[sessionID] = record
	if err := m.saveLocked(ctx); err != nil {
		if exists {
			m.sessions[sessionID] = previous
		} else {
			delete(m.sessions, sessionID)
		}
		m.mu.Unlock()
		return gateway.CloseSessionResponse{}, fmt.Errorf("persist stopping gateway session: %w", err)
	}
	m.mu.Unlock()

	response, stopErr := m.controller.Stop(ctx, sessionID)
	completedAt := m.clock()
	if stopErr == nil {
		stopErr = validateCloseResponse(sessionID, response, completedAt)
	}
	if stopErr != nil {
		persistErr := m.markRevokeFailed(ctx, sessionID, reason)
		return gateway.CloseSessionResponse{}, fmt.Errorf("stop direct session: %w", errors.Join(stopErr, persistErr))
	}
	closedAt := response.ClosedAt
	if closedAt.IsZero() {
		closedAt = completedAt
	}
	status := terminalStatus(reason)
	m.mu.Lock()
	record = m.sessions[sessionID]
	record.Status = status
	record.CloseReason = reason
	record.ClosedAt = &closedAt
	m.sessions[sessionID] = record
	saveErr := m.saveLocked(context.WithoutCancel(ctx))
	if saveErr != nil {
		record.Status = sessionRevokeFailed
		record.ClosedAt = nil
		m.sessions[sessionID] = record
	}
	m.mu.Unlock()
	if saveErr != nil {
		return gateway.CloseSessionResponse{}, fmt.Errorf("persist closed gateway session: %w", saveErr)
	}
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: status, ClosedAt: closedAt}, nil
}

func (m *Manager) Get(ctx context.Context, sessionID string) (gateway.SessionStatusResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.SessionStatusResponse{}, fmt.Errorf("session ID is invalid: %w", ErrInvalidInput)
	}
	m.mu.Lock()
	record, exists := m.sessions[sessionID]
	m.mu.Unlock()
	if !exists {
		return gateway.SessionStatusResponse{}, ErrSessionNotFound
	}
	if record.Status != sessionRunning {
		return statusFromRecord(record), nil
	}
	if record.ExpiresAt != nil && !record.ExpiresAt.After(m.clock()) {
		closed, err := m.Stop(ctx, sessionID, "ttl_expired")
		if err != nil {
			return gateway.SessionStatusResponse{}, fmt.Errorf("expire gateway session during status check: %w", err)
		}
		result := statusFromRecord(record)
		result.Status = closed.Status
		return result, nil
	}
	remote, err := m.controller.Status(ctx, sessionID)
	if err != nil {
		return gateway.SessionStatusResponse{}, fmt.Errorf("inspect direct session: %w", err)
	}
	if remote.SessionID != sessionID {
		return gateway.SessionStatusResponse{}, fmt.Errorf("session controller returned status for a different session")
	}
	if remote.Status == sessionRunning {
		if gateway.NormalizeConnectionMode(remote.ConnectionMode) != gateway.NormalizeConnectionMode(record.ConnectionMode) {
			return gateway.SessionStatusResponse{}, fmt.Errorf("session controller returned a different connection mode")
		}
		m.mu.Lock()
		current := m.sessions[sessionID]
		m.mu.Unlock()
		return statusFromRecord(current), nil
	}
	terminal := sessionClosed
	if remote.Status == sessionExpired {
		terminal = sessionExpired
	} else if remote.Status == sessionFailed {
		terminal = sessionFailed
	} else if remote.Status != sessionClosed && remote.Status != "not_found" {
		return gateway.SessionStatusResponse{}, fmt.Errorf("session controller returned invalid status")
	}
	now := m.clock()
	m.mu.Lock()
	current := m.sessions[sessionID]
	if current.Status == sessionRunning {
		previous := current
		current.Status = terminal
		current.CloseReason = "controller_status"
		current.ClosedAt = &now
		m.sessions[sessionID] = current
		if err := m.saveLocked(context.WithoutCancel(ctx)); err != nil {
			m.sessions[sessionID] = previous
			m.mu.Unlock()
			return gateway.SessionStatusResponse{}, fmt.Errorf("persist reconciled gateway session: %w", err)
		}
	}
	m.mu.Unlock()
	return statusFromRecord(current), nil
}

func (m *Manager) ReapExpired(ctx context.Context) error {
	now := m.clock()
	m.mu.Lock()
	type retry struct {
		sessionID string
		reason    string
	}
	retries := make([]retry, 0)
	for sessionID, record := range m.sessions {
		switch {
		case record.Status == sessionRunning && record.ExpiresAt != nil && !record.ExpiresAt.After(now):
			retries = append(retries, retry{sessionID: sessionID, reason: "ttl_expired"})
		case record.Status == sessionRevokeFailed:
			reason := record.CloseReason
			if reason == "" {
				reason = "retry"
			}
			if record.ExpiresAt != nil && !record.ExpiresAt.After(now) {
				reason = "ttl_expired"
			}
			retries = append(retries, retry{sessionID: sessionID, reason: reason})
		}
	}
	m.mu.Unlock()
	sort.Slice(retries, func(left, right int) bool { return retries[left].sessionID < retries[right].sessionID })
	var reapErrors []error
	for _, retry := range retries {
		if _, err := m.Stop(ctx, retry.sessionID, retry.reason); err != nil && !errors.Is(err, ErrSessionInProgress) {
			reapErrors = append(reapErrors, fmt.Errorf("reap gateway session %s: %w", retry.sessionID, err))
			m.logger.Error().Str("session_id", retry.sessionID).Bool("alert", true).Msg("gateway local revoke failed")
		}
	}
	return errors.Join(reapErrors...)
}

func (m *Manager) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := m.ReapExpired(ctx); err != nil && !errors.Is(err, context.Canceled) {
				m.logger.Error().Err(err).Msg("gateway TTL sweep failed")
			}
		}
	}
}

func (m *Manager) finishFailedStart(ctx context.Context, sessionID, reason string) error {
	response, stopErr := m.controller.Stop(context.WithoutCancel(ctx), sessionID)
	now := m.clock()
	if stopErr == nil {
		stopErr = validateCloseResponse(sessionID, response, now)
	}

	m.mu.Lock()
	record, exists := m.sessions[sessionID]
	if !exists {
		record = SessionRecord{SessionID: sessionID}
	}
	if stopErr == nil {
		record.Status = sessionFailed
		record.ClosedAt = &now
	} else {
		record.Status = sessionRevokeFailed
	}
	record.CloseReason = reason
	m.sessions[sessionID] = record
	persistErr := m.saveLocked(context.WithoutCancel(ctx))
	if persistErr != nil && stopErr == nil {
		record.Status = sessionRevokeFailed
		record.ClosedAt = nil
		m.sessions[sessionID] = record
	}
	m.mu.Unlock()
	if stopErr != nil {
		m.logger.Error().Str("session_id", sessionID).Bool("alert", true).Msg("compensate failed gateway start failed")
	}
	if persistErr != nil {
		m.logger.Error().Str("session_id", sessionID).Bool("alert", true).Msg("persist failed gateway compensation failed")
	}
	return errors.Join(stopErr, persistErr)
}

func (m *Manager) markRevokeFailed(ctx context.Context, sessionID, reason string) error {
	m.mu.Lock()
	record := m.sessions[sessionID]
	record.Status = sessionRevokeFailed
	record.CloseReason = reason
	m.sessions[sessionID] = record
	err := m.saveLocked(context.WithoutCancel(ctx))
	m.mu.Unlock()
	m.logger.Error().Str("session_id", sessionID).Bool("alert", true).Msg("gateway session revoke requires retry")
	if err != nil {
		return fmt.Errorf("persist gateway revoke failure: %w", err)
	}
	return nil
}

func (m *Manager) prepareRecoveredRetry(sessionID, reason string) {
	m.mu.Lock()
	record := m.sessions[sessionID]
	record.Status = sessionRevokeFailed
	record.CloseReason = reason
	m.sessions[sessionID] = record
	m.mu.Unlock()
}

func (m *Manager) recordWithinCurrentPolicy(record SessionRecord) bool {
	if gateway.ValidateConnectionIdentity(record.ConnectionMode, record.ClientPublicKey) != nil || record.ExpiresAt == nil || gateway.ValidateConnectionResponse(record.ConnectionMode, responseFromRecord(record)) != nil {
		return false
	}
	if record.TTLSeconds < 1 || record.TTLSeconds > int(m.maxTTL/time.Second) {
		return false
	}
	return m.catalog.Authorize(record.TargetID, record.TargetPort) == nil
}

func (m *Manager) saveLocked(ctx context.Context) error {
	records, removed := m.recordsForPersistenceLocked(m.clock())
	if err := m.store.Save(ctx, records); err != nil {
		return err
	}
	for _, sessionID := range removed {
		delete(m.sessions, sessionID)
	}
	return nil
}

func (m *Manager) recordsForPersistenceLocked(now time.Time) ([]SessionRecord, []string) {
	records := make([]SessionRecord, 0, len(m.sessions))
	terminals := make([]SessionRecord, 0)
	removed := make([]string, 0)
	cutoff := now.Add(-m.terminalRetention)
	for _, record := range m.sessions {
		if !terminalSessionStatus(record.Status) {
			records = append(records, record)
			continue
		}
		if record.ClosedAt == nil || record.ClosedAt.Before(cutoff) {
			removed = append(removed, record.SessionID)
			continue
		}
		terminals = append(terminals, record)
	}
	sort.Slice(terminals, func(left, right int) bool {
		if terminals[left].ClosedAt.Equal(*terminals[right].ClosedAt) {
			return terminals[left].SessionID < terminals[right].SessionID
		}
		return terminals[left].ClosedAt.After(*terminals[right].ClosedAt)
	})
	if len(terminals) > m.maxTerminalRecords {
		for _, record := range terminals[m.maxTerminalRecords:] {
			removed = append(removed, record.SessionID)
		}
		terminals = terminals[:m.maxTerminalRecords]
	}
	records = append(records, terminals...)
	return records, removed
}

func terminalSessionStatus(status string) bool {
	return status == sessionClosed || status == sessionExpired || status == sessionFailed
}

func (m *Manager) validateCreateRequest(request gateway.CreateSessionRequest) error {
	if err := gateway.ValidateCreateRequest(request); err != nil {
		return fmt.Errorf("validate gateway session: %v: %w", err, ErrInvalidInput)
	}
	if !id.IsUUID(request.SessionID) || !id.IsUUID(request.TargetID) {
		return fmt.Errorf("session and target IDs must be UUIDs: %w", ErrInvalidInput)
	}
	if request.TTLSeconds > int(m.maxTTL/time.Second) {
		return fmt.Errorf("session TTL exceeds gateway policy: %w", ErrInvalidInput)
	}
	if request.ExpiresAt != nil {
		now := m.clock()
		if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(time.Duration(request.TTLSeconds)*time.Second)) {
			return fmt.Errorf("session expiry is outside the approved validity: %w", ErrInvalidInput)
		}
	}
	if request.MaxConnections != gateway.MaxSessionConnections {
		return fmt.Errorf("direct access permits exactly %d concurrent connections: %w", gateway.MaxSessionConnections, ErrInvalidInput)
	}
	if err := m.catalog.Authorize(request.TargetID, request.TargetPort); err != nil {
		return fmt.Errorf("authorize gateway target: %w", err)
	}
	return nil
}

func (m *Manager) validateRecord(record SessionRecord) error {
	if !id.IsUUID(record.SessionID) {
		return ErrInvalidInput
	}
	switch record.Status {
	case sessionStarting, sessionRunning:
		if !validSessionParameters(record) || record.StartedAt == nil || record.ExpiresAt == nil || !record.ExpiresAt.After(*record.StartedAt) {
			return ErrInvalidInput
		}
		if record.RequestExpiresAt != nil && !record.RequestExpiresAt.Equal(*record.ExpiresAt) {
			return ErrInvalidInput
		}
		if record.Status == sessionRunning && !validRuntimeMetadata(record) {
			return ErrInvalidInput
		}
	case sessionStopping, sessionRevokeFailed:
		if hasAnySessionParameter(record) && !validSessionParameters(record) {
			return ErrInvalidInput
		}
	case sessionClosed, sessionExpired, sessionFailed:
		if record.ClosedAt == nil {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func validateCreateResponse(request gateway.CreateSessionRequest, response gateway.CreateSessionResponse, acceptedAt, completedAt time.Time) (time.Time, time.Time, error) {
	if response.SessionID != request.SessionID || !validProcessID(response.ProcessID) ||
		response.ListenerPort < 1 || response.ListenerPort > 65535 ||
		response.ExternalPort < 1 || response.ExternalPort > 65535 ||
		!validExposureMetadata(response.ExposureMode, response.ExposureRef) {
		return time.Time{}, time.Time{}, fmt.Errorf("session controller returned incomplete session metadata")
	}
	if response.Status != "" && response.Status != sessionRunning {
		return time.Time{}, time.Time{}, fmt.Errorf("session controller returned invalid status")
	}
	startedAt := response.StartedAt
	if startedAt.IsZero() {
		startedAt = completedAt
	}
	if startedAt.Before(acceptedAt.Add(-controllerClockSkew)) || startedAt.After(completedAt.Add(controllerClockSkew)) {
		return time.Time{}, time.Time{}, fmt.Errorf("session controller returned invalid start time")
	}
	maximumExpiry := startedAt.Add(time.Duration(request.TTLSeconds) * time.Second)
	if request.ExpiresAt != nil {
		maximumExpiry = request.ExpiresAt.UTC()
	}
	expiresAt := response.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = maximumExpiry
	}
	if !expiresAt.After(completedAt) || expiresAt.After(maximumExpiry) || !expiresAt.After(startedAt) || (request.ExpiresAt != nil && !expiresAt.Equal(maximumExpiry)) {
		return time.Time{}, time.Time{}, fmt.Errorf("session controller returned invalid expiry")
	}
	response.ExpiresAt = expiresAt
	if err := gateway.ValidateConnectionResponse(request.ConnectionMode, response); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return startedAt, expiresAt, nil
}

func validProcessID(value string) bool {
	if value == "" || len(value) > maxProcessIDBytes {
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

func validateCloseResponse(sessionID string, response gateway.CloseSessionResponse, now time.Time) error {
	if response.SessionID != sessionID {
		return fmt.Errorf("session controller closed a different session")
	}
	switch response.Status {
	case sessionClosed, sessionExpired, "not_found":
	default:
		return fmt.Errorf("session controller returned non-terminal close status")
	}
	if !response.ClosedAt.IsZero() && response.ClosedAt.After(now.Add(controllerClockSkew)) {
		return fmt.Errorf("session controller returned invalid close time")
	}
	return nil
}

func validSessionParameters(record SessionRecord) bool {
	return id.IsUUID(record.TargetID) && record.TargetPort >= 1 && record.TargetPort <= 65535 &&
		netParseIP(record.SourceIP) != "" && validTargetAccount(record.TargetAccount) &&
		record.TTLSeconds >= 1 && record.MaxConnections == gateway.MaxSessionConnections
}

func hasAnySessionParameter(record SessionRecord) bool {
	return record.TargetID != "" || record.TargetPort != 0 || record.SourceIP != "" || record.TargetAccount != "" || record.TTLSeconds != 0 || record.MaxConnections != 0
}

func validRuntimeMetadata(record SessionRecord) bool {
	return validProcessID(record.ProcessID) && record.ListenerPort >= 1 && record.ListenerPort <= 65535 &&
		record.ExternalPort >= 1 && record.ExternalPort <= 65535 && validExposureMetadata(record.ExposureMode, record.ExposureRef)
}

func normalizeCloseReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 128 {
		return "requested"
	}
	return reason
}

func terminalStatus(reason string) string {
	if reason == "ttl_expired" || reason == "expired" {
		return sessionExpired
	}
	return sessionClosed
}

func sameSessionParameters(left, right SessionRecord) bool {
	return left.WebOnly == right.WebOnly && left.SessionID == right.SessionID && left.TargetID == right.TargetID && left.TargetPort == right.TargetPort &&
		left.SourceIP == right.SourceIP && left.TargetAccount == right.TargetAccount &&
		left.TTLSeconds == right.TTLSeconds && left.MaxConnections == right.MaxConnections &&
		left.ClientPublicKey == right.ClientPublicKey && gateway.NormalizeConnectionMode(left.ConnectionMode) == gateway.NormalizeConnectionMode(right.ConnectionMode) &&
		((left.RequestExpiresAt == nil && right.RequestExpiresAt == nil) || (left.RequestExpiresAt != nil && right.RequestExpiresAt != nil && left.RequestExpiresAt.Equal(*right.RequestExpiresAt)))
}

func responseFromRecord(record SessionRecord) gateway.CreateSessionResponse {
	response := gateway.CreateSessionResponse{
		ConnectionMode:    record.ConnectionMode,
		ServerCertificate: record.ServerCertificate,
		SessionID:         record.SessionID, Status: record.Status, ProcessID: record.ProcessID,
		ListenerPort: record.ListenerPort, ExternalPort: record.ExternalPort,
		ExposureMode: record.ExposureMode, ExposureRef: record.ExposureRef,
	}
	if record.StartedAt != nil {
		response.StartedAt = *record.StartedAt
	}
	if record.ExpiresAt != nil {
		response.ExpiresAt = *record.ExpiresAt
	}
	return response
}

func statusFromRecord(record SessionRecord) gateway.SessionStatusResponse {
	return gateway.SessionStatusResponse{
		ConnectionMode: record.ConnectionMode,
		SessionID:      record.SessionID, Status: record.Status,
		ListenerPort: record.ListenerPort, ExternalPort: record.ExternalPort,
		ExposureMode: record.ExposureMode, ExposureRef: record.ExposureRef,
		ExpiresAt: record.ExpiresAt,
	}
}

func sameRecoveredExposure(record SessionRecord, response gateway.CreateSessionResponse) bool {
	return response.SessionID == record.SessionID && response.Status == sessionRunning &&
		response.ProcessID == record.ProcessID && response.ListenerPort == record.ListenerPort &&
		response.ExternalPort == record.ExternalPort && response.ExposureMode == record.ExposureMode &&
		response.ExposureRef == record.ExposureRef && response.ServerCertificate == record.ServerCertificate &&
		gateway.NormalizeConnectionMode(response.ConnectionMode) == gateway.NormalizeConnectionMode(record.ConnectionMode)
}

func validTargetAccount(value string) bool {
	if strings.TrimSpace(value) != value || len([]byte(value)) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validExposureMetadata(mode, reference string) bool {
	if mode != "direct" && mode != "kubernetes_nodeport" {
		return false
	}
	if strings.TrimSpace(reference) == "" || strings.TrimSpace(reference) != reference || len(reference) > 253 {
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
