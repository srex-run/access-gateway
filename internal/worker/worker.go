package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/observability"
	"github.com/srex-run/access-gateway/internal/service"
)

type Queue struct {
	tasks chan service.Task
}

func NewQueue(buffer int) *Queue {
	if buffer < 1 {
		buffer = 128
	}
	return &Queue{tasks: make(chan service.Task, buffer)}
}

func (q *Queue) Enqueue(ctx context.Context, task service.Task) error {
	if task.SessionID == "" {
		return fmt.Errorf("session task requires a session ID")
	}
	select {
	case q.tasks <- task:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("enqueue session task: %w", ctx.Err())
	}
}

type Handler interface {
	ProvisionSession(ctx context.Context, sessionID string) (domain.Session, error)
	RevokeSession(ctx context.Context, sessionID, reason string) (domain.Session, error)
	ReapExpired(ctx context.Context, limit int) (int, error)
}

type provisioningRecovery interface {
	ReapProvisioning(ctx context.Context, limit int) (int, error)
}

type sessionResourceReconciler interface {
	ReconcileSessionResources(context.Context) error
}

type approvalExpiryReaper interface {
	ReapApprovalExpired(ctx context.Context, limit int) (int, error)
}

type outboxProcessor interface {
	ProcessOutbox(ctx context.Context, limit int) (int, error)
}

type gatewayHealthProber interface {
	ProbeGateways(ctx context.Context) ([]service.GatewayHealthResult, error)
}

type cmdbSynchronizer interface {
	SyncCMDB(ctx context.Context) (service.CMDBSyncResult, error)
}

type cloudSynchronizer interface {
	ProcessCloudSync(context.Context) error
}

type operationalStatsProvider interface {
	GetOperationalStats(ctx context.Context) (service.OperationalStats, error)
}

type RunnerOptions struct {
	RecoveryInterval              time.Duration
	OutboxInterval                time.Duration
	GatewayHealthInterval         time.Duration
	GatewayHealthFailureThreshold int
	CMDBSyncInterval              time.Duration
	MetricsInterval               time.Duration
	Metrics                       *observability.Metrics
}

type Runner struct {
	queue                         *Queue
	handler                       Handler
	logger                        zerolog.Logger
	interval                      time.Duration
	outboxInterval                time.Duration
	gatewayHealthInterval         time.Duration
	gatewayHealthFailureThreshold int
	cmdbSyncInterval              time.Duration
	metricsInterval               time.Duration
	metrics                       *observability.Metrics
}

func NewRunner(queue *Queue, handler Handler, logger zerolog.Logger, interval time.Duration) (*Runner, error) {
	return NewRunnerWithOptions(queue, handler, logger, RunnerOptions{RecoveryInterval: interval})
}

func NewRunnerWithOptions(queue *Queue, handler Handler, logger zerolog.Logger, options RunnerOptions) (*Runner, error) {
	if queue == nil || handler == nil {
		return nil, fmt.Errorf("worker queue and handler are required")
	}
	if options.RecoveryInterval <= 0 {
		options.RecoveryInterval = time.Minute
	}
	if options.OutboxInterval <= 0 {
		options.OutboxInterval = time.Second
	}
	if options.GatewayHealthInterval <= 0 {
		options.GatewayHealthInterval = 10 * time.Second
	}
	if options.GatewayHealthFailureThreshold <= 0 {
		options.GatewayHealthFailureThreshold = 3
	}
	if options.GatewayHealthFailureThreshold > 100 {
		return nil, fmt.Errorf("gateway health failure threshold cannot exceed 100")
	}
	if options.MetricsInterval <= 0 {
		options.MetricsInterval = 30 * time.Second
	}
	return &Runner{
		queue:                         queue,
		handler:                       handler,
		logger:                        logger,
		interval:                      options.RecoveryInterval,
		outboxInterval:                options.OutboxInterval,
		gatewayHealthInterval:         options.GatewayHealthInterval,
		gatewayHealthFailureThreshold: options.GatewayHealthFailureThreshold,
		cmdbSyncInterval:              options.CMDBSyncInterval,
		metricsInterval:               options.MetricsInterval,
		metrics:                       options.Metrics,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	var background sync.WaitGroup
	if handler, ok := r.handler.(cloudSynchronizer); ok {
		background.Add(1)
		go func() {
			defer background.Done()
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				if err := handler.ProcessCloudSync(ctx); err != nil && ctx.Err() == nil {
					r.logger.Error().Err(err).Msg("process cloud asset sync failed")
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	if r.metrics != nil {
		if _, ok := r.handler.(operationalStatsProvider); ok {
			background.Add(1)
			go func() {
				defer background.Done()
				r.monitorOperationalStats(ctx)
			}()
		}
	}
	if _, ok := r.handler.(gatewayHealthProber); ok {
		background.Add(1)
		go func() {
			defer background.Done()
			r.monitorGatewayHealth(ctx)
		}()
	}
	if r.cmdbSyncInterval > 0 {
		if _, ok := r.handler.(cmdbSynchronizer); ok {
			background.Add(1)
			go func() {
				defer background.Done()
				r.monitorCMDB(ctx)
			}()
		}
	}
	defer background.Wait()

	recoveryTicker := time.NewTicker(r.interval)
	outboxTicker := time.NewTicker(r.outboxInterval)
	defer recoveryTicker.Stop()
	defer outboxTicker.Stop()
	r.reapExpired(ctx)
	r.processOutbox(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case task := <-r.queue.tasks:
			r.handleTask(ctx, task)
		case <-outboxTicker.C:
			r.processOutbox(ctx)
		case <-recoveryTicker.C:
			r.reapExpired(ctx)
		}
	}
}

func (r *Runner) monitorOperationalStats(ctx context.Context) {
	ticker := time.NewTicker(r.metricsInterval)
	defer ticker.Stop()
	r.collectOperationalStats(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.collectOperationalStats(ctx)
		}
	}
}

func (r *Runner) collectOperationalStats(ctx context.Context) {
	provider, ok := r.handler.(operationalStatsProvider)
	if !ok {
		return
	}
	stats, err := provider.GetOperationalStats(ctx)
	r.metrics.ObserveWorker("operational_metrics", err)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			r.logger.Error().Err(err).Msg("collect operational metrics failed")
		}
		return
	}
	r.metrics.SetOperationalStats(
		stats.OutboxPending, stats.OutboxOldestAgeSeconds,
		stats.DatabaseMaxOpen, stats.DatabaseOpen, stats.DatabaseInUse, stats.DatabaseIdle,
		stats.DatabaseWaitCount, stats.DatabaseWaitSeconds,
	)
}

func (r *Runner) monitorCMDB(ctx context.Context) {
	ticker := time.NewTicker(r.cmdbSyncInterval)
	defer ticker.Stop()
	r.syncCMDB(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.syncCMDB(ctx)
		}
	}
}

func (r *Runner) syncCMDB(ctx context.Context) {
	synchronizer, ok := r.handler.(cmdbSynchronizer)
	if !ok {
		return
	}
	_, err := synchronizer.SyncCMDB(ctx)
	r.metrics.ObserveWorker("cmdb_sync", err)
	if err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error().Err(err).Bool("alert", true).Str("severity", "critical").Msg("CMDB synchronization failed")
	}
}

func (r *Runner) monitorGatewayHealth(ctx context.Context) {
	ticker := time.NewTicker(r.gatewayHealthInterval)
	defer ticker.Stop()
	failures := make(map[string]int)
	r.checkGatewayHealth(ctx, failures)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.checkGatewayHealth(ctx, failures)
		}
	}
}

func (r *Runner) checkGatewayHealth(ctx context.Context, failures map[string]int) {
	ctx, span := otel.Tracer("github.com/srex-run/access-gateway/internal/worker").Start(ctx, "worker.gateway_health")
	defer span.End()
	prober, ok := r.handler.(gatewayHealthProber)
	if !ok {
		return
	}
	results, err := prober.ProbeGateways(ctx)
	r.metrics.ObserveWorker("gateway_health", err)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "gateway health probe failed")
		if !errors.Is(err, context.Canceled) {
			r.logger.Error().Err(err).Msg("probe gateways failed")
		}
		return
	}
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if result.GatewayID == "" {
			r.logger.Error().Msg("gateway readiness probe returned an empty gateway ID")
			continue
		}
		seen[result.GatewayID] = struct{}{}
		previousFailures := failures[result.GatewayID]
		r.metrics.SetGatewayReady(result.GatewayID, result.Err == nil)
		if result.Err == nil {
			if previousFailures >= r.gatewayHealthFailureThreshold {
				r.logger.Info().Str("gateway_id", result.GatewayID).Int("previous_failures", previousFailures).Msg("gateway readiness recovered")
			}
			delete(failures, result.GatewayID)
			continue
		}
		if errors.Is(result.Err, context.Canceled) {
			continue
		}
		failureCount := previousFailures + 1
		failures[result.GatewayID] = failureCount
		if failureCount >= r.gatewayHealthFailureThreshold {
			r.logger.Error().Err(result.Err).Str("gateway_id", result.GatewayID).Int("consecutive_failures", failureCount).Bool("alert", true).Str("severity", "critical").Msg("gateway readiness probe failed")
			continue
		}
		r.logger.Warn().Err(result.Err).Str("gateway_id", result.GatewayID).Int("consecutive_failures", failureCount).Msg("gateway readiness probe failed")
	}
	for gatewayID := range failures {
		if _, ok := seen[gatewayID]; !ok {
			delete(failures, gatewayID)
		}
	}
}

func (r *Runner) reapExpired(ctx context.Context) {
	ctx, span := otel.Tracer("github.com/srex-run/access-gateway/internal/worker").Start(ctx, "worker.recovery")
	defer span.End()
	if reconciler, ok := r.handler.(sessionResourceReconciler); ok {
		if err := reconciler.ReconcileSessionResources(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error().Err(err).Bool("alert", true).Msg("reconcile session agent resources failed")
		}
	}
	if _, err := r.handler.ReapExpired(ctx, 500); err != nil && !errors.Is(err, context.Canceled) {
		r.metrics.ObserveWorker("reap_expired", err)
		span.RecordError(err)
		r.logger.Error().Err(err).Msg("reap expired sessions failed")
	} else {
		r.metrics.ObserveWorker("reap_expired", nil)
	}
	// A session can be committed as provisioning immediately before the
	// worker process exits.  Recover those rows as well as expired sessions;
	// ProvisionSession is state- and gateway-idempotent, so a duplicate task
	// is harmless while a lost task would leave an approved request stranded.
	if reaper, ok := r.handler.(provisioningRecovery); ok {
		if _, err := reaper.ReapProvisioning(ctx, 500); err != nil && !errors.Is(err, context.Canceled) {
			r.metrics.ObserveWorker("reap_provisioning", err)
			span.RecordError(err)
			r.logger.Error().Err(err).Msg("reap provisioning sessions failed")
		} else {
			r.metrics.ObserveWorker("reap_provisioning", nil)
		}
	}
	if reaper, ok := r.handler.(approvalExpiryReaper); ok {
		if _, err := reaper.ReapApprovalExpired(ctx, 500); err != nil && !errors.Is(err, context.Canceled) {
			r.metrics.ObserveWorker("reap_approvals", err)
			span.RecordError(err)
			r.logger.Error().Err(err).Msg("reap expired approval requests failed")
		} else {
			r.metrics.ObserveWorker("reap_approvals", nil)
		}
	}
}

func (r *Runner) processOutbox(ctx context.Context) {
	processor, ok := r.handler.(outboxProcessor)
	if !ok {
		return
	}
	ctx, span := otel.Tracer("github.com/srex-run/access-gateway/internal/worker").Start(ctx, "worker.outbox")
	defer span.End()
	if _, err := processor.ProcessOutbox(ctx, 100); err != nil && !errors.Is(err, context.Canceled) {
		r.metrics.ObserveWorker("outbox", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, "outbox processing failed")
		r.logger.Error().Err(err).Msg("process outbox events failed")
	} else {
		r.metrics.ObserveWorker("outbox", nil)
	}
}

func (r *Runner) handleTask(ctx context.Context, task service.Task) {
	var err error
	switch task.Kind {
	case service.TaskProvision:
		_, err = r.handler.ProvisionSession(ctx, task.SessionID)
	case service.TaskRevoke:
		_, err = r.handler.RevokeSession(ctx, task.SessionID, task.Reason)
	default:
		err = fmt.Errorf("unknown task kind %q", task.Kind)
	}
	if err != nil {
		r.logger.Error().Err(err).Str("task_kind", string(task.Kind)).Str("session_id", task.SessionID).Msg("session task failed")
	}
}
