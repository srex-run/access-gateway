package observability

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry          *prometheus.Registry
	httpRequests      *prometheus.CounterVec
	httpDuration      *prometheus.HistogramVec
	workerOperations  *prometheus.CounterVec
	gatewayReady      *prometheus.GaugeVec
	managedSessions   *prometheus.GaugeVec
	overdueSessions   prometheus.Gauge
	auditSpoolPending prometheus.Gauge
	auditDeliveries   *prometheus.CounterVec
	auditEvents       prometheus.Counter
	outboxPending     prometheus.Gauge
	outboxOldestAge   prometheus.Gauge
	databasePool      *prometheus.GaugeVec
	databaseWait      *prometheus.GaugeVec
}

func NewMetrics(namespace string) (*Metrics, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "access_gateway"
	}
	metrics := &Metrics{
		registry: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "http_requests_total", Help: "HTTP requests completed by route and status.",
		}, []string{"method", "route", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "http_request_duration_seconds", Help: "HTTP request duration by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		workerOperations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "worker_operations_total", Help: "Worker operations by outcome.",
		}, []string{"operation", "result"}),
		gatewayReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "gateway_ready", Help: "Last observed Gateway Agent readiness state.",
		}, []string{"gateway_id"}),
		managedSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "managed_sessions", Help: "Gateway Agent sessions by lifecycle status.",
		}, []string{"status"}),
		overdueSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "overdue_sessions", Help: "Gateway Agent sessions still active after their local expiry deadline.",
		}),
		auditSpoolPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "audit_spool_pending", Help: "Gateway connection audit events waiting for control-plane acknowledgement.",
		}),
		auditDeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "audit_delivery_attempts_total", Help: "Gateway audit delivery attempts by outcome.",
		}, []string{"result"}),
		auditEvents: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "audit_events_delivered_total", Help: "Gateway audit events durably acknowledged by the control plane.",
		}),
		outboxPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "outbox_pending", Help: "Outbox events pending or currently leased for processing.",
		}),
		outboxOldestAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "outbox_oldest_age_seconds", Help: "Age of the oldest pending or leased outbox event.",
		}),
		databasePool: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "database_connections", Help: "Database connection pool size by state.",
		}, []string{"state"}),
		databaseWait: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "database_wait", Help: "Cumulative database connection waits and duration.",
		}, []string{"metric"}),
	}
	metrics.registry.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		metrics.httpRequests,
		metrics.httpDuration,
		metrics.workerOperations,
		metrics.gatewayReady,
		metrics.managedSessions,
		metrics.overdueSessions,
		metrics.auditSpoolPending,
		metrics.auditDeliveries,
		metrics.auditEvents,
		metrics.outboxPending,
		metrics.outboxOldestAge,
		metrics.databasePool,
		metrics.databaseWait,
	)
	return metrics, nil
}

func (m *Metrics) SetOverdueSessions(count int) {
	if m == nil || count < 0 {
		return
	}
	m.overdueSessions.Set(float64(count))
}

func (m *Metrics) SetAuditSpoolPending(count int) {
	if m == nil || count < 0 {
		return
	}
	m.auditSpoolPending.Set(float64(count))
}

func (m *Metrics) ObserveAuditDelivery(delivered int, err error) {
	if m == nil || delivered < 0 {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.auditDeliveries.WithLabelValues(result).Inc()
	if err == nil && delivered > 0 {
		m.auditEvents.Add(float64(delivered))
	}
}

func (m *Metrics) SetOperationalStats(outboxPending int64, outboxOldestAgeSeconds float64, databaseMaxOpen, databaseOpen, databaseInUse, databaseIdle int, databaseWaitCount int64, databaseWaitSeconds float64) {
	if m == nil || outboxPending < 0 || outboxOldestAgeSeconds < 0 || databaseMaxOpen < 0 || databaseOpen < 0 || databaseInUse < 0 || databaseIdle < 0 || databaseWaitCount < 0 || databaseWaitSeconds < 0 {
		return
	}
	m.outboxPending.Set(float64(outboxPending))
	m.outboxOldestAge.Set(outboxOldestAgeSeconds)
	m.databasePool.WithLabelValues("max_open").Set(float64(databaseMaxOpen))
	m.databasePool.WithLabelValues("open").Set(float64(databaseOpen))
	m.databasePool.WithLabelValues("in_use").Set(float64(databaseInUse))
	m.databasePool.WithLabelValues("idle").Set(float64(databaseIdle))
	m.databaseWait.WithLabelValues("count").Set(float64(databaseWaitCount))
	m.databaseWait.WithLabelValues("seconds").Set(databaseWaitSeconds)
}

func (m *Metrics) SetManagedSessions(status string, count int) {
	if m == nil || status == "" || count < 0 {
		return
	}
	m.managedSessions.WithLabelValues(status).Set(float64(count))
}

func (m *Metrics) ObserveHTTP(method, route string, status int, elapsed time.Duration) {
	if m == nil {
		return
	}
	if route == "" {
		route = "unmatched"
	}
	m.httpRequests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
	m.httpDuration.WithLabelValues(method, route).Observe(elapsed.Seconds())
}

func (m *Metrics) ObserveWorker(operation string, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.workerOperations.WithLabelValues(operation, result).Inc()
}

func (m *Metrics) SetGatewayReady(gatewayID string, ready bool) {
	if m == nil || gatewayID == "" {
		return
	}
	value := float64(0)
	if ready {
		value = 1
	}
	m.gatewayReady.WithLabelValues(gatewayID).Set(value)
}

func (m *Metrics) Handler(bearerToken string) http.Handler {
	handler := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
	bearerToken = strings.TrimSpace(bearerToken)
	if bearerToken == "" {
		return handler
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		const prefix = "Bearer "
		value := request.Header.Get("Authorization")
		if !strings.HasPrefix(value, prefix) || !constantTimeEqual(strings.TrimSpace(strings.TrimPrefix(value, prefix)), bearerToken) {
			response.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(response, "authentication required", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(response, request)
	})
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
