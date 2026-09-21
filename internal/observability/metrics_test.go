package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeBoundedLabelsAndOptionalAuthentication(t *testing.T) {
	metrics, err := NewMetrics("access_gateway_test")
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	metrics.ObserveHTTP(http.MethodGet, "/api/v1/sessions/{session_id}", http.StatusOK, 5*time.Millisecond)
	metrics.ObserveWorker("outbox", nil)
	metrics.SetGatewayReady("gateway-id", true)
	metrics.SetManagedSessions("running", 2)
	metrics.SetOverdueSessions(1)
	metrics.SetAuditSpoolPending(4)
	metrics.ObserveAuditDelivery(0, errors.New("delivery failed"))
	metrics.ObserveAuditDelivery(3, nil)
	metrics.SetOperationalStats(3, 12.5, 20, 8, 3, 5, 2, 0.25)

	handler := metrics.Handler("0123456789abcdef0123456789abcdef")
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized metrics status = %d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `route="/api/v1/sessions/{session_id}"`) || !strings.Contains(response.Body.String(), `gateway_id="gateway-id"`) || !strings.Contains(response.Body.String(), `status="running"} 2`) || !strings.Contains(response.Body.String(), `access_gateway_test_overdue_sessions 1`) || !strings.Contains(response.Body.String(), `access_gateway_test_audit_spool_pending 4`) || !strings.Contains(response.Body.String(), `access_gateway_test_audit_delivery_attempts_total{result="error"} 1`) || !strings.Contains(response.Body.String(), `access_gateway_test_audit_delivery_attempts_total{result="success"} 1`) || !strings.Contains(response.Body.String(), `access_gateway_test_audit_events_delivered_total 3`) || !strings.Contains(response.Body.String(), `access_gateway_test_outbox_pending 3`) || !strings.Contains(response.Body.String(), `state="in_use"} 3`) {
		t.Fatalf("metrics response = %d %s", response.Code, response.Body.String())
	}
}
