package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type requestValidationBackend struct {
	backendStub
	input service.CreateRequestInput
	err   error
	calls int
}

func (s *requestValidationBackend) CreateAccessRequest(_ context.Context, input service.CreateRequestInput) (domain.AccessRequest, error) {
	s.calls++
	s.input = input
	return domain.AccessRequest{ID: testSessionID, ApplicantID: input.ApplicantID, AssetID: input.AssetID, Status: domain.AccessRequestPendingApproval}, s.err
}

func (s *requestValidationBackend) CreateTestAccessRequest(ctx context.Context, input service.CreateRequestInput) (domain.AccessRequest, error) {
	return s.CreateAccessRequest(ctx, input)
}

func TestSessionAuditValidationResponse(t *testing.T) {
	const body = `{"region_id":"3d5116d2-9397-4c2c-93c2-4696ea13764b","asset_id":"f9c65fcf-580d-4cbe-bec9-ea6bc8e4b9ee","target_port":33306,"source_ip":"127.0.0.1","target_account":"root","reason":"test","ticket_no":null,"requested_start_at":null,"ttl_seconds":600,"emergency":false}`
	for _, message := range []string{
		"端口 33306 没有匹配的审计规则，请在系统设置 → 操作审计中配置相同资产端口，并检查资产标签条件",
		"端口 33306 匹配了多条审计规则，请在系统设置 → 操作审计中收窄资产标签条件，确保只匹配一条规则",
		"当前网关运行模式不支持操作审计代理，请将 GATEWAY_RUNTIME 配置为 local、docker 或 kubernetes，并重启 access-gateway",
	} {
		t.Run(message, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
			server.AllowDevAuth = true
			backend := &requestValidationBackend{err: fmt.Errorf("create access request: %w", &service.RequestValidationError{Message: message})}
			server.Service = backend
			request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/admin/access-tests", strings.NewReader(body))
			request.Header.Set("X-User-ID", testUserID)
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "mapped-port-audit-test")
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			var result errorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusBadRequest || result.Error != message || backend.calls != 1 || backend.input.TargetPort != 33306 {
				t.Fatalf("audit validation reason lost: %d %s: %v", response.Code, response.Body.String(), err)
			}
		})
	}
}

func TestAccessRequestValidationResponses(t *testing.T) {
	const body = `{"region_id":"22222222-2222-4222-8222-222222222222","asset_id":"33333333-3333-4333-8333-333333333333","target_port":3306,"source_ip":"127.0.0.1","target_account":"readonly","reason":"连接测试","ticket_no":null,"requested_start_at":null,"ttl_seconds":3600,"emergency":false}`
	for _, sample := range []struct {
		name, body, message string
		err                 error
		status, calls       int
	}{
		{"valid", body, "", nil, 201, 1},
		{"missing approver", body, "该资产尚未配置审批人，请先添加其他启用的用户", &service.RequestValidationError{Message: "该资产尚未配置审批人，请先添加其他启用的用户"}, 400, 1},
		{"wrapped validation", body, "申请人不能审批自己的申请", fmt.Errorf("internal context: %w", &service.RequestValidationError{Message: "申请人不能审批自己的申请"}), 400, 1},
		{"generic validation stays private", body, "申请校验失败，请刷新后重试或联系管理员检查资产配置", fmt.Errorf("private-target-address: %w", service.ErrValidation), 400, 1},
		{"server failure stays private", body, "internal server error", fmt.Errorf("private-database-detail"), 500, 1},
		{"malformed input", `{"target_port":"3306"}`, "申请格式不正确，请检查端口、时长和预约时间后重试", nil, 400, 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
			server.AllowDevAuth = true
			backend := &requestValidationBackend{err: sample.err}
			server.Service = backend
			request := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1/access-requests", strings.NewReader(sample.body))
			request.Header.Set("X-User-ID", testUserID)
			request.Header.Set("Origin", "http://console.test")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "request-test-retry")
			response := httptest.NewRecorder()
			server.Container().ServeHTTP(response, request)
			if response.Code != sample.status || backend.calls != sample.calls {
				t.Fatalf("status=%d calls=%d; want %d/%d: %s", response.Code, backend.calls, sample.status, sample.calls, response.Body.String())
			}
			if sample.status == 201 {
				if backend.input.ApplicantID != testUserID || backend.input.TargetPort != 3306 || backend.input.SourceIP != "127.0.0.1" || backend.input.IdempotencyKey != "request-test-retry" {
					t.Fatal("request fields were not preserved")
				}
				return
			}
			var result errorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error != sample.message {
				t.Fatalf("error response=%q, want %q: %v", result.Error, sample.message, err)
			}
		})
	}
}
