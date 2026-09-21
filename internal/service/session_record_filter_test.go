package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

func TestSessionRecordFilterAcceptsOpenAndReportsPublicErrors(t *testing.T) {
	for _, status := range []string{"", "open", "provisioning", "running", "revoking", "expired", "closed", "failed", "revoke_failed", "manual_intervention"} {
		filter, err := normalizeSessionRecordFilter(domain.SessionRecordFilter{Status: status, Search: " root "})
		if err != nil || filter.Status != status || filter.Search != "root" {
			t.Fatalf("valid session filter %q: %+v %v", status, filter, err)
		}
	}
	for _, sample := range []struct {
		filter  domain.SessionRecordFilter
		message string
	}{
		{domain.SessionRecordFilter{Status: "unsupported"}, "不支持的会话状态，请刷新页面后重试"},
		{domain.SessionRecordFilter{Status: "open", Search: strings.Repeat("x", 201)}, "搜索内容过长，请缩短后重试"},
		{domain.SessionRecordFilter{Status: "open", Search: strings.Repeat("中", 67)}, "搜索内容过长，请缩短后重试"},
	} {
		_, err := normalizeSessionRecordFilter(sample.filter)
		var validation *RequestValidationError
		if !errors.Is(err, ErrValidation) || !errors.As(err, &validation) || validation.Message != sample.message {
			t.Fatalf("session filter must expose an actionable validation error: %v", err)
		}
	}
}
