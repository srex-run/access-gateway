package gateway

import (
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"testing"
)

func TestWebOnlyGrantsRequireAuditedClientAndNoPublicSource(t *testing.T) {
	for _, protocol := range []string{"ssh", "mysql", "postgresql", "redis", "mongodb", "http"} {
		request := validClientCreateRequest("session", "asset", 5432)
		request.WebOnly, request.SourceIP, request.ClientPublicKey, request.ConnectionMode = true, "", "", ConnectionModeAudit
		request.AuditPolicy = operationaudit.Policy{Profile: protocol, Protocol: protocol}
		if err := ValidateCreateRequest(request); err != nil {
			t.Fatalf("%s web client rejected: %v", protocol, err)
		}
		request.SourceIP = "192.0.2.1"
		if ValidateCreateRequest(request) == nil {
			t.Fatal("web-only grant accepted public TCP identity")
		}
		request.SourceIP, request.ConnectionMode = "", ConnectionModeNative
		if ValidateCreateRequest(request) == nil {
			t.Fatal("web-only grant disabled audit")
		}
	}
}
