package service

import (
	"context"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

func TestReadOnlyAuditEventsDoNotWrite(t *testing.T) {
	// A nil store makes any attempted persistence fail this test.
	svc := &AccessService{}
	for _, eventType := range []string{"user.login", "gateway.catalog_exported", "session.credential_downloaded"} {
		if err := svc.appendAudit(context.Background(), nil, domain.AuditEvent{EventType: eventType}); err != nil {
			t.Fatalf("read event %s: %v", eventType, err)
		}
	}
}
