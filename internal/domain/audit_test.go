package domain

import (
	"slices"
	"testing"
)

func TestUserMutationAuditClassification(t *testing.T) {
	all := UserMutationEventTypes("", "")
	for _, event := range []string{"user.login", "user.get", "asset.list", "gateway.catalog_exported", "session.credential_downloaded", "session.started", "connection.backend_connected", "cmdb.sync_completed"} {
		if slices.Contains(all, event) || ClassifyAuditEvent(event).Action != "" {
			t.Fatalf("non-mutation %q included in user operation log", event)
		}
	}
	for _, event := range []string{"asset.created", "asset.updated", "asset.deleted", "rbac.role_revoked", "access_request.approval_decided", "session.force_close_requested", "user.password_changed"} {
		if !slices.Contains(all, event) {
			t.Fatalf("user mutation %q missing", event)
		}
	}
	resources := UserMutationEventTypes("resources", "create")
	if !slices.Contains(resources, "asset.created") || slices.Contains(resources, "asset.updated") || slices.Contains(resources, "user.local_created") {
		t.Fatalf("combined category and action filter: %v", resources)
	}
	if ValidAuditCategory("unknown") || ValidAuditAction("get") || ValidAuditAction("login") {
		t.Fatal("accepted an invalid audit category or read action")
	}
}
