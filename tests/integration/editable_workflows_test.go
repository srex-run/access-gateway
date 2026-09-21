//go:build integration

package integration_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestDefaultWorkflowEditing(t *testing.T) {
	for _, migrate := range []bool{false, true} {
		name := "legacy built-in workflow"
		if migrate {
			name = "migrated default workflow"
		}
		t.Run(name, func(t *testing.T) {
			database := openDatabaseAtVersion(t, 31)
			ctx := context.Background()
			flows, err := (repository.WorkflowRepository{}).List(ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			var original approvalflow.Definition
			for _, flow := range flows {
				if flow.ID == approvalflow.OwnerPlatformID {
					original = flow
				}
			}
			if !original.BuiltIn {
				t.Fatal("legacy workflow must start as built-in")
			}
			resetSchema(t, database)
			_, svc, admin := builtinRoleServiceWithDatabase(t, database)
			read := func() approvalflow.Definition {
				t.Helper()
				flows, err := svc.ListWorkflows(ctx, admin.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, flow := range flows {
					if flow.ID == approvalflow.OwnerPlatformID {
						return flow
					}
				}
				t.Fatal("default workflow not found")
				return approvalflow.Definition{}
			}
			if migrate {
				migrated := read()
				expected := original
				expected.BuiltIn = false
				expected.Revision++
				expected.UpdatedAt = migrated.UpdatedAt
				if !reflect.DeepEqual(migrated, expected) {
					t.Fatalf("migration changed workflow configuration: %+v", migrated)
				}
				original = migrated
			} else {
				// Simulate a legacy marker on the current account schema.
				if _, err := database.ExecContext(ctx, `UPDATE approval_workflows SET built_in=TRUE WHERE id=$1`, original.ID); err != nil {
					t.Fatal(err)
				}
				original = read()
			}
			input := original
			input.Name = "业务负责人及平台审批"
			input.Description = "先业务负责人审批，再由平台管理员审批。"
			input.TimeoutSeconds = 7200
			input.Enabled = false
			input.Steps = []approvalflow.Step{{Name: "业务负责人", Kind: "owners", Mode: "all"}, {Name: "平台管理", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/role=admin"}}
			ordinary, err := repository.NewUserRepository().Create(ctx, database, domain.User{ID: id.New(), Nickname: "Ordinary", Status: domain.UserStatusActive})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.SaveWorkflow(ctx, ordinary.ID, input); !errors.Is(err, service.ErrForbidden) {
				t.Fatalf("workflow management permission was not enforced: %v", err)
			}
			updated, err := svc.SaveWorkflow(ctx, admin.ID, input)
			if err != nil {
				t.Fatalf("edit default workflow: %v", err)
			}
			expected := input
			expected.BuiltIn = false
			expected.Revision++
			expected.UpdatedAt = updated.UpdatedAt
			if !reflect.DeepEqual(updated, expected) || !reflect.DeepEqual(read(), updated) {
				t.Fatalf("workflow edit did not persist: %+v", updated)
			}
			if _, err := svc.SaveWorkflow(ctx, admin.ID, input); !errors.Is(err, service.ErrStateConflict) {
				t.Fatalf("stale revision overwrote workflow changes: %v", err)
			}
			var count int
			if err := database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type='workflow.saved' AND actor_id=$1`, admin.ID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("expected one workflow save audit: count=%d err=%v", count, err)
			}
		})
	}
}
