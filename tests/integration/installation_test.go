//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/bootstrap"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
)

func TestInstallationInitializesOnceAndPreservesAccountChanges(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "initial-admin-password")
	options := bootstrap.Options{Username: " ADMIN ", Nickname: "管理员", PasswordFile: path}
	var created atomic.Int32
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			result, err := bootstrap.Initialize(ctx, database, options)
			if err != nil {
				t.Errorf("initialize concurrently: %v", err)
				return
			}
			if result.Created {
				created.Add(1)
				if result.Username != "admin" || result.PasswordFile != path {
					t.Error("incorrect initial account result")
				}
			}
		})
	}
	group.Wait()
	if created.Load() != 1 {
		t.Fatalf("initialization ran %d times", created.Load())
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(string(encoded))
	svc := authenticationService(t, database)
	user, err := svc.AuthenticateLocal(ctx, "admin", password)
	if err != nil || user.Nickname != "管理员" {
		t.Fatalf("initial administrator cannot log in: %v", err)
	}
	if err := svc.Authorize(ctx, user.ID, authz.PermissionRoleManage); err != nil {
		t.Fatalf("initial account is not an administrator: %v", err)
	}
	if err := svc.ChangePassword(ctx, user.ID, password, "changed-administrator-password"); err != nil {
		t.Fatal(err)
	}
	users := repository.NewUserRepository()
	if err := users.UpdateStatus(ctx, database, user.ID, domain.UserStatusInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE role_assignments SET revoked_at=NOW() WHERE user_id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// The marker takes priority over changed options or a missing password file.
	result, err := bootstrap.Initialize(ctx, database, bootstrap.Options{Username: "invalid username", PasswordFile: path})
	if err != nil || result.Created {
		t.Fatalf("completed installation ran again: %+v %v", result, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("restart recreated the initial password file")
	}
	credential, err := users.LocalCredentialByUser(ctx, database, user.ID)
	if err != nil || !security.CheckPassword(credential.PasswordHash, "changed-administrator-password") {
		t.Fatalf("restart reset the administrator password: %v", err)
	}
	current, err := users.GetByID(ctx, database, user.ID)
	if err != nil || current.Status != domain.UserStatusInactive {
		t.Fatalf("restart reactivated the account: %v", err)
	}
	var accounts, markers, grants, audits int
	if err := database.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users),
		(SELECT count(*) FROM installation_state), (SELECT count(*) FROM role_assignments WHERE revoked_at IS NULL),
		(SELECT count(*) FROM audit_events WHERE event_type='user.local_create')`).Scan(&accounts, &markers, &grants, &audits); err != nil || accounts != 1 || markers != 1 || grants != 0 || audits != 1 {
		t.Fatalf("unexpected initialization effects: accounts=%d markers=%d grants=%d audits=%d error=%v", accounts, markers, grants, audits, err)
	}
}

func TestInstallationFailureRollsBackAndRetries(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	options := bootstrap.Options{PasswordFile: filepath.Join(directory, "initial-admin-password")}
	if _, err := database.ExecContext(ctx, `ALTER TABLE role_assignments ADD CONSTRAINT reject_initial_admin CHECK (role <> 'admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Initialize(ctx, database, options); err == nil {
		t.Fatal("initialization succeeded without an administrator grant")
	}
	first, err := os.ReadFile(options.PasswordFile)
	if err != nil {
		t.Fatal(err)
	}
	var users, credentials, markers int
	if err := database.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users),
		(SELECT count(*) FROM local_accounts), (SELECT count(*) FROM installation_state)`).Scan(&users, &credentials, &markers); err != nil || users != 0 || credentials != 0 || markers != 0 {
		t.Fatalf("failed initialization left partial data: users=%d credentials=%d markers=%d error=%v", users, credentials, markers, err)
	}
	if _, err := database.ExecContext(ctx, `ALTER TABLE role_assignments DROP CONSTRAINT reject_initial_admin`); err != nil {
		t.Fatal(err)
	}
	result, err := bootstrap.Initialize(ctx, database, options)
	if err != nil || !result.Created || result.Username != "admin" {
		t.Fatalf("initialization retry failed: %+v %v", result, err)
	}
	second, err := os.ReadFile(options.PasswordFile)
	if err != nil || string(second) != string(first) {
		t.Fatal("retry changed the persisted initial password")
	}
}

func TestInstallationAdoptsExistingUsersWithoutChangingAccess(t *testing.T) {
	for _, existingAtMigration := range []bool{true, false} {
		name := "manual account after migration"
		if existingAtMigration {
			name = "existing installation upgrade"
		}
		t.Run(name, func(t *testing.T) {
			database := openDatabaseAtVersion(t, 33)
			ctx := context.Background()
			if !existingAtMigration {
				resetSchema(t, database)
			}
			user, err := repository.NewUserRepository().Create(ctx, database, domain.User{ID: id.New(), Username: "existing", Nickname: "已有用户", Status: domain.UserStatusInactive})
			if err != nil {
				t.Fatal(err)
			}
			if existingAtMigration {
				resetSchema(t, database)
			}
			result, err := bootstrap.Initialize(ctx, database, bootstrap.Options{})
			if err != nil || result.Created {
				t.Fatalf("existing installation was reinitialized: %+v %v", result, err)
			}
			current, err := repository.NewUserRepository().GetByID(ctx, database, user.ID)
			if err != nil || current.Username != "existing" || current.Status != domain.UserStatusInactive {
				t.Fatalf("existing account changed: %+v %v", current, err)
			}
			var users, markers, grants int
			if err := database.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users),
				(SELECT count(*) FROM installation_state), (SELECT count(*) FROM role_assignments)`).Scan(&users, &markers, &grants); err != nil || users != 1 || markers != 1 || grants != 0 {
				t.Fatalf("existing installation gained an account or role: users=%d markers=%d grants=%d error=%v", users, markers, grants, err)
			}
		})
	}
}
