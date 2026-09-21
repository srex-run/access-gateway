package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/security"
)

type Options struct {
	Username     string
	Nickname     string
	PasswordFile string
}

type Result struct {
	Created      bool
	Username     string
	PasswordFile string
}

// Initialize creates the first administrator and completion marker atomically.
// A completed installation never reads bootstrap credentials again.
func Initialize(ctx context.Context, database *sql.DB, options Options) (Result, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, fmt.Errorf("begin installation initialization: %w", err)
	}
	defer tx.Rollback()
	result, err := initialize(ctx, tx, options)
	if err != nil {
		return Result{}, fmt.Errorf("initialize installation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("commit installation initialization: %w", err)
	}
	return result, nil
}

func initialize(ctx context.Context, q repository.DBTX, options Options) (Result, error) {
	// Serialize competing initializers before testing the persistent marker.
	if _, err := q.ExecContext(ctx, `LOCK TABLE installation_state IN EXCLUSIVE MODE`); err != nil {
		return Result{}, err
	}
	var initialized bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM installation_state WHERE id=TRUE)`).Scan(&initialized); err != nil {
		return Result{}, err
	}
	if initialized {
		return Result{}, nil
	}
	// Also exclude concurrent manual account creation during the empty check.
	if _, err := q.ExecContext(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return Result{}, err
	}
	var hasUsers bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&hasUsers); err != nil {
		return Result{}, err
	}
	if hasUsers {
		return Result{}, markInitialized(ctx, q)
	}
	username := strings.TrimSpace(options.Username)
	if username == "" {
		username = "admin"
	}
	username, err := security.NormalizeUsername(username)
	if err != nil {
		return Result{}, err
	}
	nickname := strings.TrimSpace(options.Nickname)
	if nickname == "" {
		nickname = username
	}
	if len(nickname) > 128 {
		return Result{}, fmt.Errorf("administrator nickname must not exceed 128 bytes")
	}
	password, err := initialPassword(options.PasswordFile)
	if err != nil {
		return Result{}, err
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return Result{}, err
	}
	users := repository.NewUserRepository()
	user, err := users.Create(ctx, q, domain.User{ID: id.New(), Username: username, Nickname: nickname, Status: domain.UserStatusActive})
	if err != nil {
		return Result{}, err
	}
	if err := users.CreateLocalCredential(ctx, q, repository.LocalCredential{UserID: user.ID, Username: user.Username, PasswordHash: hash}); err != nil {
		return Result{}, err
	}
	if _, err := repository.NewRoleRepository().Create(ctx, q, domain.RoleAssignment{ID: id.New(), UserID: user.ID, Role: "admin", GrantedBy: user.ID}); err != nil {
		return Result{}, err
	}
	if err := repository.NewAuditEventRepository().Append(ctx, q, domain.AuditEvent{ID: id.New(), EventType: "user.local_create", ActorType: "system", SubjectUserID: &user.ID, Metadata: map[string]any{"admin": true, "bootstrap": true}}); err != nil {
		return Result{}, err
	}
	if err := markInitialized(ctx, q); err != nil {
		return Result{}, err
	}
	return Result{Created: true, Username: username, PasswordFile: options.PasswordFile}, nil
}

func markInitialized(ctx context.Context, q repository.DBTX) error {
	_, err := q.ExecContext(ctx, `INSERT INTO installation_state (id) VALUES (TRUE)`)
	return err
}
