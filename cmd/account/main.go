package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/srex-run/access-gateway/internal/db"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		if len(os.Args) != 2 {
			return fmt.Errorf("usage: account bootstrap (configured with BOOTSTRAP_ADMIN_* environment variables)")
		}
		return runBootstrap()
	}
	if len(os.Args) < 2 || (os.Args[1] != "create" && os.Args[1] != "reset-password") {
		return fmt.Errorf("usage: account bootstrap | {create|reset-password} --username USERNAME [--nickname NICKNAME] [--admin]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	username := flags.String("username", "", "local account username")
	name := flags.String("nickname", "", "nickname (defaults to username)")
	flags.StringVar(name, "name", "", "alias for --nickname")
	admin := flags.Bool("admin", false, "grant the new account the admin role")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || (command != "create" && (*admin || *name != "")) {
		return fmt.Errorf("unexpected account arguments")
	}
	normalized, err := security.NormalizeUsername(*username)
	if err != nil {
		return err
	}
	*name = strings.TrimSpace(*name)
	if *name == "" {
		*name = normalized
	}
	if !service.ValidAccountName(*name) {
		return fmt.Errorf("display name must contain 1-128 bytes")
	}
	databaseURL, err := secretstore.FromEnvironment("DATABASE_URL")
	if err != nil {
		return err
	}
	if strings.TrimSpace(databaseURL) == "" {
		return fmt.Errorf("database URL is required; set DATABASE_URL or DATABASE_URL_FILE (local development: make dev-admin)")
	}
	password, err := secretstore.FromEnvironment("LOCAL_ACCOUNT_PASSWORD")
	if err != nil {
		return err
	}
	if password == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("a terminal or LOCAL_ACCOUNT_PASSWORD_FILE is required")
		}
		fmt.Fprint(os.Stderr, "Password: ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, "Confirm password: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		if string(first) != string(second) {
			return fmt.Errorf("passwords do not match")
		}
		password = string(first)
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, db.Config{URL: databaseURL, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: 5 * time.Minute, ConnMaxIdleTime: time.Minute})
	if err != nil {
		return err
	}
	defer database.Close()
	users := repository.NewUserRepository()
	var userID string
	err = service.InTx(ctx, database, func(q repository.DBTX) error {
		if command == "create" {
			user, err := users.Create(ctx, q, domain.User{ID: id.New(), Username: normalized, Nickname: *name, Status: domain.UserStatusActive})
			if err != nil {
				return err
			}
			userID = user.ID
			if err := users.CreateLocalCredential(ctx, q, repository.LocalCredential{UserID: user.ID, Username: normalized, PasswordHash: hash}); err != nil {
				return err
			}
			if *admin {
				if _, err := repository.NewRoleRepository().Create(ctx, q, domain.RoleAssignment{ID: id.New(), UserID: user.ID, Role: "admin", GrantedBy: user.ID}); err != nil {
					return err
				}
			}
		} else {
			credential, err := users.LocalCredential(ctx, q, normalized)
			if err != nil {
				return err
			}
			userID = credential.UserID
			if _, err := users.GetByIDForUpdate(ctx, q, userID); err != nil {
				return err
			}
			if err := users.UpdateLocalPassword(ctx, q, userID, hash); err != nil {
				return err
			}
		}
		return repository.NewAuditEventRepository().Append(ctx, q, domain.AuditEvent{ID: id.New(), EventType: "user.local_" + strings.ReplaceAll(command, "-", "_"), ActorType: "system", SubjectUserID: &userID, Metadata: map[string]any{"admin": *admin}})
	})
	if err != nil {
		return err
	}
	fmt.Printf("Account %s: %s (user_id=%s)\n", command, normalized, userID)
	return nil
}
