//go:build integration

package integration_test

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/srex-run/access-gateway/internal/authn"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/feishu"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestUnifiedAccountNames(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	svc := authenticationService(t, database)
	users := repository.NewUserRepository()
	admin, err := users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: "admin-open-id", Username: "admin", Nickname: "管理员", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	local, err := svc.CreateLocalUser(ctx, admin.ID, service.CreateLocalUserInput{Username: " Alice ", Nickname: "  ", Password: "initial-password-123"})
	if err != nil || local.Username != "alice" || local.Nickname != "alice" {
		t.Fatalf("local names: %+v %v", local, err)
	}
	account, err := svc.GetAccount(ctx, local.ID)
	if err != nil || account.Username != "alice" || account.Nickname != "alice" || !slices.Contains(account.Providers, "local") {
		t.Fatalf("local account: %+v %v", account, err)
	}
	validUsername := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	seen := map[string]bool{"alice": true}
	for _, provider := range []string{"github", "oidc", "oauth2", "ldap"} {
		t.Run(provider, func(t *testing.T) {
			profile := authn.Profile{Provider: provider, Issuer: "https://identity.example", Subject: "subject", Username: "ALICE", Email: "alice@example.test"}
			user, err := svc.SyncExternalUser(ctx, profile)
			if err != nil || user.ID == local.ID || seen[user.Username] || !validUsername.MatchString(user.Username) || user.Nickname != user.Username {
				t.Fatalf("separate account with a unique username and default nickname: %+v %v", user, err)
			}
			seen[user.Username] = true
			profile.Username = "renamed"
			repeat, err := svc.SyncExternalUser(ctx, profile)
			if err != nil || repeat.ID != user.ID || repeat.Username != user.Username {
				t.Fatalf("provider rename changed account identity: %+v %v", repeat, err)
			}
			account, err := svc.GetAccount(ctx, user.ID)
			if err != nil || account.Username != user.Username || account.Nickname != user.Username || !slices.Equal(account.Providers, []string{provider}) {
				t.Fatalf("external account: %+v %v", account, err)
			}
			if _, err := users.LocalCredentialByUser(ctx, database, user.ID); !errors.Is(err, repository.ErrNotFound) {
				t.Fatalf("SSO account acquired local credentials: %v", err)
			}
		})
	}
	profile := feishu.Profile{OpenID: "feishu-new", TenantKey: "tenant", Username: "alice", Active: true}
	user, err := svc.SyncFeishuUser(ctx, profile)
	if err != nil || seen[user.Username] || !validUsername.MatchString(user.Username) || user.Nickname != user.Username {
		t.Fatalf("Feishu names: %+v %v", user, err)
	}
	profile.Username, profile.Nickname = "renamed", "张三"
	repeat, err := svc.SyncFeishuUser(ctx, profile)
	if err != nil || repeat.ID != user.ID || repeat.Username != user.Username || repeat.Nickname != "张三" {
		t.Fatalf("Feishu synchronization changed username: %+v %v", repeat, err)
	}
	updated, err := svc.UpdateManagedUser(ctx, admin.ID, local.ID, service.UpdateUserInput{Nickname: "", Status: domain.UserStatusActive, Revision: local.Revision})
	if err != nil || updated.Nickname != local.Username {
		t.Fatalf("empty nickname update: %+v %v", updated, err)
	}
	values, err := svc.ListUsers(ctx, admin.ID, user.Username, true, 10, 0)
	if err != nil || len(values) != 1 || values[0].ID != user.ID || values[0].Nickname != "张三" {
		t.Fatalf("SSO username directory lookup: %+v %v", values, err)
	}
}

func TestAccountNamesMigration(t *testing.T) {
	database := openDatabaseAtVersion(t, 32)
	ctx := context.Background()
	localID, externalID, blankID := id.New(), id.New(), id.New()
	if _, err := database.ExecContext(ctx, `INSERT INTO users (id, name, email, status) VALUES
		($1, '本地用户', 'alice@example.test', 'active'),
		($2, '外部用户', 'alice@example.test', 'active'),
		($3, '  ', NULL, 'active')`, localID, externalID, blankID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO local_accounts (user_id, username, password_hash) VALUES ($1, 'alice', 'existing-hash')`, localID); err != nil {
		t.Fatal(err)
	}
	resetSchema(t, database)
	users := repository.NewUserRepository()
	local, err := users.GetByID(ctx, database, localID)
	if err != nil || local.Username != "alice" || local.Nickname != "本地用户" {
		t.Fatalf("local account migration: %+v %v", local, err)
	}
	credential, err := users.LocalCredential(ctx, database, "alice")
	if err != nil || credential.UserID != localID || credential.PasswordHash != "existing-hash" {
		t.Fatalf("local credentials changed: %+v %v", credential, err)
	}
	external, err := users.GetByID(ctx, database, externalID)
	if err != nil || external.Username == "alice" || !strings.HasPrefix(external.Username, "alice_") || len(external.Username) > 64 || external.Nickname != "外部用户" {
		t.Fatalf("migration username collision: %+v %v", external, err)
	}
	blank, err := users.GetByID(ctx, database, blankID)
	if err != nil || blank.Username == "" || blank.Nickname != blank.Username {
		t.Fatalf("blank nickname migration: %+v %v", blank, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE users SET nickname=NULL WHERE id=$1`, localID); err != nil {
		t.Fatal(err)
	}
	local, err = users.GetByID(ctx, database, localID)
	if err != nil || local.Nickname != "alice" {
		t.Fatalf("database nickname default: %+v %v", local, err)
	}
	if err := goose.DownToContext(ctx, database, ".", 32); err != nil {
		t.Fatal(err)
	}
	var username, hash, nickname string
	if err := database.QueryRowContext(ctx, `SELECT a.username, a.password_hash, u.name FROM local_accounts a JOIN users u ON u.id=a.user_id WHERE u.id=$1`, localID).Scan(&username, &hash, &nickname); err != nil || username != "alice" || hash != "existing-hash" || nickname != "alice" {
		t.Fatalf("rollback changed credentials: username=%q nickname=%q error=%v", username, nickname, err)
	}
}
