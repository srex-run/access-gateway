//go:build integration

package repository

import (
	"maps"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
)

func TestUserLabelsPersistAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	users := NewUserRepository()
	for _, sample := range []struct {
		name   string
		labels map[string]string
	}{
		{name: "nil"},
		{name: "empty", labels: map[string]string{}},
		{name: "configured", labels: map[string]string{"team": "operations", "env": "demo"}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			created, err := users.Create(ctx, database, domain.User{
				ID: id.New(), Nickname: "Labels Test", Status: domain.UserStatusActive, Labels: sample.labels,
			})
			if err != nil {
				t.Fatal(err)
			}
			if created.Labels == nil || !maps.Equal(created.Labels, sample.labels) {
				t.Fatalf("created labels = %v, want %v", created.Labels, sample.labels)
			}
			stored, err := users.GetByID(ctx, database, created.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Labels == nil || !maps.Equal(stored.Labels, sample.labels) {
				t.Fatalf("stored labels = %v, want %v", stored.Labels, sample.labels)
			}
		})
	}
}

func TestUserStatusMutationsAgainstPostgres(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := testContext()
	users := NewUserRepository()
	for _, method := range []string{"status", "profile", "feishu"} {
		t.Run(method, func(t *testing.T) {
			user, err := users.Create(ctx, database, domain.User{
				ID: id.New(), FeishuOpenID: "ou_status_" + method, Nickname: "Status Test", Status: domain.UserStatusActive,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range []domain.UserStatus{domain.UserStatusActive, domain.UserStatusInactive, domain.UserStatusInactive, domain.UserStatusActive} {
				previous := user
				user.Status = status
				switch method {
				case "status":
					err = users.UpdateStatus(ctx, database, user.ID, status)
				case "profile":
					err = users.UpdateProfile(ctx, database, user)
				case "feishu":
					_, err = users.UpsertByFeishu(ctx, database, user)
				}
				if err != nil {
					t.Fatalf("set status to %s: %v", status, err)
				}
				user, err = users.GetByID(ctx, database, user.ID)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus := status
				if method == "feishu" && previous.Status == domain.UserStatusInactive {
					wantStatus = domain.UserStatusInactive
				}
				wantAuthVersion := previous.AuthVersion
				if previous.Status != wantStatus {
					wantAuthVersion++
				}
				if user.Status != wantStatus || user.AuthVersion != wantAuthVersion || user.Revision != previous.Revision+1 {
					t.Fatalf("status=%s auth_version=%d revision=%d, want status=%s auth_version=%d revision=%d",
						user.Status, user.AuthVersion, user.Revision, wantStatus, wantAuthVersion, previous.Revision+1)
				}
			}
		})
	}
}
