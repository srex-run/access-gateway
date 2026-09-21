//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/realtime"
)

func TestRealtimeNotificationCommitRollbackAndMultipleInstances(t *testing.T) {
	database := openIntegrationDB(t)
	ctx := context.Background()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	user, err := NewUserRepository().Create(ctx, database, domain.User{ID: id.New(), Username: "realtime-user", Nickname: "Realtime User", Status: domain.UserStatusActive})
	check(err)
	region, err := NewRegionRepository().Create(ctx, database, domain.Region{ID: id.New(), Code: "realtime", Name: "Realtime", Status: domain.ResourceStatusEnabled})
	check(err)
	gateway, err := NewGatewayRepository().Create(ctx, database, domain.Gateway{ID: id.New(), RegionID: region.ID, Name: "Realtime", ManagementEndpoint: "https://gateway.example", PublicEndpoint: "gateway.example", MaxSessions: 10, Status: domain.ResourceStatusEnabled})
	check(err)
	asset, err := NewAssetRepository().Create(ctx, database, domain.Asset{ID: id.New(), RegionID: region.ID, GatewayID: gateway.ID, Name: "Realtime", AssetType: "mysql", TargetCiphertext: "encrypted", RiskLevel: domain.RiskLevelSensitive, MaxTTLSeconds: 600, Status: domain.ResourceStatusEnabled})
	check(err)
	request, err := NewAccessRequestRepository().Create(ctx, database, domain.AccessRequest{ID: id.New(), ApplicantID: user.ID, AssetID: asset.ID, TargetPort: 3306, Reason: "realtime test", TTLSeconds: 600, Status: domain.AccessRequestPendingApproval, IdempotencyKey: id.New()})
	check(err)
	var schema string
	check(database.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema))
	dsn, err := integrationDSNWithSearchPath(os.Getenv(testDSNEnv), schema)
	check(err)
	first, err := realtime.Start(ctx, dsn, zerolog.Nop())
	check(err)
	t.Cleanup(func() { _ = first.Close() })
	second, err := realtime.Start(ctx, dsn, zerolog.Nop())
	check(err)
	t.Cleanup(func() { _ = second.Close() })
	one, cancelOne, _ := first.Subscribe(user.ID)
	two, cancelTwo, _ := second.Subscribe(user.ID)
	other, cancelOther, _ := first.Subscribe(id.New())
	defer cancelOne()
	defer cancelTwo()
	defer cancelOther()
	assertQuiet := func(events <-chan realtime.Change) {
		t.Helper()
		select {
		case event := <-events:
			t.Fatalf("unexpected event: %+v", event)
		default:
		}
	}
	receive := func(events <-chan realtime.Change, topic string) {
		t.Helper()
		select {
		case event, open := <-events:
			if !open || event.Topic != topic {
				t.Fatalf("event=%+v open=%v want=%s", event, open, topic)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %s event", topic)
		}
	}
	transaction, err := database.BeginTx(ctx, nil)
	check(err)
	defer transaction.Rollback()
	notice := domain.Notification{ID: id.New(), UserID: user.ID, EventType: "request_result", DedupeKey: id.New(), Title: "Result", Content: "Result content must not be sent in an event", RequestID: request.ID}
	check((NotificationRepository{}).Append(ctx, transaction, notice))
	assertQuiet(one)
	assertQuiet(two)
	check(transaction.Commit())
	receive(one, "notifications")
	receive(two, "notifications")
	assertQuiet(other)
	check((NotificationRepository{}).MarkRead(ctx, database, user.ID, notice.ID))
	receive(one, "notifications")
	receive(two, "notifications")

	rollback, err := database.BeginTx(ctx, nil)
	check(err)
	defer rollback.Rollback()
	check((NotificationRepository{}).MarkAllRead(ctx, rollback, user.ID))
	notice.ID, notice.DedupeKey = id.New(), id.New()
	check((NotificationRepository{}).Append(ctx, rollback, notice))
	check(rollback.Rollback())
	// A marker after rollback establishes delivery order without a sleep.
	_, err = database.ExecContext(ctx, "SELECT access_gateway_emit('catalog')")
	check(err)
	receive(one, "catalog")
	receive(two, "catalog")
	receive(other, "catalog")

	// LISTEN channels are database-wide; another installation/schema must not
	// invalidate this application's private data or leak recipient activity.
	payload, err := json.Marshal(realtime.Change{Schema: "other_installation", Topic: "notifications", UserID: user.ID})
	check(err)
	_, err = database.ExecContext(ctx, "SELECT pg_notify('access_gateway_changes', $1)", string(payload))
	check(err)
	_, err = database.ExecContext(ctx, "SELECT access_gateway_emit('catalog')")
	check(err)
	receive(one, "catalog")
	receive(two, "catalog")
}
