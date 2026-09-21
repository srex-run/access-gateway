//go:build integration

package integration_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/service"
)

func TestBrowserTransportSharedKeysAtomicConsumeAndRotation(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	cipher, err := secretstore.NewAESGCM("test-transport", []byte(strings.Repeat("t", 32)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.NewBrowserTransportService(database, cipher)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.NewBrowserTransportService(database, cipher)
	if err != nil {
		t.Fatal(err)
	}
	binding := securetransport.Binding{Method: "PATCH", Path: "/api/v1/admin/settings", Subject: "user:alice"}
	challenge, err := first.Create(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	other, err := second.Create(ctx, binding)
	if err != nil || other.KeyID != challenge.KeyID {
		t.Fatalf("replicas did not share persisted key: %v", err)
	}
	stored, err := (&repository.TransportRepository{}).ActiveKey(ctx, database)
	if err != nil || strings.Contains(stored.PrivateKeyCiphertext, "PRIVATE KEY") {
		t.Fatalf("unencrypted private key: %v", err)
	}
	request, _, err := testclient.Seal(challenge, []byte(`{"password":"integration-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	wrong := binding
	wrong.Subject = "user:bob"
	if _, _, err := second.Open(ctx, wrong, request); !errors.Is(err, securetransport.ErrInvalid) {
		t.Fatalf("actor substitution accepted: %v", err)
	}
	var consumed atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Go(func() {
			plaintext, reply, err := second.Open(ctx, binding, request)
			if err == nil {
				defer reply.Clear()
				if !strings.Contains(string(plaintext), "integration-secret") {
					t.Error("incorrect decrypted payload")
				}
				consumed.Add(1)
			} else if !errors.Is(err, securetransport.ErrInvalid) {
				t.Errorf("consume: %v", err)
			}
		})
	}
	group.Wait()
	if consumed.Load() != 1 {
		t.Fatalf("consumed %d times", consumed.Load())
	}
	// Force rotation while an old challenge is still live. Both replicas must
	// keep accepting that challenge exactly once until its database expiry.
	if _, err := database.ExecContext(ctx, `UPDATE browser_transport_keys SET expires_at = NOW() + INTERVAL '3 minutes' WHERE id = $1`, challenge.KeyID); err != nil {
		t.Fatal(err)
	}
	rotated, err := first.Create(ctx, binding)
	if err != nil || rotated.KeyID == challenge.KeyID {
		t.Fatalf("key did not rotate: %v", err)
	}
	old, _, err := testclient.Seal(other, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, reply, err := first.Open(ctx, binding, old); err != nil {
		t.Fatalf("old challenge lost during rotation: %v", err)
	} else {
		reply.Clear()
	}
	if _, err := database.ExecContext(ctx, `UPDATE browser_transport_challenges SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, rotated.ID); err != nil {
		t.Fatal(err)
	}
	expired, _, err := testclient.Seal(rotated, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.Open(ctx, binding, expired); !errors.Is(err, securetransport.ErrInvalid) {
		t.Fatalf("expired challenge accepted: %v", err)
	}
	if err := (&repository.TransportRepository{}).DeleteExpired(ctx, database); err != nil {
		t.Fatal(err)
	}
}
