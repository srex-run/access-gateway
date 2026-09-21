package sessionruntime

import (
	"context"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/gateway"
)

func TestApprovedDeadlineSurvivesRuntimeCreationAndRetry(t *testing.T) {
	for _, sample := range []struct {
		name string
		make func(*testing.T) gateway.ApprovedSessionClient
	}{
		{"kubernetes", func(t *testing.T) gateway.ApprovedSessionClient { c, _ := newRuntime(t, true); return c }},
		{"host", func(t *testing.T) gateway.ApprovedSessionClient { c, _ := newHostTestClient(t); return c }},
	} {
		t.Run(sample.name, func(t *testing.T) {
			client := sample.make(t)
			ctx := context.Background()
			request := requestFor(sessionID)
			deadline := time.Now().UTC().Add(5 * time.Minute)
			request.ExpiresAt = &deadline
			first, err := client.CreateApprovedSession(ctx, gatewayID, request, "db.internal")
			if err != nil || !first.ExpiresAt.Equal(deadline) || first.ExpiresAt.Sub(first.StartedAt) >= time.Duration(request.TTLSeconds)*time.Second {
				t.Fatalf("queued time was added back: %+v %v", first, err)
			}
			again, err := client.CreateApprovedSession(ctx, gatewayID, request, "db.internal")
			if err != nil || !again.ExpiresAt.Equal(deadline) {
				t.Fatalf("retry moved the deadline: %+v %v", again, err)
			}
			replacement := deadline.Add(time.Minute)
			request.ExpiresAt = &replacement
			if _, err := client.CreateApprovedSession(ctx, gatewayID, request, "db.internal"); err == nil {
				t.Fatal("retry with a different deadline accepted")
			}
			request = requestFor("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2")
			past := time.Now().Add(-time.Minute)
			request.ExpiresAt = &past
			if _, err := client.CreateApprovedSession(ctx, gatewayID, request, "db.internal"); err == nil {
				t.Fatal("expired grant started")
			}
			request = requestFor("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3")
			immediateDeadline := time.Now().UTC().Add(time.Duration(request.TTLSeconds) * time.Second)
			request.ExpiresAt = &immediateDeadline
			immediate, err := client.CreateApprovedSession(ctx, gatewayID, request, "db.internal")
			if err != nil || !immediate.ExpiresAt.Equal(immediateDeadline) {
				t.Fatalf("immediate approval with fractional seconds rejected: %+v %v", immediate, err)
			}
		})
	}
}
