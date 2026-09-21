package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

func TestNotificationsUsePublicURLForPlatformLinks(t *testing.T) {
	var messages []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "feishu.test" {
			t.Fatal("platform origin replaced the Feishu API destination")
		}
		if strings.Contains(request.URL.Path, "tenant_access_token") {
			return jsonHTTPResponse(map[string]any{"code": 0, "tenant_access_token": "token", "expire": 7200}), nil
		}
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		messages = append(messages, body.Content)
		return jsonHTTPResponse(map[string]any{"code": 0}), nil
	})
	notifier, err := NewHTTPNotifier(NotifierConfig{AppID: "app", AppSecret: "secret", APIBaseURL: "https://feishu.test", PublicURL: "https://access.example.test:8443/", WebApprovalOnly: true,
		HTTPClient: &http.Client{Transport: transport}, ResolveOpenID: func(context.Context, string) (string, error) { return "open-id", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	request, session := domain.AccessRequest{ID: "request-id", ApplicantID: "user"}, domain.Session{ID: "session-id"}
	for _, call := range []func() error{
		func() error { return notifier.NotifyApproval(ctx, request, []domain.Approval{{ApproverID: "user"}}) },
		func() error { return notifier.NotifyRequestResult(ctx, request) },
		func() error { return notifier.NotifySessionReady(ctx, request, session) },
		func() error { return notifier.NotifySessionClosed(ctx, request, session) },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	notifier.webApprovalOnly = false
	if err := notifier.NotifyApproval(ctx, request, []domain.Approval{{ApproverID: "user"}}); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 5 {
		t.Fatalf("notification count = %d", len(messages))
	}
	for i, path := range []string{"/approvals", "/requests/request-id", "/sessions/session-id", "/sessions/session-id", "/approvals"} {
		if !strings.Contains(messages[i], "https://access.example.test:8443"+path) {
			t.Fatalf("notification %d lost its public platform link", i)
		}
	}
}
