package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

func TestHTTPNotifierCachesTenantTokenAndSendsNoSessionToken(t *testing.T) {
	var tokenRequests atomic.Int32
	var messageRequests atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			tokenRequests.Add(1)
			return jsonHTTPResponse(map[string]any{"code": 0, "tenant_access_token": "tenant-token", "expire": 7200}), nil
		case "/open-apis/im/v1/messages":
			messageRequests.Add(1)
			if request.URL.Query().Get("receive_id_type") != "open_id" || request.Header.Get("Authorization") != "Bearer tenant-token" {
				t.Fatalf("message request authentication is invalid")
			}
			var body struct {
				ReceiveID string `json:"receive_id"`
				Content   string `json:"content"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode message: %v", err)
			}
			if body.ReceiveID != "ou-recipient" || strings.Contains(body.Content, "temporary-token") {
				t.Fatalf("unsafe message body: %+v", body)
			}
			return jsonHTTPResponse(map[string]any{"code": 0}), nil
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody}, nil
		}
	})

	notifier, err := NewHTTPNotifier(NotifierConfig{
		AppID: "app-id", AppSecret: "app-secret", APIBaseURL: "https://feishu.test",
		HTTPClient: &http.Client{Transport: transport},
		ResolveOpenID: func(_ context.Context, internalID string) (string, error) {
			if internalID != "user-id" {
				t.Fatalf("internal user ID = %q", internalID)
			}
			return "ou-recipient", nil
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPNotifier: %v", err)
	}
	request := domain.AccessRequest{ID: "request-id", ApplicantID: "user-id"}
	session := domain.Session{ID: "session-id", Status: domain.SessionRunning}
	if err := notifier.NotifySessionReady(context.Background(), request, session); err != nil {
		t.Fatalf("NotifySessionReady: %v", err)
	}
	if err := notifier.NotifySessionClosed(context.Background(), request, session); err != nil {
		t.Fatalf("NotifySessionClosed: %v", err)
	}
	if tokenRequests.Load() != 1 || messageRequests.Load() != 2 {
		t.Fatalf("requests: token=%d message=%d", tokenRequests.Load(), messageRequests.Load())
	}
}

func TestNotificationsSkipUnboundUsersAndOmitDisabledCallbackActions(t *testing.T) {
	var messages []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "tenant_access_token") {
			return jsonHTTPResponse(map[string]any{"code": 0, "tenant_access_token": "token", "expire": 7200}), nil
		}
		var body struct {
			Kind    string `json:"msg_type"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Kind != "text" || strings.Contains(body.Content, "callback") {
			t.Fatal("notification included a disabled approval action")
		}
		messages = append(messages, body.Content)
		return jsonHTTPResponse(map[string]any{"code": 0}), nil
	})
	notifier, err := NewHTTPNotifier(NotifierConfig{AppID: "app", AppSecret: "secret", WebApprovalOnly: true, HTTPClient: &http.Client{Transport: transport}, ResolveOpenID: func(_ context.Context, userID string) (string, error) {
		if userID == "bound" {
			return "open-id", nil
		}
		return "", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.NotifyApproval(context.Background(), domain.AccessRequest{ID: "request"}, []domain.Approval{{ApproverID: "unbound"}, {ApproverID: "bound"}}); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || !strings.Contains(messages[0], "审批待办") {
		t.Fatalf("notification messages = %v", messages)
	}
	ticket := "INC-2026-001"
	if err := notifier.NotifyApproval(context.Background(), domain.AccessRequest{ID: "urgent-request", Emergency: true, TicketNo: &ticket}, []domain.Approval{{ApproverID: "bound"}}); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || !strings.Contains(messages[1], "【紧急】") || !strings.Contains(messages[1], ticket) {
		t.Fatalf("urgent notification lost its priority or ticket: %v", messages)
	}
	if err := notifier.NotifyApproval(context.Background(), domain.AccessRequest{ID: "urgent-without-ticket", Emergency: true}, []domain.Approval{{ApproverID: "bound"}}); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 || !strings.Contains(messages[2], "【紧急】") || strings.Contains(messages[2], "工单") {
		t.Fatalf("urgent notification without a ticket is incorrect: %v", messages)
	}
}

func TestApprovalCardShowsUrgencyAndApprovalBasedDurationWithOptionalTicket(t *testing.T) {
	ticket := "INC-2026-001"
	blankTicket := "  "
	for _, test := range []struct {
		name       string
		urgent     bool
		ticketNo   *string
		wantTicket bool
	}{
		{name: "ordinary without ticket"},
		{name: "urgent without ticket", urgent: true},
		{name: "urgent with blank ticket", urgent: true, ticketNo: &blankTicket},
		{name: "ordinary with existing ticket", ticketNo: &ticket, wantTicket: true},
		{name: "urgent with existing ticket", urgent: true, ticketNo: &ticket, wantTicket: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := approvalCard(domain.AccessRequest{ID: "request", Emergency: test.urgent, TicketNo: test.ticketNo, TTLSeconds: 1800}, domain.Approval{ID: "approval"}, "")
			if err != nil {
				t.Fatal(err)
			}
			var card struct {
				Header struct {
					Template string
					Title    struct{ Content string }
				}
			}
			if err := json.Unmarshal([]byte(encoded), &card); err != nil {
				t.Fatal(err)
			}
			if (card.Header.Template == "red") != test.urgent || strings.Contains(card.Header.Title.Content, "【紧急】") != test.urgent {
				t.Fatalf("incorrect urgency display: %s", encoded)
			}
			if strings.Contains(encoded, "**工单**") != test.wantTicket || strings.Contains(encoded, ticket) != test.wantTicket {
				t.Fatalf("incorrect ticket display: %s", encoded)
			}
			if !strings.Contains(encoded, "审批通过后开始计时") || !strings.Contains(encoded, "approval_id") {
				t.Fatalf("approval context or actions missing: %s", encoded)
			}
		})
	}
}
