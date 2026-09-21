package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/publicurl"
)

type Notifier interface {
	NotifyApproval(ctx context.Context, request domain.AccessRequest, approvals []domain.Approval) error
	NotifyRequestResult(ctx context.Context, request domain.AccessRequest) error
	NotifySessionReady(ctx context.Context, request domain.AccessRequest, session domain.Session) error
	NotifySessionClosed(ctx context.Context, request domain.AccessRequest, session domain.Session) error
}

// OpenIDResolver bridges platform UUIDs to Feishu open_ids without making the
// notification package depend on the repository layer.
type OpenIDResolver func(context.Context, string) (string, error)

type NotifierConfig struct {
	WebApprovalOnly bool
	AppID           string
	AppSecret       string
	APIBaseURL      string
	PublicURL       string
	HTTPClient      *http.Client
	ResolveOpenID   OpenIDResolver
}

// HTTPNotifier sends best-effort Feishu IM notifications. It deliberately
// never sends target addresses, credentials, or session tokens.
type HTTPNotifier struct {
	webApprovalOnly bool
	appID           string
	appSecret       string
	baseURL         string
	publicURL       string
	client          *http.Client
	resolveOpenID   OpenIDResolver

	tokenMu      sync.Mutex
	tenantToken  string
	tokenExpires time.Time
}

func NewHTTPNotifier(config NotifierConfig) (*HTTPNotifier, error) {
	if strings.TrimSpace(config.AppID) == "" || strings.TrimSpace(config.AppSecret) == "" {
		return nil, fmt.Errorf("Feishu notifier app credentials are required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(config.APIBaseURL), "/")
	if baseURL == "" {
		baseURL = "https://open.feishu.cn"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("Feishu notifier API base URL is invalid")
	}
	if config.ResolveOpenID == nil {
		return nil, fmt.Errorf("Feishu notifier user resolver is required")
	}
	platformURL := ""
	if config.PublicURL != "" {
		origin, err := publicurl.Parse(config.PublicURL)
		if err != nil {
			return nil, err
		}
		platformURL = origin.String()
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: otelhttp.NewTransport(http.DefaultTransport),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &HTTPNotifier{appID: config.AppID, appSecret: config.AppSecret, baseURL: baseURL, publicURL: platformURL, client: client, resolveOpenID: config.ResolveOpenID, webApprovalOnly: config.WebApprovalOnly}, nil
}

func (n *HTTPNotifier) NotifyApproval(ctx context.Context, request domain.AccessRequest, approvals []domain.Approval) error {
	if len(approvals) == 0 {
		return fmt.Errorf("notify approval: no approvers")
	}
	for _, approval := range approvals {
		if n.webApprovalOnly {
			priority := ""
			ticket := ""
			if request.Emergency {
				priority = "【紧急】"
			}
			if request.TicketNo != nil && strings.TrimSpace(*request.TicketNo) != "" {
				ticket = "\n工单: " + boundedText(*request.TicketNo, 128)
			}
			if err := n.sendText(ctx, approval.ApproverID, fmt.Sprintf("%s生产资产访问申请待审批\n申请单: %s%s\n请打开访问平台的审批待办处理。%s", priority, request.ID, ticket, n.platformLink("/approvals"))); err != nil {
				return fmt.Errorf("notify approver %s: %w", approval.ApproverID, err)
			}
			continue
		}
		content, err := approvalCard(request, approval, n.platformLink("/approvals"))
		if err != nil {
			return fmt.Errorf("build approval card: %w", err)
		}
		if err := n.sendMessage(ctx, approval.ApproverID, "interactive", content); err != nil {
			return fmt.Errorf("notify approver %s: %w", approval.ApproverID, err)
		}
	}
	return nil
}

func (n *HTTPNotifier) NotifyRequestResult(ctx context.Context, request domain.AccessRequest) error {
	content := fmt.Sprintf("生产资产访问申请状态更新\n申请单: %s\n状态: %s", request.ID, request.Status)
	content += n.platformLink("/requests/" + url.PathEscape(request.ID))
	return n.sendText(ctx, request.ApplicantID, content)
}

func (n *HTTPNotifier) NotifySessionReady(ctx context.Context, request domain.AccessRequest, session domain.Session) error {
	port := 0
	if session.ExternalPort != nil {
		port = *session.ExternalPort
	}
	content := fmt.Sprintf("生产资产临时会话已就绪\n申请单: %s\n会话: %s\n状态: %s\n网关端口: %d\n到期时间: %s\n请打开访问平台查看网关地址。", request.ID, session.ID, session.Status, port, sessionExpiryText(session.ExpiresAt))
	content += n.platformLink("/sessions/" + url.PathEscape(session.ID))
	return n.sendText(ctx, request.ApplicantID, content)
}

func (n *HTTPNotifier) NotifySessionClosed(ctx context.Context, request domain.AccessRequest, session domain.Session) error {
	content := fmt.Sprintf("生产资产临时会话已关闭\n申请单: %s\n会话: %s\n状态: %s", request.ID, session.ID, session.Status)
	content += n.platformLink("/sessions/" + url.PathEscape(session.ID))
	return n.sendText(ctx, request.ApplicantID, content)
}

func (n *HTTPNotifier) sendText(ctx context.Context, internalUserID, content string) error {
	return n.sendMessage(ctx, internalUserID, "text", mustJSON(map[string]string{"text": boundedText(content, 4000)}))
}

func (n *HTTPNotifier) sendMessage(ctx context.Context, internalUserID, messageType, content string) error {
	openID, err := n.resolveOpenID(ctx, internalUserID)
	if err != nil {
		return fmt.Errorf("resolve Feishu recipient: %w", err)
	}
	openID = strings.TrimSpace(openID)
	if openID == "" {
		return nil
	}
	tenantToken, err := n.tenantAccessToken(ctx)
	if err != nil {
		return err
	}
	payload := map[string]string{
		"receive_id": openID,
		"msg_type":   messageType,
		"content":    content,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Feishu message: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.baseURL+"/open-apis/im/v1/messages?receive_id_type=open_id", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build Feishu message request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+tenantToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return fmt.Errorf("send Feishu message: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Feishu message endpoint returned %s", response.Status)
	}
	var result apiResponse
	if err := decodeJSONResponse(response.Body, &result); err != nil {
		return fmt.Errorf("decode Feishu message response: %w", err)
	}
	if result.Code != 0 {
		return fmt.Errorf("Feishu message endpoint rejected request: code=%d message=%s", result.Code, result.Message)
	}
	return nil
}

func (n *HTTPNotifier) platformLink(path string) string {
	if n.publicURL == "" {
		return ""
	}
	return "\n" + n.publicURL + path
}

func approvalCard(request domain.AccessRequest, approval domain.Approval, platformLink string) (string, error) {
	sourceIP := "-"
	if request.SourceIP != nil {
		sourceIP = *request.SourceIP
	}
	targetAccount := "-"
	if request.TargetAccount != nil {
		targetAccount = *request.TargetAccount
	}
	ticket := ""
	if request.TicketNo != nil && strings.TrimSpace(*request.TicketNo) != "" {
		ticket = "\n**工单**: " + boundedText(*request.TicketNo, 128)
	}
	title := "生产资产临时访问审批"
	template := "orange"
	if request.Emergency {
		title = "【紧急】生产资产临时访问审批"
		template = "red"
	}
	card := map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"template": template,
			"title":    map[string]string{"tag": "plain_text", "content": title},
		},
		"elements": []any{
			map[string]any{
				"tag": "div",
				"text": map[string]string{
					"tag": "lark_md",
					"content": fmt.Sprintf("**申请单**: %s\n**申请人**: %s\n**资产**: %s\n**端口**: %d\n**来源 IP**: %s\n**目标账号**: %s\n**时长**: %d 秒（审批通过后开始计时）%s\n**原因**: %s",
						request.ID, request.ApplicantID, request.AssetID, request.TargetPort, sourceIP, boundedText(targetAccount, 128), request.TTLSeconds, ticket, boundedText(request.Reason, 1000)) + platformLink,
				},
			},
			map[string]any{
				"tag": "action",
				"actions": []any{
					map[string]any{
						"tag": "button", "type": "primary",
						"text":  map[string]string{"tag": "plain_text", "content": "通过"},
						"value": map[string]string{"approval_id": approval.ID, "decision": string(domain.ApprovalApproved)},
					},
					map[string]any{
						"tag": "button", "type": "danger",
						"text":  map[string]string{"tag": "plain_text", "content": "拒绝"},
						"value": map[string]string{"approval_id": approval.ID, "decision": string(domain.ApprovalRejected)},
					},
				},
			},
		},
	}
	encoded, err := json.Marshal(card)
	if err != nil {
		return "", fmt.Errorf("encode card: %w", err)
	}
	return string(encoded), nil
}

func sessionExpiryText(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func (n *HTTPNotifier) tenantAccessToken(ctx context.Context) (string, error) {
	n.tokenMu.Lock()
	if n.tenantToken != "" && time.Now().Add(30*time.Second).Before(n.tokenExpires) {
		token := n.tenantToken
		n.tokenMu.Unlock()
		return token, nil
	}
	n.tokenMu.Unlock()

	payload, err := json.Marshal(map[string]string{"app_id": n.appID, "app_secret": n.appSecret})
	if err != nil {
		return "", fmt.Errorf("encode Feishu tenant token request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, n.baseURL+"/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build Feishu tenant token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request Feishu tenant token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Feishu tenant token endpoint returned %s", response.Status)
	}
	var result tenantTokenResponse
	if err := decodeJSONResponse(response.Body, &result); err != nil {
		return "", fmt.Errorf("decode Feishu tenant token response: %w", err)
	}
	if result.Code != 0 || result.TenantAccessToken == "" {
		return "", fmt.Errorf("Feishu tenant token endpoint rejected request: code=%d message=%s", result.Code, result.Message)
	}
	expiresIn := time.Duration(result.Expire) * time.Second
	if expiresIn <= 0 {
		expiresIn = 2 * time.Hour
	}
	n.tokenMu.Lock()
	n.tenantToken = result.TenantAccessToken
	n.tokenExpires = time.Now().Add(expiresIn)
	n.tokenMu.Unlock()
	return result.TenantAccessToken, nil
}

type apiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

type tenantTokenResponse struct {
	Code              int    `json:"code"`
	Message           string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
	Expire            int    `json:"expire"`
}

func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max < 1 {
		return ""
	}
	runes := []rune(value)
	if len(runes) > max {
		return string(runes[:max])
	}
	return value
}

type NoopNotifier struct{}

func (NoopNotifier) NotifyApproval(context.Context, domain.AccessRequest, []domain.Approval) error {
	return nil
}

func (NoopNotifier) NotifyRequestResult(context.Context, domain.AccessRequest) error {
	return nil
}

func (NoopNotifier) NotifySessionReady(context.Context, domain.AccessRequest, domain.Session) error {
	return nil
}

func (NoopNotifier) NotifySessionClosed(context.Context, domain.AccessRequest, domain.Session) error {
	return nil
}

type UnavailableNotifier struct{}

func (UnavailableNotifier) NotifyApproval(context.Context, domain.AccessRequest, []domain.Approval) error {
	return fmt.Errorf("feishu notifier is not configured")
}

func (UnavailableNotifier) NotifyRequestResult(context.Context, domain.AccessRequest) error {
	return fmt.Errorf("feishu notifier is not configured")
}

func (UnavailableNotifier) NotifySessionReady(context.Context, domain.AccessRequest, domain.Session) error {
	return fmt.Errorf("feishu notifier is not configured")
}

func (UnavailableNotifier) NotifySessionClosed(context.Context, domain.AccessRequest, domain.Session) error {
	return fmt.Errorf("feishu notifier is not configured")
}
