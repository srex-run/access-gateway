package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/operationaudit"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/terminal"
)

type AccessOptions struct {
	ClientAccessEnabled   bool `json:"client_access_enabled"`
	DemoMode              bool `json:"demo_mode"`
	DemoSessionTTLSeconds int  `json:"demo_session_ttl_seconds"`
}

type TerminalDemoDefaults struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password,omitempty"`
	Database string `json:"database,omitempty"`
}

func (s *AccessService) GetTerminalDemoDefaults(ctx context.Context, actor, sessionID string) (TerminalDemoDefaults, error) {
	if _, err := s.AuthorizeTerminal(ctx, actor, sessionID); err != nil {
		return TerminalDemoDefaults{}, err
	}
	if !s.demoMode {
		return TerminalDemoDefaults{}, nil
	}
	return TerminalDemoDefaults{Enabled: true, Password: "123456", Database: "test"}, nil
}

func requestSourceIP(request domain.AccessRequest) string {
	if request.SourceIP != nil {
		return *request.SourceIP
	}
	return ""
}

func (s *AccessService) clientAccessHost(ctx context.Context) (string, error) {
	if s.systemSettings != nil {
		current, err := s.systemSettings.Current(ctx)
		if err != nil {
			return "", err
		}
		if current.ClientAccessHost != "" {
			return current.ClientAccessHost, nil
		}
	}
	return s.publicHost(), nil
}

func (s *AccessService) clientAccessEnabled(ctx context.Context) (bool, error) {
	if s.systemSettings == nil {
		return false, nil
	}
	current, err := s.systemSettings.Current(ctx)
	if err != nil {
		return false, err
	}
	return current.ClientAccessEnabled, nil
}

// Grant creation already owns a transaction. Read its public switch through
// that transaction so even a one-connection pool cannot deadlock on a snapshot
// refresh, and the grant observes the transaction's settings state.
func (s *AccessService) clientAccessEnabledIn(ctx context.Context, q repository.DBTX) (bool, error) {
	if s.systemSettings == nil {
		return false, nil
	}
	row, err := s.systemSettings.read(ctx, q)
	if err != nil || row.Revision == 0 {
		return false, err
	}
	var options AccessOptions
	if err = json.Unmarshal(row.ConfigJSON, &options); err != nil {
		return false, err
	}
	return options.ClientAccessEnabled, nil
}

func (s *AccessService) GetAccessOptions(ctx context.Context, actor string) (AccessOptions, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionRequestManage); err != nil {
		return AccessOptions{}, err
	}
	enabled, err := s.clientAccessEnabled(ctx)
	return AccessOptions{ClientAccessEnabled: enabled, DemoMode: s.demoMode, DemoSessionTTLSeconds: int(demoSessionTTL / time.Second)}, err
}

func validateWebAccess(request domain.AccessRequest, policy operationaudit.Policy) error {
	if request.SourceIP == nil && (!terminal.Supported(policy.Protocol) || policy.Profile == "") {
		return requestValidation("请先为目标端口启用操作审计并完成连接配置；站内访问支持 SSH、MySQL、PostgreSQL、Redis、MongoDB 和 HTTP 客户端")
	}
	return nil
}

func (s *AccessService) AuthorizeTerminal(ctx context.Context, actor, sessionID string) (time.Time, error) {
	if err := s.Authorize(ctx, actor, authz.PermissionSessionManage); err != nil {
		return time.Time{}, err
	}
	view, err := s.GetSession(ctx, actor, sessionID)
	if err != nil {
		return time.Time{}, err
	}
	if !view.CanWebConnect {
		return time.Time{}, ErrForbidden
	}
	return *view.Session.ExpiresAt, nil
}

func canUseWebTerminal(actor string, session domain.Session, request domain.AccessRequest, now time.Time) bool {
	return actor == request.ApplicantID && request.Status == domain.AccessRequestApproved &&
		session.Status == domain.SessionRunning && session.ExpiresAt != nil && session.ExpiresAt.After(now) &&
		session.ConnectionMode == gateway.ConnectionModeAudit && terminal.Supported(session.AuditPolicy.Protocol)
}

func (s *AccessService) OpenTerminal(ctx context.Context, actor, sessionID, sourceIP string) (*websocket.Conn, error) {
	if _, err := s.AuthorizeTerminal(ctx, actor, sessionID); err != nil {
		return nil, err
	}
	runtime, ok := s.gateway.(gateway.TerminalClient)
	if !ok {
		return nil, ErrNotConfigured
	}
	return runtime.OpenTerminal(ctx, sessionID, sourceIP)
}
