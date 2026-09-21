package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/terminal"
)

type terminalProvider interface {
	AuthorizeTerminal(context.Context, string, string) (time.Time, error)
	OpenTerminal(context.Context, string, string, string) (*websocket.Conn, error)
}

func (s *Server) accessOptions(request *restful.Request, response *restful.Response) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	provider, ok := s.Service.(interface {
		GetAccessOptions(context.Context, string) (service.AccessOptions, error)
	})
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	value, err := provider.GetAccessOptions(request.Request.Context(), actor)
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) terminalDemoDefaults(request *restful.Request, response *restful.Response) {
	actor, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	var input struct{}
	if err := decodeJSONBody(request.Request, &input, false); err != nil {
		s.writeError(response, service.ErrValidation)
		return
	}
	provider, ok := s.Service.(interface {
		GetTerminalDemoDefaults(context.Context, string, string) (service.TerminalDemoDefaults, error)
	})
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	value, err := provider.GetTerminalDemoDefaults(request.Request.Context(), actor, request.PathParameter("session_id"))
	if err != nil {
		s.writeError(response, err)
		return
	}
	_ = response.WriteEntity(value)
}

func (s *Server) authorizeWebTerminal(request *restful.Request, response *restful.Response) (terminalProvider, string, time.Time, bool) {
	// WebSocket GET is not covered by the ordinary write-method CSRF filter.
	if !s.sameRequestOrigin(request.Request, request.HeaderParameter("Origin")) {
		s.logTerminalSetupFailure(request.PathParameter("session_id"), "origin_validation")
		_ = response.WriteHeaderAndEntity(http.StatusForbidden, errorResponse{Error: "request origin does not match the configured public URL", Code: "origin_mismatch"})
		return nil, "", time.Time{}, false
	}
	// Credentials/terminal input require TLS, except same-host development.
	peer := net.ParseIP(transportAddress(request.Request))
	if !s.secureRequest(request.Request) && (!loopbackAuthority(request.Request.Host) || peer == nil || !peer.IsLoopback()) {
		s.logTerminalSetupFailure(request.PathParameter("session_id"), "tls_required")
		s.writeError(response, service.ErrForbidden)
		return nil, "", time.Time{}, false
	}
	actor, ok := s.currentUser(request, response)
	if !ok {
		return nil, "", time.Time{}, false
	}
	provider, ok := s.Service.(terminalProvider)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return nil, "", time.Time{}, false
	}
	sessionID := request.PathParameter("session_id")
	expires, err := provider.AuthorizeTerminal(request.Request.Context(), actor, sessionID)
	if err != nil {
		s.logTerminalSetupFailure(sessionID, "session_authorization")
		if errors.Is(err, service.ErrForbidden) {
			_ = response.WriteHeaderAndEntity(http.StatusForbidden, errorResponse{Error: "session is not available to this user", Code: "terminal_unavailable"})
		} else {
			s.writeError(response, err)
		}
		return nil, "", time.Time{}, false
	}
	return provider, actor, expires, true
}

// Ordinary HTTP exposes authentication/session failures that browser WebSocket
// APIs conceal. Both paths perform the same checks; this is not a grant.
func (s *Server) webTerminalPreflight(request *restful.Request, response *restful.Response) {
	_, _, expires, ok := s.authorizeWebTerminal(request, response)
	if !ok {
		return
	}
	if s.Transport == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	_ = response.WriteEntity(map[string]any{"expires_at": expires})
}

func (s *Server) webTerminal(request *restful.Request, response *restful.Response) {
	provider, actor, expires, ok := s.authorizeWebTerminal(request, response)
	if !ok {
		return
	}
	sessionID := request.PathParameter("session_id")
	ctx, cancel := context.WithDeadline(request.Request.Context(), expires)
	defer cancel()
	if request.Request.URL.RawQuery != "" || request.Request.URL.RawPath != "" {
		s.writeError(response, service.ErrValidation)
		return
	}
	binding, ok := s.transportBinding(request, response, http.MethodGet, request.Request.URL.Path)
	if !ok || !s.allowTransport(request, response, "open") {
		return
	}
	if s.Transport == nil {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	upgradeStatus := 0
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 5 * time.Second,
		CheckOrigin:      func(r *http.Request) bool { return s.sameRequestOrigin(r, r.Header.Get("Origin")) },
		Error: func(w http.ResponseWriter, _ *http.Request, status int, _ error) {
			upgradeStatus = status
			w.Header().Set("Sec-WebSocket-Version", "13")
			http.Error(w, http.StatusText(status), status)
		},
	}
	browser, err := upgrader.Upgrade(response.ResponseWriter, request.Request, nil)
	if err != nil {
		s.logTerminalUpgradeFailure(request.Request, response.ResponseWriter, sessionID, upgradeStatus, err)
		return
	}
	defer browser.Close()
	stop := context.AfterFunc(ctx, func() { _ = browser.Close() })
	defer stop()
	// The base64 envelope is larger than a terminal message. Restore the
	// ordinary frame bound immediately after the one-time login handshake.
	browser.SetReadLimit(2 * terminal.MaxMessage)
	_ = browser.SetReadDeadline(time.Now().Add(15 * time.Second))
	kind, encrypted, err := browser.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		s.logTerminalSetupFailure(sessionID, "encrypted_start_read")
		return
	}
	plaintext, err := s.openTerminalStart(ctx, binding, encrypted)
	clear(encrypted)
	if err != nil {
		s.logTerminalSetupFailure(sessionID, "encrypted_start_validation")
		_ = browser.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = browser.WriteJSON(terminal.Message{Type: "error", Data: "终端凭据必须加密且仅能使用一次，请重新连接。"})
		return
	}
	defer clear(plaintext)
	upstream, err := provider.OpenTerminal(ctx, actor, sessionID, transportAddress(request.Request))
	if err != nil {
		s.logTerminalSetupFailure(sessionID, "worker_connect")
		_ = browser.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = browser.WriteJSON(terminal.Message{Type: "error", Data: "无法启动会话终端，请检查会话状态后重试。"})
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	// OpenTerminal uses the Agent's mutually authenticated WSS listener.
	_ = upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = upstream.WriteMessage(websocket.TextMessage, plaintext)
	clear(plaintext)
	if err != nil {
		s.logTerminalSetupFailure(sessionID, "worker_start_write")
		return
	}
	terminal.KeepAlive(ctx, browser)
	terminal.KeepAlive(ctx, upstream)
	// Recheck account/session revocation while the upgraded connection lives.
	// Worker expiry/stop independently closes all active terminal connections.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, done := context.WithTimeout(ctx, 4*time.Second)
				valid := s.terminalIdentityValid(check, request.Request, actor)
				if valid {
					_, err := provider.AuthorizeTerminal(check, actor, sessionID)
					valid = err == nil
				}
				done()
				if !valid {
					cancel()
					return
				}
			}
		}
	}()
	done := make(chan struct{}, 2)
	copyMessages := func(dst, src *websocket.Conn) {
		defer func() { done <- struct{}{} }()
		for {
			kind, data, err := src.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
					_ = dst.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
				}
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err = dst.WriteMessage(kind, data)
			clear(data)
			if err != nil {
				return
			}
		}
	}
	go copyMessages(upstream, browser)
	go copyMessages(browser, upstream)
	<-done
	cancel()
	_ = browser.Close()
	_ = upstream.Close()
	<-done
}

func (s *Server) logTerminalSetupFailure(sessionID, stage string) {
	// Never log envelopes, credentials, cookies, headers or raw transport errors.
	s.Logger.Warn().Str("session_id", sessionID).Str("stage", stage).Msg("web terminal setup failed")
}

func (s *Server) logTerminalUpgradeFailure(request *http.Request, writer http.ResponseWriter, sessionID string, status int, err error) {
	// Upgrade runs before reading any terminal credentials. Its error identifies
	// the failed handshake check or socket operation. Log only selected HTTP
	// metadata; never dump headers, the body, cookies or WebSocket key/protocol.
	bounded := func(value string) string {
		const maximum = 512
		if len(value) > maximum {
			return value[:maximum] + "..."
		}
		return value
	}
	s.Logger.Warn().Str("session_id", sessionID).Str("stage", "websocket_upgrade").
		Str("error", bounded(err.Error())).Int("http_status", status).
		Str("http_method", request.Method).Str("http_proto", request.Proto).
		Str("host", bounded(request.Host)).Str("origin", bounded(request.Header.Get("Origin"))).
		Str("connection", bounded(strings.Join(request.Header.Values("Connection"), ", "))).
		Str("upgrade", bounded(strings.Join(request.Header.Values("Upgrade"), ", "))).
		Str("websocket_version", bounded(strings.Join(request.Header.Values("Sec-WebSocket-Version"), ", "))).
		Bool("websocket_key_present", request.Header.Get("Sec-WebSocket-Key") != "").
		Str("forwarded_proto", bounded(request.Header.Get("X-Forwarded-Proto"))).
		Str("accept_encoding", bounded(request.Header.Get("Accept-Encoding"))).
		Str("response_writer", fmt.Sprintf("%T", writer)).
		Msg("web terminal WebSocket upgrade failed")
}

func (s *Server) openTerminalStart(ctx context.Context, binding securetransport.Binding, data []byte) ([]byte, error) {
	var envelope securetransport.Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || envelope.ChallengeID == "" || envelope.Envelope.Version != 1 || s.Transport == nil {
		return nil, securetransport.ErrInvalid
	}
	plaintext, reply, err := s.Transport.Open(ctx, binding, envelope)
	if err != nil {
		return nil, err
	}
	defer reply.Clear()
	var start terminal.Message
	decoder = json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if len(plaintext) > terminal.MaxMessage || decoder.Decode(&start) != nil || decoder.Decode(new(any)) != io.EOF || !start.ValidStart() {
		clear(plaintext)
		return nil, securetransport.ErrInvalid
	}
	return plaintext, nil
}

func loopbackAuthority(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]" || strings.HasPrefix(host, "localhost:") || strings.HasPrefix(host, "127.0.0.1:") || strings.HasPrefix(host, "[::1]:")
}

func (s *Server) terminalIdentityValid(ctx context.Context, request *http.Request, actor string) bool {
	if s.AllowDevAuth && strings.TrimSpace(request.Header.Get("X-User-ID")) == actor {
		return true
	}
	if s.SessionSigner == nil {
		return false
	}
	cookie, err := request.Cookie(s.SessionCookieName)
	if err != nil {
		return false
	}
	user, version, valid := s.SessionSigner.VerifyVersioned(cookie.Value, time.Now())
	if !valid || user != actor {
		return false
	}
	if s.Authentication != nil && s.Authentication.ValidateBrowserSession(ctx, user, version) != nil {
		return false
	}
	return s.MFA == nil || s.MFA.ValidateMFASession(ctx, user, s.SessionSigner.MFAVerified(cookie.Value, time.Now())) == nil
}
