package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/service"
)

func (s *Server) streamEvents(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	if origin := request.Request.Header.Get("Origin"); origin != "" && !s.sameRequestOrigin(request.Request, origin) {
		s.writeError(response, service.ErrForbidden)
		return
	}
	if s.Realtime == nil {
		response.Header().Set("Retry-After", "3")
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	events, unsubscribe, available := s.Realtime.Subscribe(userID)
	if !available {
		response.Header().Set("Retry-After", "3")
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer unsubscribe()
	// Subscribe first, then recheck identity and active status. A revocation
	// between the route filter and subscription must not be missed.
	if _, valid := s.currentUser(request, response); !valid {
		return
	}
	if err := s.requireActive(request.Request.Context(), userID); err != nil {
		s.writeError(response, err)
		return
	}
	permissions := map[string]bool{}
	for _, permission := range []authz.Permission{authz.PermissionAuditRead, authz.PermissionCatalogManage, authz.PermissionSessionOverride} {
		err := s.Service.Authorize(request.Request.Context(), userID, permission)
		if err != nil && !errors.Is(err, service.ErrForbidden) {
			s.writeError(response, err)
			return
		}
		permissions[string(permission)] = err == nil
	}

	var expired <-chan time.Time
	if cookie, err := request.Request.Cookie(s.SessionCookieName); err == nil && s.SessionSigner != nil {
		deadline, valid := s.SessionSigner.ExpiresAt(cookie.Value, time.Now())
		if !valid {
			s.writeError(response, errUnauthenticated)
			return
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	w := response.ResponseWriter
	controller := http.NewResponseController(w)
	// Override the normal 15-second HTTP write deadline only for this stream.
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.writeError(response, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(event string, data string) bool {
		if err := controller.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		if err := controller.Flush(); err != nil {
			return false
		}
		// Bound the write, not the idle wait for the next event. HTTP/2 resets
		// the stream when a write deadline expires, even with no pending write.
		err := controller.SetWriteDeadline(time.Time{})
		return err == nil || errors.Is(err, http.ErrNotSupported)
	}
	// Every connection loads a fresh snapshot. Notifications missed during an
	// outage (or before subscribing) never require a durable replay log.
	if !write("ready", "{}") {
		return
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Request.Context().Done():
			return
		case <-expired:
			write("auth-expired", "{}")
			return
		case <-heartbeat.C:
			// A keepalive carries no invalidation and never reads business data.
			if !write("heartbeat", "{}") {
				return
			}
		case change, open := <-events:
			if !open {
				return
			}
			if change.Permission != "" && !permissions[change.Permission] {
				continue
			}
			if change.Topic == "identity" || change.Topic == "settings" {
				// Reconnect through the normal active-user, cookie-version and
				// MFA checks, then reload permissions before delivering changes.
				write("reset", "{}")
				return
			}
			data, _ := json.Marshal(map[string]string{"topic": change.Topic})
			if !write("change", string(data)) {
				return
			}
		}
	}
}
