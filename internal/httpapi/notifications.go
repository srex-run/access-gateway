package httpapi

import (
	"context"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/service"
)

type notificationService interface {
	ListNotifications(context.Context, string, int, int) (domain.NotificationPage, error)
	MarkNotificationRead(context.Context, string, string) error
	MarkAllNotificationsRead(context.Context, string) error
}

func (s *Server) listNotifications(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	provider, ok := s.Service.(notificationService)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	limit, offset, err := parsePageQuery(request, 20, 100)
	if err != nil {
		s.writeError(response, err)
		return
	}
	page, err := provider.ListNotifications(request.Request.Context(), userID, limit, offset)
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	_ = response.WriteEntity(page)
}

func (s *Server) markNotificationRead(request *restful.Request, response *restful.Response) {
	userID, ok := s.currentUser(request, response)
	if !ok {
		return
	}
	provider, ok := s.Service.(notificationService)
	if !ok {
		s.writeError(response, service.ErrNotConfigured)
		return
	}
	var err error
	if notificationID := request.PathParameter("notification_id"); notificationID != "" {
		err = provider.MarkNotificationRead(request.Request.Context(), userID, notificationID)
	} else {
		err = provider.MarkAllNotificationsRead(request.Request.Context(), userID)
	}
	if err != nil {
		s.writeError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
