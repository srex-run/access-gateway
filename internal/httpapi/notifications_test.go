package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
)

type notificationBackend struct {
	*backendStub
	userID, notificationID         string
	listCalls, readCalls, allCalls int
}

func (b *notificationBackend) ListNotifications(_ context.Context, userID string, _, _ int) (domain.NotificationPage, error) {
	b.userID, b.listCalls = userID, b.listCalls+1
	return domain.NotificationPage{Items: []domain.Notification{}, UnreadCount: 2}, nil
}
func (b *notificationBackend) MarkNotificationRead(_ context.Context, userID, notificationID string) error {
	b.userID, b.notificationID, b.readCalls = userID, notificationID, b.readCalls+1
	return nil
}
func (b *notificationBackend) MarkAllNotificationsRead(_ context.Context, userID string) error {
	b.userID, b.allCalls = userID, b.allCalls+1
	return nil
}

func TestNotificationsUseAuthenticatedRecipientAndRequireSameOrigin(t *testing.T) {
	accounts := &accountStub{}
	server := newAuthServer(t, accounts, &attemptStub{true}, &loginStateMemory{values: map[string]time.Time{}}, &redirectStub{})
	backend := &notificationBackend{backendStub: &backendStub{}}
	server.Service = backend
	for _, path := range []string{"/notifications", "/notifications/read", "/notifications/22222222-2222-4222-8222-222222222222/read"} {
		method := http.MethodPost
		if path == "/notifications" {
			method = http.MethodGet
		}
		r := httptest.NewRequest(method, "http://console.test/api/v1"+path, nil)
		w := httptest.NewRecorder()
		server.Container().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s: %d", path, w.Code)
		}
	}
	cookie := &http.Cookie{Name: server.SessionCookieName, Value: server.SessionSigner.SignVersioned(testUserID, 3, time.Now().Add(time.Hour))}
	r := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/notifications?user_id=another-user", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	server.Container().ServeHTTP(w, r)
	if w.Code != http.StatusOK || backend.userID != testUserID || backend.listCalls != 1 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("recipient came from request parameters: %d %s", w.Code, backend.userID)
	}
	for _, path := range []string{"/notifications/read", "/notifications/22222222-2222-4222-8222-222222222222/read"} {
		for _, origin := range []string{"https://other.test", "http://console.test"} {
			r := httptest.NewRequest(http.MethodPost, "http://console.test/api/v1"+path, nil)
			r.AddCookie(cookie)
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			server.Container().ServeHTTP(w, r)
			want := http.StatusNoContent
			if origin != "http://console.test" {
				want = http.StatusForbidden
			}
			if w.Code != want {
				t.Fatalf("read %s origin %s: %d", path, origin, w.Code)
			}
		}
	}
	if backend.readCalls != 1 || backend.allCalls != 1 || backend.userID != testUserID {
		t.Fatalf("unprotected read mutation: %+v", backend)
	}
}
