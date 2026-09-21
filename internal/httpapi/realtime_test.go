package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/realtime"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
)

type realtimeBackend struct {
	*backendStub
	allowed map[authz.Permission]bool
}

func (b *realtimeBackend) Authorize(_ context.Context, _ string, permission authz.Permission) error {
	if b.allowed[permission] {
		return nil
	}
	return service.ErrForbidden
}

type eventRecorder struct {
	*httptest.ResponseRecorder
	frames    chan string
	deadlines []time.Time
}

func (w *eventRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.frames <- w.Body.String()
	w.Body.Reset()
}

func (w *eventRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func streamFrame(t *testing.T, w *eventRecorder) string {
	t.Helper()
	select {
	case frame := <-w.frames:
		return frame
	case <-time.After(3 * time.Second):
		t.Fatal("event stream did not flush")
		return ""
	}
}

func runEventStream(t *testing.T, server *Server, request *http.Request) (*eventRecorder, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(ctx)
	request.Header.Set("Accept", "text/event-stream")
	w := &eventRecorder{ResponseRecorder: httptest.NewRecorder(), frames: make(chan string, 16)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		otelhttp.NewHandler(server.Container(), "events.test").ServeHTTP(w, request)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("event stream leaked after cancellation")
		}
	}
	t.Cleanup(stop)
	return w, stop
}

func TestRealtimeStreamScopesEventsAndOverridesWriteDeadline(t *testing.T) {
	for _, auditReader := range []bool{false, true} {
		t.Run(map[bool]string{false: "personal", true: "auditor"}[auditReader], func(t *testing.T) {
			backend := &realtimeBackend{backendStub: &backendStub{}, allowed: map[authz.Permission]bool{authz.PermissionAuditRead: auditReader}}
			server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true; s.Realtime = realtime.NewHub() })
			r := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/events?user_id=someone-else", nil)
			r.Header.Set("X-User-ID", testUserID)
			w, stop := runEventStream(t, server, r)
			if frame := streamFrame(t, w); frame != "event: ready\ndata: {}\n\n" {
				t.Fatalf("missing initial snapshot signal: %s", frame)
			}
			server.Realtime.Publish(realtime.Change{Topic: "notifications", UserID: "someone-else"})
			server.Realtime.Publish(realtime.Change{Topic: "cloud", Permission: "catalog:manage"})
			server.Realtime.Publish(realtime.Change{Topic: "audit", Permission: "audit:read"})
			server.Realtime.Publish(realtime.Change{Topic: "notifications", UserID: testUserID})
			if auditReader {
				if got := streamFrame(t, w); got != "event: change\ndata: {\"topic\":\"audit\"}\n\n" {
					t.Fatalf("auditor event: %s", got)
				}
			}
			if got := streamFrame(t, w); got != "event: change\ndata: {\"topic\":\"notifications\"}\n\n" {
				t.Fatalf("recipient/permission isolation failed: %s", got)
			}
			server.Realtime.Publish(realtime.Change{Topic: "identity", UserID: testUserID})
			if got := streamFrame(t, w); got != "event: reset\ndata: {}\n\n" {
				t.Fatalf("permission change did not reconnect: %s", got)
			}
			stop()
			if len(w.deadlines) < 2 || !w.deadlines[0].IsZero() || w.deadlines[1].IsZero() {
				t.Fatal("production middleware prevented streaming deadline override")
			}
			if w.Header().Get("X-Accel-Buffering") != "no" || !strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
				t.Fatal("stream headers missing")
			}
		})
	}
}

func TestRealtimeStreamStaysOpenWhileIdleHTTP2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := testServer(t, &backendStub{}, func(s *Server) { s.AllowDevAuth = true; s.Realtime = realtime.NewHub() })
		clientSocket, serverSocket := net.Pipe()
		defer clientSocket.Close()
		defer serverSocket.Close()
		go (&http2.Server{}).ServeConn(serverSocket, &http2.ServeConnOpts{
			BaseConfig: &http.Server{WriteTimeout: 15 * time.Second},
			Handler:    otelhttp.NewHandler(server.Container(), "events.test"),
		})
		connection, err := (&http2.Transport{}).NewClientConn(clientSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://console.test/api/v1/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", "text/event-stream")
		request.Header.Set("X-User-ID", testUserID)
		response, err := connection.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("event stream status: %d", response.StatusCode)
		}
		frame := func(want string) {
			t.Helper()
			data := make([]byte, len(want))
			if _, err := io.ReadFull(response.Body, data); err != nil {
				t.Fatalf("idle event stream disconnected: %v", err)
			}
			if string(data) != want {
				t.Fatalf("event frame %q, want %q", data, want)
			}
		}
		frame("event: ready\ndata: {}\n\n")
		synctest.Wait()
		// Virtual time crosses the per-write deadline without wall-clock waits.
		time.Sleep(11 * time.Second)
		server.Realtime.Publish(realtime.Change{Topic: "notifications", UserID: testUserID})
		frame("event: change\ndata: {\"topic\":\"notifications\"}\n\n")
		frame("event: heartbeat\ndata: {}\n\n")
		synctest.Wait()
		time.Sleep(11 * time.Second)
		server.Realtime.Publish(realtime.Change{Topic: "sessions", UserID: testUserID})
		frame("event: change\ndata: {\"topic\":\"sessions\"}\n\n")
	})
}

func TestRealtimeStreamRejectsAnonymousCrossOriginAndUnavailable(t *testing.T) {
	server := testServer(t, &backendStub{}, func(s *Server) { s.AllowDevAuth = true; s.Realtime = realtime.NewHub() })
	for _, tc := range []struct {
		user, origin string
		unavailable  bool
		status       int
	}{
		{"", "", false, http.StatusUnauthorized},
		{testUserID, "https://other.test", false, http.StatusForbidden},
		{testUserID, "http://console.test", true, http.StatusServiceUnavailable},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/events", nil)
		r.Header.Set("Accept", "text/event-stream")
		r.Header.Set("X-User-ID", tc.user)
		r.Header.Set("Origin", tc.origin)
		if tc.unavailable {
			server.Realtime = nil
		}
		w := httptest.NewRecorder()
		server.Container().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d: %s", w.Code, tc.status, w.Body.String())
		}
	}
}

func TestRealtimeStreamEndsWhenSignedSessionExpires(t *testing.T) {
	signer, err := security.NewSessionSigner(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(t, &backendStub{}, func(s *Server) { s.SessionSigner = signer; s.Realtime = realtime.NewHub() })
	r := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/events", nil)
	r.AddCookie(&http.Cookie{Name: server.SessionCookieName, Value: signer.SignVersioned(testUserID, 0, time.Now().Add(2*time.Second))})
	w, stop := runEventStream(t, server, r)
	streamFrame(t, w)
	if got := streamFrame(t, w); got != "event: auth-expired\ndata: {}\n\n" {
		t.Fatalf("expired login was not disconnected: %s", got)
	}
	stop()
}

type realtimeRevokedBackend struct {
	*backendStub
	checks int
}

func (b *realtimeRevokedBackend) CheckActiveUser(context.Context, string) error {
	b.checks++
	if b.checks > 1 {
		return service.ErrForbidden
	}
	return nil
}

func TestRealtimeStreamRechecksUserAfterSubscribing(t *testing.T) {
	backend := &realtimeRevokedBackend{backendStub: &backendStub{}}
	server := testServer(t, backend, func(s *Server) { s.AllowDevAuth = true; s.Realtime = realtime.NewHub() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "http://console.test/api/v1/events", nil).WithContext(ctx)
	r.Header.Set("X-User-ID", testUserID)
	r.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()
	server.Container().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || backend.checks != 2 {
		t.Fatalf("revoked user opened a stream: status=%d checks=%d", w.Code, backend.checks)
	}
}
