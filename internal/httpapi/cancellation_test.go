package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"github.com/rs/zerolog"
)

func TestWriteErrorDistinguishesCancellationFromServerFailures(t *testing.T) {
	for _, sample := range []struct {
		name     string
		err      error
		canceled bool
	}{
		{"canceled request", context.Canceled, true},
		{"settings query", fmt.Errorf("get system settings: %w", context.Canceled), true},
		{"user query", fmt.Errorf("get user by id: %w", fmt.Errorf("scan user: %w", context.Canceled)), true},
		{"query timeout", fmt.Errorf("get system settings: %w", context.DeadlineExceeded), false},
		{"database failure", errors.New("database connection lost"), false},
		{"unrelated error text", errors.New("unexpected context canceled state"), false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var logs bytes.Buffer
			server := &Server{Logger: zerolog.New(&logs)}
			recorder := httptest.NewRecorder()
			response := restful.NewResponse(recorder)
			response.SetRequestAccepts(restful.MIME_JSON)
			server.writeError(response, sample.err)
			if sample.canceled {
				if recorder.Code != 499 || response.StatusCode() != 499 {
					t.Fatalf("cancellation recorded as %d", recorder.Code)
				}
				if recorder.Body.Len() != 0 || logs.Len() != 0 {
					t.Fatal("canceled request produced an error body or failure log")
				}
				return
			}
			if recorder.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), `"level":"error"`) || !strings.Contains(logs.String(), `"message":"request failed"`) {
				t.Fatalf("real server failure lost its status or error log: status=%d logs=%s", recorder.Code, &logs)
			}
			if strings.Contains(recorder.Body.String(), sample.err.Error()) {
				t.Fatal("internal failure detail exposed to client")
			}
		})
	}
}
