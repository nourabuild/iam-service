package app

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/services/kafka"
)

func TestOutboxHeaders(t *testing.T) {
	tests := []struct {
		name       string
		requestID  string
		fallback   string
		wantHeader string
		wantNil    bool
	}{
		{
			name:       "request ID takes precedence",
			requestID:  "request-id",
			fallback:   "user-id",
			wantHeader: "request-id",
		},
		{
			name:       "fallback is used without request ID",
			fallback:   "user-id",
			wantHeader: "user-id",
		},
		{
			name:    "no correlation value",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := outboxHeaders(tt.requestID, tt.fallback)
			if tt.wantNil {
				if headers != nil {
					t.Fatalf("headers = %#v, want nil", headers)
				}
				return
			}
			if got := headers[kafka.HeaderCorrelationID]; got != tt.wantHeader {
				t.Fatalf("correlation ID = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestRequestID(t *testing.T) {
	t.Run("context value takes precedence", func(t *testing.T) {
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = httptest.NewRequest("GET", "/", nil)
		context.Request.Header.Set("X-Request-ID", "header-id")
		context.Set("request_id", "context-id")

		if got := requestID(context); got != "context-id" {
			t.Fatalf("request ID = %q, want context-id", got)
		}
	})

	t.Run("header fallback", func(t *testing.T) {
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = httptest.NewRequest("GET", "/", nil)
		context.Request.Header.Set("X-Request-ID", "header-id")

		if got := requestID(context); got != "header-id" {
			t.Fatalf("request ID = %q, want header-id", got)
		}
	})
}
