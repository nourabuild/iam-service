package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequestIDValidatesInboundValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestID())
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, c.GetString("request_id"))
	})

	tests := []struct {
		name       string
		requestID  string
		wantSameID bool
	}{
		{name: "valid", requestID: "trace-123_ABC", wantSameID: true},
		{name: "surrounding whitespace is normalized", requestID: "  trace-123  ", wantSameID: true},
		{name: "too long", requestID: strings.Repeat("x", maxRequestIDLength+1)},
		{name: "contains whitespace", requestID: "two words"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Request-ID", tt.requestID)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)

			got := response.Header().Get("X-Request-ID")
			if got == "" || got != response.Body.String() {
				t.Fatalf("response request ID = %q, body = %q", got, response.Body.String())
			}
			if tt.wantSameID && got != strings.TrimSpace(tt.requestID) {
				t.Fatalf("request ID = %q, want normalized inbound ID %q", got, strings.TrimSpace(tt.requestID))
			}
			if !tt.wantSameID && got == tt.requestID {
				t.Fatalf("invalid request ID %q was trusted", got)
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(BodyLimit(4))
	router.POST("/", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345")))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}
