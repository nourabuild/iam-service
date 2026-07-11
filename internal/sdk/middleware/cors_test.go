package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCORSCredentialsPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name             string
		origins          []string
		allowCredentials bool
		requestOrigin    string
		wantOrigin       string
		wantCredentials  string
	}{
		{
			name:             "configured origin with credentials",
			origins:          []string{"https://app.example.com"},
			allowCredentials: true,
			requestOrigin:    "https://app.example.com",
			wantOrigin:       "https://app.example.com",
			wantCredentials:  "true",
		},
		{
			name:             "configured origin without credentials",
			origins:          []string{"https://app.example.com"},
			allowCredentials: false,
			requestOrigin:    "https://app.example.com",
			wantOrigin:       "https://app.example.com",
		},
		{
			name:             "wildcard forces credentials off",
			allowCredentials: true,
			requestOrigin:    "https://untrusted.example.com",
			wantOrigin:       "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(CORS(tt.origins, tt.allowCredentials))
			router.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", tt.requestOrigin)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)

			if got := response.Header().Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantOrigin)
			}
			if got := response.Header().Get("Access-Control-Allow-Credentials"); got != tt.wantCredentials {
				t.Fatalf("Access-Control-Allow-Credentials = %q, want %q", got, tt.wantCredentials)
			}
		})
	}
}
