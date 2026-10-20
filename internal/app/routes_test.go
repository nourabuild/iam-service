package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

func TestMetricsEndpoint(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "# HELP http_requests_total") {
		t.Fatal("Prometheus HTTP metrics were not exposed")
	}
}

func TestJSONBodyLimitReturnsRequestEntityTooLarge(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/login",
		strings.NewReader(`{"padding":"`+strings.Repeat("x", int(maxJSONBodyBytes))+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	engine.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
}

func TestHandlerWithSentryAndInvalidTrustedProxy(t *testing.T) {
	service := New(
		newMockStore(),
		newMockTokenService(),
		newMockPasswordResetMailer(),
		newMockEventProducer(),
	)
	router := service.Handler(config.Config{
		HTTP: config.HTTP{
			TrustedProxies: []string{"not-a-valid-proxy"},
		},
		Sentry: config.Sentry{
			DSN:          "https://public@example.com/1",
			FlushTimeout: time.Second,
		},
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/health/readiness", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
	}
}
