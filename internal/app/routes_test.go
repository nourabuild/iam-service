package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
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

func TestRegisterRoutesWithSentryAndInvalidTrustedProxy(t *testing.T) {
	service := NewApp(
		sqldb.NewMockService(),
		jwt.NewMockTokenService(),
		mailtrap.NewMockMailtrapService(),
		kafka.NewMockProducer(),
	)
	router := service.RegisterRoutes(config.Config{
		HTTP: config.HTTP{
			TrustedProxies: []string{"not-a-valid-proxy"},
		},
		Sentry: config.Sentry{
			DSN:                "https://public@example.com/1",
			SentryFlushTimeout: time.Second,
		},
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/health/readiness", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", response.Code, http.StatusOK, response.Body.String())
	}
}
