package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
)

var livenessTests = []struct {
	host                   string
	hostErr                error
	expectedHost           string
	expectedStatusCode     int
	expectedLivenessStatus string
}{
	{
		host:                   "host",
		expectedHost:           "host",
		expectedStatusCode:     http.StatusOK,
		expectedLivenessStatus: "up",
	},
	{
		host:                   "",
		expectedHost:           "unavailable",
		expectedStatusCode:     http.StatusServiceUnavailable,
		expectedLivenessStatus: "down",
	},
	{
		hostErr:                errors.New("hostname unavailable"),
		expectedHost:           "unavailable",
		expectedStatusCode:     http.StatusServiceUnavailable,
		expectedLivenessStatus: "down",
	},
}

func TestLiveness(t *testing.T) {
	const uri = "/api/v1/health/liveness"
	originalHostname := osHostname
	t.Cleanup(func() { osHostname = originalHostname })

	for _, tt := range livenessTests {
		t.Run(tt.expectedLivenessStatus, func(t *testing.T) {
			osHostname = func() (string, error) {
				return tt.host, tt.hostErr
			}

			req := httptest.NewRequest(http.MethodGet, uri, nil)
			rr := httptest.NewRecorder()
			engine.ServeHTTP(rr, req)

			var actual models.Liveness
			if err := json.Unmarshal(rr.Body.Bytes(), &actual); err != nil {
				t.Fatalf("unmarshaling liveness response: %v", err)
			}

			if actual.Host != tt.expectedHost {
				t.Errorf("host = %q, want %q", actual.Host, tt.expectedHost)
			}

			if rr.Code != tt.expectedStatusCode {
				t.Errorf("status = %d, want %d", rr.Code, tt.expectedStatusCode)
			}

			if actual.Status != tt.expectedLivenessStatus {
				t.Errorf("liveness status = %q, want %q", actual.Status, tt.expectedLivenessStatus)
			}
		})
	}
}

type unhealthyDB struct {
	sqldb.Service
}

func (unhealthyDB) Health() map[string]string {
	return map[string]string{
		"status":  "down",
		"message": "database unavailable",
	}
}

func TestReadinessUnavailableDependencies(t *testing.T) {
	app := NewApp(unhealthyDB{}, nil, nil, nil)
	router := gin.New()
	router.GET("/readiness", app.HandleReadiness)

	request := httptest.NewRequest(http.MethodGet, "/readiness", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshaling readiness body: %v", err)
	}
	if body["status"] != "down" {
		t.Errorf("status = %q, want down", body["status"])
	}
	if body["kafka"] != "disabled" {
		t.Errorf("kafka = %q, want disabled", body["kafka"])
	}
}

func TestReadiness(t *testing.T) {
	uri := "/api/v1/health/readiness"

	req := httptest.NewRequest(http.MethodGet, uri, nil)
	rr := httptest.NewRecorder()

	engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code. expected %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshaling readiness body: %v", err)
	}
	if body["status"] != "up" {
		t.Errorf("expected status up, got %q", body["status"])
	}
	// The mock producer is wired in setup_test.go, so Kafka reports enabled.
	if body["kafka"] != "enabled" {
		t.Errorf("expected kafka enabled, got %q", body["kafka"])
	}
}
