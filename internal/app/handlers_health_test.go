package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

var livenessTests = []struct {
	host                   string
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
}

func TestLiveness(t *testing.T) {
	const uri = "/api/v1/health/liveness"
	originalHostname := osHostname
	t.Cleanup(func() { osHostname = originalHostname })

	for _, tt := range livenessTests {
		t.Run(tt.expectedLivenessStatus, func(t *testing.T) {
			osHostname = func() (string, error) {
				return tt.host, nil
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
