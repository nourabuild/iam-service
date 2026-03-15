package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

// This was a unit test

var livenessTest = []struct {
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
	var uri = "/api/v1/health/liveness"

	for _, tt := range livenessTest {
		osHostname = func() (string, error) {
			return tt.host, nil
		}

		req, _ := http.NewRequest(http.MethodGet, uri, nil)

		rr := httptest.NewRecorder()

		engine.ServeHTTP(rr, req)

		var actual models.Liveness
		json.Unmarshal(rr.Body.Bytes(), &actual)

		if actual.Host != tt.expectedHost {
			t.Errorf("Expected host. expected %s, got %s", tt.expectedHost, actual.Host)
		}

		if rr.Code != tt.expectedStatusCode {
			t.Errorf("Expected status code. expected %d, got %d", tt.expectedStatusCode, rr.Code)
		}

		if actual.Status != tt.expectedLivenessStatus {
			t.Errorf("Expected liveness status. expected %s, got %s", tt.expectedLivenessStatus, actual.Status)
		}

	}

}

func TestReadiness(t *testing.T) {
	uri := "/api/v1/health/readiness"

	req, _ := http.NewRequest(http.MethodGet, uri, nil)

	rr := httptest.NewRecorder()

	engine.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("Expected status code. expected %d, got %d", http.StatusOK, rr.Code)
	}
}

// Docker required
// go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out -o coverage.html

// Not required:
// go test -coverprofile=coverage.out ./internal/app/... && go tool cover -html=coverage.out -o coverage.html
