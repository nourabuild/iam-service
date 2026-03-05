package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/stretchr/testify/assert"
)

func TestLiveness(t *testing.T) {
	a := &App{}
	router := a.RegisterRoutes()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health/liveness", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var actual models.Liveness
	err := json.Unmarshal(w.Body.Bytes(), &actual)
	assert.NoError(t, err)

	expected := models.Liveness{
		Status:     "up",
		Host:       actual.Host,
		GOMAXPROCS: actual.GOMAXPROCS,
	}

	assert.Equal(t, expected, actual)
}
