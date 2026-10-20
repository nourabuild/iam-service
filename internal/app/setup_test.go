package app

import (
	"net/http"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

var engine http.Handler

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	// Handler tests exercise endpoint behavior; limiter behavior has focused
	// tests in the middleware package.
	credRate = rate.Inf
	pwResetRate = rate.Inf
	refreshRate = rate.Inf
	userRate = rate.Inf
	adminRate = rate.Inf

	mockDB := newMockStore()
	mockJWT := newMockTokenService()
	mockMailtrap := newMockPasswordResetMailer()
	mockKafka := newMockEventProducer()

	app := New(
		mockDB,
		mockJWT,
		mockMailtrap,
		mockKafka,
	)

	engine = app.Handler(config.Config{})

	code := m.Run()
	os.Exit(code)
}
