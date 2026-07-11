package app

import (
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"golang.org/x/time/rate"
)

var engine *gin.Engine

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	// Handler tests exercise endpoint behavior; limiter behavior has focused
	// tests in the middleware package.
	credRate = rate.Inf
	pwResetRate = rate.Inf
	refreshRate = rate.Inf
	userRate = rate.Inf
	adminRate = rate.Inf

	mockDB := sqldb.NewMockService()
	mockJWT := jwt.NewMockTokenService()
	mockMailtrap := mailtrap.NewMockMailtrapService()

	mockKafka := kafka.NewMockProducer()

	app := NewApp(
		mockDB,
		mockJWT,
		mockMailtrap,
		mockKafka,
	)

	engine = app.RegisterRoutes(config.Config{})

	code := m.Run()
	os.Exit(code)
}
