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
)

var engine *gin.Engine

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

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

	engine = app.RegisterRoutes(config.Sentry{})

	code := m.Run()
	os.Exit(code)
}
