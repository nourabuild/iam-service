package app

import (
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

var engine *gin.Engine

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	mockDB := sqldb.NewMockService()
	mockSentry := sentry.NewMockSentryService()
	// Not necessary to add defer mockSentry.Close(),
	// os.Exit will terminate the process before the deferred function is executed.
	mockJWT := jwt.NewMockTokenService()
	mockMailtrap := mailtrap.NewMockMailtrapService()

	app := NewApp(
		mockDB,
		mockSentry,
		mockJWT,
		mockMailtrap,
	)

	engine = app.RegisterRoutes()

	code := m.Run()
	os.Exit(code)
}
