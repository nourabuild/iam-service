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

	mockDb := sqldb.NewMockService()

	sentrySvc := sentry.NewMockSentryService()
	defer sentrySvc.Close()

	jwtSvc := jwt.NewMockTokenService()

	mailtrapSvc := mailtrap.NewMockMailtrapService()

	app := NewApp(
		mockDb,
		sentrySvc,
		jwtSvc,
		mailtrapSvc,
	)

	engine = app.RegisterRoutes()

	os.Exit(m.Run())
}
