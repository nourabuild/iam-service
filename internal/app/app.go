package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

type App struct {
	db     sqldb.Service
	sentry *sentry.SentryService
	jwt    *jwt.TokenService
}

func NewApp(db sqldb.Service, sentry *sentry.SentryService, jwt *jwt.TokenService) *App {
	return &App{db: db, sentry: sentry, jwt: jwt}
}
