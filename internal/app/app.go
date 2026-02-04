package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

type App struct {
	db     sqldb.Service
	sentry *sentry.SentryService
	jwt    *jwt.TokenService
	email  mailtrap.Service
}

func NewApp(
	db sqldb.Service,
	sentry *sentry.SentryService,
	jwt *jwt.TokenService,
	email mailtrap.Service,
) *App {
	return &App{
		db:     db,
		sentry: sentry,
		jwt:    jwt,
		email:  email,
	}
}
