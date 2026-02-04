package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

type App struct {
	db       sqldb.Service
	sentry   *sentry.SentryService
	jwt      *jwt.TokenService
	mailtrap *mailtrap.MailtrapService
}

func NewApp(
	db sqldb.Service,
	sentry *sentry.SentryService,
	jwt *jwt.TokenService,
	mailtrap *mailtrap.MailtrapService,
) *App {
	return &App{
		db:       db,
		sentry:   sentry,
		jwt:      jwt,
		mailtrap: mailtrap,
	}
}
