package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

type App struct {
	db       sqldb.Service
	sentry   sentry.SentryRepository
	jwt      jwt.TokenRepository
	mailtrap mailtrap.MailtrapRepository
}

func NewApp(
	db sqldb.Service,
	sentry sentry.SentryRepository,
	jwt jwt.TokenRepository,
	mailtrap mailtrap.MailtrapRepository,
) *App {
	return &App{
		db:       db,
		sentry:   sentry,
		jwt:      jwt,
		mailtrap: mailtrap,
	}
}
