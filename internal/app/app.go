package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

type App struct {
	db       sqldb.Service
	sentry   sentry.SentryRepository
	jwt      jwt.TokenRepository
	mailtrap mailtrap.MailtrapRepository
	kafka    kafka.Producer
}

func NewApp(
	db sqldb.Service,
	sentry sentry.SentryRepository,
	jwt jwt.TokenRepository,
	mailtrap mailtrap.MailtrapRepository,
	kafka kafka.Producer,
) *App {
	return &App{
		db:       db,
		sentry:   sentry,
		jwt:      jwt,
		mailtrap: mailtrap,
		kafka:    kafka,
	}
}
