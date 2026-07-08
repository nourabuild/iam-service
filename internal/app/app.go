package app

import (
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
)

type App struct {
	db       sqldb.Service
	jwt      jwt.TokenRepository
	mailtrap mailtrap.MailtrapRepository
	kafka    kafka.KafkaRepository
}

func NewApp(
	db sqldb.Service,
	jwt jwt.TokenRepository,
	mailtrap mailtrap.MailtrapRepository,
	kafka kafka.KafkaRepository,
) *App {
	return &App{
		db:       db,
		jwt:      jwt,
		mailtrap: mailtrap,
		kafka:    kafka,
	}
}
