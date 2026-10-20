package app

import (
	"context"
	"database/sql"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

type userStore interface {
	GetUserByID(context.Context, string) (models.User, error)
	GetUserByEmail(context.Context, string) (models.User, error)
	CreateUser(context.Context, models.NewUser, func(models.User) *models.OutboxMessage) (models.User, error)
	ListUsers(context.Context) ([]models.User, error)
	UpdateUser(context.Context, string, models.UpdateUser, func(models.User) *models.OutboxMessage) (models.User, error)
	PromoteUserToAdmin(context.Context, string, func(models.User) *models.OutboxMessage) (models.User, error)
	DemoteUserFromAdmin(context.Context, string, func(models.User) *models.OutboxMessage) (models.User, error)
}

type refreshTokenStore interface {
	CreateRefreshToken(context.Context, models.NewRefreshToken) (models.RefreshToken, error)
	GetRefreshTokenByToken(context.Context, []byte) (models.RefreshToken, error)
	RotateRefreshToken(context.Context, string, models.NewRefreshToken) (models.RefreshToken, error)
	DeleteRefreshTokensByUserID(context.Context, string) error
}

type passwordStore interface {
	CreatePasswordResetToken(context.Context, models.NewPasswordResetToken) (models.PasswordResetToken, error)
	ResetPassword(context.Context, string, []byte) error
	UpdateUserPasswordAndRevokeTokens(context.Context, string, []byte) error
}

type outboxStore interface {
	FetchUnpublishedOutbox(context.Context, int) ([]models.OutboxRow, error)
	MarkOutboxPublished(context.Context, []int64) error
}

type store interface {
	userStore
	refreshTokenStore
	passwordStore
	outboxStore
	Ping(context.Context) error
	Stats() sql.DBStats
}

type tokenService interface {
	IssuePair(models.User, time.Time) (jwt.TokenPair, error)
	ParseAccessToken(string) (models.Principal, error)
}

type passwordResetMailer interface {
	SendPasswordResetEmail(context.Context, string, string) error
}

// EventProducer publishes IAM lifecycle events.
type EventProducer interface {
	Produce(context.Context, string, []byte, any, map[string]string) error
}

// Server owns the IAM service's HTTP handlers and background jobs.
type Server struct {
	db       store
	tokens   tokenService
	mailer   passwordResetMailer
	producer EventProducer
}

// New constructs a Server from its runtime dependencies.
func New(
	db store,
	tokens tokenService,
	mailer passwordResetMailer,
	producer EventProducer,
) *Server {
	return &Server{
		db:       db,
		tokens:   tokens,
		mailer:   mailer,
		producer: producer,
	}
}
