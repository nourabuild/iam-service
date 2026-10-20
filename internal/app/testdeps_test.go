package app

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

const testPasswordHash = "$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK"

var (
	_ store               = (*mockStore)(nil)
	_ tokenService        = (*mockTokenService)(nil)
	_ passwordResetMailer = (*mockPasswordResetMailer)(nil)
	_ EventProducer       = (*mockEventProducer)(nil)
)

type mockStore struct{}

func newMockStore() *mockStore {
	return &mockStore{}
}

func (*mockStore) CreatePasswordResetToken(_ context.Context, token models.NewPasswordResetToken) (models.PasswordResetToken, error) {
	if token.UserID == "db_create_reset_token_error" {
		return models.PasswordResetToken{}, errors.New("error creating password reset token")
	}

	return models.PasswordResetToken{
		ID:        "reset-token-id",
		UserID:    token.UserID,
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (*mockStore) CreateRefreshToken(_ context.Context, token models.NewRefreshToken) (models.RefreshToken, error) {
	if token.UserID == "db_create_refresh_token_error" || string(token.Token) == "db_create_refresh_token_error" {
		return models.RefreshToken{}, errors.New("error creating refresh token")
	}

	now := time.Now().UTC()
	return models.RefreshToken{
		ID:        "refresh-token-id",
		UserID:    token.UserID,
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (*mockStore) CreateUser(
	_ context.Context,
	user models.NewUser,
	eventFn func(models.User) *models.OutboxMessage,
) (models.User, error) {
	if user.Account == "db_create_user_error" {
		return models.User{}, errors.New("error creating user")
	}
	if user.Account == "duplicated_user" {
		return models.User{}, sqldb.ErrDuplicate
	}

	createdUserID := "user-id"
	if user.Account == "jwt_generate_tokens_error" {
		createdUserID = "jwt_generate_tokens_error"
	}
	if user.Account == "db_create_refresh_token_error" {
		createdUserID = "db_create_refresh_token_error"
	}

	created := models.User{ID: createdUserID, Role: models.RoleUser}
	if eventFn != nil {
		_ = eventFn(created)
	}
	return created, nil
}

func (*mockStore) DeleteExpiredPasswordResetTokens(context.Context) error {
	return nil
}

func (*mockStore) DeleteExpiredRefreshTokens(context.Context) error {
	return nil
}

func (*mockStore) DeleteRefreshTokensByUserID(_ context.Context, userID string) error {
	if userID == "db_delete_user_refresh_tokens_error" {
		return errors.New("error deleting refresh tokens")
	}
	return nil
}

func (*mockStore) ConsumePasswordResetToken(_ context.Context, token string) (models.PasswordResetToken, error) {
	if token == "invalid-reset-token" {
		return models.PasswordResetToken{}, sqldb.ErrNotFound
	}
	if token == "db_get_reset_token_error" {
		return models.PasswordResetToken{}, errors.New("error consuming password reset token")
	}

	now := time.Now().UTC()
	return models.PasswordResetToken{
		ID:        "reset-token-id",
		UserID:    "user-id",
		Token:     token,
		ExpiresAt: now.Add(time.Hour),
		UsedAt:    &now,
		CreatedAt: now,
	}, nil
}

func (*mockStore) GetRefreshTokenByToken(_ context.Context, token []byte) (models.RefreshToken, error) {
	stringToken := string(token)
	if stringToken == "db_get_refresh_token_error" || stringToken == "jwt_parse_refresh_error" {
		return models.RefreshToken{}, errors.New("error getting refresh token")
	}
	if stringToken == "missing_refresh_token" || stringToken == "jwt_invalid_refresh_token" {
		return models.RefreshToken{}, sqldb.ErrNotFound
	}

	now := time.Now().UTC()
	userID := "user-id"
	switch stringToken {
	case "jwt_generate_access_error_token":
		userID = "jwt_generate_access_error_token"
	case "db_get_refresh_user_error":
		userID = "db_get_user_error"
	}
	refreshToken := models.RefreshToken{
		ID:        "refresh-token-id",
		UserID:    userID,
		Token:     token,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}

	if stringToken == "expired_refresh_token" || stringToken == "jwt_expired_refresh_token" {
		refreshToken.ExpiresAt = now.Add(-time.Hour)
	}
	if stringToken == "revoked_refresh_token" {
		revokedAt := now.Add(-time.Minute)
		refreshToken.RevokedAt = &revokedAt
	}

	return refreshToken, nil
}

func (*mockStore) RotateRefreshToken(
	_ context.Context,
	currentTokenID string,
	token models.NewRefreshToken,
) (models.RefreshToken, error) {
	if currentTokenID == "missing_refresh_token" {
		return models.RefreshToken{}, sqldb.ErrNotFound
	}
	if token.UserID == "db_create_refresh_token_error" {
		return models.RefreshToken{}, errors.New("error rotating refresh token")
	}

	now := time.Now().UTC()
	return models.RefreshToken{
		ID:        "rotated-refresh-token-id",
		UserID:    token.UserID,
		Token:     token.Token,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (*mockStore) GetUserByAccount(_ context.Context, account string) (models.User, error) {
	if account == "db_get_user_error" {
		return models.User{}, errors.New("error getting user")
	}
	if account == "missing_user" {
		return models.User{}, sqldb.ErrNotFound
	}

	return models.User{
		ID:       "user-id",
		Account:  account,
		Email:    "user@example.com",
		Role:     models.RoleUser,
		Password: []byte(testPasswordHash),
	}, nil
}

func (*mockStore) GetUserByEmail(_ context.Context, email string) (models.User, error) {
	if email == "db_get_user_error@test.loc" {
		return models.User{}, errors.New("error getting user")
	}
	if email == "missing_user@test.loc" {
		return models.User{}, sqldb.ErrNotFound
	}

	userID := "user-id"
	if email == "db_create_refresh_token_error@test.loc" {
		userID = "db_create_refresh_token_error"
	}
	if email == "jwt_generate_tokens_error@test.loc" {
		userID = "jwt_generate_tokens_error"
	}

	return models.User{
		ID:       userID,
		Email:    email,
		Role:     models.RoleUser,
		Password: []byte(testPasswordHash),
	}, nil
}

func (*mockStore) GetUserByID(_ context.Context, userID string) (models.User, error) {
	if userID == "db_get_user_error" {
		return models.User{}, errors.New("error getting user")
	}
	if userID == "missing_user" {
		return models.User{}, sqldb.ErrNotFound
	}

	return models.User{
		ID:       userID,
		Account:  "test-user",
		Email:    "user@example.com",
		Role:     models.RoleUser,
		Password: []byte(testPasswordHash),
	}, nil
}

func (*mockStore) Ping(context.Context) error {
	return nil
}

func (*mockStore) Stats() sql.DBStats {
	return sql.DBStats{}
}

func (*mockStore) ListUsers(context.Context) ([]models.User, error) {
	return []models.User{{
		ID:      "user-id",
		Email:   "user@example.com",
		Account: "test-user",
		Role:    models.RoleUser,
	}}, nil
}

func (*mockStore) PromoteUserToAdmin(
	_ context.Context,
	userID string,
	eventFn func(models.User) *models.OutboxMessage,
) (models.User, error) {
	if userID == "db_promote_user_error" {
		return models.User{}, errors.New("error promoting user")
	}
	if userID == "missing_user" {
		return models.User{}, sqldb.ErrNotFound
	}

	user := models.User{ID: userID, IsAdmin: true, Role: models.RoleAdmin}
	if eventFn != nil {
		_ = eventFn(user)
	}
	return user, nil
}

func (*mockStore) DemoteUserFromAdmin(
	_ context.Context,
	userID string,
	eventFn func(models.User) *models.OutboxMessage,
) (models.User, error) {
	if userID == "db_demote_user_error" {
		return models.User{}, errors.New("error demoting user")
	}
	if userID == "missing_user" {
		return models.User{}, sqldb.ErrNotFound
	}

	user := models.User{ID: userID, Role: models.RoleUser}
	if eventFn != nil {
		_ = eventFn(user)
	}
	return user, nil
}

func (*mockStore) FetchUnpublishedOutbox(context.Context, int) ([]models.OutboxRow, error) {
	return nil, nil
}

func (*mockStore) MarkOutboxPublished(context.Context, []int64) error {
	return nil
}

func (*mockStore) DeletePublishedOutbox(context.Context, time.Duration) error {
	return nil
}

func (*mockStore) RevokeRefreshToken(_ context.Context, tokenID string) error {
	if tokenID == "db_revoke_refresh_token_error" {
		return errors.New("error revoking refresh token")
	}
	return nil
}

func (*mockStore) ResetPassword(_ context.Context, token string, _ []byte) error {
	switch token {
	case "invalid-reset-token":
		return sqldb.ErrNotFound
	case "db_get_reset_token_error":
		return errors.New("error resetting password")
	default:
		return nil
	}
}

func (*mockStore) UpdateUserPassword(_ context.Context, userID string, _ []byte) error {
	if userID == "db_update_user_password_error" {
		return errors.New("error updating user password")
	}
	return nil
}

func (*mockStore) UpdateUserPasswordAndRevokeTokens(_ context.Context, userID string, _ []byte) error {
	if userID == "db_update_user_password_error" {
		return errors.New("error updating user password")
	}
	return nil
}

func (*mockStore) UpdateUser(
	_ context.Context,
	userID string,
	update models.UpdateUser,
	eventFn func(models.User) *models.OutboxMessage,
) (models.User, error) {
	if userID == "db_update_user_error" {
		return models.User{}, errors.New("error updating user")
	}
	if update.Account == "taken_account" {
		return models.User{}, sqldb.ErrDuplicate
	}
	user := models.User{
		ID:        userID,
		Name:      update.Name,
		Account:   update.Account,
		Email:     "user@example.com",
		Bio:       update.Bio,
		DOB:       update.DOB,
		City:      update.City,
		Phone:     update.Phone,
		Role:      models.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if eventFn != nil {
		_ = eventFn(user)
	}
	return user, nil
}

type mockTokenService struct{}

func newMockTokenService() *mockTokenService {
	return &mockTokenService{}
}

func (*mockTokenService) IssuePair(user models.User, now time.Time) (jwt.TokenPair, error) {
	if user.ID == "jwt_generate_tokens_error" || user.ID == "jwt_generate_access_error_token" {
		return jwt.TokenPair{}, errors.New("error generating tokens")
	}

	return jwt.TokenPair{
		AccessToken:           "accessToken",
		AccessTokenExpiresAt:  now.Add(15 * time.Minute),
		RefreshToken:          "refreshToken",
		RefreshTokenExpiresAt: now.Add(30 * 24 * time.Hour),
	}, nil
}

func (*mockTokenService) ParseAccessToken(tokenString string) (models.Principal, error) {
	switch tokenString {
	case "jwt_parse_access_error":
		return models.Principal{}, errors.New("error parsing access token")
	case "jwt_invalid_access_token":
		return models.Principal{}, errors.New("invalid token")
	case "jwt_admin_access_token":
		return models.Principal{ID: "user-id", Role: models.RoleAdmin}, nil
	case "jwt_db_update_password_error":
		return models.Principal{ID: "db_update_user_password_error", Role: models.RoleUser}, nil
	default:
		return models.Principal{ID: "user-id", Role: models.RoleUser}, nil
	}
}

type mockPasswordResetMailer struct{}

func newMockPasswordResetMailer() *mockPasswordResetMailer {
	return &mockPasswordResetMailer{}
}

func (*mockPasswordResetMailer) SendPasswordResetEmail(context.Context, string, string) error {
	return nil
}

type mockEventProducer struct{}

func newMockEventProducer() *mockEventProducer {
	return &mockEventProducer{}
}

func (*mockEventProducer) Produce(context.Context, string, []byte, any, map[string]string) error {
	return nil
}
