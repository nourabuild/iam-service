package sqldb

import (
	"context"
	"errors"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

type mockService struct{}

func NewMockService() Service {
	return &mockService{}
}

// Close implements [Service].
func (m *mockService) Close() error {
	return nil
}

// CreatePasswordResetToken implements [Service].
func (m *mockService) CreatePasswordResetToken(ctx context.Context, token models.NewPasswordResetToken) (models.PasswordResetToken, error) {
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

// CreateRefreshToken implements [Service].
func (m *mockService) CreateRefreshToken(ctx context.Context, token models.NewRefreshToken) (models.RefreshToken, error) {
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

// CreateUser implements [Service].
func (m *mockService) CreateUser(ctx context.Context, user models.NewUser) (models.User, error) {
	if user.Account == "db_create_user_error" {
		return models.User{}, errors.New("error creating user")
	}
	if user.Account == "duplicated_user" {
		return models.User{}, ErrDBDuplicatedEntry
	}

	createdUserID := "user-id"
	if user.Account == "jwt_generate_tokens_error" {
		createdUserID = "jwt_generate_tokens_error"
	}
	if user.Account == "db_create_refresh_token_error" {
		createdUserID = "db_create_refresh_token_error"
	}

	return models.User{ID: createdUserID}, nil
}

// DeleteExpiredPasswordResetTokens implements [Service].
func (m *mockService) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	return nil
}

// DeleteExpiredRefreshTokens implements [Service].
func (m *mockService) DeleteExpiredRefreshTokens(ctx context.Context) error {
	return nil
}

// DeleteRefreshTokensByUserID implements [Service].
func (m *mockService) DeleteRefreshTokensByUserID(ctx context.Context, userID string) error {
	if userID == "db_delete_user_refresh_tokens_error" {
		return errors.New("error deleting refresh tokens")
	}
	return nil
}

// GetPasswordResetToken implements [Service].
func (m *mockService) GetPasswordResetToken(ctx context.Context, token string) (models.PasswordResetToken, error) {
	if token == "invalid-reset-token" {
		return models.PasswordResetToken{}, ErrDBNotFound
	}
	if token == "db_get_reset_token_error" {
		return models.PasswordResetToken{}, errors.New("error getting password reset token")
	}

	return models.PasswordResetToken{
		ID:        "reset-token-id",
		UserID:    "user-id",
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// GetRefreshTokenByToken implements [Service].
func (m *mockService) GetRefreshTokenByToken(ctx context.Context, token []byte) (models.RefreshToken, error) {
	stringToken := string(token)
	if stringToken == "db_get_refresh_token_error" {
		return models.RefreshToken{}, errors.New("error getting refresh token")
	}
	if stringToken == "missing_refresh_token" {
		return models.RefreshToken{}, ErrDBNotFound
	}

	now := time.Now().UTC()
	refreshToken := models.RefreshToken{
		ID:        "refresh-token-id",
		UserID:    "user-id",
		Token:     token,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}

	if stringToken == "expired_refresh_token" {
		refreshToken.ExpiresAt = now.Add(-time.Hour)
	}
	if stringToken == "revoked_refresh_token" {
		revokedAt := now.Add(-time.Minute)
		refreshToken.RevokedAt = &revokedAt
	}

	return refreshToken, nil
}

// GetUserByAccount implements [Service].
func (m *mockService) GetUserByAccount(ctx context.Context, account string) (models.User, error) {
	if account == "db_get_user_error" {
		return models.User{}, errors.New("error getting user")
	}
	if account == "missing_user" {
		return models.User{}, ErrDBNotFound
	}

	return models.User{
		ID:      "user-id",
		Account: account,
		Email:   "user@example.com",
		// This is a dummy user for testing purposes. The password is "password" hashed with bcrypt.
		Password: []byte("$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK"),
	}, nil
}

// GetUserByEmail implements [Service].
func (m *mockService) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	if email == "db_get_user_error@test.loc" {
		return models.User{}, errors.New("error getting user")
	}
	if email == "missing_user@test.loc" {
		return models.User{}, ErrDBNotFound
	}

	userID := "user-id"
	if email == "db_create_refresh_token_error@test.loc" {
		userID = "db_create_refresh_token_error"
	}
	if email == "jwt_generate_tokens_error@test.loc" {
		userID = "jwt_generate_tokens_error"
	}

	return models.User{
		ID:    userID,
		Email: email,
		// This is a dummy user for testing purposes. The password is "password" hashed with bcrypt.
		Password: []byte("$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK"),
	}, nil
}

// GetUserByID implements [Service].
func (m *mockService) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	if userID == "db_get_user_error" {
		return models.User{}, errors.New("error getting user")
	}
	if userID == "missing_user" {
		return models.User{}, ErrDBNotFound
	}

	return models.User{
		ID:      userID,
		Account: "test-user",
		Email:   "user@example.com",
		// This is a dummy user for testing purposes. The password is "password" hashed with bcrypt.
		Password: []byte("$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK"),
	}, nil
}

// Health implements [Service].
func (m *mockService) Health() map[string]string {
	var res = make(map[string]string)
	return res
}

// ListUsers implements [Service].
func (m *mockService) ListUsers(ctx context.Context) ([]models.User, error) {
	return []models.User{{ID: "user-id", Email: "user@example.com", Account: "test-user"}}, nil
}

// MarkPasswordResetTokenAsUsed implements [Service].
func (m *mockService) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID string) error {
	if tokenID == "db_mark_reset_token_used_error" {
		return errors.New("error marking reset token as used")
	}
	return nil
}

// PromoteUserToAdmin implements [Service].
func (m *mockService) PromoteUserToAdmin(ctx context.Context, userID string) (models.User, error) {
	if userID == "db_promote_user_error" {
		return models.User{}, errors.New("error promoting user")
	}
	if userID == "missing_user" {
		return models.User{}, ErrDBNotFound
	}

	return models.User{ID: userID, IsAdmin: true}, nil
}

// DemoteUserFromAdmin implements [Service].
func (m *mockService) DemoteUserFromAdmin(ctx context.Context, userID string) (models.User, error) {
	if userID == "db_demote_user_error" {
		return models.User{}, errors.New("error demoting user")
	}
	if userID == "missing_user" {
		return models.User{}, ErrDBNotFound
	}

	return models.User{ID: userID, IsAdmin: false}, nil
}

// RevokeRefreshToken implements [Service].
func (m *mockService) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	if tokenID == "db_revoke_refresh_token_error" {
		return errors.New("error revoking refresh token")
	}
	return nil
}

// UpdateUserPassword implements [Service].
func (m *mockService) UpdateUserPassword(ctx context.Context, userID string, newPassword []byte) error {
	if userID == "db_update_user_password_error" {
		return errors.New("error updating user password")
	}
	return nil
}
