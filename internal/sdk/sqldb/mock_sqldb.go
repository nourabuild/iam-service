package sqldb

import (
	"context"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

type mockService struct{}

// Close implements [Service].
func (m *mockService) Close() error {
	panic("unimplemented")
}

// CreatePasswordResetToken implements [Service].
func (m *mockService) CreatePasswordResetToken(ctx context.Context, token models.NewPasswordResetToken) (models.PasswordResetToken, error) {
	panic("unimplemented")
}

// CreateRefreshToken implements [Service].
func (m *mockService) CreateRefreshToken(ctx context.Context, token models.NewRefreshToken) (models.RefreshToken, error) {
	return models.RefreshToken{}, nil
}

// CreateUser implements [Service].
func (m *mockService) CreateUser(ctx context.Context, user models.NewUser) (models.User, error) {
	return models.User{ID: "user-id"}, nil
}

// DeleteExpiredPasswordResetTokens implements [Service].
func (m *mockService) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	panic("unimplemented")
}

// DeleteExpiredRefreshTokens implements [Service].
func (m *mockService) DeleteExpiredRefreshTokens(ctx context.Context) error {
	panic("unimplemented")
}

// DeleteRefreshTokensByUserID implements [Service].
func (m *mockService) DeleteRefreshTokensByUserID(ctx context.Context, userID string) error {
	panic("unimplemented")
}

// GetPasswordResetToken implements [Service].
func (m *mockService) GetPasswordResetToken(ctx context.Context, token string) (models.PasswordResetToken, error) {
	panic("unimplemented")
}

// GetRefreshTokenByToken implements [Service].
func (m *mockService) GetRefreshTokenByToken(ctx context.Context, token []byte) (models.RefreshToken, error) {
	return models.RefreshToken{ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// GetUserByAccount implements [Service].
func (m *mockService) GetUserByAccount(ctx context.Context, account string) (models.User, error) {
	panic("unimplemented")
}

// GetUserByEmail implements [Service].
func (m *mockService) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	return models.User{
		// This is a dummy user for testing purposes. The password is "password" hashed with bcrypt.
		Password: []byte("$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK"),
	}, nil
}

// GetUserByID implements [Service].
func (m *mockService) GetUserByID(ctx context.Context, userID string) (models.User, error) {
	panic("unimplemented")
}

// Health implements [Service].
func (m *mockService) Health() map[string]string {
	var res = make(map[string]string)
	return res
}

// ListUsers implements [Service].
func (m *mockService) ListUsers(ctx context.Context) ([]models.User, error) {
	panic("unimplemented")
}

// MarkPasswordResetTokenAsUsed implements [Service].
func (m *mockService) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID string) error {
	panic("unimplemented")
}

// PromoteUserToAdmin implements [Service].
func (m *mockService) PromoteUserToAdmin(ctx context.Context, userID string) (models.User, error) {
	panic("unimplemented")
}

// RevokeRefreshToken implements [Service].
func (m *mockService) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	panic("unimplemented")
}

// UpdateUserPassword implements [Service].
func (m *mockService) UpdateUserPassword(ctx context.Context, userID string, newPassword []byte) error {
	panic("unimplemented")
}

func NewMockService() Service {
	return &mockService{}
}
