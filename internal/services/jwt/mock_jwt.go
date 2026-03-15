package jwt

import "context"

type mockTokenService struct{}

func NewMockTokenService() TokenRepository {
	return &mockTokenService{}
}

// GenerateAccessToken implements [TokenRepository].
func (m *mockTokenService) GenerateAccessToken(ctx context.Context, subject string, isAdmin bool) (string, error) {
	return "accessToken", nil
}

// GenerateTokens implements [TokenRepository].
func (m *mockTokenService) GenerateTokens(ctx context.Context, subject string, isAdmin bool) (accessToken string, refreshToken string, err error) {
	return "accessToken", "refreshToken", nil
}

// GetSubjectFromToken implements [TokenRepository].
func (m *mockTokenService) GetSubjectFromToken(ctx context.Context, tokenString string) (string, error) {
	panic("unimplemented")
}

// ParseAccessToken implements [TokenRepository].
func (m *mockTokenService) ParseAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	panic("unimplemented")
}

// ParseRefreshToken implements [TokenRepository].
func (m *mockTokenService) ParseRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	return &Claims{}, nil
}

// RefreshTokens implements [TokenRepository].
func (m *mockTokenService) RefreshTokens(ctx context.Context, refreshToken string) (accessToken string, newRefreshToken string, err error) {
	panic("unimplemented")
}

// ValidateAccessToken implements [TokenRepository].
func (m *mockTokenService) ValidateAccessToken(ctx context.Context, tokenString string) error {
	panic("unimplemented")
}
