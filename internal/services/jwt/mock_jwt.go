package jwt

import (
	"context"
	"errors"
)

type mockTokenService struct{}

func NewMockTokenService() TokenRepository {
	return &mockTokenService{}
}

// GenerateAccessToken implements [TokenRepository].
func (m *mockTokenService) GenerateAccessToken(ctx context.Context, subject string, isAdmin bool) (string, error) {
	if subject == "jwt_generate_access_error" {
		return "", errors.New("error generating access token")
	}
	return "accessToken", nil
}

// GenerateTokens implements [TokenRepository].
func (m *mockTokenService) GenerateTokens(ctx context.Context, subject string, isAdmin bool) (accessToken string, refreshToken string, err error) {
	if subject == "jwt_generate_tokens_error" {
		return "", "", errors.New("error generating tokens")
	}
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
	switch tokenString {
	case "jwt_expired_refresh_token":
		return nil, ErrExpiredToken
	case "jwt_invalid_refresh_token":
		return nil, ErrInvalidToken
	case "jwt_parse_refresh_error":
		return nil, errors.New("error parsing refresh token")
	case "jwt_generate_access_error_token":
		claims := &Claims{}
		claims.Subject = "jwt_generate_access_error"
		return claims, nil
	default:
		claims := &Claims{}
		claims.Subject = "user-id"
		return claims, nil
	}
}

// RefreshTokens implements [TokenRepository].
func (m *mockTokenService) RefreshTokens(ctx context.Context, refreshToken string) (accessToken string, newRefreshToken string, err error) {
	panic("unimplemented")
}

// ValidateAccessToken implements [TokenRepository].
func (m *mockTokenService) ValidateAccessToken(ctx context.Context, tokenString string) error {
	panic("unimplemented")
}
