// Package jwt provides a simple and secure JWT (JSON Web Token) service.
//
// JWTs are used for authentication - they let your server verify that a request
// comes from a logged-in user without checking a database on every request.
//
// This package handles two types of tokens:
//   - Access Token:  Short-lived (15 min), used for API requests
//   - Refresh Token: Long-lived (7 days), used to get new access tokens
package jwt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// =============================================================================
// Errors
// =============================================================================

// These are our custom errors. Using package-level errors like this makes it
// easy to check what went wrong: errors.Is(err, jwt.ErrExpiredToken)
var (
	ErrInvalidToken     = errors.New("jwt: invalid token")
	ErrExpiredToken     = errors.New("jwt: token has expired")
	ErrTokenNotFound    = errors.New("jwt: token not found")
	ErrInvalidClaims    = errors.New("jwt: invalid claims")
	ErrTokenNotYetValid = errors.New("jwt: token not yet valid")
)

// =============================================================================
// Token Service
// =============================================================================

// TokenService creates and validates JWT tokens.
// Create one instance and reuse it throughout your application.
type TokenService struct {
	accessSecret       []byte
	refreshSecret      []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	issuer             string
	parser             *jwt.Parser
}

// NewTokenService creates a new TokenService.
//
// It reads configuration from environment variables:
//   - JWT_ACCESS_SECRET:  Secret key for access tokens (required)
//   - JWT_REFRESH_SECRET: Secret key for refresh tokens (required)
//   - JWT_ISSUER:         Token issuer name (optional, default: "app")
//
// Example:
//
//	service := jwt.NewTokenService()
//	tokens, err := service.GenerateTokens(ctx, "user-123")
func NewTokenService() *TokenService {
	// Read secrets from environment variables
	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if accessSecret == "" {
		accessSecret = "default-access-secret-change-in-production!"
	}

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		refreshSecret = "default-refresh-secret-change-in-production"
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "app"
	}

	// Create parser with security options
	parser := jwt.NewParser(
		// Only accept HS256 algorithm - prevents "algorithm confusion" attacks
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),

		// Reject tokens without an expiration time
		jwt.WithExpirationRequired(),

		// Enforce strict base64 encoding
		jwt.WithStrictDecoding(),

		// Validate issuer
		jwt.WithIssuer(issuer),
	)

	return &TokenService{
		accessSecret:       []byte(accessSecret),
		refreshSecret:      []byte(refreshSecret),
		accessTokenExpiry:  15 * time.Minute,
		refreshTokenExpiry: 7 * 24 * time.Hour,
		issuer:             issuer,
		parser:             parser,
	}
}

// =============================================================================
// Public Methods
// =============================================================================

// GenerateTokens creates a new access and refresh token pair.
//
// Call this after a user successfully logs in.
// The subject is typically the user's ID.
//
// Example:
//
//	accessToken, refreshToken, err := service.GenerateTokens(ctx, "user-123")
//	if err != nil {
//	    return err
//	}
func (s *TokenService) GenerateTokens(ctx context.Context, subject string) (accessToken, refreshToken string, err error) {
	now := time.Now()

	// Create access token
	accessToken, err = s.createToken(subject, now.Add(s.accessTokenExpiry), s.accessSecret)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	// Create refresh token
	refreshToken, err = s.createToken(subject, now.Add(s.refreshTokenExpiry), s.refreshSecret)
	if err != nil {
		return "", "", fmt.Errorf("creating refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ParseAccessToken validates an access token and returns its claims.
//
// Call this in your authentication middleware to verify requests.
//
// Example:
//
//	claims, err := service.ParseAccessToken(ctx, tokenFromHeader)
//	if err != nil {
//	    http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	    return
//	}
//	userID := claims.Subject
func (s *TokenService) ParseAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	return s.parseToken(tokenString, s.accessSecret)
}

// ParseRefreshToken validates a refresh token and returns its claims.
func (s *TokenService) ParseRefreshToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	return s.parseToken(tokenString, s.refreshSecret)
}

// RefreshTokens creates new tokens using a valid refresh token.
//
// Call this when the client's access token has expired.
//
// Example:
//
//	newAccess, newRefresh, err := service.RefreshTokens(ctx, oldRefreshToken)
//	if err != nil {
//	    http.Error(w, "Please log in again", http.StatusUnauthorized)
//	    return
//	}
func (s *TokenService) RefreshTokens(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	// Validate the refresh token
	claims, err := s.ParseRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Create new tokens for the same user
	return s.GenerateTokens(ctx, claims.Subject)
}

// ValidateAccessToken checks if a token is valid.
//
// Example:
//
//	if err := service.ValidateAccessToken(ctx, token); err != nil {
//	    http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	    return
//	}
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) error {
	_, err := s.ParseAccessToken(ctx, tokenString)
	return err
}

// GetSubjectFromToken extracts the subject (usually user ID) from a token.
//
// Example:
//
//	userID, err := service.GetSubjectFromToken(ctx, token)
func (s *TokenService) GetSubjectFromToken(ctx context.Context, tokenString string) (string, error) {
	claims, err := s.ParseAccessToken(ctx, tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// =============================================================================
// Private Methods
// =============================================================================

// createToken builds and signs a JWT with the given parameters.
func (s *TokenService) createToken(subject string, expiresAt time.Time, secret []byte) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    s.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// parseToken validates a token string and extracts its claims.
func (s *TokenService) parseToken(tokenString string, secret []byte) (*jwt.RegisteredClaims, error) {
	if tokenString == "" {
		return nil, ErrTokenNotFound
	}

	claims := &jwt.RegisteredClaims{}

	token, err := s.parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		return nil, convertError(err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// convertError transforms jwt library errors into our custom errors.
func convertError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %v", ErrExpiredToken, err)
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf("%w: %v", ErrTokenNotYetValid, err)
	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w: token is malformed", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w: signature is invalid", ErrInvalidToken)
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	default:
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
}
