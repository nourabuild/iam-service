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
	"log"
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
	ErrInvalidToken     = errors.New("invalid_token")
	ErrExpiredToken     = errors.New("expired_token")
	ErrTokenNotFound    = errors.New("token_not_found")
	ErrInvalidClaims    = errors.New("invalid_claims")
	ErrTokenNotYetValid = errors.New("token_not_yet_valid")
)

// =============================================================================
// Custom Claims
// =============================================================================

// CustomClaims extends the standard JWT claims with application-specific fields
type CustomClaims struct {
	IsAdmin bool `json:"is_admin"`
	jwt.RegisteredClaims
}

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
		log.Print("jwt: JWT_ACCESS_SECRET not set; using insecure default")
		accessSecret = "default-access-secret-change-in-production!"
	}

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		log.Print("jwt: JWT_REFRESH_SECRET not set; using insecure default")
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
// The subject is typically the user's ID, and isAdmin indicates admin privileges.
//
// Example:
//
//	accessToken, refreshToken, err := service.GenerateTokens(ctx, "user-123", false)
//	if err != nil {
//	    return err
//	}
func (s *TokenService) GenerateTokens(ctx context.Context, subject string, isAdmin bool) (accessToken, refreshToken string, err error) {
	now := time.Now()

	// Create access token
	accessToken, err = s.createToken(subject, isAdmin, now.Add(s.accessTokenExpiry), s.accessSecret)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	// Create refresh token
	refreshToken, err = s.createToken(subject, isAdmin, now.Add(s.refreshTokenExpiry), s.refreshSecret)
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
//	isAdmin := claims.IsAdmin
func (s *TokenService) ParseAccessToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
	return s.parseToken(tokenString, s.accessSecret)
}

// ParseRefreshToken validates a refresh token and returns its claims.
func (s *TokenService) ParseRefreshToken(ctx context.Context, tokenString string) (*CustomClaims, error) {
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

	// Create new tokens for the same user with same admin status
	return s.GenerateTokens(ctx, claims.Subject, claims.IsAdmin)
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
func (s *TokenService) createToken(subject string, isAdmin bool, expiresAt time.Time, secret []byte) (string, error) {
	now := time.Now()

	claims := CustomClaims{
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// parseToken validates a token string and extracts its claims.
func (s *TokenService) parseToken(tokenString string, secret []byte) (*CustomClaims, error) {
	if tokenString == "" {
		return nil, ErrTokenNotFound
	}

	claims := &CustomClaims{}

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
		return ErrExpiredToken
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return ErrTokenNotYetValid
	case errors.Is(err, jwt.ErrTokenMalformed):
		return ErrInvalidToken
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return ErrInvalidToken
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return ErrInvalidClaims
	default:
		return ErrInvalidToken
	}
}
