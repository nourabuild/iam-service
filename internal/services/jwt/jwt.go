// Package jwt provides a simple and secure JWT (JSON Web Token) service.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid_token")
	ErrExpiredToken     = errors.New("expired_token")
	ErrTokenNotFound    = errors.New("token_not_found")
	ErrInvalidClaims    = errors.New("invalid_claims")
	ErrTokenNotYetValid = errors.New("token_not_yet_valid")
)

// Claims extends the standard JWT claims with application-specific fields
type Claims struct {
	IsAdmin bool `json:"is_admin"`
	jwt.RegisteredClaims
}

type TokenRepository interface {
	GenerateTokens(ctx context.Context, subject string, isAdmin bool) (accessToken, refreshToken string, err error)
	GenerateAccessToken(ctx context.Context, subject string, isAdmin bool) (string, error)
	ParseAccessToken(ctx context.Context, tokenString string) (*Claims, error)
	ParseRefreshToken(ctx context.Context, tokenString string) (*Claims, error)
	RefreshTokens(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)
	ValidateAccessToken(ctx context.Context, tokenString string) error
	GetSubjectFromToken(ctx context.Context, tokenString string) (string, error)
}

type TokenService struct {
	AccessTokenSecretKey  []byte
	RefreshTokenSecretKey []byte
	AccessTokenExpiry     time.Duration
	RefreshTokenExpiry    time.Duration
	Issuer                string
	Parser                *jwt.Parser
}

func NewTokenService() *TokenService {
	issuer := envOrDefault("JWT_ISSUER", "your-app-name")
	accessSecret := envOrDefault("JWT_ACCESS_TOKEN_SECRET", "your-access-token-secret")
	refreshSecret := envOrDefault("JWT_REFRESH_TOKEN_SECRET", "your-refresh-token-secret")

	return &TokenService{
		AccessTokenSecretKey:  []byte(accessSecret),
		RefreshTokenSecretKey: []byte(refreshSecret),
		AccessTokenExpiry:     15 * time.Minute,
		RefreshTokenExpiry:    30 * 24 * time.Hour,
		Issuer:                issuer,
		Parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithStrictDecoding(),
			jwt.WithIssuer(issuer),
		),
	}
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
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
	accessToken, err = s.createToken(subject, isAdmin, now.Add(s.AccessTokenExpiry), s.AccessTokenSecretKey)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	// Create refresh token
	refreshToken, err = s.createToken(subject, isAdmin, now.Add(s.RefreshTokenExpiry), s.RefreshTokenSecretKey)
	if err != nil {
		return "", "", fmt.Errorf("creating refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// GenerateAccessToken creates only an access token for a user.
func (s *TokenService) GenerateAccessToken(ctx context.Context, subject string, isAdmin bool) (string, error) {
	now := time.Now()

	accessToken, err := s.createToken(subject, isAdmin, now.Add(s.AccessTokenExpiry), s.AccessTokenSecretKey)
	if err != nil {
		return "", fmt.Errorf("creating access token: %w", err)
	}

	return accessToken, nil
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
func (s *TokenService) ParseAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return s.parseToken(tokenString, s.AccessTokenSecretKey)
}

// ParseRefreshToken validates a refresh token and returns its claims.
func (s *TokenService) ParseRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	return s.parseToken(tokenString, s.RefreshTokenSecretKey)
}

// RefreshTokens creates a new access token and reuses the same refresh token.
//
// Call this when the client's access token has expired.
//
// Example:
//
//	newAccess, sameRefresh, err := service.RefreshTokens(ctx, oldRefreshToken)
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

	// Reuse refresh token until expiry/revocation; only issue a new access token.
	accessToken, err = s.GenerateAccessToken(ctx, claims.Subject, claims.IsAdmin)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	return accessToken, refreshToken, nil
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

	claims := Claims{
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// parseToken validates a token string and extracts its claims.
func (s *TokenService) parseToken(tokenString string, secret []byte) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrTokenNotFound
	}

	claims := &Claims{}

	token, err := s.Parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
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
