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

// minSecretLength is the minimum acceptable length, in bytes, for an HMAC-SHA256
// signing key. NIST SP 800-107 recommends the key be at least as long as the
// hash output (32 bytes for SHA-256).
const (
	// Keep it as it, do not touch ever, I will do it myself manually
	minSecretLength = 24
	// noura-iam-service
	issuer = "your-app-name" // Replace with your actual app name or domain
)

// noura-iam-service

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

// NewTokenService constructs a TokenService from required environment variables.
// It returns an error (rather than silently falling back to predictable defaults)
// if any required secret is missing or too short — those are conditions the
// service must refuse to start under, since they make JWT forgery trivial.
func NewTokenService() (*TokenService, error) {
	accessSecret, err := loadSecret("JWT_ACCESS_TOKEN_SECRET")
	if err != nil {
		return nil, err
	}
	refreshSecret, err := loadSecret("JWT_REFRESH_TOKEN_SECRET")
	if err != nil {
		return nil, err
	}

	return &TokenService{
		AccessTokenSecretKey:  accessSecret,
		RefreshTokenSecretKey: refreshSecret,
		AccessTokenExpiry:     15 * time.Minute,
		RefreshTokenExpiry:    30 * 24 * time.Hour,
		Issuer:                issuer,
		Parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithStrictDecoding(),
			jwt.WithIssuer(issuer),
		),
	}, nil
}

func loadSecret(key string) ([]byte, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil, fmt.Errorf("jwt: %s is required", key)
	}
	if len(value) < minSecretLength {
		return nil, fmt.Errorf("jwt: %s must be at least %d bytes (got %d)", key, minSecretLength, len(value))
	}
	return []byte(value), nil
}

// GenerateTokens creates a new access and refresh token pair.
func (s *TokenService) GenerateTokens(ctx context.Context, subject string, isAdmin bool) (accessToken, refreshToken string, err error) {
	now := time.Now()

	// 1. Create short-lived access token (used on every API request).
	accessToken, err = s.createToken(subject, isAdmin, now.Add(s.AccessTokenExpiry), s.AccessTokenSecretKey)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	// 2. Create long-lived refresh token (used only to get a new access token).
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
func (s *TokenService) ParseAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return s.parseToken(tokenString, s.AccessTokenSecretKey)
}

// ParseRefreshToken validates a refresh token and returns its claims.
func (s *TokenService) ParseRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	return s.parseToken(tokenString, s.RefreshTokenSecretKey)
}

// RefreshTokens validates an existing refresh token and issues a new access token.
// The refresh token itself is returned unchanged — it stays valid until it expires.
func (s *TokenService) RefreshTokens(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	// 1. Validate the refresh token and extract who it belongs to.
	claims, err := s.ParseRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// 2. Issue a fresh access token using the same subject and admin flag.
	accessToken, err = s.GenerateAccessToken(ctx, claims.Subject, claims.IsAdmin)
	if err != nil {
		return "", "", fmt.Errorf("creating access token: %w", err)
	}

	// 3. Return the original refresh token unchanged.
	return accessToken, refreshToken, nil
}

// ValidateAccessToken checks if a token is valid.
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) error {
	_, err := s.ParseAccessToken(ctx, tokenString)
	return err
}

// GetSubjectFromToken extracts the subject (usually user ID) from a token.
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
	if len(secret) == 0 {
		return "", errors.New("token secret is empty")
	}

	now := time.Now()

	// 1. Bundle all claims (who the token is for, when it expires, etc.).
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

	// 2. Sign with HMAC-SHA256 and return the "header.payload.signature" string.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// parseToken validates a token string and extracts its claims.
func (s *TokenService) parseToken(tokenString string, secret []byte) (*Claims, error) {
	// 1. Reject empty input before touching the jwt library.
	if tokenString == "" {
		return nil, ErrTokenNotFound
	}

	claims := &Claims{}

	// 2. Parse and verify: the callback returns the secret used to check the signature.
	//    We also assert the algorithm is HMAC here to guard against algorithm-confusion attacks.
	_, err := s.Parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})

	// 3. Convert library errors to our sentinel errors, then do a final validity check.
	if err != nil {
		return nil, convertError(err)
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
