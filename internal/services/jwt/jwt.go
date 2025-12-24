// Package jwt provides JWT token generation and validation.
package jwt

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrTokenNotFound    = errors.New("token not found")
	ErrInvalidTokenType = errors.New("invalid token type")
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	Issuer           = "iam-service"
)

// Claims represents the JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenService handles JWT token operations
type TokenService struct {
	accessSecretKey      []byte
	refreshSecretKey     []byte
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
	audience             []string
}

// NewTokenService creates a new token service with separate secrets for access and refresh tokens
// Reads secrets from environment variables and uses default durations
func NewTokenService() *TokenService {
	return &TokenService{
		accessSecretKey:      []byte(os.Getenv("JWT_ACCESS_SECRET")),
		refreshSecretKey:     []byte(os.Getenv("JWT_REFRESH_SECRET")),
		accessTokenDuration:  15 * time.Minute,
		refreshTokenDuration: 7 * 24 * time.Hour,
		audience:             []string{"iam-service-api"},
	}
}

// TokenPair represents an access and refresh token pair
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// createToken is a helper function to generate a single token with the given parameters
func (s *TokenService) createToken(userID, email, tokenType string, duration time.Duration, secret []byte) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Type:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings(s.audience),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(), // Unique token ID for tracking/revocation
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// GenerateToken creates both access and refresh tokens for a user
func (s *TokenService) GenerateToken(userID, email string) (*TokenPair, error) {
	// Create access token
	accessTokenString, err := s.createToken(userID, email, TokenTypeAccess, s.accessTokenDuration, s.accessSecretKey)
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshTokenString, err := s.createToken(userID, email, TokenTypeRefresh, s.refreshTokenDuration, s.refreshSecretKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

// ParseToken validates and parses a JWT token (tries both access and refresh secrets)
func (s *TokenService) ParseToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience("iam-service-api"),
	)

	// Try access token secret first
	_, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return s.accessSecretKey, nil
	})

	// If access secret fails, try refresh secret
	if err != nil {
		claims = &Claims{} // Reset claims
		_, err = parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return s.refreshSecretKey, nil
		})
	}

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ParseAccessToken specifically parses and validates an access token
func (s *TokenService) ParseAccessToken(tokenString string) (*Claims, error) {
	claims, err := s.parseTokenWithSecret(tokenString, s.accessSecretKey)
	if err != nil {
		return nil, err
	}

	if claims.Type != TokenTypeAccess {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// ParseRefreshToken specifically parses and validates a refresh token
func (s *TokenService) ParseRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.parseTokenWithSecret(tokenString, s.refreshSecretKey)
	if err != nil {
		return nil, err
	}

	if claims.Type != TokenTypeRefresh {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

// parseTokenWithSecret is a helper to parse a token with a specific secret
func (s *TokenService) parseTokenWithSecret(tokenString string, secret []byte) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience("iam-service-api"),
	)

	_, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// RefreshToken validates a refresh token and generates a new token pair
func (s *TokenService) RefreshToken(refreshTokenString string) (*TokenPair, error) {
	// Parse and validate the refresh token using the specific refresh token parser
	claims, err := s.ParseRefreshToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	// Generate new token pair
	// Note: In production, you should invalidate the old refresh token (store JTI in Redis/DB)
	return s.GenerateToken(claims.UserID, claims.Email)
}
