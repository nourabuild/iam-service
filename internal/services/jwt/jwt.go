// Package jwt issues and validates access tokens and creates refresh tokens.
package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/errs"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

const accessTokenType = "access"

// Service issues and validates IAM bearer tokens.
type Service struct {
	secret          []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

type claims struct {
	jwt.RegisteredClaims

	IsAdmin   bool   `json:"is_admin"`
	Role      string `json:"role"`
	TokenType string `json:"typ"`
}

// TokenPair contains a newly issued access token and refresh token.
type TokenPair struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// New constructs a token Service from cfg.
func New(cfg config.Auth) *Service {
	return &Service{
		secret:          []byte(cfg.JWTSecret),
		issuer:          cfg.Issuer,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
	}
}

// IssuePair creates a signed access token and a random refresh token.
func (s *Service) IssuePair(user models.User, now time.Time) (TokenPair, error) {
	accessToken, accessExpiresAt, err := s.issueAccessToken(user, now)
	if err != nil {
		return TokenPair{}, fmt.Errorf("issue access token: %w", err)
	}

	refreshToken, err := newRefreshToken()
	if err != nil {
		return TokenPair{}, fmt.Errorf("issue refresh token: %w", err)
	}

	return TokenPair{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: now.Add(s.refreshTokenTTL),
	}, nil
}

func (s *Service) issueAccessToken(user models.User, now time.Time) (string, time.Time, error) {
	accessExpiresAt := now.Add(s.accessTokenTTL)
	claims := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		IsAdmin:   user.IsAdmin,
		Role:      roleForUser(user),
		TokenType: accessTokenType,
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return accessToken, accessExpiresAt, nil
}

// ParseAccessToken validates tokenString and returns its authenticated principal.
func (s *Service) ParseAccessToken(tokenString string) (models.Principal, error) {
	claims := new(claims)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		if err == nil {
			err = errors.New("token is invalid")
		}
		return models.Principal{}, errs.Wrap(err, errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	if claims.TokenType != accessTokenType {
		return models.Principal{}, errs.Wrap(errors.New("token type is not access"), errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	if claims.Subject == "" {
		return models.Principal{}, errs.Wrap(errors.New("token subject is empty"), errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	return models.Principal{ID: claims.Subject, Role: roleForClaims(claims)}, nil
}

func roleForUser(user models.User) string {
	if user.Role.Valid() {
		return string(user.Role)
	}
	if user.IsAdmin {
		return string(models.RoleAdmin)
	}
	return string(models.RoleUser)
}

func roleForClaims(claims *claims) models.Role {
	if role := models.Role(claims.Role); role.Valid() {
		return role
	}
	if claims.IsAdmin {
		return models.RoleAdmin
	}
	return models.RoleUser
}

func newRefreshToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
