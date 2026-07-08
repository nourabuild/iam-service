package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"time"

	"github.com/nourabuild/iam-service/internal/sdk/errs"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

const accessTokenType = "access"

type TokenRepository interface {
	IssuePair(user models.User, now time.Time) (TokenPair, error)
	ParseAccessToken(token string) (models.Principal, error)
}

type TokenService struct {
	secret          []byte
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

type Claims struct {
	IsAdmin   bool   `json:"is_admin"`
	Role      string `json:"role"`
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
}

func NewTokenService(cfg config.AuthConfig) *TokenService {
	return &TokenService{
		secret:          []byte(cfg.JWTSecret),
		issuer:          cfg.Issuer,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
	}
}

func (m *TokenService) IssuePair(user models.User, now time.Time) (TokenPair, error) {
	accessToken, accessExpiresAt, err := m.IssueAccessToken(user, now)
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, refreshHash, err := NewRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenHash:      refreshHash,
		RefreshTokenExpiresAt: now.Add(m.refreshTokenTTL),
	}, nil
}

func (m *TokenService) IssueAccessToken(user models.User, now time.Time) (string, time.Time, error) {
	accessExpiresAt := now.Add(m.accessTokenTTL)
	claims := Claims{
		IsAdmin:   user.IsAdmin,
		Role:      roleForUser(user),
		TokenType: accessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return accessToken, accessExpiresAt, nil
}

func (m *TokenService) ParseAccessToken(tokenString string) (models.Principal, error) {
	claims := new(Claims)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		if err == nil {
			err = errors.New("token is invalid")
		}
		return models.Principal{}, errs.Wrap(err, errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	if claims.TokenType != "" && claims.TokenType != accessTokenType {
		return models.Principal{}, errs.Wrap(errors.New("token type is not access"), errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	if claims.Subject == "" {
		return models.Principal{}, errs.Wrap(errors.New("token subject is empty"), errs.ErrUnauthorized.Status, errs.ErrUnauthorized.Key)
	}
	return models.Principal{ID: claims.Subject, Role: roleForClaims(claims)}, nil
}

func roleForUser(user models.User) string {
	if user.Role != "" {
		return string(user.Role)
	}
	if user.IsAdmin {
		return string(models.RoleAdmin)
	}
	return string(models.RoleUser)
}

func roleForClaims(claims *Claims) models.Role {
	if claims.Role != "" {
		return models.Role(claims.Role)
	}
	if claims.IsAdmin {
		return models.RoleAdmin
	}
	return models.RoleUser
}

func NewRefreshToken() (string, []byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	hash := HashRefreshToken(token)
	return token, hash, nil
}

func HashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
