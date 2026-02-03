package app

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) HandleRegister(c *gin.Context) {
	// Parse multipart form (for future file uploads), fall back to standard form parsing.
	if err := c.Request.ParseMultipartForm(10 << 20); err != nil { // 10 MB max
		// Fall back to standard form parsing.
		if err := c.Request.ParseForm(); err != nil {
			a.toSentry(c, "register", "parse_form", sentry.LevelError, err)
			writeError(c, ErrUnmarshal, nil)
			return
		}
	}

	name := strings.TrimSpace(c.PostForm("name"))
	account := strings.TrimSpace(c.PostForm("account"))
	email := strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")

	req := models.NewUser{
		Name:     name,
		Account:  account,
		Email:    email,
		Password: []byte(password),
	}

	errCode, validationErrors := validateRegisterInput(req)
	if errCode != "" {
		writeError(c, errCode, validationErrors)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(req.Password, bcryptCost)
	if err != nil {
		a.toSentry(c, "register", "bcrypt", sentry.LevelError, err)
		writeError(c, ErrHashPassword, nil)
		return
	}

	newUser := models.NewUser{
		Name:            req.Name,
		Account:         req.Account,
		Email:           req.Email,
		Password:        hashedPassword,
		PasswordConfirm: req.PasswordConfirm,
	}

	createdUser, err := a.db.CreateUser(c.Request.Context(), newUser)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			writeError(c, ErrUserExists, nil)
			return
		}
		a.toSentry(c, "register", "db", sentry.LevelError, err)
		writeError(c, ErrCreateUser, nil)
		return
	}

	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), createdUser.ID, createdUser.IsAdmin)
	if err != nil {
		a.toSentry(c, "register", "jwt", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), createdUser.ID, refreshToken, 7*24*time.Hour); err != nil {
		a.toSentry(c, "register", "db_token", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "login", "unmarshal", sentry.LevelError, err)
		writeError(c, ErrUnmarshal, nil)
		return
	}

	req.Account = strings.TrimSpace(req.Account)

	if validationErrors := validateLoginInput(req); len(validationErrors) > 0 {
		writeError(c, ErrMissingFields, validationErrors)
		return
	}

	user, err := a.db.GetUserByAccount(c.Request.Context(), req.Account)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrInvalidCredentials, nil)
			return
		}
		a.toSentry(c, "login", "db", sentry.LevelError, err)
		writeError(c, ErrProcessLogin, nil)
		return
	}

	// Always return the same error for auth failures to avoid account enumeration.
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		writeError(c, ErrInvalidCredentials, nil)
		return
	}

	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), user.ID, user.IsAdmin)
	if err != nil {
		a.toSentry(c, "login", "jwt", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), user.ID, refreshToken, 30*24*time.Hour); err != nil {
		a.toSentry(c, "login", "db_token", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "refresh", "unmarshal", sentry.LevelError, err)
		writeError(c, ErrUnmarshal, nil)
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if validationErrors := validateRefreshInput(req); len(validationErrors) > 0 {
		writeError(c, ErrMissingFields, validationErrors)
		return
	}

	claims, err := a.jwt.ParseRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		a.toSentry(c, "refresh", "jwt", sentry.LevelError, err)
		var errCode string
		switch {
		case errors.Is(err, jwt.ErrExpiredToken):
			errCode = ErrExpiredToken
		case errors.Is(err, jwt.ErrInvalidToken):
			errCode = ErrInvalidToken
		default:
			errCode = ErrUnauthorized
		}
		writeError(c, errCode, nil)
		return
	}

	storedToken, err := a.db.GetRefreshTokenByToken(c.Request.Context(), []byte(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrInvalidToken, nil)
			return
		}
		a.toSentry(c, "refresh", "db", sentry.LevelError, err)
		writeError(c, ErrUnauthorized, nil)
		return
	}

	if storedToken.RevokedAt != nil {
		writeError(c, ErrInvalidToken, nil)
		return
	}

	if time.Now().After(storedToken.ExpiresAt) {
		writeError(c, ErrExpiredToken, nil)
		return
	}

	accessToken, newRefreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), claims.Subject, claims.IsAdmin)
	if err != nil {
		a.toSentry(c, "refresh", "jwt_generate", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	// Revoke old refresh token to prevent reuse (rotation).
	if err := a.db.RevokeRefreshToken(c.Request.Context(), storedToken.ID); err != nil {
		a.toSentry(c, "refresh", "db_revoke", sentry.LevelError, err)
	}

	if err := a.storeRefreshToken(c.Request.Context(), claims.Subject, newRefreshToken, 30*24*time.Hour); err != nil {
		a.toSentry(c, "refresh", "db_token", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: newRefreshToken})
}
