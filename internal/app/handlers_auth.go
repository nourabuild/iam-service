package app

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8
	minAccountLength  = 6
	bcryptCost        = bcrypt.DefaultCost

	maxRegisterFormMemory int64 = 10 << 20 // 10 MB
	registerRefreshTTL          = 7 * 24 * time.Hour
	authRefreshTTL              = 30 * 24 * time.Hour
)

type LoginRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type passwordComplexity struct {
	hasUpper   bool
	hasNumber  bool
	hasSpecial bool
}

func parseMultipartOrForm(r *http.Request, maxMemory int64) error {
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		if errors.Is(err, http.ErrNotMultipart) {
			return r.ParseForm()
		}
		return err
	}
	return nil
}

func (a *App) HandleRegister(c *gin.Context) {
	if err := parseMultipartOrForm(c.Request, maxRegisterFormMemory); err != nil {
		a.toSentry(c, "register", "parse_form", sentry.LevelError, err)
		writeError(c, ErrUnmarshal, nil)
		return
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

	if err := a.storeRefreshToken(c.Request.Context(), createdUser.ID, refreshToken, registerRefreshTTL); err != nil {
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

	if err := a.storeRefreshToken(c.Request.Context(), user.ID, refreshToken, authRefreshTTL); err != nil {
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
		if !errors.Is(err, jwt.ErrExpiredToken) && !errors.Is(err, jwt.ErrInvalidToken) {
			a.toSentry(c, "refresh", "jwt", sentry.LevelError, err)
		}
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

	if time.Now().UTC().After(storedToken.ExpiresAt) {
		writeError(c, ErrExpiredToken, nil)
		return
	}

	accessToken, newRefreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), claims.Subject, claims.IsAdmin)
	if err != nil {
		a.toSentry(c, "refresh", "jwt_generate", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	if err := a.db.RevokeRefreshToken(c.Request.Context(), storedToken.ID); err != nil {
		a.toSentry(c, "refresh", "db_revoke", sentry.LevelError, err)
	}

	if err := a.storeRefreshToken(c.Request.Context(), claims.Subject, newRefreshToken, authRefreshTTL); err != nil {
		a.toSentry(c, "refresh", "db_token", sentry.LevelError, err)
		writeError(c, ErrGenerateTokens, nil)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: newRefreshToken})
}

func validateRegisterInput(req models.NewUser) (string, map[string]string) {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.Name) == "" {
		validationErrors["name"] = "name_required"
	}
	if strings.TrimSpace(req.Account) == "" {
		validationErrors["account"] = "account_required"
	}
	if strings.TrimSpace(req.Email) == "" {
		validationErrors["email"] = "email_required"
	}
	if len(req.Password) == 0 {
		validationErrors["password"] = "password_required"
	}

	if len(validationErrors) > 0 {
		return ErrMissingFields, validationErrors
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		validationErrors["email"] = "invalid_email_format"
	}

	if len(req.Account) < minAccountLength {
		validationErrors["account"] = "account_too_short"
	}

	var complexity passwordComplexity
	if len(req.Password) < minPasswordLength {
		validationErrors["password"] = "password_too_short"
	} else {
		complexity = passwordComplexityFlags(req.Password)
		if !complexity.hasUpper {
			validationErrors["password"] = "password_no_uppercase"
		} else if !complexity.hasNumber {
			validationErrors["password"] = "password_no_number"
		} else if !complexity.hasSpecial {
			validationErrors["password"] = "password_no_special_char"
		}
	}

	if len(validationErrors) == 0 {
		return "", nil
	}

	return primaryRegisterError(validationErrors, req.Password, complexity), validationErrors
}

func validateLoginInput(req LoginRequest) map[string]string {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.Account) == "" {
		validationErrors["account"] = "account_required"
	}
	if req.Password == "" {
		validationErrors["password"] = "password_required"
	}

	if len(validationErrors) == 0 {
		return nil
	}

	return validationErrors
}

func validateRefreshInput(req RefreshRequest) map[string]string {
	validationErrors := make(map[string]string)

	if strings.TrimSpace(req.RefreshToken) == "" {
		validationErrors["refresh_token"] = "refresh_token_required"
	}

	if len(validationErrors) == 0 {
		return nil
	}

	return validationErrors
}

func passwordComplexityFlags(password []byte) passwordComplexity {
	var complexity passwordComplexity
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			complexity.hasUpper = true
		case char >= '0' && char <= '9':
			complexity.hasNumber = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			complexity.hasSpecial = true
		}
		if complexity.hasUpper && complexity.hasNumber && complexity.hasSpecial {
			break
		}
	}

	return complexity
}

func primaryRegisterError(details map[string]string, password []byte, complexity passwordComplexity) string {
	errCode := ErrInvalidEmail
	if _, hasAccountErr := details["account"]; hasAccountErr {
		errCode = ErrAccountTooShort
	}
	if _, hasPasswordErr := details["password"]; hasPasswordErr {
		if len(password) < minPasswordLength {
			errCode = ErrPasswordTooShort
		} else if !complexity.hasUpper {
			errCode = ErrPasswordNoUppercase
		} else if !complexity.hasNumber {
			errCode = ErrPasswordNoNumber
		} else if !complexity.hasSpecial {
			errCode = ErrPasswordNoSpecialChar
		}
	}

	return errCode
}
