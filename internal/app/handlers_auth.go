package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
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

	resetTokenLength = 32            // 32 bytes = 64 hex characters
	resetTokenTTL    = 1 * time.Hour // Token expires in 1 hour
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
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
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
		writeError(c, http.StatusBadRequest, errCode, validationErrors)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(req.Password, bcryptCost)
	if err != nil {
		a.toSentry(c, "register", "bcrypt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
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
			writeError(c, http.StatusConflict, "user_already_exists", nil)
			return
		}
		a.toSentry(c, "register", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_user_error", nil)
		return
	}

	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), createdUser.ID, createdUser.IsAdmin)
	if err != nil {
		a.toSentry(c, "register", "jwt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), createdUser.ID, refreshToken, registerRefreshTTL); err != nil {
		a.toSentry(c, "register", "db_token", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "login", "unmarshal", sentry.LevelError, err)
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.Account = strings.TrimSpace(req.Account)

	if validationErrors := validateLoginInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	user, err := a.db.GetUserByAccount(c.Request.Context(), req.Account)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_credentials", nil)
			return
		}
		a.toSentry(c, "login", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_login_error", nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_credentials", nil)
		return
	}

	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), user.ID, user.IsAdmin)
	if err != nil {
		a.toSentry(c, "login", "jwt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), user.ID, refreshToken, authRefreshTTL); err != nil {
		a.toSentry(c, "login", "db_token", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "refresh", "unmarshal", sentry.LevelError, err)
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if validationErrors := validateRefreshInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
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
			errCode = "expired_token"
		case errors.Is(err, jwt.ErrInvalidToken):
			errCode = "invalid_token"
		default:
			errCode = "unauthorized"
		}
		writeError(c, http.StatusUnauthorized, errCode, nil)
		return
	}

	storedToken, err := a.db.GetRefreshTokenByToken(c.Request.Context(), []byte(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.toSentry(c, "refresh", "db", sentry.LevelError, err)
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	if storedToken.RevokedAt != nil {
		writeError(c, http.StatusUnauthorized, "invalid_token", nil)
		return
	}

	if time.Now().UTC().After(storedToken.ExpiresAt) {
		writeError(c, http.StatusUnauthorized, "expired_token", nil)
		return
	}

	accessToken, newRefreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), claims.Subject, claims.IsAdmin)
	if err != nil {
		a.toSentry(c, "refresh", "jwt_generate", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.db.RevokeRefreshToken(c.Request.Context(), storedToken.ID); err != nil {
		a.toSentry(c, "refresh", "db_revoke", sentry.LevelError, err)
	}

	if err := a.storeRefreshToken(c.Request.Context(), claims.Subject, newRefreshToken, authRefreshTTL); err != nil {
		a.toSentry(c, "refresh", "db_token", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
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
		return "missing_required_fields", validationErrors
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
	errCode := "invalid_email"
	if _, hasAccountErr := details["account"]; hasAccountErr {
		errCode = "account_too_short"
	}
	if _, hasPasswordErr := details["password"]; hasPasswordErr {
		if len(password) < minPasswordLength {
			errCode = "password_too_short"
		} else if !complexity.hasUpper {
			errCode = "password_must_contain_uppercase"
		} else if !complexity.hasNumber {
			errCode = "password_must_contain_number"
		} else if !complexity.hasSpecial {
			errCode = "password_must_contain_special_character"
		}
	}

	return errCode
}

// ---------------------------------------------
// Password Management
// ---------------------------------------------

// ForgotPasswordRequest represents the request body for forgot password
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents the request body for password reset
type ResetPasswordRequest struct {
	Token           string `json:"token" binding:"required"`
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// HandleForgotPassword handles password reset requests
func (a *App) HandleForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	// Get user by email
	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			// Don't reveal if email exists or not (security best practice)
			// Return success even if user not found
			c.JSON(http.StatusOK, gin.H{
				"message": "If the email exists, a password reset link has been sent",
			})
			return
		}
		a.toSentry(c, "forgot_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_reset_token_error", nil)
		return
	}

	// Generate secure random token
	token, err := generateSecureToken(resetTokenLength)
	if err != nil {
		a.toSentry(c, "forgot_password", "token_generation", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_reset_token_error", nil)
		return
	}

	// Create password reset token in database
	_, err = a.db.CreatePasswordResetToken(c.Request.Context(), models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	})
	if err != nil {
		a.toSentry(c, "forgot_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_reset_token_error", nil)
		return
	}

	// Send password reset email
	err = a.mailtrap.SendPasswordResetEmail(user.Email, token)
	if err != nil {
		a.toSentry(c, "forgot_password", "email", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_send_reset_email_error", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// HandleResetPassword handles password reset with token
func (a *App) HandleResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	// Validate passwords match
	if req.Password != req.PasswordConfirm {
		writeError(c, http.StatusUnauthorized, "password_mismatch", map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.Password); err != nil {
		writeError(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Get and validate reset token
	resetToken, err := a.db.GetPasswordResetToken(c.Request.Context(), req.Token)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusBadRequest, "invalid_or_expired_reset_token", nil)
			return
		}
		a.toSentry(c, "reset_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_reset_password_error", nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		a.toSentry(c, "reset_password", "bcrypt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Update user password
	err = a.db.UpdateUserPassword(c.Request.Context(), resetToken.UserID, hashedPassword)
	if err != nil {
		a.toSentry(c, "reset_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_reset_password_error", nil)
		return
	}

	// Mark token as used
	err = a.db.MarkPasswordResetTokenAsUsed(c.Request.Context(), resetToken.ID)
	if err != nil {
		// Log error but don't fail the request since password was already updated
		a.toSentry(c, "reset_password", "db", sentry.LevelWarning, err)
	}

	// Optionally revoke all refresh tokens for security
	err = a.db.DeleteRefreshTokensByUserID(c.Request.Context(), resetToken.UserID)
	if err != nil {
		// Log error but don't fail the request
		a.toSentry(c, "reset_password", "db", sentry.LevelWarning, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been reset successfully",
	})
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// validatePassword validates password complexity requirements
func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return errors.New("password_too_short")
	}

	complexity := passwordComplexityFlags([]byte(password))
	if !complexity.hasUpper {
		return errors.New("password_must_contain_uppercase")
	}
	if !complexity.hasNumber {
		return errors.New("password_must_contain_number")
	}
	if !complexity.hasSpecial {
		return errors.New("password_must_contain_special_character")
	}

	return nil
}
