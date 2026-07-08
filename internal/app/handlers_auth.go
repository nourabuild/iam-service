package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8
	// maxPasswordLength is bcrypt's hard input limit: GenerateFromPassword
	// returns an error beyond 72 bytes, so reject it as validation instead.
	maxPasswordLength = 72
	minAccountLength  = 6
	bcryptCost        = bcrypt.DefaultCost

	maxRegisterFormMemory int64 = 10 << 20 // 10 MB

	resetTokenLength = 32            // 32 bytes = 64 hex characters
	resetTokenTTL    = 1 * time.Hour // Token expires in 1 hour
)

var generateFromPassword = bcrypt.GenerateFromPassword

type LoginRequest struct {
	Email    string `json:"email"`
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
	ctx := c.Request.Context()
	if err := parseMultipartOrForm(c.Request, maxRegisterFormMemory); err != nil {
		a.report(c, "register", "parse_form", slog.LevelError, err)
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	account := strings.TrimSpace(c.PostForm("account"))
	email := normalizeEmail(c.PostForm("email"))
	password := c.PostForm("password")
	passwordConfirm := c.PostForm("password_confirm")

	req := models.NewUser{
		Name:            name,
		Account:         account,
		Email:           email,
		Password:        []byte(password),
		PasswordConfirm: []byte(passwordConfirm),
	}

	errCode, validationErrors := validateRegisterInput(req)
	if errCode != "" {
		writeError(c, http.StatusBadRequest, errCode, validationErrors)
		return
	}

	hashedPassword, err := generateFromPassword(req.Password, bcryptCost)
	if err != nil {
		a.report(c, "register", "bcrypt", slog.LevelError, err)
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

	// The UserCreated event is written to the outbox in the same transaction
	// as the user row; the relay delivers it to Kafka at-least-once.
	requestID := c.GetHeader("X-Request-ID")
	createdUser, err := a.db.CreateUser(ctx, newUser, func(u models.User) *models.OutboxMessage {
		return &models.OutboxMessage{
			Topic: kafka.ProduceTopicUserCreated,
			Key:   u.ID,
			Payload: models.UserCreatedEvent{
				EventType:  "UserCreated",
				UserID:     u.ID,
				Name:       u.Name,
				Email:      u.Email,
				Account:    u.Account,
				IsAdmin:    u.IsAdmin,
				Role:       u.Role,
				OccurredAt: time.Now().UTC(),
			},
			Headers: outboxHeaders(requestID, u.ID),
		}
	})
	if err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			writeError(c, http.StatusConflict, "user_already_exists", nil)
			return
		}
		a.report(c, "register", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_user_error", nil)
		return
	}

	tokenPair, err := a.jwt.IssuePair(createdUser, time.Now().UTC())
	if err != nil {
		a.report(c, "register", "jwt", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.storeRefreshToken(ctx, createdUser.ID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		a.report(c, "register", "db_token", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (a *App) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.report(c, "login", "unmarshal", slog.LevelError, err)
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if validationErrors := validateLoginInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_credentials", nil)
			return
		}
		a.report(c, "login", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_login_error", nil)
		return
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_credentials", nil)
		return
	}

	tokenPair, err := a.jwt.IssuePair(user, time.Now().UTC())
	if err != nil {
		a.report(c, "login", "jwt", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), user.ID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		a.report(c, "login", "db_token", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (a *App) HandleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.report(c, "refresh", "unmarshal", slog.LevelError, err)
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if validationErrors := validateRefreshInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	storedToken, err := a.db.GetRefreshTokenByToken(c.Request.Context(), []byte(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.report(c, "refresh", "db", slog.LevelError, err)
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	// Reuse detection: if a token that was already rotated (revoked) shows up
	// again, treat it as evidence of theft. Burn every refresh token for this
	// user so both the attacker and the legitimate client are forced back
	// through full authentication.
	if storedToken.RevokedAt != nil {
		if delErr := a.db.DeleteRefreshTokensByUserID(c.Request.Context(), storedToken.UserID); delErr != nil {
			a.report(c, "refresh", "db_revoke_all", slog.LevelError, delErr)
		}
		a.report(c, "refresh", "reuse_detected", slog.LevelWarn,
			errors.New("revoked refresh token replayed"))
		writeError(c, http.StatusUnauthorized, "invalid_token", nil)
		return
	}

	if time.Now().UTC().After(storedToken.ExpiresAt) {
		writeError(c, http.StatusUnauthorized, "expired_token", nil)
		return
	}

	user, err := a.db.GetUserByID(c.Request.Context(), storedToken.UserID)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.report(c, "refresh", "db_user", slog.LevelError, err)
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	// Rotate: issue a fresh (access, refresh) pair and retire the presented one.
	tokenPair, err := a.jwt.IssuePair(user, time.Now().UTC())
	if err != nil {
		a.report(c, "refresh", "jwt_generate", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.storeRefreshToken(c.Request.Context(), storedToken.UserID, tokenPair.RefreshToken, tokenPair.RefreshTokenExpiresAt); err != nil {
		a.report(c, "refresh", "db_token", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if err := a.db.RevokeRefreshToken(c.Request.Context(), storedToken.ID); err != nil {
		// Old token survived as un-revoked: surface for ops but don't fail the
		// request — the new token is already issued and stored.
		a.report(c, "refresh", "db_revoke", slog.LevelWarn, err)
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
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
	if len(req.PasswordConfirm) == 0 {
		validationErrors["password_confirm"] = "password_confirm_required"
	}

	if len(validationErrors) > 0 {
		return "missing_required_fields", validationErrors
	}

	if !bytes.Equal(req.Password, req.PasswordConfirm) {
		validationErrors["password_confirm"] = "password_mismatch"
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
	} else if len(req.Password) > maxPasswordLength {
		validationErrors["password"] = "password_too_long"
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

	if strings.TrimSpace(req.Email) == "" {
		validationErrors["email"] = "email_required"
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
	if _, hasConfirmErr := details["password_confirm"]; hasConfirmErr {
		errCode = "password_mismatch"
	}
	if _, hasAccountErr := details["account"]; hasAccountErr {
		errCode = "account_too_short"
	}
	if _, hasPasswordErr := details["password"]; hasPasswordErr {
		if len(password) < minPasswordLength {
			errCode = "password_too_short"
		} else if len(password) > maxPasswordLength {
			errCode = "password_too_long"
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
	Token           string `json:"token"` // Optional in body, can come from query param
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// HandleForgotPassword handles password reset requests.
//
// The response body is intentionally identical for "user exists" and "user
// does not exist" — including on internal failures — so the endpoint cannot
// be used to probe for registered emails. Operational failures are reported
// through structured logs instead of the client.
func (a *App) HandleForgotPassword(c *gin.Context) {
	const genericMessage = "If the email exists, a password reset link has been sent"
	respondGeneric := func() {
		c.JSON(http.StatusOK, gin.H{"message": genericMessage})
	}

	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.Email = normalizeEmail(req.Email)

	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, sqldb.ErrDBNotFound) {
			a.report(c, "forgot_password", "db", slog.LevelError, err)
		}
		respondGeneric()
		return
	}

	token, err := generateSecureToken(resetTokenLength)
	if err != nil {
		a.report(c, "forgot_password", "token_generation", slog.LevelError, err)
		respondGeneric()
		return
	}

	if _, err := a.db.CreatePasswordResetToken(c.Request.Context(), models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	}); err != nil {
		a.report(c, "forgot_password", "db", slog.LevelError, err)
		respondGeneric()
		return
	}

	if err := a.mailtrap.SendPasswordResetEmail(user.Email, token); err != nil {
		a.report(c, "forgot_password", "email", slog.LevelError, err)
	}

	respondGeneric()
}

// HandleResetPassword handles password reset with token
func (a *App) HandleResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	// Get token from query parameter if not in request body
	if req.Token == "" {
		req.Token = c.Query("token")
	}

	// Validate token is present
	if req.Token == "" {
		writeError(c, http.StatusBadRequest, "missing_reset_token", map[string]string{
			"token": "token_required",
		})
		return
	}

	// Validate passwords match (input validation, not an auth failure)
	if req.Password != req.PasswordConfirm {
		writeError(c, http.StatusBadRequest, "password_mismatch", map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.Password); err != nil {
		writeError(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Atomically redeem the reset token: it is marked used in the same
	// statement that validates it, so a concurrent request presenting the
	// same token loses the race and gets "invalid_or_expired".
	resetToken, err := a.db.ConsumePasswordResetToken(c.Request.Context(), req.Token)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusBadRequest, "invalid_or_expired_reset_token", nil)
			return
		}
		a.report(c, "reset_password", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_reset_password_error", nil)
		return
	}

	// Hash new password
	hashedPassword, err := generateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		a.report(c, "reset_password", "bcrypt", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Update user password
	err = a.db.UpdateUserPassword(c.Request.Context(), resetToken.UserID, hashedPassword)
	if err != nil {
		a.report(c, "reset_password", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_reset_password_error", nil)
		return
	}

	// Optionally revoke all refresh tokens for security
	err = a.db.DeleteRefreshTokensByUserID(c.Request.Context(), resetToken.UserID)
	if err != nil {
		// Log error but don't fail the request
		a.report(c, "reset_password", "db", slog.LevelWarn, err)
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
	if len(password) > maxPasswordLength {
		return errors.New("password_too_long")
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
