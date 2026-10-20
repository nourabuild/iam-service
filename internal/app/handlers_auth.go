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
	"golang.org/x/crypto/bcrypt"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
)

const (
	minPasswordLength = 8
	// maxPasswordLength is bcrypt's hard input limit: GenerateFromPassword
	// returns an error beyond 72 bytes, so reject it as validation instead.
	maxPasswordLength = 72
	minAccountLength  = 6
	bcryptCost        = bcrypt.DefaultCost

	maxRegisterBodyBytes int64 = 10 << 20 // 10 MB

	resetTokenLength = 32            // 32 bytes = 64 hex characters
	resetTokenTTL    = 1 * time.Hour // Token expires in 1 hour
)

var generateFromPassword = bcrypt.GenerateFromPassword
var generateResetToken = generateSecureToken
var readRandomBytes = rand.Read

// dummyPasswordHash equalizes the expensive bcrypt path for unknown users so
// login response timing does not reveal whether an email is registered.
var dummyPasswordHash = []byte("$2a$10$Vt2o6/8XZ46Ga5QIXQGDUuW8fBES0LtU7EKi2TlCSnk2kGkN.a6XK")

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type registerRequest struct {
	Name            string
	Account         string
	Email           string
	Password        []byte
	PasswordConfirm []byte
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

func (a *Server) handleRegister(c *gin.Context) {
	ctx := c.Request.Context()
	if err := parseMultipartOrForm(c.Request, maxRegisterBodyBytes); err != nil {
		writeRequestError(c, err)
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	account := strings.TrimSpace(c.PostForm("account"))
	email := normalizeEmail(c.PostForm("email"))
	password := c.PostForm("password")
	passwordConfirm := c.PostForm("password_confirm")

	req := registerRequest{
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
		Name:     req.Name,
		Account:  req.Account,
		Email:    req.Email,
		Password: hashedPassword,
	}

	// The UserCreated event is written to the outbox in the same transaction
	// as the user row; the relay delivers it to Kafka at-least-once.
	correlationID := requestID(c)
	createdUser, err := a.db.CreateUser(ctx, newUser, func(u models.User) *models.OutboxMessage {
		return &models.OutboxMessage{
			Topic: models.TopicUserCreated,
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
			Headers: outboxHeaders(correlationID, u.ID),
		}
	})
	if err != nil {
		if errors.Is(err, sqldb.ErrDuplicate) {
			writeError(c, http.StatusConflict, "user_already_exists", nil)
			return
		}
		a.report(c, "register", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_create_user_error", nil)
		return
	}

	tokenPair, err := a.tokens.IssuePair(createdUser, time.Now().UTC())
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

	c.JSON(http.StatusCreated, tokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (a *Server) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeRequestError(c, err)
		return
	}

	req.Email = normalizeEmail(req.Email)

	if validationErrors := validateLoginInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sqldb.ErrNotFound) {
			_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(req.Password))
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

	tokenPair, err := a.tokens.IssuePair(user, time.Now().UTC())
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

	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func (a *Server) handleRefresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeRequestError(c, err)
		return
	}

	req.RefreshToken = strings.TrimSpace(req.RefreshToken)

	if validationErrors := validateRefreshInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	storedToken, err := a.db.GetRefreshTokenByToken(c.Request.Context(), []byte(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sqldb.ErrNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.report(c, "refresh", "db", slog.LevelError, err)
		writeError(c, http.StatusServiceUnavailable, "service_unavailable", nil)
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
		if errors.Is(err, sqldb.ErrNotFound) {
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.report(c, "refresh", "db_user", slog.LevelError, err)
		writeError(c, http.StatusServiceUnavailable, "service_unavailable", nil)
		return
	}

	// Rotate: issue a fresh (access, refresh) pair and retire the presented one.
	tokenPair, err := a.tokens.IssuePair(user, time.Now().UTC())
	if err != nil {
		a.report(c, "refresh", "jwt_generate", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	if _, err := a.db.RotateRefreshToken(c.Request.Context(), storedToken.ID, models.NewRefreshToken{
		UserID:    storedToken.UserID,
		Token:     []byte(tokenPair.RefreshToken),
		ExpiresAt: tokenPair.RefreshTokenExpiresAt,
	}); err != nil {
		if errors.Is(err, sqldb.ErrNotFound) {
			// Another request rotated this token after our initial lookup.
			writeError(c, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		a.report(c, "refresh", "db_rotate", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_generate_tokens_error", nil)
		return
	}

	c.JSON(http.StatusOK, tokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

func validateRegisterInput(req registerRequest) (string, map[string]string) {
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

	address, err := mail.ParseAddress(req.Email)
	if err != nil || address.Address != req.Email {
		validationErrors["email"] = "invalid_email_format"
	}

	if len(req.Account) < minAccountLength {
		validationErrors["account"] = "account_too_short"
	}

	var complexity passwordComplexity
	switch {
	case len(req.Password) < minPasswordLength:
		validationErrors["password"] = "password_too_short"
	case len(req.Password) > maxPasswordLength:
		validationErrors["password"] = "password_too_long"
	default:
		complexity = passwordComplexityFlags(req.Password)
		switch {
		case !complexity.hasUpper:
			validationErrors["password"] = "password_no_uppercase"
		case !complexity.hasNumber:
			validationErrors["password"] = "password_no_number"
		case !complexity.hasSpecial:
			validationErrors["password"] = "password_no_special_char"
		}
	}

	if len(validationErrors) == 0 {
		return "", nil
	}

	return primaryRegisterError(validationErrors, req.Password, complexity), validationErrors
}

func validateLoginInput(req loginRequest) map[string]string {
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

func validateRefreshInput(req refreshRequest) map[string]string {
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
		switch {
		case len(password) < minPasswordLength:
			errCode = "password_too_short"
		case len(password) > maxPasswordLength:
			errCode = "password_too_long"
		case !complexity.hasUpper:
			errCode = "password_must_contain_uppercase"
		case !complexity.hasNumber:
			errCode = "password_must_contain_number"
		case !complexity.hasSpecial:
			errCode = "password_must_contain_special_character"
		}
	}

	return errCode
}

// ---------------------------------------------
// Password Management
// ---------------------------------------------

type forgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type resetPasswordRequest struct {
	Token           string `json:"token"` // Optional in body, can come from query param
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// handleForgotPassword handles password reset requests.
//
// The response body is intentionally identical for "user exists" and "user
// does not exist" — including on internal failures — so the endpoint cannot
// be used to probe for registered emails. Operational failures are reported
// through structured logs instead of the client.
func (a *Server) handleForgotPassword(c *gin.Context) {
	const genericMessage = "If the email exists, a password reset link has been sent"
	respondGeneric := func() {
		c.JSON(http.StatusOK, gin.H{"message": genericMessage})
	}

	var req forgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeRequestError(c, err)
		return
	}

	req.Email = normalizeEmail(req.Email)

	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, sqldb.ErrNotFound) {
			a.report(c, "forgot_password", "db", slog.LevelError, err)
		}
		respondGeneric()
		return
	}

	token, err := generateResetToken(resetTokenLength)
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

	if err := a.mailer.SendPasswordResetEmail(c.Request.Context(), user.Email, token); err != nil {
		a.report(c, "forgot_password", "email", slog.LevelError, err)
	}

	respondGeneric()
}

// handleResetPassword handles password reset with a token.
func (a *Server) handleResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeRequestError(c, err)
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

	// Hash before consuming the one-time token. A local hashing failure should
	// not force the user to request another reset email.
	hashedPassword, err := generateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		a.report(c, "reset_password", "bcrypt", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Consume the reset token, update the password, and revoke active sessions
	// in one database transaction.
	err = a.db.ResetPassword(c.Request.Context(), req.Token, hashedPassword)
	if err != nil {
		if errors.Is(err, sqldb.ErrNotFound) {
			writeError(c, http.StatusBadRequest, "invalid_or_expired_reset_token", nil)
			return
		}
		a.report(c, "reset_password", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_reset_password_error", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been reset successfully",
	})
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := readRandomBytes(bytes); err != nil {
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
