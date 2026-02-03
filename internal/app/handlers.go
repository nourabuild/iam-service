package app

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLength = 8
	minAccountLength  = 6
	bcryptCost        = bcrypt.DefaultCost
)

const (
	ErrUnmarshal             = "invalid_request_body"
	ErrMissingFields         = "missing_required_fields"
	ErrInvalidEmail          = "invalid_email"
	ErrPasswordTooShort      = "password_too_short"
	ErrPasswordNoUppercase   = "password_must_contain_uppercase"
	ErrPasswordNoNumber      = "password_must_contain_number"
	ErrPasswordNoSpecialChar = "password_must_contain_special_character"
	ErrAccountTooShort       = "account_too_short"
	ErrUserExists            = "user_already_exists"
	ErrInvalidCredentials    = "invalid_credentials"
	ErrUnauthorized          = "unauthorized"
	ErrForbidden             = "forbidden"
	ErrHashPassword          = "internal_hash_error"
	ErrCreateUser            = "internal_create_user_error"
	ErrProcessLogin          = "internal_login_error"
	ErrRetrieveUsers         = "internal_retrieve_users_error"
	ErrGenerateTokens        = "internal_generate_tokens_error"
	ErrExpiredToken          = "expired_token"
	ErrInvalidToken          = "invalid_token"
	ErrMissingAuthHeader     = "missing_authorization_header"
	ErrInvalidAuthHeader     = "invalid_authorization_header"
	ErrUserNotFound          = "user_not_found"
	ErrVerifyUser            = "internal_verify_user_error"
)

var errorStatusMap = map[string]int{
	ErrUnmarshal:             http.StatusBadRequest,
	ErrMissingFields:         http.StatusBadRequest,
	ErrInvalidEmail:          http.StatusBadRequest,
	ErrPasswordTooShort:      http.StatusBadRequest,
	ErrPasswordNoUppercase:   http.StatusBadRequest,
	ErrPasswordNoNumber:      http.StatusBadRequest,
	ErrPasswordNoSpecialChar: http.StatusBadRequest,
	ErrAccountTooShort:       http.StatusBadRequest,
	ErrUserExists:            http.StatusConflict,
	ErrInvalidCredentials:    http.StatusUnauthorized,
	ErrUnauthorized:          http.StatusUnauthorized,
	ErrForbidden:             http.StatusForbidden,
	ErrHashPassword:          http.StatusInternalServerError,
	ErrCreateUser:            http.StatusInternalServerError,
	ErrProcessLogin:          http.StatusInternalServerError,
	ErrRetrieveUsers:         http.StatusInternalServerError,
	ErrGenerateTokens:        http.StatusInternalServerError,
	ErrExpiredToken:          http.StatusUnauthorized,
	ErrInvalidToken:          http.StatusUnauthorized,
	ErrMissingAuthHeader:     http.StatusUnauthorized,
	ErrInvalidAuthHeader:     http.StatusUnauthorized,
	ErrUserNotFound:          http.StatusUnauthorized,
	ErrVerifyUser:            http.StatusInternalServerError,
}

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

type UserResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Account   string    `json:"account"`
	Email     string    `json:"email"`
	Bio       *string   `json:"bio,omitempty"`
	DOB       *string   `json:"dob,omitempty"`
	City      *string   `json:"city,omitempty"`
	Phone     *string   `json:"phone,omitempty"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

type LivenessResponse struct {
	Status     string `json:"status"`
	Host       string `json:"host"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}

type App struct {
	db     sqldb.Service
	sentry *sentry.SentryService
	jwt    *jwt.TokenService
}

func NewApp(db sqldb.Service, sentry *sentry.SentryService, jwt *jwt.TokenService) *App {
	return &App{db: db, sentry: sentry, jwt: jwt}
}

func (a *App) HandleReadiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)

	c.JSON(http.StatusOK, a.db.Health())
}

func (a *App) HandleLiveness(c *gin.Context) {
	host, _ := os.Hostname()
	if host == "" {
		host = "unavailable"
	}

	c.JSON(http.StatusOK, LivenessResponse{
		Status:     "up",
		Host:       host,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	})
}

func (a *App) HandleRegister(c *gin.Context) {
	// Parse multipart form (for future file uploads)
	if err := c.Request.ParseMultipartForm(10 << 20); err != nil { // 10 MB max
		// Try JSON as fallback
		if err := c.Request.ParseForm(); err != nil {
			a.toSentry(c, "register", "parse_form", sentry.LevelError, err)
			status, ok := errorStatusMap[ErrUnmarshal]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrUnmarshal})
			return
		}
	}

	// Get form values
	name := c.PostForm("name")
	account := c.PostForm("account")
	email := c.PostForm("email")
	password := c.PostForm("password")

	// Create request object
	req := models.NewUser{
		Name:     name,
		Account:  account,
		Email:    email,
		Password: []byte(password),
	}

	// Collect all validation errors
	validationErrors := make(map[string]string)

	// Check for missing fields
	if req.Name == "" {
		validationErrors["name"] = "name_required"
	}
	if req.Account == "" {
		validationErrors["account"] = "account_required"
	}
	if req.Email == "" {
		validationErrors["email"] = "email_required"
	}
	if len(req.Password) == 0 {
		validationErrors["password"] = "password_required"
	}

	// If we have missing fields, return early
	if len(validationErrors) > 0 {
		status, ok := errorStatusMap[ErrMissingFields]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{
			Error:   ErrMissingFields,
			Details: validationErrors,
		})
		return
	}

	// Validate email format
	if _, err := mail.ParseAddress(req.Email); err != nil {
		validationErrors["email"] = "invalid_email_format"
	}

	// Validate account length
	if len(req.Account) < minAccountLength {
		validationErrors["account"] = "account_too_short"
	}

	// Validate password length
	if len(req.Password) < minPasswordLength {
		validationErrors["password"] = "password_too_short"
	}

	// Validate password complexity
	var hasUpper, hasNumber, hasSpecial bool
	for _, char := range string(req.Password) {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			hasSpecial = true
		}
	}

	if !hasUpper {
		validationErrors["password"] = "password_no_uppercase"
	} else if !hasNumber {
		validationErrors["password"] = "password_no_number"
	} else if !hasSpecial {
		validationErrors["password"] = "password_no_special_char"
	}

	// If we have any validation errors, return them
	if len(validationErrors) > 0 {
		// Determine the primary error code
		errCode := ErrInvalidEmail
		if _, hasAccountErr := validationErrors["account"]; hasAccountErr {
			errCode = ErrAccountTooShort
		}
		if _, hasPasswordErr := validationErrors["password"]; hasPasswordErr {
			if len(req.Password) < minPasswordLength {
				errCode = ErrPasswordTooShort
			} else if !hasUpper {
				errCode = ErrPasswordNoUppercase
			} else if !hasNumber {
				errCode = ErrPasswordNoNumber
			} else if !hasSpecial {
				errCode = ErrPasswordNoSpecialChar
			}
		}

		status, ok := errorStatusMap[errCode]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{
			Error:   errCode,
			Details: validationErrors,
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(req.Password, bcryptCost)
	if err != nil {
		a.toSentry(c, "register", "bcrypt", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrHashPassword]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrHashPassword})
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
			status, ok := errorStatusMap[ErrUserExists]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrUserExists})
			return
		}
		a.toSentry(c, "register", "db", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrCreateUser]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrCreateUser})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), createdUser.ID, createdUser.IsAdmin)
	if err != nil {
		a.toSentry(c, "register", "jwt", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	// Store refresh token in database
	refreshTokenExpiry := time.Now().Add(7 * 24 * time.Hour) // 7 days
	_, err = a.db.CreateRefreshToken(c.Request.Context(), models.NewRefreshToken{
		UserID:    createdUser.ID,
		Token:     []byte(refreshToken),
		ExpiresAt: refreshTokenExpiry,
	})
	if err != nil {
		a.toSentry(c, "register", "db_token", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "login", "unmarshal", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrUnmarshal]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrUnmarshal})
		return
	}

	// Collect all validation errors
	validationErrors := make(map[string]string)

	// Check for missing fields
	if req.Account == "" {
		validationErrors["account"] = "account_required"
	}
	if req.Password == "" {
		validationErrors["password"] = "password_required"
	}

	// If we have missing fields, return early
	if len(validationErrors) > 0 {
		status, ok := errorStatusMap[ErrMissingFields]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{
			Error:   ErrMissingFields,
			Details: validationErrors,
		})
		return
	}

	user, err := a.db.GetUserByAccount(c.Request.Context(), req.Account)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			status, ok := errorStatusMap[ErrInvalidCredentials]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrInvalidCredentials})
			return
		}
		a.toSentry(c, "login", "db", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrProcessLogin]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrProcessLogin})
		return
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
		status, ok := errorStatusMap[ErrInvalidCredentials]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrInvalidCredentials})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), user.ID, user.IsAdmin)
	if err != nil {
		a.toSentry(c, "login", "jwt", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	// Store refresh token in database
	refreshTokenExpiry := time.Now().Add(30 * 24 * time.Hour) // 30 days
	_, err = a.db.CreateRefreshToken(c.Request.Context(), models.NewRefreshToken{
		UserID:    user.ID,
		Token:     []byte(refreshToken),
		ExpiresAt: refreshTokenExpiry,
	})
	if err != nil {
		a.toSentry(c, "login", "db_token", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (a *App) HandleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.toSentry(c, "refresh", "unmarshal", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrUnmarshal]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrUnmarshal})
		return
	}

	// Collect all validation errors
	validationErrors := make(map[string]string)

	// Check for missing fields
	if req.RefreshToken == "" {
		validationErrors["refresh_token"] = "refresh_token_required"
	}

	// If we have missing fields, return early
	if len(validationErrors) > 0 {
		status, ok := errorStatusMap[ErrMissingFields]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{
			Error:   ErrMissingFields,
			Details: validationErrors,
		})
		return
	}

	// Parse refresh token to validate JWT
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
		status, ok := errorStatusMap[errCode]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: errCode})
		return
	}

	// Check if refresh token exists in database and is not revoked
	storedToken, err := a.db.GetRefreshTokenByToken(c.Request.Context(), []byte(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			status, ok := errorStatusMap[ErrInvalidToken]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrInvalidToken})
			return
		}
		a.toSentry(c, "refresh", "db", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrUnauthorized]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrUnauthorized})
		return
	}

	// Check if token is revoked
	if storedToken.RevokedAt != nil {
		status, ok := errorStatusMap[ErrInvalidToken]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrInvalidToken})
		return
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		status, ok := errorStatusMap[ErrExpiredToken]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrExpiredToken})
		return
	}

	// Generate new tokens
	accessToken, newRefreshToken, err := a.jwt.GenerateTokens(c.Request.Context(), claims.Subject, claims.IsAdmin)
	if err != nil {
		a.toSentry(c, "refresh", "jwt_generate", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	// Revoke old refresh token
	if err := a.db.RevokeRefreshToken(c.Request.Context(), storedToken.ID); err != nil {
		a.toSentry(c, "refresh", "db_revoke", sentry.LevelError, err)
		// Don't fail the request if revocation fails, just log it
	}

	// Store new refresh token in database
	refreshTokenExpiry := time.Now().Add(30 * 24 * time.Hour) // 30 days
	_, err = a.db.CreateRefreshToken(c.Request.Context(), models.NewRefreshToken{
		UserID:    claims.Subject,
		Token:     []byte(newRefreshToken),
		ExpiresAt: refreshTokenExpiry,
	})
	if err != nil {
		a.toSentry(c, "refresh", "db_token", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrGenerateTokens]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrGenerateTokens})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{AccessToken: accessToken, RefreshToken: newRefreshToken})
}

func (a *App) HandleWhoAmI(c *gin.Context) {
	userID, err := middleware.GetClaims(c)
	if err != nil {
		status, ok := errorStatusMap[ErrUnauthorized]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrUnauthorized})
		return
	}

	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "whoami", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			status, ok := errorStatusMap[ErrUserNotFound]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrUserNotFound})
		} else {
			status, ok := errorStatusMap[ErrVerifyUser]
			if !ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, ErrorResponse{Error: ErrVerifyUser})
		}
		return
	}

	c.JSON(http.StatusOK, UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Account:   user.Account,
		Email:     user.Email,
		Bio:       user.Bio,
		DOB:       user.DOB,
		City:      user.City,
		Phone:     user.Phone,
		IsAdmin:   user.IsAdmin,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

func (a *App) HandleListUsers(c *gin.Context) {
	users, err := a.db.ListUsers(c.Request.Context())
	if err != nil {
		a.toSentry(c, "list_users", "db", sentry.LevelError, err)
		status, ok := errorStatusMap[ErrRetrieveUsers]
		if !ok {
			status = http.StatusInternalServerError
		}
		c.JSON(status, ErrorResponse{Error: ErrRetrieveUsers})
		return
	}

	response := make([]UserResponse, 0, len(users))
	for _, u := range users {
		response = append(response, UserResponse{
			ID:        u.ID,
			Name:      u.Name,
			Account:   u.Account,
			Email:     u.Email,
			Bio:       u.Bio,
			DOB:       u.DOB,
			City:      u.City,
			Phone:     u.Phone,
			IsAdmin:   u.IsAdmin,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

func (a *App) toSentry(c *gin.Context, handler, errType string, level sentry.Level, err error) {
	a.sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("handler", handler)
		scope.SetExtra("error_type", errType)
		scope.SetLevel(level)
		if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
			scope.SetTag("request_id", reqID)
		}
		a.sentry.CaptureException(err)
	})
}
