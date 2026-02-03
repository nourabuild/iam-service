// Package app provides HTTP handlers for the IAM service.
package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	sentrygo "github.com/getsentry/sentry-go"
	"github.com/nourabuild/iam-service/internal/sdk/jwt"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	db     sqldb.Service
	sentry *sentry.SentryService
	jwt    *jwt.TokenService
}

func NewApp(
	db sqldb.Service,
	sentry *sentry.SentryService,
	jwt *jwt.TokenService,
) *App {
	return &App{
		db:     db,
		sentry: sentry,
		jwt:    jwt,
	}
}

var (
	ErrLivenessFailed     = errors.New("liveness check failed")
	ErrReadinessFailed    = errors.New("readiness check failed")
	ErrInvalidJSON        = errors.New("invalid JSON request body")
	ErrMissingFields      = errors.New("missing required fields")
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrMissingAuthHeader  = errors.New("missing authorization header")
	ErrInvalidAuthHeader  = errors.New("invalid authorization header format")
)

// =============================================================================
// Health Check Handlers
// =============================================================================

func (a *App) HandleReadiness(w http.ResponseWriter, r *http.Request) {
	// Database check
	resp, err := json.Marshal(a.db.Health())

	if err != nil {
		http.Error(w, ErrReadinessFailed.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (a *App) HandleLiveness(w http.ResponseWriter, r *http.Request) {
	// API check
	host, err := os.Hostname()
	if err != nil {
		host = "unavailable"
	}

	info := map[string]string{
		"status":     "up",
		"host":       host,
		"GOMAXPROCS": strconv.Itoa(runtime.GOMAXPROCS(0)),
	}

	jsonResp, err := json.Marshal(info)
	if err != nil {
		http.Error(w, ErrLivenessFailed.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonResp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// =============================================================================
// Auth Handlers
// =============================================================================

// RegisterRequest represents the request body for user registration

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// LoginResponse represents the response for successful login
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Account string `json:"account"`
		Email   string `json:"email"`
		IsAdmin bool   `json:"is_admin"`
	} `json:"user"`
}

func (a *App) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "parse_multipart_form")
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Debug: Print form values
	fmt.Println("Received Form Data:")
	for key, values := range r.PostForm {
		fmt.Printf("%s: %v\n", key, values)
	}

	user := models.NewUser{
		Name:            r.FormValue("name"),
		Account:         r.FormValue("account"),
		Email:           r.FormValue("email"),
		Password:        []byte(r.FormValue("password")),
		PasswordConfirm: []byte(r.FormValue("password_confirm")),
	}

	// Parse JSON request body
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "json_decode")
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Validate required fields
	if user.Name == "" || user.Account == "" || user.Email == "" || len(user.Password) == 0 {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("missing_field", getMissingField(user))
			a.sentry.CaptureMessage("Registration validation failed: missing fields")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingFields.Error()})
		return
	}

	// Validate email format (basic check)
	if !strings.Contains(user.Email, "@") || !strings.Contains(user.Email, ".") {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("email", user.Email)
			a.sentry.CaptureMessage("Registration validation failed: invalid email")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidEmail.Error()})
		return
	}

	// Validate password length
	if len(user.Password) < 8 {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("password_length", len(user.Password))
			a.sentry.CaptureMessage("Registration validation failed: password too short")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrPasswordTooShort.Error()})
		return
	}

	// Hash password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword(user.Password, bcrypt.DefaultCost)
	if err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "bcrypt_hash")
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to process password"})
		return
	}

	// Create new user
	newUser := models.NewUser{
		Name:            user.Name,
		Account:         user.Account,
		Email:           user.Email,
		Password:        hashedPassword,
		PasswordConfirm: user.PasswordConfirm,
	}

	createdUser, err := a.db.CreateUser(r.Context(), newUser)
	if err != nil {
		// Check if user already exists
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			a.sentry.WithScope(func(scope *sentrygo.Scope) {
				scope.SetTag("handler", "register")
				scope.SetExtra("error_type", "user_exists")
				scope.SetExtra("email", user.Email)
				a.sentry.CaptureMessage("Registration failed: user already exists")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUserExists.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("email", user.Email)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to create user"})
		return
	}

	// Generate JWT tokens for automatic login
	accessToken, refreshToken, err := a.jwt.GenerateTokens(r.Context(), createdUser.ID)
	if err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "jwt_generation")
			scope.SetExtra("user_id", createdUser.ID)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to generate tokens"})
		return
	}

	// Success! Return tokens and user info (same as login)
	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	response.User.ID = createdUser.ID
	response.User.Name = createdUser.Name
	response.User.Account = createdUser.Account
	response.User.Email = createdUser.Email
	response.User.IsAdmin = createdUser.IsAdmin

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// getMissingField returns which field is missing from the request
func getMissingField(req models.NewUser) string {
	if req.Name == "" {
		return "name"
	}
	if req.Account == "" {
		return "account"
	}
	if req.Email == "" {
		return "email"
	}
	if len(req.Password) == 0 {
		return "password"
	}
	if len(req.PasswordConfirm) == 0 {
		return "password_confirm"
	}
	return "unknown"
}

func (a *App) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Parse JSON request body
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "json_decode")
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Validate required fields
	if input.Email == "" || input.Password == "" {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("missing_field", func() string {
				if input.Email == "" {
					return "email"
				}
				return "password"
			}())
			a.sentry.CaptureMessage("Login validation failed: missing fields")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingFields.Error()})
		return
	}

	// Look up user by email
	user, err := a.db.GetUserByEmail(r.Context(), input.Email)
	if err != nil {
		// Don't reveal whether user exists or not - use generic error
		if errors.Is(err, sqldb.ErrDBNotFound) {
			a.sentry.WithScope(func(scope *sentrygo.Scope) {
				scope.SetTag("handler", "login")
				scope.SetExtra("error_type", "user_not_found")
				scope.SetExtra("email", input.Email)
				a.sentry.CaptureMessage("Login failed: user not found")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidCredentials.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("email", input.Email)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to process login"})
		return
	}

	// Compare password with hashed password
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(input.Password)); err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "invalid_password")
			scope.SetExtra("email", input.Email)
			scope.SetExtra("user_id", user.ID)
			a.sentry.CaptureMessage("Login failed: invalid password")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidCredentials.Error()})
		return
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := a.jwt.GenerateTokens(r.Context(), user.ID)
	if err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "jwt_generation")
			scope.SetExtra("user_id", user.ID)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to generate tokens"})
		return
	}

	// Success! Return tokens and user info
	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	response.User.ID = user.ID
	response.User.Name = user.Name
	response.User.Account = user.Account
	response.User.Email = user.Email
	response.User.IsAdmin = user.IsAdmin

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (a *App) HandleRefresh(w http.ResponseWriter, r *http.Request) {

}

func (a *App) HandleWhoAmI(w http.ResponseWriter, r *http.Request) {
	// Extract Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "missing_auth_header")
			a.sentry.CaptureMessage("WhoAmI failed: missing authorization header")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingAuthHeader.Error()})
		return
	}

	// Extract token from "Bearer <token>" format
	token, err := extractBearerToken(authHeader)
	if err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "invalid_auth_header")
			scope.SetExtra("auth_header", authHeader)
			a.sentry.CaptureMessage("WhoAmI failed: invalid authorization header format")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidAuthHeader.Error()})
		return
	}

	// Parse and validate JWT token
	claims, err := a.jwt.ParseAccessToken(r.Context(), token)
	if err != nil {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "jwt_parse_error")
			a.sentry.CaptureException(err)
		})

		// Determine appropriate error message
		errorMsg := ErrUnauthorized.Error()
		if errors.Is(err, jwt.ErrExpiredToken) {
			errorMsg = "token has expired"
		} else if errors.Is(err, jwt.ErrInvalidToken) {
			errorMsg = "invalid token"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: errorMsg})
		return
	}

	// Get user ID from token claims
	userID := claims.Subject
	if userID == "" {
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "missing_subject")
			a.sentry.CaptureMessage("WhoAmI failed: token missing subject")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUnauthorized.Error()})
		return
	}

	// Look up user by ID
	user, err := a.db.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			a.sentry.WithScope(func(scope *sentrygo.Scope) {
				scope.SetTag("handler", "whoami")
				scope.SetExtra("error_type", "user_not_found")
				scope.SetExtra("user_id", userID)
				a.sentry.CaptureMessage("WhoAmI failed: user not found")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUserNotFound.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentrygo.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("user_id", userID)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to retrieve user"})
		return
	}

	// Success! Return user info
	response := models.User{
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
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// extractBearerToken extracts the token from "Bearer <token>" format
func extractBearerToken(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", ErrInvalidAuthHeader
	}
	return parts[1], nil
}
