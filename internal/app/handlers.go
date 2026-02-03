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
	"time"

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
	ErrForbidden          = errors.New("forbidden: admin access required")
)

// =============================================================================
// Middleware
// =============================================================================

// RequireAdmin is middleware that checks if the user is an admin
func (a *App) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "missing_auth_header")
				scope.SetLevel(sentry.LevelWarning)
				a.sentry.CaptureMessage("Admin check failed: missing authorization header")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingAuthHeader.Error()})
			return
		}

		// Extract token from "Bearer <token>" format
		token, err := extractBearerToken(authHeader)
		if err != nil {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "invalid_auth_header")
				scope.SetLevel(sentry.LevelWarning)
				a.sentry.CaptureMessage("Admin check failed: invalid authorization header")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidAuthHeader.Error()})
			return
		}

		// Parse and validate JWT token
		claims, err := a.jwt.ParseAccessToken(r.Context(), token)
		if err != nil {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "jwt_parse_error")
				scope.SetLevel(sentry.LevelError)
				a.sentry.CaptureException(err)
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUnauthorized.Error()})
			return
		}

		// Get user ID from token
		userID := claims.Subject
		if userID == "" {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "missing_subject")
				scope.SetLevel(sentry.LevelWarning)
				a.sentry.CaptureMessage("Admin check failed: token missing subject")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUnauthorized.Error()})
			return
		}

		// Look up user to check admin status
		user, err := a.db.GetUserByID(r.Context(), userID)
		if err != nil {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "user_not_found")
				scope.SetExtra("user_id", userID)
				scope.SetLevel(sentry.LevelError)
				a.sentry.CaptureException(err)
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUnauthorized.Error()})
			return
		}

		// Check if user is admin
		if !user.IsAdmin {
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("middleware", "admin")
				scope.SetExtra("error_type", "not_admin")
				scope.SetExtra("user_id", userID)
				scope.SetExtra("email", user.Email)
				scope.SetLevel(sentry.LevelInfo)
				a.sentry.CaptureMessage("Admin check failed: user is not an admin")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrForbidden.Error()})
			return
		}

		// User is admin, proceed to next handler
		next(w, r)
	}
}

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

func (a *App) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "parse_multipart_form")
			scope.SetLevel(sentry.LevelError)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "json_decode")
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Validate required fields
	if user.Name == "" || user.Account == "" || user.Email == "" || len(user.Password) == 0 {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("missing_field", getMissingField(user))
			scope.SetLevel(sentry.LevelInfo)
			a.sentry.CaptureMessage("Registration validation failed: missing fields")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingFields.Error()})
		return
	}

	// Validate email format (basic check)
	if !strings.Contains(user.Email, "@") || !strings.Contains(user.Email, ".") {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("email", user.Email)
			scope.SetLevel(sentry.LevelInfo)
			a.sentry.CaptureMessage("Registration validation failed: invalid email")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidEmail.Error()})
		return
	}

	// Validate password length
	if len(user.Password) < 8 {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("password_length", len(user.Password))
			scope.SetLevel(sentry.LevelInfo)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "bcrypt_hash")
			scope.SetLevel(sentry.LevelError)
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
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("handler", "register")
				scope.SetExtra("error_type", "user_exists")
				scope.SetExtra("email", user.Email)
				scope.SetLevel(sentry.LevelInfo)
				a.sentry.CaptureMessage("Registration failed: user already exists")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUserExists.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("email", user.Email)
			scope.SetLevel(sentry.LevelError)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "register")
			scope.SetExtra("error_type", "jwt_generation")
			scope.SetExtra("user_id", createdUser.ID)
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to generate tokens"})
		return
	}

	// Success! Return tokens
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}); err != nil {
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "json_decode")
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Validate required fields
	if input.Email == "" || input.Password == "" {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "validation")
			scope.SetExtra("missing_field", func() string {
				if input.Email == "" {
					return "email"
				}
				return "password"
			}())
			scope.SetLevel(sentry.LevelInfo)
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
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("handler", "login")
				scope.SetExtra("error_type", "user_not_found")
				scope.SetExtra("email", input.Email)
				scope.SetLevel(sentry.LevelInfo)
				a.sentry.CaptureMessage("Login failed: user not found")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidCredentials.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("email", input.Email)
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to process login"})
		return
	}

	// Compare password with hashed password
	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(input.Password)); err != nil {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "invalid_password")
			scope.SetExtra("email", input.Email)
			scope.SetExtra("user_id", user.ID)
			scope.SetLevel(sentry.LevelInfo)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "login")
			scope.SetExtra("error_type", "jwt_generation")
			scope.SetExtra("user_id", user.ID)
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to generate tokens"})
		return
	}

	// Success! Return tokens
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (a *App) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}

	// Parse JSON request body
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "refresh")
			scope.SetExtra("error_type", "json_decode")
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrInvalidJSON.Error()})
		return
	}

	// Validate refresh token field
	if input.RefreshToken == "" {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "refresh")
			scope.SetExtra("error_type", "validation")
			scope.SetLevel(sentry.LevelInfo)
			a.sentry.CaptureMessage("Refresh failed: missing refresh token")
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: ErrMissingFields.Error()})
		return
	}

	// Generate new tokens using refresh token
	accessToken, refreshToken, err := a.jwt.RefreshTokens(r.Context(), input.RefreshToken)
	if err != nil {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "refresh")
			scope.SetExtra("error_type", "jwt_refresh_error")
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		// Determine appropriate error message
		errorMsg := ErrUnauthorized.Error()
		if errors.Is(err, jwt.ErrExpiredToken) {
			errorMsg = "refresh token has expired"
		} else if errors.Is(err, jwt.ErrInvalidToken) {
			errorMsg = "invalid refresh token"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: errorMsg})
		return
	}

	// Success! Return new tokens
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (a *App) HandleWhoAmI(w http.ResponseWriter, r *http.Request) {
	// Extract Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "missing_auth_header")
			scope.SetLevel(sentry.LevelWarning)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "invalid_auth_header")
			scope.SetExtra("auth_header", authHeader)
			scope.SetLevel(sentry.LevelWarning)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "jwt_parse_error")
			scope.SetLevel(sentry.LevelError)
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
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "missing_subject")
			scope.SetLevel(sentry.LevelWarning)
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
			a.sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetTag("handler", "whoami")
				scope.SetExtra("error_type", "user_not_found")
				scope.SetExtra("user_id", userID)
				scope.SetLevel(sentry.LevelWarning)
				a.sentry.CaptureMessage("WhoAmI failed: user not found")
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Error: ErrUserNotFound.Error()})
			return
		}

		// Database error
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "whoami")
			scope.SetExtra("error_type", "database")
			scope.SetExtra("user_id", userID)
			scope.SetLevel(sentry.LevelError)
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

func (a *App) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	// Get all users from database
	users, err := a.db.ListUsers(r.Context())
	if err != nil {
		a.sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("handler", "list_users")
			scope.SetExtra("error_type", "database")
			scope.SetLevel(sentry.LevelError)
			a.sentry.CaptureException(err)
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "failed to retrieve users"})
		return
	}

	// Transform users to exclude sensitive data (passwords)
	type UserResponse struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Account   string    `json:"account"`
		Email     string    `json:"email"`
		Bio       *string   `json:"bio"`
		DOB       *string   `json:"dob"`
		City      *string   `json:"city"`
		Phone     *string   `json:"phone"`
		IsAdmin   bool      `json:"is_admin"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	response := make([]UserResponse, len(users))
	for i, user := range users {
		response[i] = UserResponse{
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
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// =============================================================================
// Helpers
// =============================================================================

// extractBearerToken extracts the token from "Bearer <token>" format
func extractBearerToken(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", ErrInvalidAuthHeader
	}
	return parts[1], nil
}
