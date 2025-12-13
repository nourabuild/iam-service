package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/nourabuild/iam-service/internal/sdk/errs"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/hash"
	"github.com/nourabuild/iam-service/internal/services/jwt"
)

// type app struct {
// 	db       sqldb.Service
// 	hash     *hash.HashService
// 	token    *jwt.TokenService
// 	mailtrap *mailtrap.MailtrapService
// 	sentry   *sentry.SentryService
// }

// func newApp(
// 	db sqldb.Service,
// 	hash *hash.HashService,
// 	token *jwt.TokenService,
// 	mailtrap *mailtrap.MailtrapService,
// 	sentry *sentry.SentryService,
// ) *app {
// 	return &app{
// 		db:       db,
// 		hash:     hash,
// 		token:    token,
// 		mailtrap: mailtrap,
// 		sentry:   sentry,
// 	}
// }

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, appErr *errs.Error) {
	JSON(w, appErr.HTTPStatus(), appErr)
}

// =============================================================================
// Health Check Handlers
// =============================================================================

func (s *Server) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	// Database check
	resp, err := json.Marshal(s.sqldb.Health())
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	// API check
	host, err := os.Hostname()
	if err != nil {
		host = "unavailable"
	}

	info := map[string]string{
		"status":     "up",
		"host":       host,
		"GOMAXPROCS": string(rune(runtime.GOMAXPROCS(0))),
	}

	jsonResp, err := json.Marshal(info)
	if err != nil {
		http.Error(w, "Failed to marshal health check response", http.StatusInternalServerError)
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

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	respondErr := func(code errs.ErrCode, err error, msg string, args ...any) {
		var appErr *errs.Error
		if msg != "" {
			appErr = errs.Newf(code, msg, args...)
		} else {
			appErr = errs.New(code, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		respondErr(errs.InvalidArgument, err, "")
		return
	}

	name := r.FormValue("name")
	account := r.FormValue("account")
	email := r.FormValue("email")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	// Validation
	for _, v := range []struct {
		cond bool
		msg  string
	}{
		{name == "", "name is required"},
		{len(name) < 3, "name must be at least 3 characters"},
		{len(name) > 40, "name must be at most 40 characters"},
		{account == "", "account is required"},
		{len(account) < 6, "account must be at least 6 characters"},
		{len(account) > 30, "account must be at most 30 characters"},
		{email == "", "email is required"},
		{password == "", "password is required"},
		{len(password) < 8, "password must be at least 8 characters"},
		{len(password) > 32, "password must be at most 32 characters"},
		{passwordConfirm == "", "password confirmation is required"},
		{password != passwordConfirm, "passwords do not match"},
	} {
		if v.cond {
			respondErr(errs.InvalidArgument, nil, v.msg)
			return
		}
	}

	ctx := r.Context()

	// Check email uniqueness
	if _, err := s.sqldb.GetUserByEmail(ctx, email); err == nil {
		respondErr(errs.AlreadyExists, nil, "user with email %s already exists", email)
		return
	} else if !errors.Is(err, sqldb.ErrDBNotFound) {
		respondErr(errs.Internal, err, "")
		return
	}

	// Check account uniqueness
	if _, err := s.sqldb.GetUserByAccount(ctx, account); err == nil {
		respondErr(errs.AlreadyExists, nil, "user with account %s already exists", account)
		return
	} else if !errors.Is(err, sqldb.ErrDBNotFound) {
		respondErr(errs.Internal, err, "")
		return
	}

	hashedPassword, err := hash.NewHashService().HashPassword(password)
	if err != nil {
		respondErr(errs.Internal, err, "")
		return
	}

	user, err := s.sqldb.CreateUser(ctx, models.NewUser{
		Name:     name,
		Account:  account,
		Email:    email,
		Password: []byte(hashedPassword),
	})
	if err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			respondErr(errs.AlreadyExists, nil, "user already exists")
			return
		}
		respondErr(errs.Internal, err, "")
		return
	}

	tokens, err := jwt.NewTokenService().GenerateToken(user.ID, user.Email)
	if err != nil {
		respondErr(errs.Internal, err, "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":      "Registration successful",
		"access_token": tokens.AccessToken,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	respondErr := func(code errs.ErrCode, err error, msg string, args ...any) {
		var appErr *errs.Error
		if msg != "" {
			appErr = errs.Newf(code, msg, args...)
		} else {
			appErr = errs.New(code, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
	}

	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		respondErr(errs.InvalidArgument, err, "")
		return
	}

	// Validation
	for _, v := range []struct {
		cond bool
		msg  string
	}{
		{credentials.Email == "", "email is required"},
		{credentials.Password == "", "password is required"},
	} {
		if v.cond {
			respondErr(errs.InvalidArgument, nil, v.msg)
			return
		}
	}

	ctx := r.Context()

	// Get user by email
	user, err := s.sqldb.GetUserByEmail(ctx, credentials.Email)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			respondErr(errs.Unauthenticated, nil, "invalid email or password")
			return
		}
		respondErr(errs.Internal, err, "")
		return
	}

	// Verify password
	hashService := hash.NewHashService()
	if !hashService.CheckPasswordHash(credentials.Password, string(user.Password)) {
		respondErr(errs.Unauthenticated, nil, "invalid email or password")
		return
	}

	// Generate tokens
	tokens, err := jwt.NewTokenService().GenerateToken(user.ID, user.Email)
	if err != nil {
		respondErr(errs.Internal, err, "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":       "Login successful",
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	var tokenReq struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&tokenReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: Implement token refresh logic
	// - Validate refresh token
	// - Check if token is expired or revoked
	// - Generate new access token
	// - Optionally rotate refresh token
	// - Return new tokens to client

	resp := map[string]string{
		"message":       "Token refreshed successfully",
		"access_token":  "new_placeholder_access_token",
		"refresh_token": "new_placeholder_refresh_token",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// =============================================================================
// Password Management Handlers
// =============================================================================

func (s *Server) handlePasswordForgotRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement password forgot request logic
	// - Validate email format
	// - Check if user exists with this email
	// - Generate password reset token
	// - Send reset email with token/link
	// - Store token with expiration in database

	// Always return success to prevent email enumeration attacks
	resp := map[string]string{
		"message": "If an account exists with this email, you will receive password reset instructions",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handlePasswordForgotConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement password forgot confirm logic
	// - Validate token exists and is not expired
	// - Validate new password meets requirements
	// - Hash new password
	// - Update user's password in database
	// - Invalidate reset token
	// - Optionally invalidate all existing sessions

	resp := map[string]string{
		"message": "Password has been reset successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement password reset logic (authenticated user changing their password)
	// - Get user from request context (requires auth middleware)
	// - Verify current password is correct
	// - Validate new password meets requirements
	// - Hash new password
	// - Update user's password in database
	// - Optionally invalidate other sessions

	resp := map[string]string{
		"message": "Password has been changed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// =============================================================================
// Current User Handlers
// =============================================================================

func (s *Server) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	respondErr := func(code errs.ErrCode, err error, msg string, args ...any) {
		var appErr *errs.Error
		if msg != "" {
			appErr = errs.Newf(code, msg, args...)
		} else {
			appErr = errs.New(code, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
	}

	// Get claims from context (set by auth middleware)
	claims, ok := middleware.GetClaimsFromContext(r.Context())
	if !ok {
		respondErr(errs.Unauthenticated, nil, "user not authenticated")
		return
	}

	ctx := r.Context()

	// Fetch user from database
	user, err := s.sqldb.GetUserById(ctx, claims.UserID)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			respondErr(errs.NotFound, nil, "user not found")
			return
		}
		respondErr(errs.Internal, err, "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handleUpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	var updates struct {
		Name    *string `json:"name,omitempty"`
		Account *string `json:"account,omitempty"`
		Email   *string `json:"email,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement update current user logic
	// - Get user ID from request context (requires auth middleware)
	// - Validate update fields
	// - Check for conflicts (e.g., email/account already taken)
	// - Update user in database
	// - Return updated user data

	user := models.User{
		ID:        "placeholder_id",
		Name:      "John Doe Updated",
		Account:   "johndoe",
		Email:     "john@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handleDeleteCurrentUser(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement delete current user logic
	// - Get user ID from request context (requires auth middleware)
	// - Optionally require password confirmation
	// - Soft delete or hard delete user from database
	// - Invalidate all user sessions/tokens
	// - Return success response

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// User Profile Handlers
// =============================================================================

func (s *Server) handleGetUserProfile(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if account == "" {
		appErr := errs.Newf(errs.InvalidArgument, "account parameter is required")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement get user profile logic (authenticated, full profile)
	// - Verify requester is authenticated (requires auth middleware)
	// - Fetch user by account from database
	// - Return user profile (may include more details for authenticated users)

	user := models.User{
		ID:        "placeholder_id",
		Name:      "Jane Doe",
		Account:   account,
		Email:     "jane@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handleGetPublicUserProfile(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("account")
	if account == "" {
		appErr := errs.Newf(errs.InvalidArgument, "account parameter is required")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// TODO: Implement get public user profile logic (no auth required, limited data)
	// - Fetch user by account from database
	// - Return only public profile fields (no email, etc.)

	publicProfile := struct {
		Name    string `json:"name"`
		Account string `json:"account"`
	}{
		Name:    "Jane Doe",
		Account: account,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(publicProfile); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func (s *Server) handleSearchUsers(w http.ResponseWriter, r *http.Request) {
	var searchReq struct {
		Query  string `json:"query"`
		Limit  int    `json:"limit,omitempty"`
		Offset int    `json:"offset,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&searchReq); err != nil {
		appErr := errs.New(errs.InvalidArgument, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(appErr.HTTPStatus())
		json.NewEncoder(w).Encode(appErr)
		return
	}

	// Set defaults
	if searchReq.Limit <= 0 || searchReq.Limit > 100 {
		searchReq.Limit = 20
	}

	// TODO: Implement user search logic
	// - Validate search query
	// - Search users by name, account, or email (depending on requirements)
	// - Apply pagination (limit/offset)
	// - Return matching users (public fields only)

	results := struct {
		Users  []models.User `json:"users"`
		Total  int           `json:"total"`
		Limit  int           `json:"limit"`
		Offset int           `json:"offset"`
	}{
		Users: []models.User{
			{
				ID:        "1",
				Name:      "John Doe",
				Account:   "johndoe",
				Email:     "john@example.com",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Total:  1,
		Limit:  searchReq.Limit,
		Offset: searchReq.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

// RegisterRoutes configures all application routes and returns the HTTP handler
func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	s.registerHealthRoutes(mux)
	s.registerAuthRoutes(mux)
	s.registerUserRoutes(mux)

	return middleware.WrapMiddleware(mux,
		middleware.CorsMiddleware,
		middleware.LoggingMiddleware,
	)
}

// registerHealthRoutes configures health check endpoints
func (s *Server) registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health/readiness", s.handleReadinessCheck)
	mux.HandleFunc("GET /api/v1/health/liveness", s.handleLivenessCheck)
}

// registerAuthRoutes configures authentication endpoints
func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/refresh", s.handleTokenRefresh)
}

// registerUserRoutes configures user management endpoints
func (s *Server) registerUserRoutes(mux *http.ServeMux) {
	// Password management
	mux.HandleFunc("POST /api/v1/users/password/forgot", s.handlePasswordForgotRequest)
	mux.HandleFunc("POST /api/v1/users/password/forgot/confirm", s.handlePasswordForgotConfirm)
	mux.Handle("POST /api/v1/users/password/reset", middleware.AuthMiddleware(http.HandlerFunc(s.handlePasswordReset)))

	// Current user operations (protected)
	mux.Handle("GET /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(s.handleGetCurrentUser)))
	mux.Handle("PATCH /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(s.handleUpdateCurrentUser)))
	mux.Handle("DELETE /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(s.handleDeleteCurrentUser)))

	// User lookup and search
	mux.Handle("GET /api/v1/users/{account}/profile", middleware.AuthMiddleware(http.HandlerFunc(s.handleGetUserProfile)))
	mux.HandleFunc("GET /api/v1/users/{account}/public", s.handleGetPublicUserProfile)
	mux.HandleFunc("POST /api/v1/users/search", s.handleSearchUsers)
}
