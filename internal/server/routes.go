package server

import (
	"net/http"
)

// RegisterRoutes configures all application routes and returns the HTTP handler
func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	s.registerHealthRoutes(mux)
	s.registerAuthRoutes(mux)
	s.registerUserRoutes(mux)

	return WrapMiddleware(mux,
		s.corsMiddleware,
		s.loggingMiddleware,
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
	mux.Handle("POST /api/v1/users/password/reset", s.authMiddleware(http.HandlerFunc(s.handlePasswordReset)))

	// Current user operations (protected)
	mux.Handle("GET /api/v1/users/me", s.authMiddleware(http.HandlerFunc(s.handleGetCurrentUser)))
	mux.Handle("PATCH /api/v1/users/me", s.authMiddleware(http.HandlerFunc(s.handleUpdateCurrentUser)))
	mux.Handle("DELETE /api/v1/users/me", s.authMiddleware(http.HandlerFunc(s.handleDeleteCurrentUser)))

	// User lookup and search
	mux.Handle("GET /api/v1/users/{account}/profile", s.authMiddleware(http.HandlerFunc(s.handleGetUserProfile)))
	mux.HandleFunc("GET /api/v1/users/{account}/public", s.handleGetPublicUserProfile)
	mux.HandleFunc("POST /api/v1/users/search", s.handleSearchUsers)
}
