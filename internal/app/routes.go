package app

import (
	"net/http"

	"github.com/nourabuild/iam-service/internal/sdk/middleware"
)

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

// RegisterRoutes configures all application routes and returns the HTTP handler
func (a *App) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	a.registerHealthRoutes(mux)
	a.registerAuthRoutes(mux)
	a.registerUserRoutes(mux)

	// Built-in CSRF Protection
	// csrf := http.NewCrossOriginProtection()
	// csrf.AddTrustedOrigin("http://localhost:8080")
	// csrf.AddTrustedOrigin("https://api.meets.noura.software")
	// return csrf.Handler

	mid := []middleware.MidFunc{
		middleware.OtelMiddleware(a.tracer),
		middleware.CorsMiddleware,
		middleware.LoggingMiddleware,
	}

	return middleware.WrapMiddleware(mux, mid...)
}

// registerHealthRoutes configures health check endpoints
func (a *App) registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health/readiness", a.HandleReadinessCheck)
	mux.HandleFunc("GET /api/v1/health/liveness", a.HandleLivenessCheck)
}

// registerAuthRoutes configures authentication endpoints
func (a *App) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", a.HandleLogin)
	mux.HandleFunc("POST /api/v1/auth/register", a.HandleRegister)
	mux.HandleFunc("POST /api/v1/auth/refresh", a.HandleTokenRefresh)
}

// registerUserRoutes configures user management endpoints
func (a *App) registerUserRoutes(mux *http.ServeMux) {
	// Password management
	mux.HandleFunc("POST /api/v1/users/password/forgot", a.HandlePasswordForgotRequest)
	mux.HandleFunc("POST /api/v1/users/password/forgot/confirm", a.HandlePasswordForgotConfirm)
	mux.Handle("POST /api/v1/users/password/reset", middleware.AuthMiddleware(http.HandlerFunc(a.HandlePasswordReset)))

	// Current user operations (protected)
	mux.Handle("GET /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(a.HandleGetCurrentUser)))
	mux.Handle("PATCH /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(a.HandleUpdateCurrentUser)))
	mux.Handle("DELETE /api/v1/users/me", middleware.AuthMiddleware(http.HandlerFunc(a.HandleDeleteCurrentUser)))

	// User lookup and search
	mux.Handle("GET /api/v1/users/{account}/profile", middleware.AuthMiddleware(http.HandlerFunc(a.HandleGetUserProfile)))
	mux.HandleFunc("GET /api/v1/users/{account}/public", a.HandleGetPublicUserProfile)
	mux.HandleFunc("POST /api/v1/users/search", a.HandleSearchUsers)
}
