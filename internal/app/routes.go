// Package app provides HTTP handlers for the IAM service.
package app

import (
	"net/http"
)

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

// RegisterRoutes configures all application routes and returns the HTTP handler
func (a *App) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	a.registerHealthRoutes(mux)
	a.registerAuthRoutes(mux)

	return mux
}

func (a *App) registerHealthRoutes(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc("GET /api/v1/health/readiness", a.HandleReadiness)
	mux.HandleFunc("GET /api/v1/health/liveness", a.HandleLiveness)
}

func (a *App) registerAuthRoutes(mux *http.ServeMux) {
	// Public auth routes
	mux.HandleFunc("POST /api/v1/auth/register", a.HandleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", a.HandleLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", a.HandleRefresh)

	// Protected routes
	mux.HandleFunc("GET /api/v1/user/whoami", a.HandleWhoAmI)

	// Admin-only routes
	mux.HandleFunc("GET /api/v1/admin/users", a.RequireAdmin(a.HandleListUsers))
}
