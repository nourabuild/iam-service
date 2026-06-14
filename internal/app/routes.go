// Package app provides HTTP handlers for the IAM service.
package app

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"golang.org/x/time/rate"
)

// Per-IP rate-limit policy. Credential endpoints are the tightest; refresh
// and user reads are looser; health checks are exempt.
//
// This is basic protection for development and early deployments. Long-term
// enforcement belongs at the API gateway, applied consistently across all
// services (see NOTES.md) — do not grow this into a distributed limiter.
var (
	credRate     = rate.Every(12 * time.Second) // 5/min
	credBurst    = 5
	pwResetRate  = rate.Every(20 * time.Second) // 3/min
	pwResetBurst = 3
	refreshRate  = rate.Every(2 * time.Second) // 30/min
	refreshBurst = 30
	userRate     = rate.Every(time.Second) // 60/min
	userBurst    = 30
	adminRate    = rate.Every(2 * time.Second) // 30/min
	adminBurst   = 30
)

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

func (a *App) RegisterRoutes() *gin.Engine {
	router := gin.New()

	// Only honour X-Forwarded-For from proxies we control; otherwise a client
	// can spoof its IP to dodge per-IP rate limits and pollute logs. An empty
	// TRUSTED_PROXIES (the default) trusts no proxy at all.
	if err := router.SetTrustedProxies(trustedProxies()); err != nil {
		slog.Warn("set trusted proxies", "error", err)
	}

	// Global middleware chain
	router.Use(gin.Recovery())      // Panic recovery
	router.Use(middleware.Logger()) // Custom slog logger
	router.Use(middleware.CORS())   // CORS support

	// API v1 route group
	v1 := router.Group("/api/v1")
	{
		// Health check routes (public, unlimited — used by load balancers).
		health := v1.Group("/health")
		{
			health.GET("/readiness", a.HandleReadiness)
			health.GET("/liveness", a.HandleLiveness)
		}

		// Auth routes (public). Each endpoint group gets its own limiter
		// instance so traffic on /login doesn't consume budget from /refresh.
		auth := v1.Group("/auth")
		{
			auth.POST("/register", middleware.RateLimit(credRate, credBurst), a.HandleRegister)
			auth.POST("/login", middleware.RateLimit(credRate, credBurst), a.HandleLogin)
			auth.POST("/refresh", middleware.RateLimit(refreshRate, refreshBurst), a.HandleRefresh)
			auth.POST("/password/forgot", middleware.RateLimit(pwResetRate, pwResetBurst), a.HandleForgotPassword)
			auth.POST("/password/reset", middleware.RateLimit(pwResetRate, pwResetBurst), a.HandleResetPassword)
		}

		// User routes (protected - requires authentication)
		user := v1.Group("/user")
		user.Use(middleware.RateLimit(userRate, userBurst))
		user.Use(middleware.Authenticate(a.jwt))
		{
			user.GET("/me", a.HandleMe)
			user.POST("/me/password/change", a.HandlePasswordChange)
			user.POST("/me/account", a.HandleUpdateAccount)
		}

		// Admin routes (protected - requires admin role)
		admin := v1.Group("/admin")
		admin.Use(middleware.RateLimit(adminRate, adminBurst))
		admin.Use(middleware.Authenticate(a.jwt))
		admin.Use(middleware.AuthorizeAdmin())
		{
			admin.GET("/users", a.HandleListUsers)
			admin.POST("/:user_id/roles/grant", a.HandleGrantAdminRole)
			admin.POST("/:user_id/roles/revoke", a.HandleRevokeAdminRole)
		}
	}

	return router
}

// trustedProxies parses TRUSTED_PROXIES, a comma-separated list of proxy IPs
// or CIDRs whose forwarding headers may be believed.
func trustedProxies() []string {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	proxies := make([]string, 0, len(parts))
	for _, part := range parts {
		if p := strings.TrimSpace(part); p != "" {
			proxies = append(proxies, p)
		}
	}
	return proxies
}
