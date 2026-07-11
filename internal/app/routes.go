// Package app provides HTTP handlers for the IAM service.
package app

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/observability"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Per-IP rate-limit policy. Credential endpoints are the tightest; refresh
// and user reads are looser; health checks are exempt.
//
// This is basic protection for development and early deployments. Long-term
// enforcement belongs at the API gateway, applied consistently across all
// services (see README.md) — do not grow this into a distributed limiter.
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

const maxJSONBodyBytes int64 = 1 << 20 // 1 MB

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

func (a *App) RegisterRoutes(cfg config.Config) *gin.Engine {
	router := gin.New()
	logger := slog.Default()

	// Only honour X-Forwarded-For from proxies we control; otherwise a client
	// can spoof its IP to dodge per-IP rate limits and pollute logs. An empty
	// TRUSTED_PROXIES (the default) trusts no proxy at all.
	if err := router.SetTrustedProxies(cfg.HTTP.TrustedProxies); err != nil {
		slog.Error("set trusted proxies; forwarding headers disabled", "error", err)
		_ = router.SetTrustedProxies(nil)
	}

	// Global middleware chain
	router.Use(middleware.RequestID())      // Correlation IDs
	router.Use(middleware.Recovery(logger)) // Panic recovery
	if cfg.Sentry.DSN != "" {
		router.Use(sentry.SentryMiddleware(cfg.Sentry))
		router.Use(sentry.SentryRequestContext())
	}
	router.Use(observability.Tracing())                                           // Distributed request traces
	router.Use(middleware.Logger(logger))                                         // Custom slog logger
	router.Use(observability.Metrics())                                           // HTTP request metrics
	router.Use(middleware.SecurityHeaders())                                      // Conservative response headers
	router.Use(middleware.CORS(cfg.CORS.AllowOrigins, cfg.CORS.AllowCredentials)) // CORS support

	// Deployments should restrict this operational endpoint at the ingress or
	// service-network layer.
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

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
			auth.POST("/register", middleware.RateLimit(credRate, credBurst), middleware.BodyLimit(maxRegisterBodyBytes), a.HandleRegister)
			auth.POST("/login", middleware.RateLimit(credRate, credBurst), middleware.BodyLimit(maxJSONBodyBytes), a.HandleLogin)
			auth.POST("/refresh", middleware.RateLimit(refreshRate, refreshBurst), middleware.BodyLimit(maxJSONBodyBytes), a.HandleRefresh)
			auth.POST("/password/forgot", middleware.RateLimit(pwResetRate, pwResetBurst), middleware.BodyLimit(maxJSONBodyBytes), a.HandleForgotPassword)
			auth.POST("/password/reset", middleware.RateLimit(pwResetRate, pwResetBurst), middleware.BodyLimit(maxJSONBodyBytes), a.HandleResetPassword)
		}

		// User routes (protected - requires authentication)
		user := v1.Group("/user")
		user.Use(middleware.RateLimit(userRate, userBurst))
		user.Use(middleware.BodyLimit(maxJSONBodyBytes))
		user.Use(middleware.Authenticate(a.jwt))
		if cfg.Sentry.DSN != "" {
			user.Use(sentry.SentryPrincipal())
		}
		{
			user.GET("/me", a.HandleMe)
			user.POST("/me/password/change", a.HandlePasswordChange)
			user.POST("/me/account", a.HandleUpdateAccount)
		}

		// Admin routes (protected - requires admin role)
		admin := v1.Group("/admin")
		admin.Use(middleware.RateLimit(adminRate, adminBurst))
		admin.Use(middleware.BodyLimit(maxJSONBodyBytes))
		admin.Use(middleware.Authenticate(a.jwt))
		if cfg.Sentry.DSN != "" {
			admin.Use(sentry.SentryPrincipal())
		}
		admin.Use(middleware.AuthorizeAdmin())
		{
			admin.GET("/users", a.HandleListUsers)
			admin.POST("/:user_id/roles/grant", a.HandleGrantAdminRole)
			admin.POST("/:user_id/roles/revoke", a.HandleRevokeAdminRole)
		}
	}

	return router
}
