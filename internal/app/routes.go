// Package app provides HTTP handlers for the IAM service.
package app

import (
	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
)

// ----------------------------------------------------------------------------
// Route Registration
// ----------------------------------------------------------------------------

func (a *App) RegisterRoutes() *gin.Engine {
	router := gin.New()

	// Global middleware chain
	router.Use(gin.Recovery())      // Panic recovery
	router.Use(middleware.Logger()) // Custom slog logger
	router.Use(middleware.CORS())   // CORS support

	// API v1 route group
	v1 := router.Group("/api/v1")
	{
		// Health check routes (public)
		health := v1.Group("/health")
		{
			health.GET("/readiness", a.HandleReadiness)
			health.GET("/liveness", a.HandleLiveness)
		}

		// Auth routes (public)
		auth := v1.Group("/auth")
		{
			auth.POST("/register", a.HandleRegister)
			auth.POST("/login", a.HandleLogin)
			auth.POST("/refresh", a.HandleRefresh)
			auth.POST("/password/forgot", a.HandleForgotPassword) // Request password reset email (public).
			auth.POST("/password/reset", a.HandleResetPassword)   // Complete password reset with email token (public).
		}

		// User routes (protected - requires authentication)
		user := v1.Group("/user")
		user.Use(middleware.Authenticate(a.jwt))
		{
			user.GET("/me", a.HandleMe)
			user.POST("/me/password/change", a.HandlePasswordChange) // Change password with current password (authenticated).
			// update my account
			user.POST("/me/account", a.HandleUpdateAccount) // Update user account information (authenticated).
		}

		// Admin routes (protected - requires admin role)
		admin := v1.Group("/admin")
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

// // Package app provides HTTP handlers for the IAM service.
// package app

// import (
// 	"github.com/gin-gonic/gin"
// 	"github.com/nourabuild/iam-service/internal/sdk/middleware"
// 	"golang.org/x/time/rate"
// )

// // Per-IP rate-limit policy. Rates are expressed as events-per-minute and
// // converted to events-per-second for rate.Limiter.
// //
// // Conservative defaults — tune by deployment. Credential endpoints are the
// // tightest; refresh and user reads are looser; health checks are exempt.
// var (
// 	credRate     = rate.Every(12 * 1e9) // 5/min  (1 every 12s)
// 	credBurst    = 5
// 	pwResetRate  = rate.Every(20 * 1e9) // 3/min  (1 every 20s)
// 	pwResetBurst = 3
// 	refreshRate  = rate.Every(2 * 1e9) // 30/min
// 	refreshBurst = 30
// 	userRate     = rate.Every(1e9) // 60/min
// 	userBurst    = 30
// 	adminRate    = rate.Every(2 * 1e9) // 30/min
// 	adminBurst   = 30
// )

// // ----------------------------------------------------------------------------
// // Route Registration
// // ----------------------------------------------------------------------------

// func (a *App) RegisterRoutes() *gin.Engine {
// 	router := gin.New()

// 	// TODO(deploy): call router.SetTrustedProxies(...) once the deployment
// 	// topology is known. The default trusts all forwarded headers, which lets
// 	// an attacker reset their rate-limit bucket by spoofing X-Forwarded-For.
// 	// See internal/sdk/middleware/ratelimit.go for context.

// 	// Global middleware chain
// 	router.Use(gin.Recovery())      // Panic recovery
// 	router.Use(middleware.Logger()) // Custom slog logger
// 	router.Use(middleware.CORS())   // CORS support

// 	// API v1 route group
// 	v1 := router.Group("/api/v1")
// 	{
// 		// Health check routes (public, unlimited — used by load balancers).
// 		health := v1.Group("/health")
// 		{
// 			health.GET("/readiness", a.HandleReadiness)
// 			health.GET("/liveness", a.HandleLiveness)
// 		}

// 		// Auth routes (public). Each endpoint group gets its own limiter
// 		// instance so traffic on /login doesn't consume budget from /refresh.
// 		auth := v1.Group("/auth")
// 		{
// 			auth.POST("/register", middleware.RateLimit(credRate, credBurst), a.HandleRegister)
// 			auth.POST("/login", middleware.RateLimit(credRate, credBurst), a.HandleLogin)
// 			auth.POST("/refresh", middleware.RateLimit(refreshRate, refreshBurst), a.HandleRefresh)
// 			auth.POST("/password/forgot", middleware.RateLimit(pwResetRate, pwResetBurst), a.HandleForgotPassword)
// 			auth.POST("/password/reset", middleware.RateLimit(pwResetRate, pwResetBurst), a.HandleResetPassword)
// 		}

// 		// User routes (protected - requires authentication)
// 		user := v1.Group("/user")
// 		user.Use(middleware.RateLimit(userRate, userBurst))
// 		user.Use(middleware.Authenticate(a.jwt))
// 		{
// 			user.GET("/me", a.HandleMe)
// 			user.POST("/me/password/change", a.HandlePasswordChange)
// 			user.POST("/me/account", a.HandleUpdateAccount)
// 		}

// 		// Admin routes (protected - requires admin role)
// 		admin := v1.Group("/admin")
// 		admin.Use(middleware.RateLimit(adminRate, adminBurst))
// 		admin.Use(middleware.Authenticate(a.jwt))
// 		admin.Use(middleware.AuthorizeAdmin())
// 		{
// 			admin.GET("/users", a.HandleListUsers)
// 			admin.POST("/:user_id/roles/grant", a.HandleGrantAdminRole)
// 			admin.POST("/:user_id/roles/revoke", a.HandleRevokeAdminRole)
// 		}
// 	}

// 	return router
// }
