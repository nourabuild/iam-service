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
			user.POST("/password/change", a.HandlePasswordChange) // Change password with current password (authenticated).
		}

		// Admin routes (protected - requires admin role)
		admin := v1.Group("/admin")
		admin.Use(middleware.Authenticate(a.jwt))
		admin.Use(middleware.AuthorizeAdmin())
		{
			admin.GET("/users", a.HandleListUsers)
			// // make admin post
			admin.POST("/:user_id/roles/grant", a.HandleGrantAdminRole)
		}
	}

	return router
}
