package app

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) HandleMe(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, ErrUnauthorized, nil)
		return
	}

	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "whoami", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrUserNotFound, nil)
			return
		}
		writeError(c, ErrVerifyUser, nil)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (a *App) HandleListUsers(c *gin.Context) {
	users, err := a.db.ListUsers(c.Request.Context())
	if err != nil {
		a.toSentry(c, "list_users", "db", sentry.LevelError, err)
		writeError(c, ErrRetrieveUsers, nil)
		return
	}

	c.JSON(http.StatusOK, users)
}

func (a *App) HandleGrantAdminRole(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		writeError(c, ErrInvalidUserID, nil)
		return
	}

	user, err := a.db.PromoteUserToAdmin(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "promote_user", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrUserNotFound, nil)
			return
		}
		writeError(c, ErrPromoteUser, nil)
		return
	}

	c.JSON(http.StatusOK, user)
}

// ChangePasswordRequest represents the request body for password change
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// HandlePasswordChange handles password change for authenticated users
func (a *App) HandlePasswordChange(c *gin.Context) {
	// Get authenticated user ID
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, ErrUnauthorized, nil)
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, ErrUnmarshal, nil)
		return
	}

	// Validate new passwords match
	if req.NewPassword != req.PasswordConfirm {
		writeError(c, ErrPasswordMismatch, map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(c, err.Error(), nil)
		return
	}

	// Get user from database
	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrUserNotFound, nil)
			return
		}
		writeError(c, ErrUpdatePassword, nil)
		return
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(req.CurrentPassword))
	if err != nil {
		writeError(c, ErrPasswordMismatch, map[string]string{
			"field": "current_password",
		})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		a.toSentry(c, "change_password", "bcrypt", sentry.LevelError, err)
		writeError(c, ErrHashPassword, nil)
		return
	}

	// Update password
	err = a.db.UpdateUserPassword(c.Request.Context(), userID, hashedPassword)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		writeError(c, ErrUpdatePassword, nil)
		return
	}

	// Optionally revoke all refresh tokens for security (force re-login on all devices)
	err = a.db.DeleteRefreshTokensByUserID(c.Request.Context(), userID)
	if err != nil {
		// Log error but don't fail the request
		a.toSentry(c, "change_password", "db", sentry.LevelWarning, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been changed successfully",
	})
}
