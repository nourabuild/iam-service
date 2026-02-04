package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

const (
	resetTokenLength = 32                // 32 bytes = 64 hex characters
	resetTokenTTL    = 1 * time.Hour     // Token expires in 1 hour
)

// ForgotPasswordRequest represents the request body for forgot password
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents the request body for password reset
type ResetPasswordRequest struct {
	Token           string `json:"token" binding:"required"`
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// ChangePasswordRequest represents the request body for password change
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	PasswordConfirm string `json:"password_confirm" binding:"required"`
}

// HandleForgotPassword handles password reset requests
func (a *App) HandleForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, ErrUnmarshal, nil)
		return
	}

	// Get user by email
	user, err := a.db.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			// Don't reveal if email exists or not (security best practice)
			// Return success even if user not found
			c.JSON(http.StatusOK, gin.H{
				"message": "If the email exists, a password reset link has been sent",
			})
			return
		}
		a.toSentry(c, "forgot_password", "db", sentry.LevelError, err)
		writeError(c, ErrCreateResetToken, nil)
		return
	}

	// Generate secure random token
	token, err := generateSecureToken(resetTokenLength)
	if err != nil {
		a.toSentry(c, "forgot_password", "token_generation", sentry.LevelError, err)
		writeError(c, ErrCreateResetToken, nil)
		return
	}

	// Create password reset token in database
	_, err = a.db.CreatePasswordResetToken(c.Request.Context(), models.NewPasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	})
	if err != nil {
		a.toSentry(c, "forgot_password", "db", sentry.LevelError, err)
		writeError(c, ErrCreateResetToken, nil)
		return
	}

	// Send password reset email
	err = a.email.SendPasswordResetEmail(user.Email, token)
	if err != nil {
		a.toSentry(c, "forgot_password", "email", sentry.LevelError, err)
		writeError(c, ErrSendResetEmail, nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// HandleResetPassword handles password reset with token
func (a *App) HandleResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, ErrUnmarshal, nil)
		return
	}

	// Validate passwords match
	if req.Password != req.PasswordConfirm {
		writeError(c, ErrPasswordMismatch, map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.Password); err != nil {
		writeError(c, err.Error(), nil)
		return
	}

	// Get and validate reset token
	resetToken, err := a.db.GetPasswordResetToken(c.Request.Context(), req.Token)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrInvalidResetToken, nil)
			return
		}
		a.toSentry(c, "reset_password", "db", sentry.LevelError, err)
		writeError(c, ErrResetPassword, nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		a.toSentry(c, "reset_password", "bcrypt", sentry.LevelError, err)
		writeError(c, ErrHashPassword, nil)
		return
	}

	// Update user password
	err = a.db.UpdateUserPassword(c.Request.Context(), resetToken.UserID, hashedPassword)
	if err != nil {
		a.toSentry(c, "reset_password", "db", sentry.LevelError, err)
		writeError(c, ErrResetPassword, nil)
		return
	}

	// Mark token as used
	err = a.db.MarkPasswordResetTokenAsUsed(c.Request.Context(), resetToken.ID)
	if err != nil {
		// Log error but don't fail the request since password was already updated
		a.toSentry(c, "reset_password", "db", sentry.LevelWarning, err)
	}

	// Optionally revoke all refresh tokens for security
	err = a.db.DeleteRefreshTokensByUserID(c.Request.Context(), resetToken.UserID)
	if err != nil {
		// Log error but don't fail the request
		a.toSentry(c, "reset_password", "db", sentry.LevelWarning, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password has been reset successfully",
	})
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

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// validatePassword validates password complexity requirements
func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return errors.New(ErrPasswordTooShort)
	}

	complexity := passwordComplexityFlags([]byte(password))
	if !complexity.hasUpper {
		return errors.New(ErrPasswordNoUppercase)
	}
	if !complexity.hasNumber {
		return errors.New(ErrPasswordNoNumber)
	}
	if !complexity.hasSpecial {
		return errors.New(ErrPasswordNoSpecialChar)
	}

	return nil
}
