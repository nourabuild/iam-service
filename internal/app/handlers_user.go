package app

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/sentry"
	"golang.org/x/crypto/bcrypt"
)

func (a *App) HandleUpdateAccount(c *gin.Context) {
	ctx := c.Request.Context()
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	var req models.UpdateUser
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Account = strings.TrimSpace(req.Account)

	if validationErrors := validateUpdateAccountInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	user, err := a.db.UpdateUser(c.Request.Context(), userID, req)
	if err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			writeError(c, http.StatusConflict, "account_already_taken", nil)
			return
		}
		a.toSentry(c, "update_account", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_update_account_error", nil)
		return
	}

	if a.kafka != nil {
		_ = a.kafka.Produce(ctx, kafka.ProduceTopicUserUpdated, []byte(user.ID), models.UserUpdatedEvent{
			EventType:     "user.updated",
			UserID:        user.ID,
			Name:          user.Name,
			Email:         user.Email,
			Account:       user.Account,
			Bio:           user.Bio,
			DOB:           user.DOB,
			City:          user.City,
			Phone:         user.Phone,
			AvatarPhotoID: user.AvatarPhotoID,
			IsAdmin:       user.IsAdmin,
			OccurredAt:    time.Now().UTC(),
		})
	}

	c.JSON(http.StatusOK, user)
}

func validateUpdateAccountInput(req models.UpdateUser) map[string]string {
	validationErrors := make(map[string]string)
	if req.Name == "" {
		validationErrors["name"] = "name_required"
	}
	if req.Account == "" {
		validationErrors["account"] = "account_required"
	} else if len(req.Account) < minAccountLength {
		validationErrors["account"] = "account_too_short"
	}
	if len(validationErrors) == 0 {
		return nil
	}
	return validationErrors
}

func (a *App) HandleMe(c *gin.Context) {
	ctx := c.Request.Context()
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	user, err := a.db.GetUserByID(ctx, userID)
	if err != nil {
		a.toSentry(c, "whoami", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_verify_user_error", nil)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (a *App) HandleListUsers(c *gin.Context) {
	ctx := c.Request.Context()

	users, err := a.db.ListUsers(ctx)
	if err != nil {
		a.toSentry(c, "list_users", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_retrieve_users_error", nil)
		return
	}

	c.JSON(http.StatusOK, users)
}

func (a *App) HandleGrantAdminRole(c *gin.Context) {
	ctx := c.Request.Context()

	userID := c.Param("user_id")
	if userID == "" {
		writeError(c, http.StatusBadRequest, "invalid_user_id", nil)
		return
	}

	user, err := a.db.PromoteUserToAdmin(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "promote_user", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_promote_user_error", nil)
		return
	}

	if a.kafka != nil {
		_ = a.kafka.Produce(ctx, kafka.ProduceTopicUserUpdated, []byte(user.ID), models.UserUpdatedEvent{
			EventType:     "user.updated",
			UserID:        user.ID,
			Name:          user.Name,
			Email:         user.Email,
			Account:       user.Account,
			Bio:           user.Bio,
			DOB:           user.DOB,
			City:          user.City,
			Phone:         user.Phone,
			AvatarPhotoID: user.AvatarPhotoID,
			IsAdmin:       user.IsAdmin,
			OccurredAt:    time.Now().UTC(),
		})
	}

	c.JSON(http.StatusOK, user)
}

func (a *App) HandleRevokeAdminRole(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		writeError(c, http.StatusBadRequest, "invalid_user_id", nil)
		return
	}

	user, err := a.db.DemoteUserFromAdmin(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "demote_user", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_demote_user_error", nil)
		return
	}

	if a.kafka != nil {
		_ = a.kafka.Produce(c.Request.Context(), kafka.ProduceTopicUserUpdated, []byte(user.ID), models.UserUpdatedEvent{
			EventType:     "user.updated",
			UserID:        user.ID,
			Name:          user.Name,
			Email:         user.Email,
			Account:       user.Account,
			Bio:           user.Bio,
			DOB:           user.DOB,
			City:          user.City,
			Phone:         user.Phone,
			AvatarPhotoID: user.AvatarPhotoID,
			IsAdmin:       user.IsAdmin,
			OccurredAt:    time.Now().UTC(),
		})
	}

	c.JSON(http.StatusOK, user)
}

// ChangePasswordRequest represents the request body for password change
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	PasswordConfirm string `json:"password_confirm"`
}

// HandlePasswordChange handles password change for authenticated users
func (a *App) HandlePasswordChange(c *gin.Context) {
	// Get authenticated user ID
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", nil)
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
		return
	}

	if validationErrors := validatePasswordChangeInput(req); len(validationErrors) > 0 {
		writeError(c, http.StatusBadRequest, "missing_required_fields", validationErrors)
		return
	}

	// Validate new passwords match
	if req.NewPassword != req.PasswordConfirm {
		writeError(c, http.StatusUnauthorized, "password_mismatch", map[string]string{
			"field": "password_confirm",
		})
		return
	}

	// Validate password complexity
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(c, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Get user from database
	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
		return
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(req.CurrentPassword))
	if err != nil {
		writeError(c, http.StatusUnauthorized, "password_mismatch", map[string]string{
			"field": "current_password",
		})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		a.toSentry(c, "change_password", "bcrypt", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Update password
	err = a.db.UpdateUserPassword(c.Request.Context(), userID, hashedPassword)
	if err != nil {
		a.toSentry(c, "change_password", "db", sentry.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
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

func validatePasswordChangeInput(req ChangePasswordRequest) map[string]string {
	validationErrors := make(map[string]string)

	if req.CurrentPassword == "" {
		validationErrors["current_password"] = "current_password_required"
	}
	if req.NewPassword == "" {
		validationErrors["new_password"] = "new_password_required"
	}
	if req.PasswordConfirm == "" {
		validationErrors["password_confirm"] = "password_confirm_required"
	}

	if len(validationErrors) == 0 {
		return nil
	}

	return validationErrors
}
