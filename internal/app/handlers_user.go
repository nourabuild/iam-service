package app

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"golang.org/x/crypto/bcrypt"
)

// userUpdatedOutbox builds the outbox event announcing a user's new state,
// written transactionally with the mutation that produced it.
func userUpdatedOutbox(requestID string) sqldb.OutboxEventFunc {
	return func(user models.User) *models.OutboxMessage {
		return &models.OutboxMessage{
			Topic: kafka.ProduceTopicUserUpdated,
			Key:   user.ID,
			Payload: models.UserUpdatedEvent{
				EventType:     "UserUpdated",
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
				Role:          user.Role,
				OccurredAt:    time.Now().UTC(),
			},
			Headers: outboxHeaders(requestID, user.ID),
		}
	}
}

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

	user, err := a.db.UpdateUser(ctx, userID, req, userUpdatedOutbox(requestID(c)))
	if err != nil {
		if errors.Is(err, sqldb.ErrDBDuplicatedEntry) {
			writeError(c, http.StatusConflict, "account_already_taken", nil)
			return
		}
		a.report(c, "update_account", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_update_account_error", nil)
		return
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
		a.report(c, "whoami", "db", slog.LevelError, err)
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
		a.report(c, "list_users", "db", slog.LevelError, err)
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

	user, err := a.db.PromoteUserToAdmin(ctx, userID, userUpdatedOutbox(requestID(c)))
	if err != nil {
		a.report(c, "promote_user", "db", slog.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			// The *target* user doesn't exist; the caller's auth is fine.
			writeError(c, http.StatusNotFound, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_promote_user_error", nil)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (a *App) HandleRevokeAdminRole(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		writeError(c, http.StatusBadRequest, "invalid_user_id", nil)
		return
	}

	user, err := a.db.DemoteUserFromAdmin(c.Request.Context(), userID, userUpdatedOutbox(requestID(c)))
	if err != nil {
		a.report(c, "demote_user", "db", slog.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			// The *target* user doesn't exist; the caller's auth is fine.
			writeError(c, http.StatusNotFound, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_demote_user_error", nil)
		return
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

	// Validate new passwords match. This is input validation, not an auth
	// failure — a 401 here would trip frontend auto-logout interceptors.
	if req.NewPassword != req.PasswordConfirm {
		writeError(c, http.StatusBadRequest, "password_mismatch", map[string]string{
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
		a.report(c, "change_password", "db", slog.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, http.StatusUnauthorized, "user_not_found", nil)
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
		return
	}

	// Verify current password. 400 rather than 401: the bearer token is
	// valid, the user just mistyped — don't trigger client-side logout.
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(req.CurrentPassword))
	if err != nil {
		writeError(c, http.StatusBadRequest, "password_mismatch", map[string]string{
			"field": "current_password",
		})
		return
	}

	// Hash new password
	hashedPassword, err := generateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		a.report(c, "change_password", "bcrypt", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_hash_error", nil)
		return
	}

	// Update the password and revoke all refresh sessions atomically.
	err = a.db.UpdateUserPasswordAndRevokeTokens(c.Request.Context(), userID, hashedPassword)
	if err != nil {
		a.report(c, "change_password", "db", slog.LevelError, err)
		writeError(c, http.StatusInternalServerError, "internal_update_password_error", nil)
		return
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
