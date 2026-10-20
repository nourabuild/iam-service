package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nourabuild/iam-service/internal/sdk/models"
	sentrysvc "github.com/nourabuild/iam-service/internal/services/sentry"
)

func writeError(c *gin.Context, status int, errCode string, details map[string]string) {
	response := gin.H{
		"error": errCode,
	}

	if len(details) > 0 {
		response["details"] = details
	}

	c.JSON(status, response)
}

func writeRequestError(c *gin.Context, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeError(c, http.StatusRequestEntityTooLarge, "request_too_large", nil)
		return
	}
	writeError(c, http.StatusBadRequest, "invalid_request_body", nil)
}

// normalizeEmail canonicalizes an email address so lookups and the unique
// index on lower(email) agree: User@X.com and user@x.com are the same identity.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// =============================================================================
func (a *Server) storeRefreshToken(ctx context.Context, userID, refreshToken string, expiresAt time.Time) error {
	_, err := a.db.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    userID,
		Token:     []byte(refreshToken),
		ExpiresAt: expiresAt,
	})
	return err
}

// outboxHeaders builds the correlation headers stored alongside an outbox
// event, falling back to the affected user ID only when no request ID exists.
func outboxHeaders(requestID, fallback string) map[string]string {
	correlationID := requestID
	if correlationID == "" {
		correlationID = fallback
	}
	if correlationID == "" {
		return nil
	}
	return map[string]string{models.HeaderCorrelationID: correlationID}
}

func requestID(c *gin.Context) string {
	if value := c.GetString("request_id"); value != "" {
		return value
	}
	return c.GetHeader("X-Request-ID")
}

func (a *Server) report(c *gin.Context, handler, errType string, level slog.Level, err error) {
	a.reportBackground(c.Request.Context(), handler, errType, level, err, requestID(c))
}

func (a *Server) reportBackground(ctx context.Context, handler, errType string, level slog.Level, err error, requestID string) {
	tags := map[string]string{
		"handler":    handler,
		"error_type": errType,
	}
	if requestID != "" {
		tags["request_id"] = requestID
	}

	attrs := []any{
		"handler", handler,
		"error_type", errType,
		"error", err,
	}
	if requestID != "" {
		attrs = append(attrs, "request_id", requestID)
	}
	slog.Default().Log(ctx, level, "application_error", attrs...)
	sentrysvc.CaptureException(ctx, err, sentrysvc.LevelFromSlog(level), tags)
}
