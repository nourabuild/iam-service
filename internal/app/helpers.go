package app

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/services/kafka"
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

// normalizeEmail canonicalizes an email address so lookups and the unique
// index on lower(email) agree: User@X.com and user@x.com are the same identity.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// =============================================================================
func (a *App) storeRefreshToken(ctx context.Context, userID, refreshToken string, expiresAt time.Time) error {
	_, err := a.db.CreateRefreshToken(ctx, models.NewRefreshToken{
		UserID:    userID,
		Token:     []byte(refreshToken),
		ExpiresAt: expiresAt,
	})
	return err
}

// outboxHeaders builds the correlation headers stored alongside an outbox
// event: the inbound X-Request-ID when present, otherwise the user ID.
func outboxHeaders(requestID, fallback string) map[string]string {
	correlationID := requestID
	if correlationID == "" {
		correlationID = fallback
	}
	if correlationID == "" {
		return nil
	}
	return map[string]string{kafka.HeaderCorrelationID: correlationID}
}

func (a *App) report(c *gin.Context, handler, errType string, level slog.Level, err error) {
	requestID := c.GetHeader("X-Request-ID")
	if value := c.GetString("request_id"); value != "" {
		requestID = value
	}
	a.reportBackground(c.Request.Context(), handler, errType, level, err, requestID)
}

func (a *App) reportBackground(ctx context.Context, handler, errType string, level slog.Level, err error, requestID string) {
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
