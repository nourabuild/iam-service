package app

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/sentry"
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
func (a *App) storeRefreshToken(ctx context.Context, userID, refreshToken string, ttl time.Duration) error {
	expiresAt := time.Now().UTC().Add(ttl)
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

// =============================================================================
func (a *App) toSentry(c *gin.Context, handler, errType string, level sentry.Level, err error) {
	a.toSentryBackground(handler, errType, level, err, c.GetHeader("X-Request-ID"))
}

// toSentryBackground reports an error without touching the request context,
// so it is safe to call from goroutines that outlive the handler.
func (a *App) toSentryBackground(handler, errType string, level sentry.Level, err error, requestID string) {
	a.sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("handler", handler)
		scope.SetExtra("error_type", errType)
		scope.SetLevel(level)
		if requestID != "" {
			scope.SetTag("request_id", requestID)
		}
		a.sentry.CaptureException(err)
	})
}
