package app

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
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

// =============================================================================
func (a *App) toSentry(c *gin.Context, handler, errType string, level sentry.Level, err error) {
	a.sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("handler", handler)
		scope.SetExtra("error_type", errType)
		scope.SetLevel(level)
		if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
			scope.SetTag("request_id", reqID)
		}
		a.sentry.CaptureException(err)
	})
}
