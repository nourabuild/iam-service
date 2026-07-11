package middleware

import (
	"log/slog"
	"runtime/debug"

	"github.com/nourabuild/iam-service/internal/sdk/errs"

	"github.com/gin-gonic/gin"
)

func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		if logger != nil {
			logger.ErrorContext(c.Request.Context(), "panic recovered",
				"panic", recovered,
				"request_id", c.GetString("request_id"),
				"stack", string(debug.Stack()),
			)
		}

		c.AbortWithStatusJSON(errs.ErrInternal.Status, gin.H{
			"error": errs.ErrInternal.Key,
		})
	})
}
