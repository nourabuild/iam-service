package middleware

import (
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS returns configured cross-origin request middleware for Gin.
func CORS(allowOrigins []string, allowCredentials bool) gin.HandlerFunc {
	if len(allowOrigins) == 0 {
		allowOrigins = []string{"*"}
	}
	if allowCredentials && len(allowOrigins) == 1 && allowOrigins[0] == "*" {
		allowCredentials = false
		log.Print("cors: disabling credentials for wildcard origin")
	}

	config := cors.Config{
		AllowOrigins:     allowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Timezone", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: allowCredentials,
		MaxAge:           12 * time.Hour,
	}

	return cors.New(config)
}
