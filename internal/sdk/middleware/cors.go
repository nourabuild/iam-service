package middleware

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS returns a configured CORS middleware for Gin
func CORS() gin.HandlerFunc {
	allowOrigins := parseOrigins(os.Getenv("CORS_ALLOW_ORIGINS"))
	allowCredentials := strings.EqualFold(os.Getenv("CORS_ALLOW_CREDENTIALS"), "true")
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
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: allowCredentials,
		MaxAge:           12 * time.Hour,
	}

	return cors.New(config)
}

func parseOrigins(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin != "" {
			origins = append(origins, origin)
		}
	}

	return origins
}
