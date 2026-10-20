package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

type tokenParser interface {
	ParseAccessToken(string) (models.Principal, error)
}

// Authenticate validates the Authorization header and attaches user context.
func Authenticate(tokens tokenParser) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_authorization_header"})
			c.Abort()
			return
		}

		// Expect "Bearer <token>" format.
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_authorization_header"})
			c.Abort()
			return
		}

		principal, err := tokens.ParseAccessToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if principal.ID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if !principal.Role.Valid() {
			principal.Role = models.RoleUser
		}

		SetPrincipal(c, principal)
		c.Next()
	}
}
