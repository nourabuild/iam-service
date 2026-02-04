package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthorizeAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get is_admin from context (set by Authenticate middleware).
		isAdminVal, exists := c.Get(IsAdminKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		isAdmin, ok := isAdminVal.(bool)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}
