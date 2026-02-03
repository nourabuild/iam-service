package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// GetUserID fetches the authenticated user ID from the request context.
func GetUserID(c *gin.Context) (string, error) {
	userID, ok := c.Get(UserIDKey)
	if !ok {
		return "", errors.New("user_id not found in context")
	}

	id, ok := userID.(string)
	if !ok || id == "" {
		return "", errors.New("invalid user_id in context")
	}

	return id, nil
}
