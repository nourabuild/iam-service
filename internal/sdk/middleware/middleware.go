package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func GetClaims(c *gin.Context) (string, error) {
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
