// Package middleware provides HTTP middleware for authentication and authorization.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nourabuild/iam-service/internal/sdk/errs"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

const principalKey = "principal"

// GetUserID fetches the authenticated user ID from the request context.
func SetPrincipal(c *gin.Context, principal models.Principal) {
	c.Set(principalKey, principal)
}

func Principal(c *gin.Context) (models.Principal, error) {
	value, ok := c.Get(principalKey)
	if !ok {
		return models.Principal{}, errs.ErrUnauthorized
	}
	principal, ok := value.(models.Principal)
	if !ok || principal.ID == "" {
		return models.Principal{}, errs.ErrUnauthorized
	}
	return principal, nil
}

func RequirePrincipal(c *gin.Context) models.Principal {
	principal, err := Principal(c)
	if err != nil {
		panic(err)
	}
	return principal
}

func ParseUUIDParam(c *gin.Context, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		return uuid.Nil, errs.New(http.StatusBadRequest, "invalid_id")
	}
	return id, nil
}

func GetUserID(c *gin.Context) (string, error) {
	principal, err := Principal(c)
	if err != nil {
		return "", err
	}
	return principal.ID, nil
}
