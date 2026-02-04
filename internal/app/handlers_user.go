package app

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

func (a *App) HandleWhoAmI(c *gin.Context) {
	userID, err := middleware.GetUserID(c)
	if err != nil {
		writeError(c, ErrUnauthorized, nil)
		return
	}

	user, err := a.db.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		a.toSentry(c, "whoami", "db", sentry.LevelError, err)
		if errors.Is(err, sqldb.ErrDBNotFound) {
			writeError(c, ErrUserNotFound, nil)
			return
		}
		writeError(c, ErrVerifyUser, nil)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (a *App) HandleListUsers(c *gin.Context) {
	users, err := a.db.ListUsers(c.Request.Context())
	if err != nil {
		a.toSentry(c, "list_users", "db", sentry.LevelError, err)
		writeError(c, ErrRetrieveUsers, nil)
		return
	}

	c.JSON(http.StatusOK, users)
}
