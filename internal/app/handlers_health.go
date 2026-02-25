package app

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

func (a *App) HandleReadiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)

	c.JSON(http.StatusOK, a.db.Health())
}

func (a *App) HandleLiveness(c *gin.Context) {
	host, _ := os.Hostname()
	if host == "" {
		host = "unavailable"
	}

	c.JSON(http.StatusOK, models.Liveness{
		Status:     "up",
		Host:       host,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	})
}
