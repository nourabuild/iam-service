package app

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
)

type LivenessResponse struct {
	Status     string `json:"status"`
	Host       string `json:"host"`
	GOMAXPROCS int    `json:"gomaxprocs"`
}

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

	c.JSON(http.StatusOK, LivenessResponse{
		Status:     "up",
		Host:       host,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	})
}
