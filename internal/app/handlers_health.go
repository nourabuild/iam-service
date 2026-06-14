package app

import (
	"net/http"
	"os"
	"runtime"

	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/models"
)

var osHostname = os.Hostname

// HandleReadiness reports whether this instance can serve traffic. A non-200
// status takes the instance out of rotation, so the DB being unreachable must
// surface as 503 — not as a 200 with "down" in the body.
func (a *App) HandleReadiness(c *gin.Context) {
	stats := a.db.Health()

	// Kafka is optional-but-degraded: the service runs without it, but
	// operators need to see that events are not being published.
	if a.kafka != nil {
		stats["kafka"] = "enabled"
	} else {
		stats["kafka"] = "disabled"
	}

	status := http.StatusOK
	if stats["status"] != "up" {
		status = http.StatusServiceUnavailable
	}

	c.JSON(status, stats)
}

func (a *App) HandleLiveness(c *gin.Context) {
	host, _ := osHostname()
	if host == "" {
		host = "unavailable"
		c.JSON(http.StatusServiceUnavailable, models.Liveness{
			Status:     "down",
			Host:       host,
			GOMAXPROCS: runtime.GOMAXPROCS(0),
		})
		return
	}

	c.JSON(http.StatusOK, models.Liveness{
		Status:     "up",
		Host:       host,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	})
}
