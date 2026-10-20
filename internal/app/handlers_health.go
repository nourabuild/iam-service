package app

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nourabuild/iam-service/internal/sdk/models"
)

var osHostname = os.Hostname

// handleReadiness reports whether this instance can serve traffic. A non-200
// status takes the instance out of rotation, so the DB being unreachable must
// surface as 503 — not as a 200 with "down" in the body.
func (a *Server) handleReadiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
	defer cancel()

	dbStats := a.db.Stats()
	stats := map[string]string{
		"open_connections":    strconv.Itoa(dbStats.OpenConnections),
		"in_use":              strconv.Itoa(dbStats.InUse),
		"idle":                strconv.Itoa(dbStats.Idle),
		"wait_count":          strconv.FormatInt(dbStats.WaitCount, 10),
		"wait_duration":       dbStats.WaitDuration.String(),
		"max_idle_closed":     strconv.FormatInt(dbStats.MaxIdleClosed, 10),
		"max_lifetime_closed": strconv.FormatInt(dbStats.MaxLifetimeClosed, 10),
	}
	status := http.StatusOK
	if err := a.db.Ping(ctx); err != nil {
		status = http.StatusServiceUnavailable
		stats["status"] = "down"
		stats["error"] = "database unavailable"
	} else {
		stats["status"] = "up"
		stats["message"] = "It's healthy"
	}

	// Kafka is optional-but-degraded: the service runs without it, but
	// operators need to see that events are not being published.
	if a.producer != nil {
		stats["kafka"] = "enabled"
	} else {
		stats["kafka"] = "disabled"
	}

	c.JSON(status, stats)
}

func (a *Server) handleLiveness(c *gin.Context) {
	host, err := osHostname()
	if err != nil || host == "" {
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
