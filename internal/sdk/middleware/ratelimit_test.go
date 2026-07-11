package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/gin-gonic/gin"
)

func TestLimiterStoreEnforcesBurst(t *testing.T) {
	store := newLimiterStore(rate.Every(time.Hour), 1)
	if !store.allow("192.0.2.1") {
		t.Fatal("first request should be allowed")
	}
	if store.allow("192.0.2.1") {
		t.Fatal("second request should exhaust the burst")
	}
	if !store.allow("192.0.2.2") {
		t.Fatal("a different IP should have its own bucket")
	}
}

func TestRateLimitReturnsPolicyRetryDelay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", RateLimit(rate.Every(3*time.Second), 1), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	if got := second.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want 3", got)
	}
}

func TestLimiterStorePrunesIdleVisitors(t *testing.T) {
	store := newLimiterStore(rate.Inf, 1)
	store.visitors["stale"] = &visitor{
		limiter:  rate.NewLimiter(rate.Inf, 1),
		lastSeen: time.Now().Add(-evictAfter - time.Minute),
	}
	store.lastSweep = time.Now().Add(-2 * time.Minute)

	if !store.allow("active") {
		t.Fatal("active visitor should be allowed")
	}
	if _, ok := store.visitors["stale"]; ok {
		t.Fatal("idle visitor was not pruned")
	}
}
