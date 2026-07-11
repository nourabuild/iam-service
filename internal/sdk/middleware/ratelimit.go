package middleware

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimit returns a per-IP token-bucket limiter as a Gin middleware.
//
//   - r is the steady-state refill rate (events per second).
//   - burst is the maximum burst the bucket can absorb before requests are
//     rejected with HTTP 429.
//
// Each instance keeps its own map of IP -> *rate.Limiter so different routes
// can apply different policies (e.g. tighter limits on /login than /me).
//
// IMPORTANT: The IP used as the key comes from gin.Context.ClientIP(), which
// honours X-Forwarded-For / X-Real-IP. If this service runs behind a proxy
// you do not control (or no proxy at all), set engine.SetTrustedProxies(...)
// so a spoofed header can't be used to reset an attacker's bucket.
func RateLimit(r rate.Limit, burst int) gin.HandlerFunc {
	store := newLimiterStore(r, burst)
	retryAfter := strconv.Itoa(retryAfterSeconds(r))

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !store.allow(ip) {
			c.Header("Retry-After", retryAfter)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

func retryAfterSeconds(limit rate.Limit) int {
	if limit <= 0 {
		return 60
	}
	if limit == rate.Inf {
		return 1
	}
	return max(1, int(math.Ceil(1/float64(limit))))
}

// limiterStore is a concurrency-safe map of IP -> token bucket. An idle bucket
// is evicted by a background sweeper after evictAfter elapses with no use,
// so a steady stream of unique IPs can't grow the map without bound.
type limiterStore struct {
	mu        sync.Mutex
	visitors  map[string]*visitor
	rate      rate.Limit
	burst     int
	lastSweep time.Time
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const evictAfter = 10 * time.Minute

func newLimiterStore(r rate.Limit, burst int) *limiterStore {
	return &limiterStore{
		visitors:  make(map[string]*visitor),
		rate:      r,
		burst:     burst,
		lastSweep: time.Now(),
	}
}

func (s *limiterStore) allow(ip string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastSweep) >= time.Minute {
		s.sweep(now.Add(-evictAfter))
		s.lastSweep = now
	}

	v, ok := s.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(s.rate, s.burst)}
		s.visitors[ip] = v
	}
	v.lastSeen = now
	return v.limiter.AllowN(now, 1)
}

// sweep removes idle visitors. The caller holds s.mu. Pruning on traffic keeps
// limiter instances bounded without leaking a background goroutine per route.
func (s *limiterStore) sweep(cutoff time.Time) {
	for ip, v := range s.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(s.visitors, ip)
		}
	}
}
