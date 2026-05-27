package middleware

import (
	"net/http"
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
	// Bypass under gin.TestMode: handler tests fire many requests from the
	// same (empty) client IP, which would always trip the limiter and obscure
	// the behavior under test. Production and dev modes are unaffected.
	if gin.Mode() == gin.TestMode {
		return func(c *gin.Context) { c.Next() }
	}

	store := newLimiterStore(r, burst)

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !store.allow(ip) {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

// limiterStore is a concurrency-safe map of IP -> token bucket. An idle bucket
// is evicted by a background sweeper after evictAfter elapses with no use,
// so a steady stream of unique IPs can't grow the map without bound.
type limiterStore struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     rate.Limit
	burst    int
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const evictAfter = 10 * time.Minute

func newLimiterStore(r rate.Limit, burst int) *limiterStore {
	s := &limiterStore{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    burst,
	}
	go s.sweep()
	return s
}

func (s *limiterStore) allow(ip string) bool {
	s.mu.Lock()
	v, ok := s.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(s.rate, s.burst)}
		s.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	limiter := v.limiter
	s.mu.Unlock()
	return limiter.Allow()
}

func (s *limiterStore) sweep() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-evictAfter)
		s.mu.Lock()
		for ip, v := range s.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(s.visitors, ip)
			}
		}
		s.mu.Unlock()
	}
}
