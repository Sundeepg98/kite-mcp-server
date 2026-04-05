package app

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipRateLimiter provides per-IP rate limiting.
type ipRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    burst,
	}
}

func (l *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	l.mu.RLock()
	limiter, exists := l.limiters[ip]
	l.mu.RUnlock()
	if exists {
		return limiter
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Double-check after acquiring write lock
	if limiter, exists = l.limiters[ip]; exists {
		return limiter
	}
	limiter = rate.NewLimiter(l.rate, l.burst)
	l.limiters[ip] = limiter
	return limiter
}

// cleanup removes stale entries. Active clients will recreate their limiters
// on next request. Called periodically by a background goroutine.
func (l *ipRateLimiter) cleanup() {
	l.mu.Lock()
	l.limiters = make(map[string]*rate.Limiter)
	l.mu.Unlock()
}

// rateLimiters holds all per-endpoint-group rate limiters.
type rateLimiters struct {
	auth  *ipRateLimiter // /oauth/register, /oauth/authorize, /auth/browser-login
	token *ipRateLimiter // /oauth/token
	mcp   *ipRateLimiter // /mcp, /sse, /message
	done  chan struct{}   // closed during shutdown to stop the cleanup goroutine
}

// newRateLimiters creates rate limiters for each endpoint group and starts
// a background goroutine that clears stale entries every 10 minutes.
func newRateLimiters() *rateLimiters {
	rl := &rateLimiters{
		auth:  newIPRateLimiter(rate.Limit(2), 5),   // 2/sec, burst 5
		token: newIPRateLimiter(rate.Limit(5), 10),   // 5/sec, burst 10
		mcp:   newIPRateLimiter(rate.Limit(20), 40),  // 20/sec, burst 40
		done:  make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.auth.cleanup()
				rl.token.cleanup()
				rl.mcp.cleanup()
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit.
func (rl *rateLimiters) Stop() {
	close(rl.done)
}

// rateLimit returns middleware that limits requests per client IP.
// It checks Fly-Client-IP first (set by Fly.io proxy), then falls back
// to r.RemoteAddr.
func rateLimit(limiter *ipRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			// Fly.io sets Fly-Client-IP header with the real client IP
			if flyIP := r.Header.Get("Fly-Client-IP"); flyIP != "" {
				ip = flyIP
			}
			if !limiter.getLimiter(ip).Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimitFunc is a convenience wrapper that rate-limits an http.HandlerFunc.
func rateLimitFunc(limiter *ipRateLimiter, handler http.HandlerFunc) http.Handler {
	return rateLimit(limiter)(http.HandlerFunc(handler))
}
