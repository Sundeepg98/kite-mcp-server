package app

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/oauth"
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

// userRateLimiter provides per-authenticated-user rate limiting.
// Structurally identical to ipRateLimiter but keyed by email (from JWT claims)
// instead of IP. Prevents a single authenticated user from hammering endpoints
// across rotating IPs (botnet, VPN, etc).
type userRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

func newUserRateLimiter(r rate.Limit, burst int) *userRateLimiter {
	return &userRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    burst,
	}
}

func (l *userRateLimiter) getLimiter(email string) *rate.Limiter {
	l.mu.RLock()
	limiter, exists := l.limiters[email]
	l.mu.RUnlock()
	if exists {
		return limiter
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Double-check after acquiring write lock
	if limiter, exists = l.limiters[email]; exists {
		return limiter
	}
	limiter = rate.NewLimiter(l.rate, l.burst)
	l.limiters[email] = limiter
	return limiter
}

// cleanup removes stale entries. Active users will recreate their limiters
// on next request. Called periodically by a background goroutine.
func (l *userRateLimiter) cleanup() {
	l.mu.Lock()
	l.limiters = make(map[string]*rate.Limiter)
	l.mu.Unlock()
}

// rateLimiters holds all per-endpoint-group rate limiters.
type rateLimiters struct {
	auth           *ipRateLimiter // /oauth/register, /oauth/authorize, /auth/browser-login
	token          *ipRateLimiter // /oauth/token
	mcp            *ipRateLimiter // /mcp, /sse, /message
	// Per-user limiters applied after authentication (layered on top of IP limits).
	// An authenticated user must pass both IP and user checks. Matching defaults
	// to the IP tiers — second layer defends against botnet/VPN IP rotation.
	authUser       *userRateLimiter // auth endpoints, keyed by authenticated email
	tokenUser      *userRateLimiter // token endpoint, keyed by authenticated email
	mcpUser        *userRateLimiter // MCP endpoints, keyed by authenticated email
	done           chan struct{}  // closed during shutdown to stop the cleanup goroutine
	cleanupInterval time.Duration // injectable for testing (default 10 min)
	// stopOnce guards Stop() so rl.done is only closed once even when
	// multiple graceful-shutdown paths (signal handler + test teardown)
	// both invoke Stop on the same rateLimiters instance. Without this,
	// the second close of rl.done would panic with "close of closed channel".
	stopOnce sync.Once
}

// newRateLimiters creates rate limiters for each endpoint group and starts
// a background goroutine that clears stale entries every 10 minutes.
func newRateLimiters() *rateLimiters {
	rl := &rateLimiters{
		auth:            newIPRateLimiter(rate.Limit(2), 5),   // 2/sec, burst 5
		token:           newIPRateLimiter(rate.Limit(5), 10),   // 5/sec, burst 10
		mcp:             newIPRateLimiter(rate.Limit(20), 40),  // 20/sec, burst 40
		// Per-user limits match their IP-layer counterparts. Defense-in-depth:
		// IP limit caps per-source traffic; user limit caps per-identity traffic
		// across source rotation.
		authUser:        newUserRateLimiter(rate.Limit(2), 5),
		tokenUser:       newUserRateLimiter(rate.Limit(5), 10),
		mcpUser:         newUserRateLimiter(rate.Limit(20), 40),
		done:            make(chan struct{}),
		cleanupInterval: 10 * time.Minute,
	}
	go func() {
		ticker := time.NewTicker(rl.cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.auth.cleanup()
				rl.token.cleanup()
				rl.mcp.cleanup()
				rl.authUser.cleanup()
				rl.tokenUser.cleanup()
				rl.mcpUser.cleanup()
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit.
//
// Stop is idempotent: calling it multiple times is safe and only the first
// call closes the cleanup channel. This guards against the case where more
// than one graceful-shutdown path (e.g. the HTTP signal handler and a test
// teardown) both try to Stop the same rateLimiters instance, which would
// otherwise produce `panic: close of closed channel`.
func (rl *rateLimiters) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.done)
	})
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
			} else {
				// Strip port from RemoteAddr (e.g. "127.0.0.1:12345" → "127.0.0.1")
				// so all connections from the same IP share one limiter.
				if host, _, err := net.SplitHostPort(ip); err == nil {
					ip = host
				}
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

// rateLimitUser returns middleware that limits requests per authenticated user
// email. The email is extracted from the request context populated by
// oauth.RequireAuth. If no email is present (e.g. middleware ordering bug or
// anonymous endpoint), this middleware is a no-op so it fails open rather than
// breaking unauthenticated paths.
//
// Layered after rateLimit (IP) + RequireAuth, this blocks a single authenticated
// identity from abusing endpoints across rotating source IPs.
func rateLimitUser(limiter *userRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email := oauth.EmailFromContext(r.Context())
			if email == "" {
				// No authenticated identity — skip user-scope check. IP-scope
				// check upstream is the only guard in this case.
				next.ServeHTTP(w, r)
				return
			}
			if !limiter.getLimiter(email).Allow() {
				// X-RateLimit-Scope lets clients distinguish user-level blocks
				// from IP-level blocks so they can back off appropriately.
				w.Header().Set("X-RateLimit-Scope", "user")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
