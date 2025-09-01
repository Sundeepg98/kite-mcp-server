package web

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiterEntry holds a rate limiter and its last access time
type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter manages rate limiting for incoming requests.
type RateLimiter struct {
	limiters       map[string]*limiterEntry
	mu             sync.Mutex
	cleanupCancel  context.CancelFunc
	cleanupRunning bool
}

// NewRateLimiter creates a new rate limiter manager.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*limiterEntry),
	}
}

func (m *RateLimiter) getLimiter(ip string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.limiters[ip]
	if !exists {
		// Allow 5 requests every 12 seconds.
		limiter := rate.NewLimiter(rate.Every(12*time.Second), 5)
		entry = &limiterEntry{
			limiter:    limiter,
			lastAccess: time.Now(),
		}
		m.limiters[ip] = entry

		// Start cleanup goroutine if not already running
		if !m.cleanupRunning {
			m.startCleanup()
		}
	} else {
		// Update last access time
		entry.lastAccess = time.Now()
	}

	return entry.limiter
}

// Middleware returns a middleware that enforces rate limiting.
func (m *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !m.getLimiter(ip).Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startCleanup starts the background cleanup goroutine
func (m *RateLimiter) startCleanup() {
	if m.cleanupRunning {
		return
	}

	m.cleanupRunning = true
	ctx, cancel := context.WithCancel(context.Background())
	m.cleanupCancel = cancel

	go m.cleanupRoutine(ctx)
}

// StopCleanup stops the background cleanup goroutine
func (m *RateLimiter) StopCleanup() {
	if m.cleanupCancel != nil {
		m.cleanupCancel()
		m.cleanupRunning = false
	}
}

// cleanupRoutine periodically removes inactive rate limiters
func (m *RateLimiter) cleanupRoutine(ctx context.Context) {
	// Clean up limiters that haven't been used for 1 hour
	const maxIdleTime = time.Hour
	const cleanupInterval = 30 * time.Minute

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupInactive(maxIdleTime)
		}
	}
}

// cleanupInactive removes rate limiters that haven't been used for the specified duration
func (m *RateLimiter) cleanupInactive(maxIdleTime time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	toDelete := make([]string, 0)

	for ip, entry := range m.limiters {
		if now.Sub(entry.lastAccess) > maxIdleTime {
			toDelete = append(toDelete, ip)
		}
	}

	for _, ip := range toDelete {
		delete(m.limiters, ip)
	}

	// If no limiters left, stop the cleanup routine to save resources
	if len(m.limiters) == 0 {
		if m.cleanupCancel != nil {
			m.cleanupCancel()
			m.cleanupRunning = false
		}
	}
}
