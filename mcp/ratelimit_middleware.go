package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// TierMultiplierFunc resolves a per-user throttling multiplier from their
// email. Returning <=0 means "use base limit" (effectively identity).
// This is a narrow port: the rate limiter knows nothing about billing,
// only that some users get a bigger bucket than others.
type TierMultiplierFunc func(email string) int

// ToolRateLimiter tracks per-user, per-tool call rates.
//
// All mutable state (counters, limits, tierMult) sits under mu so that
// SetLimits can swap the limit map atomically while the Middleware goroutine
// is executing under live traffic — the hot-reload contract invoked via
// SIGHUP in production.
type ToolRateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateBucket
	limits   map[string]int // tool name -> max calls per minute
	tierMult TierMultiplierFunc
}

type rateBucket struct {
	count       int
	windowStart time.Time
}

// NewToolRateLimiter creates a rate limiter with per-tool limits.
// The input map is copied — callers are free to mutate their copy
// afterwards without affecting the live limiter.
func NewToolRateLimiter(limits map[string]int) *ToolRateLimiter {
	cp := make(map[string]int, len(limits))
	for k, v := range limits {
		cp[k] = v
	}
	return &ToolRateLimiter{
		counters: make(map[string]*rateBucket),
		limits:   cp,
	}
}

// SetLimits replaces the per-tool limit map atomically. Existing in-flight
// counters (rateBucket entries) are preserved so an operator's config
// update does not silently reset everyone's window — the *cap* changes,
// not the current count. Tools removed from the new map fall through as
// "unlimited" (hasLimit==false in Middleware) on subsequent calls.
//
// Wired via SIGHUP in app/wire.go: an operator edits the config source
// (env var bundle, TOML, etc.) and signals the running process. The
// reload handler re-parses and calls SetLimits; no restart, no dropped
// in-flight tool calls.
func (rl *ToolRateLimiter) SetLimits(limits map[string]int) {
	cp := make(map[string]int, len(limits))
	for k, v := range limits {
		cp[k] = v
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limits = cp
}

// CurrentLimits returns a snapshot copy of the per-tool caps currently
// in effect. Intended for diagnostics (`/admin/ratelimit` handler, tests)
// — never mutate the returned map, but callers are free to read it
// concurrently with SetLimits without risk.
func (rl *ToolRateLimiter) CurrentLimits() map[string]int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	out := make(map[string]int, len(rl.limits))
	for k, v := range rl.limits {
		out[k] = v
	}
	return out
}

// WithTierMultiplier attaches a tier resolver after construction so the
// middleware ordering (registered at startup) is not disturbed. Late binding
// is intentional: the multiplier is invoked per-request, so it can be wired
// after the middleware is already attached to the server.
func (rl *ToolRateLimiter) WithTierMultiplier(fn TierMultiplierFunc) *ToolRateLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.tierMult = fn
	return rl
}

func (rl *ToolRateLimiter) effectiveLimit(baseLimit int, email string) int {
	if email == "" {
		return baseLimit
	}
	rl.mu.Lock()
	fn := rl.tierMult
	rl.mu.Unlock()
	if fn == nil {
		return baseLimit
	}
	mult := fn(email)
	if mult <= 0 {
		return baseLimit
	}
	return baseLimit * mult
}

// Middleware returns a ToolHandlerMiddleware that enforces per-tool rate limits.
func (rl *ToolRateLimiter) Middleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			toolName := request.Params.Name

			// Single critical section: read limit, update counter,
			// resolve tier multiplier. SetLimits can swap rl.limits
			// concurrently — without this lock an in-flight call would
			// race the swap and in Go's map model that is a data race
			// (not merely a consistency issue).
			email := oauth.EmailFromContext(ctx)
			key := email + ":" + toolName

			rl.mu.Lock()
			baseLimit, hasLimit := rl.limits[toolName]
			if !hasLimit {
				rl.mu.Unlock()
				return next(ctx, request)
			}
			limit := baseLimit
			if email != "" && rl.tierMult != nil {
				if mult := rl.tierMult(email); mult > 0 {
					limit = baseLimit * mult
				}
			}
			bucket, exists := rl.counters[key]
			now := time.Now()
			if !exists || now.Sub(bucket.windowStart) > time.Minute {
				bucket = &rateBucket{count: 0, windowStart: now}
				rl.counters[key] = bucket
			}
			bucket.count++
			count := bucket.count
			rl.mu.Unlock()

			if count > limit {
				return gomcp.NewToolResultError(fmt.Sprintf(
					"Rate limit exceeded: %s allows %d calls/minute. Try again shortly.", toolName, limit)), nil
			}

			return next(ctx, request)
		}
	}
}
