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
func NewToolRateLimiter(limits map[string]int) *ToolRateLimiter {
	return &ToolRateLimiter{
		counters: make(map[string]*rateBucket),
		limits:   limits,
	}
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
			baseLimit, hasLimit := rl.limits[toolName]
			if !hasLimit {
				return next(ctx, request)
			}

			email := oauth.EmailFromContext(ctx)
			limit := rl.effectiveLimit(baseLimit, email)
			key := email + ":" + toolName

			rl.mu.Lock()
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
