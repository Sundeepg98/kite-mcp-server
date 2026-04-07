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

// ToolRateLimiter tracks per-user, per-tool call rates.
type ToolRateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateBucket
	limits   map[string]int // tool name -> max calls per minute
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

// Middleware returns a ToolHandlerMiddleware that enforces per-tool rate limits.
func (rl *ToolRateLimiter) Middleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			toolName := request.Params.Name
			limit, hasLimit := rl.limits[toolName]
			if !hasLimit {
				return next(ctx, request)
			}

			email := oauth.EmailFromContext(ctx)
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
