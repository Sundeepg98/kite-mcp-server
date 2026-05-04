package mcp

import (
	"context"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/zerodha/kite-mcp-server/mcp/middleware"
)

// middleware_aliases.go — Anchor 1 PR 1.2 (per .research/anchor-1-and-
// 3-pr-design.md commit 04e069a). Backward-compatibility shims for the
// types, functions, and constants that moved into mcp/middleware.
//
// After this PR, mcp/middleware is the canonical home for the
// middleware sub-package: CircuitBreaker, ToolRateLimiter,
// CorrelationMiddleware, TimeoutMiddleware, the MiddlewareSpec /
// MiddlewareRegistry / MiddlewareBuilder DSL, and the
// BuildMiddlewareChain / BuildChainFromSpec / ValidateSpec orchestrators.
//
// The aliases below preserve the legacy mcp.X reference path for the
// 2 external callers identified empirically:
//   - app/providers/mcpserver.go (mcp.MiddlewareRegistry,
//     mcp.MiddlewareBuilder, mcp.BuildChainFromSpec,
//     mcp.DefaultBuiltInSpec, mcp.BuildMiddlewareChain,
//     mcp.ValidateSpec)
//   - app/ratelimit_reload.go (mcp.ToolRateLimiter)
// without forcing a touch-everywhere rewrite.
//
// SCOPE NARROWING vs AUDIT
//
// The audit (commit 04e069a) listed 7 files for mcp/middleware:
// circuitbreaker_middleware.go, correlation_middleware.go,
// middleware_chain.go, middleware_dsl.go, plugin_middleware.go,
// ratelimit_middleware.go, timeout_middleware.go. Empirical analysis
// found plugin_middleware.go directly accesses unexported fields on
// DefaultRegistry (middlewareMu, middlewareEntries) which live in
// plugin_registry.go — that file's natural home is mcp/plugin
// (semantic name match + co-resident unexported field access). PR 1.3
// (mcp/plugin) moves plugin_middleware.go alongside plugin_registry.go
// where the field-level access stays in-package.
//
// PR 1.2 therefore moves only 6 of the 7 audited files, with
// plugin_middleware.go deferred to PR 1.3. Same audit-error pattern as
// PR 1.1 (decorator_chain.go) — the audit's per-file clustering missed
// a cross-package field-level dependency. Documented here so PR 1.3
// honours the rebalanced inventory.

// ---------------------------------------------------------------------
// Type aliases — exported symbols from mcp/middleware re-exposed under mcp.X
// ---------------------------------------------------------------------

type (
	CircuitState        = middleware.CircuitState
	CircuitBreaker      = middleware.CircuitBreaker
	ToolRateLimiter     = middleware.ToolRateLimiter
	TierMultiplierFunc  = middleware.TierMultiplierFunc
	MiddlewareBuilder   = middleware.MiddlewareBuilder
	MiddlewareRegistry  = middleware.MiddlewareRegistry
	MiddlewareSpec      = middleware.MiddlewareSpec
)

// ---------------------------------------------------------------------
// Var passthroughs
// ---------------------------------------------------------------------

// DefaultBuiltInOrder is the canonical chain ordering (X-Request-ID
// → Timeout → Audit → Hooks → CircuitBreaker → RiskGuard →
// RateLimiter → Billing → Paper → Dashboard URL). Re-exposed here
// for app/providers/mcpserver.go's chain orchestration.
var DefaultBuiltInOrder = middleware.DefaultBuiltInOrder

// ---------------------------------------------------------------------
// Function passthroughs
// ---------------------------------------------------------------------

// NewCircuitBreaker constructs a circuit breaker with the given
// failure threshold + open duration.
func NewCircuitBreaker(failureThreshold int, openDuration time.Duration) *CircuitBreaker {
	return middleware.NewCircuitBreaker(failureThreshold, openDuration)
}

// NewToolRateLimiter constructs a per-tool token-bucket limiter.
func NewToolRateLimiter(limits map[string]int) *ToolRateLimiter {
	return middleware.NewToolRateLimiter(limits)
}

// CorrelationIDFromContext reads the X-Request-ID off ctx (or
// upstream "request_id" key) and returns the empty string when
// absent.
func CorrelationIDFromContext(ctx context.Context) string {
	return middleware.CorrelationIDFromContext(ctx)
}

// CorrelationMiddleware returns the X-Request-ID propagator
// middleware.
func CorrelationMiddleware() server.ToolHandlerMiddleware {
	return middleware.CorrelationMiddleware()
}

// TimeoutMiddleware returns a middleware that aborts handler
// invocations exceeding the given timeout.
func TimeoutMiddleware(timeout time.Duration) server.ToolHandlerMiddleware {
	return middleware.TimeoutMiddleware(timeout)
}

// BuildMiddlewareChain assembles a slice of middleware in the given
// order from the supplied registry. Used by the operator-override
// path in app/providers/mcpserver.go.
func BuildMiddlewareChain(entries map[string]MiddlewareBuilder, order []string) ([]server.ToolHandlerMiddleware, error) {
	return middleware.BuildMiddlewareChain(entries, order)
}

// ValidateSpec is the fail-fast spec validator.
func ValidateSpec(spec MiddlewareSpec) error {
	return middleware.ValidateSpec(spec)
}

// BuildChainFromSpec validates the spec and constructs the middleware
// chain. Used by app/providers/mcpserver.go's wire-up.
func BuildChainFromSpec(spec MiddlewareSpec) ([]server.ToolHandlerMiddleware, error) {
	return middleware.BuildChainFromSpec(spec)
}

// DefaultBuiltInSpec returns the production spec wiring the
// DefaultBuiltInOrder against the supplied registry.
func DefaultBuiltInSpec(registry MiddlewareRegistry) MiddlewareSpec {
	return middleware.DefaultBuiltInSpec(registry)
}
