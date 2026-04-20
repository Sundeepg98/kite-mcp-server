package mcp

import (
	"fmt"

	"github.com/mark3labs/mcp-go/server"
)

// MiddlewareBuilder produces a tool-handler middleware on demand. Builders
// close over whatever dependencies the middleware needs (audit store,
// riskguard, billing store, etc.) so BuildMiddlewareChain can stay a pure
// named-list composer that doesn't know about concrete middleware deps.
//
// A nil builder is legal — it models "this middleware is optional and
// disabled in the current build" (e.g., billing when STRIPE_SECRET_KEY
// is unset). BuildMiddlewareChain silently skips nil builders so the
// same named order constant can be used across dev/prod configurations.
type MiddlewareBuilder func() server.ToolHandlerMiddleware

// DefaultBuiltInOrder is the canonical ordering for built-in middleware
// as applied in app/wire.go. The list flows outer-to-inner: correlation
// wraps timeout wraps audit etc., so correlation sees every request and
// dashboardurl sits closest to the real tool handler.
//
// Semantics of each slot:
//   - correlation: injects X-Request-ID / CallID into ctx for tracing
//   - timeout: kills runaway tool handlers (30s default)
//   - audit: writes tool_calls row (every call, even failures)
//   - hooks: plugin before/after hooks (rolegate, telegramnotify)
//   - circuitbreaker: freezes all tools on error-rate spike
//   - riskguard: pre-trade safety checks (kill switch, caps, rate)
//   - ratelimit: per-tool-per-user throttle
//   - billing: tier gating (Pro/Premium/Family)
//   - papertrading: intercepts order tools when paper mode is on
//   - dashboardurl: appends dashboard_url hint to tool responses
//
// Reordering has semantic consequences: audit BEFORE riskguard means
// riskguard-blocked orders are still logged; reversing would drop
// them from the audit trail. Tests guard the default. Operators who
// override via Config take responsibility for those semantics.
var DefaultBuiltInOrder = []string{
	"correlation",
	"timeout",
	"audit",
	"hooks",
	"circuitbreaker",
	"riskguard",
	"ratelimit",
	"billing",
	"papertrading",
	"dashboardurl",
}

// BuildMiddlewareChain composes a runtime-configurable middleware chain
// from a named registry. entries maps each middleware name to its
// builder; order lists the names in outer-to-inner sequence. The
// returned slice is ready to be fed to server.WithToolHandlerMiddleware
// one entry at a time in app/wire.go.
//
// Rules:
//   - entries[name] == nil → skipped silently (optional middleware)
//   - name absent from entries → error (typo in config surfaces early)
//   - order may contain a subset of entries (operator pruning is OK)
//   - order may be empty → chain is empty; caller gets no middleware
//
// mcp-go applies WithToolHandlerMiddleware in append-order and wraps
// each new one AROUND the existing chain. Callers that want the
// returned chain[i] to run in the list's stated outer-to-inner order
// therefore invoke WithToolHandlerMiddleware on chain[0] first, then
// chain[1], etc. (Same semantics as the current hardcoded wire.go.)
func BuildMiddlewareChain(entries map[string]MiddlewareBuilder, order []string) ([]server.ToolHandlerMiddleware, error) {
	out := make([]server.ToolHandlerMiddleware, 0, len(order))
	for _, name := range order {
		builder, ok := entries[name]
		if !ok {
			return nil, fmt.Errorf("mcp: middleware %q is not registered", name)
		}
		if builder == nil {
			continue // optional middleware — disabled in this build
		}
		out = append(out, builder())
	}
	return out, nil
}
