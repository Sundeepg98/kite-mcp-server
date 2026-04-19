package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// PluginMiddlewareEntry is a registered plugin-contributed middleware.
// Order determines composition position (ascending — low order outer,
// high order inner). Stable ordering means plugin middleware slot into
// the tool-handler chain deterministically relative to each other.
type PluginMiddlewareEntry struct {
	Name       string
	Order      int
	Middleware server.ToolHandlerMiddleware
}

// RegisterMiddleware installs a plugin middleware on DefaultRegistry
// at a specific Order position. Plugin middleware wraps around the
// built-in handler chain; higher Order values sit closer to the real
// handler.
//
// Returns an error when:
//   - name is empty (needed for logs and dedup);
//   - mw is nil.
//
// Ordering guidance (relative to built-in middleware in app/wire.go):
//   - built-ins occupy the stack positions between the MCP server and
//     the real handler;
//   - plugin middleware registered here is composed via
//     PluginMiddlewareChain, which app/wire.go appends AFTER all
//     built-ins, so plugin middleware sees every tool call and can
//     observe/transform results after built-in riskguard, billing,
//     and rate-limiting have already run;
//   - within the plugin chain, Order=100 wraps Order=500 wraps
//     Order=900, so the innermost plugin middleware (closest to the
//     real handler) has the highest Order.
func RegisterMiddleware(name string, mw server.ToolHandlerMiddleware, order int) error {
	return DefaultRegistry.RegisterMiddleware(name, mw, order)
}

// ListPluginMiddleware returns registered entries in Order ascending
// from DefaultRegistry. Safe for concurrent use; returned slice is a
// copy.
func ListPluginMiddleware() []PluginMiddlewareEntry {
	return DefaultRegistry.ListMiddleware()
}

// PluginMiddlewareCount returns the number of registered plugin
// middleware on DefaultRegistry.
func PluginMiddlewareCount() int {
	return DefaultRegistry.MiddlewareCount()
}

// ClearPluginMiddleware drops every registered plugin middleware on
// DefaultRegistry. Test-only; production code never calls this.
func ClearPluginMiddleware() {
	DefaultRegistry.middlewareMu.Lock()
	defer DefaultRegistry.middlewareMu.Unlock()
	DefaultRegistry.middlewareEntries = make(map[string]PluginMiddlewareEntry)
}

// PluginMiddlewareChain returns a single ToolHandlerMiddleware that
// composes every registered plugin middleware in Order ascending. The
// returned middleware is idempotent-safe against zero registrations —
// it returns a transparent passthrough when the registry is empty.
//
// Wire-up: app/wire.go appends this as its terminal
// WithToolHandlerMiddleware call so plugin middleware runs inside
// every built-in middleware (after correlation/timeout/audit/hook/
// circuitbreaker/riskguard/rate-limit/billing/paper/dashboard have
// wrapped the chain). Adding built-in middleware above this point
// never shifts plugin middleware relative to the handler.
//
// Panic recovery: each plugin middleware is wrapped by safeWrapMiddleware,
// which inserts a per-layer defer-recover. A panicking middleware
// surfaces as an IsError=true CallToolResult and is marked Failed in
// PluginHealth; the sibling middleware and the handler-chain above it
// are unaffected. This gives every plugin-contributed middleware the
// same crash-isolation contract as the around-hook layer, without
// requiring plugin authors to remember to install their own recover.
func PluginMiddlewareChain() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		entries := ListPluginMiddleware()
		if len(entries) == 0 {
			return next
		}
		// Compose right-to-left so entries[0] (lowest Order) ends up
		// as the outermost wrapper.
		handler := next
		for i := len(entries) - 1; i >= 0; i-- {
			handler = safeWrapMiddleware(entries[i], handler)
		}
		return handler
	}
}

// safeWrapMiddleware applies entry.Middleware to inner, wrapping the
// resulting handler with a defer-recover. The recovery surface:
//
//   - result = IsError=true CallToolResult naming the plugin and
//     panic value (MCP client sees a clean error, not a dropped
//     connection);
//   - err = nil (the failure IS the result — matches the around-hook
//     panic contract in registry.go);
//   - PluginHealth records HealthStateFailed for the plugin name so
//     the admin panel lights up red.
func safeWrapMiddleware(entry PluginMiddlewareEntry, inner server.ToolHandlerFunc) server.ToolHandlerFunc {
	wrapped := entry.Middleware(inner)
	return func(ctx context.Context, req mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				ReportPluginHealth(entry.Name, HealthStatus{
					State:   HealthStateFailed,
					Message: "middleware panic: " + fmt.Sprint(r),
				})
				result = mcp.NewToolResultError(
					fmt.Sprintf("plugin middleware %q panicked: %v", entry.Name, r))
				err = nil
			}
		}()
		return wrapped(ctx, req)
	}
}

// Compile-time interface assertions — keep the exported
// ToolHandlerMiddleware signature aligned with mcp-go.
var _ server.ToolHandlerMiddleware = PluginMiddlewareChain()
var _ = func() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, nil
	}
}
