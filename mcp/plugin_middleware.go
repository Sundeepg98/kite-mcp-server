package mcp

import (
	"context"
	"fmt"
	"sort"
	"sync"

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

// pluginMiddlewareRegistry holds plugin-contributed tool-handler
// middleware. Separate from the app's wire.go-managed chain of
// built-in middleware (correlation, timeout, audit, hook, circuit
// breaker, riskguard, rate limit, billing, paper, dashboard) — plugin
// middleware runs AFTER all built-ins via PluginMiddlewareChain, which
// app/wire.go appends as the terminal WithToolHandlerMiddleware call.
//
// Keyed by Name for last-wins on duplicate registration (matches
// RegisterWidget + plugin_commands conventions).
var pluginMiddlewareRegistry = struct {
	mu      sync.RWMutex
	entries map[string]PluginMiddlewareEntry
}{
	entries: make(map[string]PluginMiddlewareEntry),
}

// RegisterMiddleware installs a plugin middleware at a specific Order
// position. Plugin middleware wraps around the built-in handler chain;
// higher Order values sit closer to the real handler.
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
	if name == "" {
		return fmt.Errorf("mcp: middleware name is empty")
	}
	if mw == nil {
		return fmt.Errorf("mcp: middleware %q is nil", name)
	}
	pluginMiddlewareRegistry.mu.Lock()
	defer pluginMiddlewareRegistry.mu.Unlock()
	pluginMiddlewareRegistry.entries[name] = PluginMiddlewareEntry{
		Name:       name,
		Order:      order,
		Middleware: mw,
	}
	return nil
}

// ListPluginMiddleware returns registered entries in Order ascending.
// Safe for concurrent use; returned slice is a copy.
func ListPluginMiddleware() []PluginMiddlewareEntry {
	pluginMiddlewareRegistry.mu.RLock()
	defer pluginMiddlewareRegistry.mu.RUnlock()
	out := make([]PluginMiddlewareEntry, 0, len(pluginMiddlewareRegistry.entries))
	for _, e := range pluginMiddlewareRegistry.entries {
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// PluginMiddlewareCount returns the number of registered plugin
// middleware. Intended for the /admin/plugins surface and tests.
func PluginMiddlewareCount() int {
	pluginMiddlewareRegistry.mu.RLock()
	defer pluginMiddlewareRegistry.mu.RUnlock()
	return len(pluginMiddlewareRegistry.entries)
}

// ClearPluginMiddleware drops every registered plugin middleware.
// Test-only; production code never calls this.
func ClearPluginMiddleware() {
	pluginMiddlewareRegistry.mu.Lock()
	defer pluginMiddlewareRegistry.mu.Unlock()
	pluginMiddlewareRegistry.entries = make(map[string]PluginMiddlewareEntry)
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
// Panic recovery: individual plugin middleware are NOT wrapped in a
// defer/recover here. A middleware that panics deserves to surface
// loudly — the recovery net is at the around-hook layer
// (OnToolExecution), which runs INSIDE this chain. Keeping panic
// policy in one place (around-hook) prevents subtle
// "where-is-the-error-coming-from" debugging sessions.
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
			handler = entries[i].Middleware(handler)
		}
		return handler
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
