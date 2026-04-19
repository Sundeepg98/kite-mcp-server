package app

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// PluginRoute is a registered plugin HTTP route. Pattern follows the
// net/http.ServeMux rules (exact path match, or trailing slash for
// subtree).
type PluginRoute struct {
	Pattern string
	Handler http.HandlerFunc
}

// reservedRoutePrefixes are path prefixes owned by the built-in HTTP
// surface (setupMux in http.go). Plugins that try to register under
// these prefixes are rejected — built-in routes cannot be shadowed
// because their handlers carry OAuth gating, admin auth, rate-limit
// middleware, and CSP headers that plugins cannot safely replicate.
var reservedRoutePrefixes = []string{
	"/oauth/",
	"/auth/",
	"/admin/",
	"/callback",
	"/dashboard",
	"/.well-known/",
	"/mcp",          // MCP endpoint
	"/pricing",      // built-in pricing page
	"/checkout/",    // billing checkout flow
	"/billing/",     // billing portal
	"/webhooks/",    // Stripe webhooks, etc.
	"/telegram/",    // Telegram webhook receiver
}

var pluginRouteRegistry = struct {
	mu     sync.RWMutex
	routes map[string]PluginRoute
}{
	routes: make(map[string]PluginRoute),
}

// RegisterRoute installs a plugin HTTP handler at the given pattern.
// Returns an error when:
//   - pattern is empty;
//   - pattern does not start with "/";
//   - handler is nil;
//   - pattern starts with any reservedRoutePrefix (built-in namespace).
//
// Duplicate patterns replace the prior handler (last-wins lifecycle,
// matches other plugin registries across the codebase).
//
// Plugins SHOULD use a /plugin/<name>/... namespace to keep their
// routes identifiable in log lines, but this is a convention not a
// hard constraint. Any non-reserved path is accepted.
func RegisterRoute(pattern string, handler http.HandlerFunc) error {
	if pattern == "" {
		return fmt.Errorf("app: plugin route pattern is empty")
	}
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("app: plugin route pattern %q must start with '/'", pattern)
	}
	if handler == nil {
		return fmt.Errorf("app: plugin route %q handler is nil", pattern)
	}
	for _, prefix := range reservedRoutePrefixes {
		if strings.HasPrefix(pattern, prefix) {
			return fmt.Errorf("app: plugin route %q collides with reserved prefix %q", pattern, prefix)
		}
	}
	pluginRouteRegistry.mu.Lock()
	defer pluginRouteRegistry.mu.Unlock()
	pluginRouteRegistry.routes[pattern] = PluginRoute{
		Pattern: pattern,
		Handler: handler,
	}
	return nil
}

// ListPluginRoutes returns a snapshot of registered plugin routes.
// Safe for concurrent use; the returned slice is a copy. Order is
// insertion order (Go map iteration is random, so we sort by pattern
// for determinism).
func ListPluginRoutes() []PluginRoute {
	pluginRouteRegistry.mu.RLock()
	defer pluginRouteRegistry.mu.RUnlock()
	out := make([]PluginRoute, 0, len(pluginRouteRegistry.routes))
	for _, r := range pluginRouteRegistry.routes {
		out = append(out, r)
	}
	// Deterministic order for tests and admin listings.
	// Simple insertion-sort is fine — plugin route counts are small.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Pattern > out[j].Pattern; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// PluginRouteCount returns the number of registered plugin routes.
func PluginRouteCount() int {
	pluginRouteRegistry.mu.RLock()
	defer pluginRouteRegistry.mu.RUnlock()
	return len(pluginRouteRegistry.routes)
}

// ClearPluginRoutes drops every registered plugin route. Test-only.
func ClearPluginRoutes() {
	pluginRouteRegistry.mu.Lock()
	defer pluginRouteRegistry.mu.Unlock()
	pluginRouteRegistry.routes = make(map[string]PluginRoute)
}

// MountPluginRoutes attaches every registered plugin route to the
// supplied ServeMux. Called once by setupMux in app/http.go after the
// built-in routes are wired so plugin routes cannot shadow built-ins
// even via a pattern-specificity accident.
//
// Nil-mux safe (no-op) — matches the defensive wire-up pattern used
// elsewhere in the app package.
func MountPluginRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	pluginRouteRegistry.mu.RLock()
	routes := make([]PluginRoute, 0, len(pluginRouteRegistry.routes))
	for _, r := range pluginRouteRegistry.routes {
		routes = append(routes, r)
	}
	pluginRouteRegistry.mu.RUnlock()
	for _, r := range routes {
		mux.HandleFunc(r.Pattern, r.Handler)
	}
}
