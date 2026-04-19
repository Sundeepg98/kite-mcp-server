package mcp

import (
	"context"
	"fmt"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// WidgetHandler is the function signature a plugin implements to serve
// its ui:// resource. It mirrors server.ResourceHandlerFunc (so the
// wire-up layer can pass it directly to MCPServer.AddResource) but is
// aliased here to keep plugin authors off the mark3labs/mcp-go import
// for the common case.
type WidgetHandler func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error)

// PluginWidget is a registered plugin-supplied MCP App resource.
// Exposed via ListPluginWidgets so the wire-up layer (the package that
// builds the MCPServer) can iterate and install each widget.
type PluginWidget struct {
	URI     string
	Name    string
	Handler WidgetHandler
}

// widgetURIScheme is the MCP Apps resource URI prefix that hosts
// (Claude.ai, Claude Desktop, ChatGPT, VS Code Copilot, Goose)
// interpret as "render this as an inline widget". Plugins MUST use
// this scheme — http:// or file:// URIs would not be rendered inline
// and could be a security red flag if accepted.
const widgetURIScheme = "ui://"

// RegisterWidget installs a plugin-supplied MCP App widget on the
// package-level DefaultRegistry. Production callers (examples/,
// app/wire.go, kc/telegram plugin adapters) call this free function;
// parallel tests that need state isolation construct their own
// Registry via NewRegistry() and call the equivalent method on it.
//
// Returns an error when:
//
//   - uri is empty or does not begin with "ui://" (other schemes are
//     not inline-rendered by any known MCP host);
//   - name is empty (clients display Name in their widget menu);
//   - handler is nil;
//   - uri collides with a built-in widget URI from appResources
//     (built-ins are off-limits — a plugin MUST NOT be able to swap
//     the portfolio/activity/orders widgets for its own HTML, which
//     would bypass our CSP and data-injection guarantees).
//
// Re-registering the same URI replaces the prior Handler (last-wins).
// Thread-safe: Registry.RegisterWidget takes its own lock.
func RegisterWidget(uri, name string, handler WidgetHandler) error {
	return DefaultRegistry.RegisterWidget(uri, name, handler)
}

// ListPluginWidgets returns a snapshot of every registered plugin
// widget in registration order from DefaultRegistry.
func ListPluginWidgets() []PluginWidget {
	return DefaultRegistry.ListWidgets()
}

// ClearPluginWidgets removes all plugin-registered widgets from
// DefaultRegistry. Primarily for test isolation on tests that have
// opted to share DefaultRegistry (most new parallel tests should
// construct an isolated Registry via NewRegistry() instead).
func ClearPluginWidgets() {
	DefaultRegistry.widgetMu.Lock()
	defer DefaultRegistry.widgetMu.Unlock()
	DefaultRegistry.widgets = make(map[string]PluginWidget)
	DefaultRegistry.widgetOrdered = nil
}

// PluginWidgetCount returns the number of widgets registered on
// DefaultRegistry.
func PluginWidgetCount() int {
	return DefaultRegistry.WidgetCount()
}

// validateWidgetURI enforces the ui:// prefix + non-empty path.
// Everything after the scheme is permitted (ui://plugin/x, ui://x/y/z)
// because the MCP Apps spec does not impose a structure beyond the
// scheme. Hosts route on the full URI string.
func validateWidgetURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("mcp: widget URI is empty")
	}
	if !strings.HasPrefix(uri, widgetURIScheme) {
		return fmt.Errorf("mcp: widget URI %q must start with %q", uri, widgetURIScheme)
	}
	if len(uri) <= len(widgetURIScheme) {
		return fmt.Errorf("mcp: widget URI %q has no path after scheme", uri)
	}
	return nil
}

// builtInWidgetURIs returns the set of ui:// URIs owned by
// appResources. Computed lazily on every call — appResources is a
// short fixed list (~17 entries) so caching is not worth the
// invalidation complexity. The map is a fresh allocation per call,
// which also makes it safe to mutate in tests if ever needed.
func builtInWidgetURIs() map[string]bool {
	m := make(map[string]bool, len(appResources))
	for _, r := range appResources {
		m[r.URI] = true
	}
	return m
}
