package plugin

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

// builtInWidgetURISet is the set of ui:// URIs owned by the mcp/
// root's appResources list. Anchor 1 PR 1.3 (per .research/anchor-
// 1-and-3-pr-design.md): set once at startup by mcp/ root via
// SetBuiltInWidgetURIs because the appResources slice itself stays
// in mcp/ext_apps.go (intertwined with extAppManagerPort interface
// and per-widget DataFunc closures that call into kc.Manager) and
// is therefore not a candidate for relocation.
//
// Concurrent reads are safe: SetBuiltInWidgetURIs is called exactly
// once at init() time before any RegisterWidget call. After that
// the slice is read-only.
var builtInWidgetURISet map[string]bool

// SetBuiltInWidgetURIs initialises the URI-collision-check set from
// the mcp/ root's appResources list. mcp/ root calls this from
// aliases.go's init(). Subsequent calls overwrite the previous set
// (test fixtures may reset).
func SetBuiltInWidgetURIs(uris []string) {
	m := make(map[string]bool, len(uris))
	for _, u := range uris {
		m[u] = true
	}
	builtInWidgetURISet = m
}

// builtInWidgetURIs returns the set of ui:// URIs owned by the
// builtin widget pack. Returns an empty map when SetBuiltInWidgetURIs
// has not been called — RegisterWidget then accepts every URI without
// the collision check (test ergonomic).
func builtInWidgetURIs() map[string]bool {
	if builtInWidgetURISet == nil {
		return map[string]bool{}
	}
	// Return a fresh copy so callers can't mutate our state.
	cp := make(map[string]bool, len(builtInWidgetURISet))
	for k, v := range builtInWidgetURISet {
		cp[k] = v
	}
	return cp
}
