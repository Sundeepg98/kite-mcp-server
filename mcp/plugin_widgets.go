package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"

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

// pluginWidgetRegistry holds plugin-registered widgets. Separate from
// the built-in appResources slice so the boundary is clear: built-ins
// are owned by RegisterAppResources and include tight control over
// HTML templating, data injection, and MIME type; plugins supply
// their own ResourceContents — we only track (URI, Name, Handler).
var pluginWidgetRegistry = struct {
	mu       sync.RWMutex
	widgets  map[string]PluginWidget // keyed by URI (enforces uniqueness + last-wins)
	ordered  []string                // preserves registration order for ListPluginWidgets
}{
	widgets: make(map[string]PluginWidget),
}

// widgetURIScheme is the MCP Apps resource URI prefix that hosts
// (Claude.ai, Claude Desktop, ChatGPT, VS Code Copilot, Goose)
// interpret as "render this as an inline widget". Plugins MUST use
// this scheme — http:// or file:// URIs would not be rendered inline
// and could be a security red flag if accepted.
const widgetURIScheme = "ui://"

// RegisterWidget installs a plugin-supplied MCP App widget. Returns
// an error when:
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
// Re-registering the same URI is permitted and replaces the prior
// Handler (last-wins). This matches the Telegram plugin-command
// registry semantics and supports a plugin reloading itself.
//
// Thread-safe: callable from any goroutine, but the expected usage
// is once-per-plugin at app wiring time. The hot-path (resource
// fetch) takes only the reader lock via ListPluginWidgets.
func RegisterWidget(uri, name string, handler WidgetHandler) error {
	if err := validateWidgetURI(uri); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("mcp: widget name is empty for URI %q", uri)
	}
	if handler == nil {
		return fmt.Errorf("mcp: widget handler is nil for URI %q", uri)
	}
	if builtInWidgetURIs()[uri] {
		return fmt.Errorf("mcp: %q is a built-in widget URI — plugins cannot override it", uri)
	}

	pluginWidgetRegistry.mu.Lock()
	defer pluginWidgetRegistry.mu.Unlock()
	if _, existed := pluginWidgetRegistry.widgets[uri]; !existed {
		pluginWidgetRegistry.ordered = append(pluginWidgetRegistry.ordered, uri)
	}
	pluginWidgetRegistry.widgets[uri] = PluginWidget{
		URI:     uri,
		Name:    name,
		Handler: handler,
	}
	return nil
}

// ListPluginWidgets returns a snapshot of every registered plugin
// widget in registration order. Callers are the app wire-up layer
// (which enumerates these and calls MCPServer.AddResource for each)
// and tests. Safe for concurrent use; the returned slice is a copy.
func ListPluginWidgets() []PluginWidget {
	pluginWidgetRegistry.mu.RLock()
	defer pluginWidgetRegistry.mu.RUnlock()
	out := make([]PluginWidget, 0, len(pluginWidgetRegistry.ordered))
	for _, uri := range pluginWidgetRegistry.ordered {
		if w, ok := pluginWidgetRegistry.widgets[uri]; ok {
			out = append(out, w)
		}
	}
	return out
}

// ClearPluginWidgets removes all plugin-registered widgets. Primarily
// for test isolation — production code never needs this because
// plugin widgets are registered once at startup.
func ClearPluginWidgets() {
	pluginWidgetRegistry.mu.Lock()
	defer pluginWidgetRegistry.mu.Unlock()
	pluginWidgetRegistry.widgets = make(map[string]PluginWidget)
	pluginWidgetRegistry.ordered = nil
}

// PluginWidgetCount returns the number of registered plugin widgets.
// Exposed for the health/status admin surface and tests.
func PluginWidgetCount() int {
	pluginWidgetRegistry.mu.RLock()
	defer pluginWidgetRegistry.mu.RUnlock()
	return len(pluginWidgetRegistry.widgets)
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
