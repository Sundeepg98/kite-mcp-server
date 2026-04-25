package mcp

import (
	"github.com/mark3labs/mcp-go/server"
)

// FullPluginMiddleware bundles a middleware with its name + order so a
// caller can pass several middlewares to RegisterFullPlugin without
// repeating Registry.RegisterMiddleware boilerplate.
type FullPluginMiddleware struct {
	Name       string
	Order      int
	Middleware server.ToolHandlerMiddleware
}

// FullPluginWidget bundles a widget URI + name + handler.
type FullPluginWidget struct {
	URI     string
	Name    string
	Handler WidgetHandler
}

// FullPluginOpts collects every plugin-registration surface a typical
// plugin uses. Closes Plugin#22 — most plugins today write 4-5
// sequential Register* calls plus their own boilerplate err-check
// chain. This struct + RegisterFullPlugin replace that.
//
// Every field is optional. A plugin that only registers tools may
// leave Middleware/Widgets/Lifecycle/SBOM unset; the helper skips
// nil/empty sections.
type FullPluginOpts struct {
	Info       PluginInfo
	Tools      []Tool
	Middleware []FullPluginMiddleware
	Widgets    []FullPluginWidget
	Lifecycle  map[string]PluginLifecycle
	SBOM       *PluginSBOMEntry
}

// RegisterFullPlugin applies opts to DefaultRegistry in a fixed order
// (Info → Tools → Middleware → Widgets → Lifecycle → SBOM) and returns
// the FIRST error encountered. On error, sections registered earlier
// remain registered — the helper does not roll back. Plugin authors
// are expected to call this once, near process start; partial-state
// recovery is the operator's restart, not the helper's job.
//
// Info.Name + Version are required (RegisterPluginInfo enforces).
// Empty Tools / Middleware / Widgets / Lifecycle / SBOM are no-ops.
func RegisterFullPlugin(opts FullPluginOpts) error {
	if opts.Info.Name != "" {
		if err := DefaultRegistry.RegisterPluginInfo(opts.Info); err != nil {
			return err
		}
	}
	if len(opts.Tools) > 0 {
		DefaultRegistry.RegisterPlugins(opts.Tools...)
	}
	for _, m := range opts.Middleware {
		if err := DefaultRegistry.RegisterMiddleware(m.Name, m.Middleware, m.Order); err != nil {
			return err
		}
	}
	for _, w := range opts.Widgets {
		if err := DefaultRegistry.RegisterWidget(w.URI, w.Name, w.Handler); err != nil {
			return err
		}
	}
	for name, lc := range opts.Lifecycle {
		DefaultRegistry.RegisterPluginLifecycle(name, lc)
	}
	if opts.SBOM != nil {
		if err := DefaultRegistry.RegisterSBOM(*opts.SBOM); err != nil {
			return err
		}
	}
	return nil
}
