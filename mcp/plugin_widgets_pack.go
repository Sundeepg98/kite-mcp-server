package mcp

import (
	"context"
	"log/slog"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// builtinWidgetDataFunc is the contract for a widget data function in
// this pack: take the authenticated caller's email (extracted from ctx
// by the shared handler) and return a JSON-serialisable value. A nil
// return value becomes "null" in the injected data (matches
// injectData's behaviour used by the built-in widget system in
// ext_apps.go).
//
// The manager and auditStore are captured at RegisterBuiltinWidgetPack
// time via closure — they may be nil when widgets are registered in
// tests without a live manager, and handlers defensively handle that
// case.
// Phase 3a Batch 6b: manager param narrowed from *kc.Manager to
// extAppManagerPort. *kc.Manager satisfies the interface (per the
// provider assertions in kc/manager_interfaces.go), so existing test
// callers passing `mgr` compile unchanged.
type builtinWidgetDataFunc func(ctx context.Context, manager extAppManagerPort, email string) any

// builtinWidgetDef describes one widget in the pack.
type builtinWidgetDef struct {
	URI          string
	Name         string
	TemplateHTML string
	DataFunc     builtinWidgetDataFunc
}

// RegisterBuiltinWidgetPack installs the five built-in extension
// widgets (sector donut, P&L sparkline, margin gauge, IP-whitelist
// status, returns matrix) through the plugin-widget registry. Wiring:
//
//	sched := RegisterBuiltinWidgetPack(kcManager, auditStore, logger)
//
// Registration is idempotent: calling twice registers the same five
// widget URIs, which re-use the prior slot via RegisterWidget's
// last-wins lifecycle. That's a property we rely on for app re-init
// tests and re-registration after feature-flag flips.
//
// Why a separate "pack" helper instead of inlining each widget into
// appResources in ext_apps.go:
//   - keeps the original 17 built-in widgets untouched;
//   - the new 5 are delivered through the PLUGIN widget surface so
//     they exercise the same registration, collision-check, and
//     dispatch code paths that real third-party plugins will use
//     — eating our own dog food;
//   - test isolation: each widget's data function is a pure
//     (manager, email) -> any mapping, unit-testable without
//     spinning up the MCP server.
func RegisterBuiltinWidgetPack(manager *kc.Manager, auditStore *audit.Store, logger *slog.Logger) error {
	// Widget defs grow one commit at a time — each new widget appends
	// to this slice alongside its own plugin_widget_*.go file.
	defs := []builtinWidgetDef{
		{
			URI:          "ui://kite-mcp/sector-donut",
			Name:         "Sector Exposure Donut",
			TemplateHTML: sectorDonutTemplateHTML,
			DataFunc:     sectorDonutWidgetData,
		},
		{
			URI:          "ui://kite-mcp/pnl-sparkline",
			Name:         "P&L Sparkline",
			TemplateHTML: pnlSparklineTemplateHTML,
			DataFunc:     pnlSparklineWidgetData,
		},
		{
			URI:          "ui://kite-mcp/margin-gauge",
			Name:         "Margin Utilization Gauge",
			TemplateHTML: marginGaugeTemplateHTML,
			DataFunc:     marginGaugeWidgetData,
		},
		{
			URI:          "ui://kite-mcp/ip-whitelist-status",
			Name:         "IP Whitelist Status",
			TemplateHTML: ipWhitelistTemplateHTML,
			DataFunc:     ipWhitelistWidgetData,
		},
		{
			URI:          "ui://kite-mcp/returns-matrix",
			Name:         "Multi-Day Returns Matrix",
			TemplateHTML: returnsMatrixTemplateHTML,
			DataFunc:     returnsMatrixWidgetData,
		},
	}
	for _, def := range defs {
		def := def // capture
		handler := func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
			email := oauth.EmailFromContext(ctx)
			// The DataFunc contract tolerates empty email — it returns
			// an unauthenticated shape — so we don't short-circuit
			// here. Keeps "anonymous preview" behaviour consistent
			// with the ext_apps.go built-in widget contract.
			//
			// Panic-isolated via SafeCall: a buggy DataFunc renders
			// as an error panel inside the widget rather than
			// crashing the ReadResource request.
			data, err := SafeCall(def.URI, func() (any, error) {
				return def.DataFunc(ctx, manager, email), nil
			})
			if err != nil {
				data = map[string]any{"error": err.Error()}
				ReportPluginHealth(def.URI, HealthStatus{
					State:   HealthStateFailed,
					Message: "DataFunc panicked: " + err.Error(),
				})
			}
			html := injectData(def.TemplateHTML, data)
			return []gomcp.ResourceContents{
				gomcp.TextResourceContents{
					URI:      def.URI,
					MIMEType: ResourceMIMEType,
					Text:     html,
				},
			}, nil
		}
		if err := RegisterWidget(def.URI, def.Name, handler); err != nil {
			if logger != nil {
				logger.Error("RegisterBuiltinWidgetPack: failed to register widget",
					"uri", def.URI, "error", err)
			}
			return err
		}
	}
	if logger != nil {
		logger.Info("Builtin widget pack registered", "count", len(defs))
	}
	_ = auditStore // reserved for future data functions that need audit queries (e.g., returns-matrix historical)
	return nil
}
