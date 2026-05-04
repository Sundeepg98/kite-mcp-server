package ops

import (
	"html/template"

	"github.com/zerodha/kite-mcp-server/kc/ops/shared"
)

// Backward-compatibility type aliases + function passthroughs for
// the overview-render primitives relocated to kc/ops/shared in Anchor
// 3 PR 3.1. The 4 in-tree non-test callsites (admin_render.go's
// boolClass call, handler.go's overviewFragmentTemplates +
// overviewToTemplateData calls, handler_metrics.go's renderFragment
// calls, overview_sse.go's overview-render calls) were updated in
// the same PR to use the shared.X exported names directly. The
// passthroughs below preserve the deprecated lowercase identifiers
// for any in-package test that may still reference them; they will
// be removed in a future cleanup PR.
type (
	StatCard             = shared.StatCard
	ToolUsageRow         = shared.ToolUsageRow
	OverviewTemplateData = shared.OverviewTemplateData
)

// overviewToTemplateData is a passthrough to
// shared.OverviewToTemplateData for backward compatibility.
func overviewToTemplateData(d OverviewData) OverviewTemplateData {
	return shared.OverviewToTemplateData(d)
}

// boolClass is a passthrough to shared.BoolClass for backward
// compatibility.
func boolClass(cond bool, cls string) string {
	return shared.BoolClass(cond, cls)
}

// overviewFragmentTemplates is a passthrough to
// shared.OverviewFragmentTemplates for backward compatibility.
func overviewFragmentTemplates() (*template.Template, error) {
	return shared.OverviewFragmentTemplates()
}

// renderFragment is a passthrough to shared.RenderFragment for
// backward compatibility.
func renderFragment(t *template.Template, name string, data any) (string, error) {
	return shared.RenderFragment(t, name, data)
}
