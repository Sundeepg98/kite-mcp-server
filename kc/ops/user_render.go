package ops

import (
	"html/template"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/ops/user"
)

// user_render.go — Anchor 3 PR 3.3 (per .research/anchor-1-and-3-
// pr-design.md). Backward-compatibility shim for the user-render
// foundation file relocated to kc/ops/user.
//
// EMPIRICAL SCOPE NARROWING vs AUDIT (third time, same lesson)
//
// The audit's PR 3.3 inventory listed 30 files for kc/ops/user.
// Empirical analysis found the vast majority are pinned to kc/ops:
//
// METHOD-PINNED to kc/ops (cannot move):
//   - api_handlers.go         — methods on *Handler
//   - api_alerts.go           — methods on *AlertsHandler (declared
//                               in handler_alerts.go in kc/ops)
//   - api_orders.go           — methods on *OrdersHandler (kc/ops)
//   - api_paper.go            — methods on *PaperHandler (kc/ops)
//   - api_portfolio.go        — methods on *PortfolioHandler (kc/ops)
//   - api_tax.go              — methods on *TaxHandler (kc/ops)
//   - api_activity.go         — methods on *ActivityHandler (declared
//                               in same file but referenced widely
//                               across kc/ops dashboard_*.go files)
//   - dashboard_*.go (7 files) — methods on *DashboardHandler and
//                                per-domain handlers (all kc/ops)
//
// CROSS-REFERENCE pinning (cannot move without capitalising private
// types in api_*.go, which would expand the kc/ops public API):
//   - user_alerts_render.go     — takes []enrichedActiveAlert,
//                                 []enrichedTriggeredAlert,
//                                 alertsSummary (api_alerts.go,
//                                 unexported)
//   - user_orders_render.go     — takes []orderEntry (api_orders.go,
//                                 unexported)
//   - user_portfolio_render.go  — takes []holdingItem, []positionItem
//                                 (api_portfolio.go, unexported)
//   - user_paper_render.go      — depends on PaperEntries types
//                                 (kc/ops, unexported)
//   - user_safety_render.go     — uses map[string]any from
//                                 dashboard_safety.go's buildSafetyData
//   - user_activity_render.go   — depends on user_render.go's
//                                 UserStatCard (the only one that
//                                 could move IF user_render.go went
//                                 first)
//
// LEAF EXTRACTABLE (ONLY user_render.go):
//   user_render.go defines UserStatCard + 9 formatter helpers
//   (FmtINR, FmtINRShort, FmtPrice, FmtPct, PnlClass, FmtTimeDDMon,
//    FmtTimeHMS, FmtDurationMs, UserDashboardFragmentTemplates,
//    RenderUserFragment). Zero kc/ops cross-refs. True leaf.
//
// THIS PR's NARROW EXTRACTION
//
// NEW kc/ops/user/user_render.go (~160 LOC) — the foundation file
// relocated and capitalised. The other 6 user_*_render.go files KEEP
// in kc/ops because they consume package-private types from api_*.go.
//
// kc/ops keeps backward-compat type alias for UserStatCard + 10
// lowercase function passthroughs so the 45+ in-tree call sites in
// dashboard_*.go + api_*.go + user_*_render.go (still in kc/ops)
// continue to compile without rewrite.
//
// FUTURE WORK
//
// A follow-on PR could capitalise the 6 helper types
// (enrichedActiveAlert, enrichedTriggeredAlert, alertsSummary,
// holdingItem, positionItem, orderEntry) in api_*.go to unblock the
// remaining 6 user_*_render.go files moving to kc/ops/user. That
// expands the kc/ops public API surface, so it's deliberately
// deferred — the audit's "30-file extraction" was empirically over-
// aggressive; the realistic narrow-extraction floor is 1 file
// (user_render.go).

// ---------------------------------------------------------------------
// Type alias — UserStatCard relocated to kc/ops/user
// ---------------------------------------------------------------------

type UserStatCard = user.UserStatCard

// ---------------------------------------------------------------------
// Lowercase function passthroughs — preserved for the 45+ in-package
// kc/ops callers that reference the helpers by their pre-PR names.
// New code should call user.FmtINR etc. directly.
// ---------------------------------------------------------------------

func fmtINR(v float64) string         { return user.FmtINR(v) }
func fmtINRShort(v float64) string    { return user.FmtINRShort(v) }
func fmtPrice(v float64) string       { return user.FmtPrice(v) }
func fmtPct(v float64) string         { return user.FmtPct(v) }
func pnlClass(v float64) string       { return user.PnlClass(v) }
func fmtTimeDDMon(t time.Time) string { return user.FmtTimeDDMon(t) }
func fmtTimeHMS(t time.Time) string   { return user.FmtTimeHMS(t) }
func fmtDurationMs(ms int64) string   { return user.FmtDurationMs(ms) }
func userDashboardFragmentTemplates() (*template.Template, error) {
	return user.UserDashboardFragmentTemplates()
}
func renderUserFragment(t *template.Template, name string, data any) (string, error) {
	return user.RenderUserFragment(t, name, data)
}
