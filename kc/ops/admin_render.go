package ops

import (
	"html/template"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/ops/admin"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// admin_render.go — Anchor 3 PR 3.2 (per .research/anchor-1-and-3-
// pr-design.md). Backward-compatibility shims for the
// types + functions that moved into kc/ops/admin.
//
// EMPIRICAL SCOPE NARROWING vs AUDIT
//
// The audit's PR 3.2 inventory listed 6 files for kc/ops/admin
// (handler_admin.go, admin_render.go, handler_metrics.go,
// handler_credentials.go, handler_logs.go, handler_telemetry.go).
// Empirical analysis found 5 of those 6 (every "handler_*.go"
// file) define methods on *kc/ops.Handler:
//
//   handler_admin.go        — 11 methods on *Handler
//   handler_metrics.go      — 2 methods on *Handler
//   handler_credentials.go  — 3 methods on *Handler
//   handler_logs.go         — 1 method on *Handler
//   handler_telemetry.go    — 4 methods on *Handler
//
// Go forbids defining methods on a type from outside the type's
// declaring package. These 5 files structurally MUST stay in
// kc/ops/. Only admin_render.go (free functions + DTO types) is
// extractable.
//
// Same narrow-extraction pattern PR 3.1 used for kc/ops/shared.
// The audit's per-file clustering missed the method-receiver
// constraint.
//
// THIS PR's NARROW EXTRACTION
//
// kc/ops/admin/render.go (~340 LOC) — DTO types (SessionRow,
// SessionsTemplateData, TickerRow, TickersTemplateData, AlertRow,
// TelegramMapping, AlertsTemplateData, UserRow, UsersTemplateData,
// MetricsToolRow, MetricsTemplateData) + free functions
// (FmtTimeStr, SessionsToTemplateData, TickersToTemplateData,
// AlertsToTemplateData, UsersToTemplateData, MetricsToTemplateData,
// AdminFragmentTemplates, FormatFloat, FormatInt). All capitalised
// for cross-package consumption.
//
// kc/ops keeps backward-compatibility type aliases + lowercase
// function passthroughs so the 11 in-tree non-admin_render call
// sites in handler_*.go continue to compile without rewrite.

// ---------------------------------------------------------------------
// Type aliases — DTOs relocated to kc/ops/admin
// ---------------------------------------------------------------------

type (
	SessionRow             = admin.SessionRow
	SessionsTemplateData   = admin.SessionsTemplateData
	TickerRow              = admin.TickerRow
	TickersTemplateData    = admin.TickersTemplateData
	AlertRow               = admin.AlertRow
	TelegramMapping        = admin.TelegramMapping
	AlertsTemplateData     = admin.AlertsTemplateData
	UserRow                = admin.UserRow
	UsersTemplateData      = admin.UsersTemplateData
	MetricsToolRow         = admin.MetricsToolRow
	MetricsTemplateData    = admin.MetricsTemplateData
)

// ---------------------------------------------------------------------
// Lowercase function passthroughs — preserved for in-package
// kc/ops handler_*.go callers (sessionsToTemplateData,
// tickersToTemplateData, etc.) so they don't need rewrite. New
// code should call admin.SessionsToTemplateData etc. directly.
// ---------------------------------------------------------------------

func fmtTimeStr(t time.Time) string {
	return admin.FmtTimeStr(t)
}

func sessionsToTemplateData(sessions []SessionInfo) SessionsTemplateData {
	return admin.SessionsToTemplateData(sessions)
}

func tickersToTemplateData(d TickerData) TickersTemplateData {
	return admin.TickersToTemplateData(d)
}

func alertsToTemplateData(d AlertData) AlertsTemplateData {
	return admin.AlertsToTemplateData(d)
}

func usersToTemplateData(list []*users.User, currentEmail string) UsersTemplateData {
	return admin.UsersToTemplateData(list, currentEmail)
}

func metricsToTemplateData(stats *audit.Stats, toolMetrics []audit.ToolMetric, uptimeSeconds int) MetricsTemplateData {
	return admin.MetricsToTemplateData(stats, toolMetrics, uptimeSeconds)
}

func adminFragmentTemplates() (*template.Template, error) {
	return admin.AdminFragmentTemplates()
}

func formatFloat(f float64) string {
	return admin.FormatFloat(f)
}

func formatInt(n int) string {
	return admin.FormatInt(n)
}
