// Package shared holds the kc/ops sub-package's foundation types —
// pure DTOs (OverviewData, SessionInfo, TickerData, AlertData) and
// the LogBuffer / TeeHandler observability primitives — extracted
// from kc/ops/ to enable the planned Anchor 3 fan-out (PRs 3.2 admin,
// 3.3 user) per .research/anchor-1-and-3-pr-design.md.
//
// Anchor 3 PR 3.1 (this package): foundation extraction. Only files
// with NO method receivers on kc/ops.Handler / kc/ops.DashboardHandler
// were moved here — Go forbids cross-package method declarations, so
// any file with a `func (h *Handler) X()` body MUST stay in kc/ops.
//
// The audit's original PR 3.1 inventory (.research/anchor-1-and-3-
// pr-design.md commit 04e069a) listed 5 files as "shared"; empirical
// inspection showed 3 of those (data.go, page_handlers.go,
// overview_sse.go) have method receivers on Handler / DashboardHandler
// and CANNOT move. Only the DTO halves of data.go (this file) plus
// logbuffer.go and overview_render.go (next files) are structurally
// extractable.
//
// kc/ops keeps backward-compatibility type aliases (e.g.,
// `type OverviewData = shared.OverviewData`) so the 15-file in-tree
// reverse-dep set + the 3 external consumers (app/app.go, main.go,
// main_test.go) continue to compile via the kc/ops.X reference path
// unchanged. Same alias-shim pattern Anchor 5 PRs 5.2/5.4/5.6
// established.
package shared

import (
	"time"

	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-ticker"
)

// OverviewData is the dashboard's top-level snapshot DTO. Built by
// kc/ops.Handler.buildOverview() (which stays in kc/ops/data.go
// because it has a *Handler receiver) and consumed by the template
// renderers + JSON API responses.
type OverviewData struct {
	Version            string           `json:"version"`
	Uptime             string           `json:"uptime"`
	ActiveSessions     int              `json:"active_sessions"`
	ActiveTickers      int              `json:"active_tickers"`
	TotalAlerts        int              `json:"total_alerts"`
	ActiveAlerts       int              `json:"active_alerts"`
	CachedTokens       int              `json:"cached_tokens"`
	PerUserCredentials int              `json:"per_user_credentials"`
	ToolUsage          map[string]int64 `json:"tool_usage"`
	DailyUsers         int64            `json:"daily_users"`
	GlobalFrozen       bool             `json:"global_frozen"`
	// Runtime / observability
	HeapAllocMB float64 `json:"heap_alloc_mb"`
	Goroutines  int     `json:"goroutines"`
	GCPauseMs   float64 `json:"gc_pause_ms"`
	DBSizeMB    float64 `json:"db_size_mb"`
}

// SessionInfo describes a single active MCP session. Built by
// kc/ops.Handler.buildSessions() (stays in kc/ops/data.go).
type SessionInfo struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TickerData wraps the per-user ticker subscription list.
type TickerData struct {
	Tickers []ticker.UserTickerInfo `json:"tickers"`
}

// AlertData wraps the per-email alert + telegram subscription maps.
type AlertData struct {
	Alerts   map[string][]*alerts.Alert `json:"alerts"`
	Telegram map[string]int64           `json:"telegram"`
}
