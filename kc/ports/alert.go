package ports

import (
	"github.com/algo2go/kite-mcp-alerts"
)

// AlertPort is the bounded-context contract for alert-subsystem access:
// the alert store (per-user alert CRUD), the optional SQLite database
// that backs alerts and several adjacent stores, and the three
// alert-adjacent components — Telegram notifier, trailing-stop manager,
// and P&L snapshot service — exposed through the Manager.
//
// Method set (5 accessors, union of existing narrow providers):
//   - AlertStore()         → alerts.AlertStoreInterface
//   - AlertDB()            → *alerts.DB
//   - TelegramNotifier()   → *alerts.TelegramNotifier
//   - TrailingStopManager()→ *alerts.TrailingStopManager
//   - PnLService()         → *alerts.PnLSnapshotService
//
// Anchor 5 PR 5.3 (per .research/anchor-5-prs-design.md, Wave B-2):
// dropped the kc-parent import. PR 5.2 had relocated AlertStoreInterface
// from kc/interfaces.go to kc/alerts/store_interface.go, leaving a
// type alias `kc.AlertStoreInterface = alerts.AlertStoreInterface`
// in kc/interfaces.go. This PR rewrites the AlertStore() return type
// to reference alerts.AlertStoreInterface directly, severing the last
// reason this file imported the kc parent. Type aliases preserve
// assignment-compatibility at every reverse-dep call site (5 files
// in mcp/ — alert_deps.go, common_deps.go, context_tool.go,
// read_deps.go, session_deps.go — continue to build unchanged).
//
// Consumers currently reach these through *kc.Manager (app/wire.go,
// app/http.go, mcp/admin_server_tools.go, kc/manager_queries_*.go).
// The five legacy provider types in kc/manager_interfaces.go stay as
// deprecated aliases until Phase B/D migrates remaining call sites.
type AlertPort interface {
	AlertStore() alerts.AlertStoreInterface
	AlertDB() *alerts.DB
	TelegramNotifier() *alerts.TelegramNotifier
	TrailingStopManager() *alerts.TrailingStopManager
	PnLService() *alerts.PnLSnapshotService
}
