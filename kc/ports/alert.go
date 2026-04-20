package ports

import (
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// AlertPort is the bounded-context contract for alert-subsystem access:
// the alert store (per-user alert CRUD), the optional SQLite database
// that backs alerts and several adjacent stores, and the three
// alert-adjacent components — Telegram notifier, trailing-stop manager,
// and P&L snapshot service — exposed through the Manager.
//
// Method set (5 accessors, union of existing narrow providers):
//   - AlertStore()         → kc.AlertStoreInterface
//   - AlertDB()            → *alerts.DB
//   - TelegramNotifier()   → *alerts.TelegramNotifier
//   - TrailingStopManager()→ *alerts.TrailingStopManager
//   - PnLService()         → *alerts.PnLSnapshotService
//
// Consumers currently reach these through *kc.Manager (app/wire.go,
// app/http.go, mcp/admin_server_tools.go, kc/manager_queries_*.go).
// The five legacy provider types in kc/manager_interfaces.go stay as
// deprecated aliases until Phase B/D migrates remaining call sites.
type AlertPort interface {
	AlertStore() kc.AlertStoreInterface
	AlertDB() *alerts.DB
	TelegramNotifier() *alerts.TelegramNotifier
	TrailingStopManager() *alerts.TrailingStopManager
	PnLService() *alerts.PnLSnapshotService
}
