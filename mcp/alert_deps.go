package mcp

import (
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/ports"
)

// AlertDepsFields is the alerts-context subset of ToolHandlerDeps:
// price/composite alerts, telegram notifier wiring, alert DB, and the
// trailing-stop manager (which lives in the same alerts pipeline). New
// alert-context ports added here do NOT collide with session, order, or
// admin agent edits.
//
// Investment K — see session_deps.go for rationale.
//
// Phase B/D F1 close: the five fields Alerts / TelegramNotifier /
// AlertDB / TrailingStop / PnL all consolidated to ports.AlertPort
// (5-method composite). Each call site reaches through the same port;
// the field-level surface widens but production callers continue to
// work because *kc.Manager satisfies ports.AlertPort. TelegramStore
// stays as the narrow kc.TelegramStoreProvider — it's the per-user
// chat-ID store, not part of the AlertPort surface.
type AlertDepsFields struct {
	Alerts           ports.AlertPort
	Telegram         kc.TelegramStoreProvider
	TelegramNotifier ports.AlertPort
	AlertDB          ports.AlertPort
	TrailingStop     ports.AlertPort
	PnL              ports.AlertPort
}

func newAlertDeps(manager *kc.Manager) AlertDepsFields {
	return AlertDepsFields{
		Alerts:           manager,
		Telegram:         manager,
		TelegramNotifier: manager,
		AlertDB:          manager,
		TrailingStop:     manager,
		PnL:              manager,
	}
}
