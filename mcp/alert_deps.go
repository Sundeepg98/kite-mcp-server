package mcp

import "github.com/zerodha/kite-mcp-server/kc"

// AlertDepsFields is the alerts-context subset of ToolHandlerDeps:
// price/composite alerts, telegram notifier wiring, alert DB, and the
// trailing-stop manager (which lives in the same alerts pipeline). New
// alert-context ports added here do NOT collide with session, order, or
// admin agent edits.
//
// Investment K — see session_deps.go for rationale.
type AlertDepsFields struct {
	Alerts           kc.AlertStoreProvider
	Telegram         kc.TelegramStoreProvider
	TelegramNotifier kc.TelegramNotifierProvider
	AlertDB          kc.AlertDBProvider
	TrailingStop     kc.TrailingStopManagerProvider
}

func newAlertDeps(manager *kc.Manager) AlertDepsFields {
	return AlertDepsFields{
		Alerts:           manager,
		Telegram:         manager,
		TelegramNotifier: manager,
		AlertDB:          manager,
		TrailingStop:     manager,
	}
}
