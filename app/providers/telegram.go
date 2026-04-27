package providers

import "github.com/zerodha/kite-mcp-server/kc/alerts"

// telegram.go — Wave D Phase 2 Slice P2.4a (Batch 1). Pure
// passthrough provider for the Telegram push-notification sender.
//
// CONSTRUCTION OWNERSHIP
//
// The *alerts.TelegramNotifier is constructed inside kc.NewWithOptions
// via WithTelegramBotToken (see kc/manager_init.go:initTelegramNotifier).
// When TELEGRAM_BOT_TOKEN is empty or the bot factory fails, the
// notifier stays nil — kc treats it as "Telegram disabled" and the
// rest of the system reads a nil pointer.
//
// PROVIDER SCOPE
//
// The composition site (app/wire.go) exposes the notifier to the Fx
// graph via fx.Supply(kcManager.TelegramNotifier()). This file
// declares the canonical Provide* function for the same value, kept
// in sync with the package convention documented in logger.go:
//
//	"Every other dependency in this package surfaces via a Provide*
//	 function. Treating the logger the same way makes the provider
//	 graph readable as a single list of Provide* declarations rather
//	 than a mixed Supply+Provide composition."
//
// Downstream consumers (P2.4b scheduler briefings, P2.4c riskGuard
// auto-freeze, P2.4d mcpserver telegramnotify.Hook) will inject
// *alerts.TelegramNotifier via Fx graph wiring instead of calling
// kcManager.TelegramNotifier() inline.
//
// NIL CONTRACT
//
// The provider returns nil when input is nil (matches all existing
// wire.go consumer patterns at lines 355, 636, 934 which nil-check
// the notifier before use). It does NOT synthesize a no-op fallback;
// callers handle the "Telegram disabled" path explicitly.

// ProvideTelegramNotifier exposes the Telegram push-notification
// sender to the Fx graph. Pure passthrough — no I/O, no goroutines,
// safe to call from any provider context.
//
// The notifier is constructed upstream (kc.NewWithOptions); this
// provider's only job is to surface it under the package's uniform
// Provide* convention.
func ProvideTelegramNotifier(notifier *alerts.TelegramNotifier) *alerts.TelegramNotifier {
	return notifier
}
