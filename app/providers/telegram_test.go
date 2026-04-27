package providers

import (
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// telegram_test.go covers the Telegram-notifier provider. Wave D
// Phase 2 Slice P2.4a (Batch 1).
//
// The provider is a pure passthrough: the *alerts.TelegramNotifier
// is constructed inside kc.NewWithOptions via WithTelegramBotToken,
// and the App composition exposes it to the Fx graph via fx.Supply.
// ProvideTelegramNotifier is the canonical Provide* entry-point so
// every dependency in this package surfaces via the same convention
// (matches ProvideLogger in logger.go).
//
// No init work, no state mutation, no computed value. Downstream
// consumers (P2.4c riskGuard auto-freeze closure, P2.4d mcpserver
// telegramnotify.Hook, P2.4b scheduler briefings) will inject the
// returned *alerts.TelegramNotifier via Fx graph wiring.

// TestProvideTelegramNotifier_Passthrough verifies that a non-nil
// notifier passes through unchanged. Construction happens upstream
// (kc.NewWithOptions); the provider's only job is to expose it.
func TestProvideTelegramNotifier_Passthrough(t *testing.T) {
	t.Parallel()

	// We construct an *alerts.TelegramNotifier struct-literal here.
	// The notifier's behaviour is exhaustively tested in
	// kc/alerts/telegram_test.go; this test only pins the
	// passthrough contract, not the notifier itself.
	in := &alerts.TelegramNotifier{}

	out := ProvideTelegramNotifier(in)
	if out != in {
		t.Errorf("expected passthrough; got different *alerts.TelegramNotifier pointer")
	}
}

// TestProvideTelegramNotifier_NilSupplied verifies that a nil
// notifier (the "no TELEGRAM_BOT_TOKEN configured" path in
// kc/manager_init.go:initTelegramNotifier) passes through as nil.
// Downstream consumers must nil-check; the provider does not
// synthesize a no-op fallback.
//
// This matches the existing app/wire.go consumer pattern at
// line 355, 636, 934 where `notifier := kcManager.TelegramNotifier()`
// is followed by `if notifier == nil { ... skip ... }`.
func TestProvideTelegramNotifier_NilSupplied(t *testing.T) {
	t.Parallel()

	got := ProvideTelegramNotifier(nil)
	if got != nil {
		t.Errorf("expected nil passthrough; got %T", got)
	}
}
