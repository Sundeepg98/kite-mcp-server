package mcp

import (
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// pluginEventSubscription is a single plugin-registered subscription.
// Captured at registration time on the Registry and installed into
// the app's EventDispatcher by InstallPluginEventSubscriptions, which
// app/wire.go calls once after the dispatcher is constructed.
type pluginEventSubscription struct {
	eventType string
	handler   func(domain.Event)
}

// SubscribePluginEvent registers a plugin handler for a domain event
// type (e.g. "order.placed", "alert.triggered") on DefaultRegistry.
// The subscription is recorded in the plugin registry and installed
// onto the live EventDispatcher during app startup via
// InstallPluginEventSubscriptions.
//
// Plugins call this at wire-up time (init or main) BEFORE the app
// constructs its dispatcher. Subscriptions registered after
// InstallPluginEventSubscriptions has run are silently ignored —
// there's no "live re-wire" semantics because every built-in
// subscription in app/wire.go follows the same "subscribe once at
// startup" discipline and the dispatcher has no unsubscribe API.
//
// Returns an error when eventType is empty or handler is nil. A nil
// handler would NPE the dispatcher on first dispatch, so failing
// loudly at registration is preferable.
func SubscribePluginEvent(eventType string, handler func(domain.Event)) error {
	return DefaultRegistry.SubscribePluginEvent(eventType, handler)
}

// InstallPluginEventSubscriptions wires every DefaultRegistry-registered
// plugin subscription into the supplied dispatcher. Called once by
// app/wire.go immediately after the built-in domain event
// subscriptions are wired, so plugin handlers fire alongside the
// built-in audit persister for the same event.
//
// Safe to call with a nil dispatcher (no-op) — matches the defensive
// pattern elsewhere in the codebase for optional subsystem wiring.
func InstallPluginEventSubscriptions(d *domain.EventDispatcher) {
	DefaultRegistry.InstallPluginEventSubscriptions(d)
}

// ListPluginEventSubscriptions returns a snapshot of every registered
// subscription from DefaultRegistry keyed by event type. Used by the
// /admin plugins-list surface and tests.
func ListPluginEventSubscriptions() map[string]int {
	return DefaultRegistry.ListEventSubscriptions()
}

// PluginEventSubscriptionCount returns the total plugin subscription
// count on DefaultRegistry.
func PluginEventSubscriptionCount() int {
	return DefaultRegistry.EventSubscriptionCount()
}

// ClearPluginEventSubscriptions drops every registered plugin
// subscription on DefaultRegistry. Test-only; production code never
// calls this because subscriptions are installed once at startup and
// never removed.
func ClearPluginEventSubscriptions() {
	DefaultRegistry.eventMu.Lock()
	defer DefaultRegistry.eventMu.Unlock()
	DefaultRegistry.eventSubscriptions = nil
}
