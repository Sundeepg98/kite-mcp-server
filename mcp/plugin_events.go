package mcp

import (
	"fmt"
	"sync"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// pluginEventSubscription is a single plugin-registered subscription.
// Captured at registration time and installed into the app's
// EventDispatcher by InstallPluginEventSubscriptions, which app/wire.go
// calls once after the dispatcher is constructed.
type pluginEventSubscription struct {
	eventType string
	handler   func(domain.Event)
}

var pluginEventRegistry = struct {
	mu            sync.RWMutex
	subscriptions []pluginEventSubscription
}{}

// SubscribePluginEvent registers a plugin handler for a domain event
// type (e.g. "order.placed", "alert.triggered"). The subscription is
// recorded in the plugin registry and installed onto the live
// EventDispatcher during app startup via InstallPluginEventSubscriptions.
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
	if eventType == "" {
		return fmt.Errorf("mcp: plugin event subscription has empty event type")
	}
	if handler == nil {
		return fmt.Errorf("mcp: plugin event subscription for %q has nil handler", eventType)
	}
	pluginEventRegistry.mu.Lock()
	defer pluginEventRegistry.mu.Unlock()
	pluginEventRegistry.subscriptions = append(pluginEventRegistry.subscriptions, pluginEventSubscription{
		eventType: eventType,
		handler:   handler,
	})
	return nil
}

// InstallPluginEventSubscriptions wires every registered plugin
// subscription into the supplied dispatcher. Called once by app/wire.go
// immediately after the built-in domain event subscriptions are wired,
// so plugin handlers fire alongside the built-in audit persister for
// the same event.
//
// Safe to call with a nil dispatcher (no-op) — matches the defensive
// pattern elsewhere in the codebase for optional subsystem wiring.
func InstallPluginEventSubscriptions(d *domain.EventDispatcher) {
	if d == nil {
		return
	}
	pluginEventRegistry.mu.RLock()
	subs := append([]pluginEventSubscription(nil), pluginEventRegistry.subscriptions...)
	pluginEventRegistry.mu.RUnlock()
	for _, s := range subs {
		d.Subscribe(s.eventType, s.handler)
	}
}

// ListPluginEventSubscriptions returns a snapshot of every registered
// subscription keyed by event type, with values giving the number of
// plugin subscribers for that type. Used by the /admin plugins-list
// surface and tests.
func ListPluginEventSubscriptions() map[string]int {
	pluginEventRegistry.mu.RLock()
	defer pluginEventRegistry.mu.RUnlock()
	counts := make(map[string]int)
	for _, s := range pluginEventRegistry.subscriptions {
		counts[s.eventType]++
	}
	return counts
}

// PluginEventSubscriptionCount returns the total number of registered
// plugin subscriptions (summed across event types).
func PluginEventSubscriptionCount() int {
	pluginEventRegistry.mu.RLock()
	defer pluginEventRegistry.mu.RUnlock()
	return len(pluginEventRegistry.subscriptions)
}

// ClearPluginEventSubscriptions drops every registered plugin
// subscription. Test-only; production code never calls this because
// subscriptions are installed once at startup and never removed.
func ClearPluginEventSubscriptions() {
	pluginEventRegistry.mu.Lock()
	defer pluginEventRegistry.mu.Unlock()
	pluginEventRegistry.subscriptions = nil
}
