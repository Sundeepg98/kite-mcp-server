package mcp

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// TestSubscribePluginEvent registers a plugin event subscription,
// installs it into a fresh EventDispatcher, and confirms the handler
// fires when the matching event is dispatched.
func TestSubscribePluginEvent(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	var seen atomic.Int32
	require.NoError(t, SubscribePluginEvent("order.placed", func(e domain.Event) {
		seen.Add(1)
	}))

	d := domain.NewEventDispatcher()
	InstallPluginEventSubscriptions(d)

	d.Dispatch(domain.OrderPlacedEvent{Timestamp: time.Now()})
	assert.Equal(t, int32(1), seen.Load())
}

// TestSubscribePluginEvent_MultipleEventTypes — one dispatcher, many
// plugin subscriptions for different event types; each fires only on
// its own type.
func TestSubscribePluginEvent_MultipleEventTypes(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	var placedCount, alertCount atomic.Int32
	require.NoError(t, SubscribePluginEvent("order.placed", func(e domain.Event) {
		placedCount.Add(1)
	}))
	require.NoError(t, SubscribePluginEvent("alert.triggered", func(e domain.Event) {
		alertCount.Add(1)
	}))

	d := domain.NewEventDispatcher()
	InstallPluginEventSubscriptions(d)

	d.Dispatch(domain.OrderPlacedEvent{Timestamp: time.Now()})
	d.Dispatch(domain.OrderPlacedEvent{Timestamp: time.Now()})
	d.Dispatch(domain.AlertTriggeredEvent{Timestamp: time.Now()})

	assert.Equal(t, int32(2), placedCount.Load())
	assert.Equal(t, int32(1), alertCount.Load())
}

// TestSubscribePluginEvent_RejectsInvalid — empty event type and nil
// handler both fail at registration.
func TestSubscribePluginEvent_RejectsInvalid(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	assert.Error(t, SubscribePluginEvent("", func(e domain.Event) {}))
	assert.Error(t, SubscribePluginEvent("order.placed", nil))
}

// TestListPluginEventSubscriptions returns every registered event
// type (deduplicated). Used by the admin plugins-list surface.
func TestListPluginEventSubscriptions(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	_ = SubscribePluginEvent("order.placed", func(e domain.Event) {})
	_ = SubscribePluginEvent("order.placed", func(e domain.Event) {}) // second subscriber
	_ = SubscribePluginEvent("alert.triggered", func(e domain.Event) {})

	types := ListPluginEventSubscriptions()
	assert.Len(t, types, 2, "two distinct event types")
	// Counts reflect total subscribers per type.
	assert.Equal(t, 2, types["order.placed"])
	assert.Equal(t, 1, types["alert.triggered"])
}

// TestInstallPluginEventSubscriptions_NilDispatcher is a no-op (safe
// to call from tests or dev mode where the dispatcher hasn't been
// wired yet).
func TestInstallPluginEventSubscriptions_NilDispatcher(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	_ = SubscribePluginEvent("order.placed", func(e domain.Event) {})
	// Must not panic on nil dispatcher.
	InstallPluginEventSubscriptions(nil)
}
