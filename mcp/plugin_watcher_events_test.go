package mcp

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// plugin_watcher_events_test.go — Event-source contract tests for the
// plugin-watcher aggregate. Verifies that every mutation surface
// (WatchPluginBinary register, ClearPluginWatches unregister, debounce
// reload-fire, watcher Start/Stop) dispatches the matching typed
// domain.Plugin*Event via the SetPluginWatcherEventDispatcher hook.
//
// Pattern mirrors kc/usecases/watchlist_events_test.go (commit aeb3e8c)
// + kc/billing/billing_store_test.go's TierChanged tests (562f623) —
// the canonical "lift store mutations to typed domain events" template
// inside this codebase.

// captureDispatcher is a lock-protected slice of every event the
// dispatcher receives, in dispatch order. Used by every test below.
type captureDispatcher struct {
	mu     sync.Mutex
	events []domain.Event
}

func (c *captureDispatcher) record(e domain.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureDispatcher) snapshot() []domain.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]domain.Event, len(c.events))
	copy(out, c.events)
	return out
}

// installCaptureDispatcher wires a fresh dispatcher with the supplied
// capture as a wildcard subscriber across every plugin.* event type.
// Returns the dispatcher so the caller can inspect and the cleanup hook
// the test must defer.
func installCaptureDispatcher(t *testing.T) (*domain.EventDispatcher, *captureDispatcher) {
	t.Helper()
	cap := &captureDispatcher{}
	d := domain.NewEventDispatcher()
	for _, eventType := range []string{
		"plugin.registered",
		"plugin.unregistered",
		"plugin.reload_triggered",
		"plugin.watcher_started",
		"plugin.watcher_stopped",
	} {
		d.Subscribe(eventType, cap.record)
	}
	prev := pluginWatcherDispatcher.Load()
	SetPluginWatcherEventDispatcher(d)
	t.Cleanup(func() {
		SetPluginWatcherEventDispatcher(prev)
	})
	return d, cap
}

// TestWatchPluginBinary_DispatchesRegisteredEvent verifies registering
// a NEW path emits a typed PluginRegisteredEvent with the path + base
// name set, and a fresh timestamp.
func TestWatchPluginBinary_DispatchesRegisteredEvent(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	_, cap := installCaptureDispatcher(t)

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	require.NoError(t, WatchPluginBinary(binary, &stubReloadable{}))

	events := cap.snapshot()
	require.Len(t, events, 1, "exactly one event should be dispatched")
	ev, ok := events[0].(domain.PluginRegisteredEvent)
	require.True(t, ok, "event must be PluginRegisteredEvent, got %T", events[0])
	abs, _ := filepath.Abs(binary)
	assert.Equal(t, abs, ev.Path)
	assert.Equal(t, "fake-plugin", ev.PluginName)
	assert.WithinDuration(t, time.Now(), ev.Timestamp, 2*time.Second)
}

// TestWatchPluginBinary_DispatcherIsNilSafe — the watcher must continue
// to function with no dispatcher installed (production wiring may run
// in modes where the EventDispatcher is intentionally absent).
func TestWatchPluginBinary_DispatcherIsNilSafe(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	prev := pluginWatcherDispatcher.Load()
	SetPluginWatcherEventDispatcher(nil)
	t.Cleanup(func() { SetPluginWatcherEventDispatcher(prev) })

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	// Should not panic / error with nil dispatcher.
	assert.NoError(t, WatchPluginBinary(binary, &stubReloadable{}))
	assert.Equal(t, 1, PluginWatcherCount())
}

// TestWatchPluginBinary_DuplicatePathSilentOnReWatch — re-watching the
// same path with a fresh BinaryReloadable updates the registry but does
// NOT emit a second PluginRegisteredEvent. Auditors see the lifecycle
// boundary (first watch), not the value churn.
func TestWatchPluginBinary_DuplicatePathSilentOnReWatch(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	_, cap := installCaptureDispatcher(t)

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	require.NoError(t, WatchPluginBinary(binary, &stubReloadable{}))
	require.NoError(t, WatchPluginBinary(binary, &stubReloadable{}))

	events := cap.snapshot()
	registered := 0
	for _, e := range events {
		if _, ok := e.(domain.PluginRegisteredEvent); ok {
			registered++
		}
	}
	assert.Equal(t, 1, registered,
		"only the first WatchPluginBinary for a given path should emit registered")
}

// TestClearPluginWatches_DispatchesUnregisteredPerEntry — every dropped
// entry emits a PluginUnregisteredEvent with the original path, even
// when multiple entries existed. Order isn't guaranteed (map iteration)
// but the SET of paths must be exhaustive.
func TestClearPluginWatches_DispatchesUnregisteredPerEntry(t *testing.T) {
	LockDefaultRegistryForTest(t)
	_, cap := installCaptureDispatcher(t)

	tmp := t.TempDir()
	binA := filepath.Join(tmp, "plugin-a")
	binB := filepath.Join(tmp, "plugin-b")
	require.NoError(t, os.WriteFile(binA, []byte("a"), 0o755))
	require.NoError(t, os.WriteFile(binB, []byte("b"), 0o755))
	require.NoError(t, WatchPluginBinary(binA, &stubReloadable{}))
	require.NoError(t, WatchPluginBinary(binB, &stubReloadable{}))

	ClearPluginWatches()

	events := cap.snapshot()
	unregisteredPaths := map[string]bool{}
	for _, e := range events {
		if u, ok := e.(domain.PluginUnregisteredEvent); ok {
			unregisteredPaths[u.Path] = true
		}
	}
	absA, _ := filepath.Abs(binA)
	absB, _ := filepath.Abs(binB)
	assert.True(t, unregisteredPaths[absA], "plugin-a must emit unregistered")
	assert.True(t, unregisteredPaths[absB], "plugin-b must emit unregistered")
	assert.Len(t, unregisteredPaths, 2, "exactly two unregistered events expected")
}

// TestClearPluginWatches_NilDispatcherIsSafe — clearing with no
// dispatcher installed must not panic.
func TestClearPluginWatches_NilDispatcherIsSafe(t *testing.T) {
	LockDefaultRegistryForTest(t)
	prev := pluginWatcherDispatcher.Load()
	SetPluginWatcherEventDispatcher(nil)
	t.Cleanup(func() { SetPluginWatcherEventDispatcher(prev) })

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))
	require.NoError(t, WatchPluginBinary(binary, &stubReloadable{}))

	assert.NotPanics(t, ClearPluginWatches)
}

// TestStartStopWatcher_EmitsLifecyclePair — Start emits started, Stop
// emits stopped, in that order. Idempotent re-Start does NOT emit a
// second started.
func TestStartStopWatcher_EmitsLifecyclePair(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	_, cap := installCaptureDispatcher(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, StartPluginBinaryWatcher(ctx))
	// Idempotent re-Start: must NOT emit another started.
	require.NoError(t, StartPluginBinaryWatcher(ctx))

	StopPluginBinaryWatcher()

	events := cap.snapshot()
	var started, stopped int
	var startedIdx, stoppedIdx int = -1, -1
	for i, e := range events {
		switch e.(type) {
		case domain.PluginWatcherStartedEvent:
			started++
			if startedIdx < 0 {
				startedIdx = i
			}
		case domain.PluginWatcherStoppedEvent:
			stopped++
			if stoppedIdx < 0 {
				stoppedIdx = i
			}
		}
	}
	assert.Equal(t, 1, started, "exactly one started event expected (idempotent re-Start is silent)")
	assert.Equal(t, 1, stopped, "exactly one stopped event expected")
	assert.Greater(t, stoppedIdx, startedIdx,
		"stopped must come AFTER started in dispatch order")
}

// TestStopBeforeStart_NoStoppedEmit — calling Stop without a prior
// successful Start must NOT emit a PluginWatcherStoppedEvent (the
// guard at watcherState.started==false short-circuits before any
// state mutation).
func TestStopBeforeStart_NoStoppedEmit(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	_, cap := installCaptureDispatcher(t)

	StopPluginBinaryWatcher()

	events := cap.snapshot()
	for _, e := range events {
		_, isStopped := e.(domain.PluginWatcherStoppedEvent)
		assert.False(t, isStopped,
			"Stop without prior Start must NOT emit watcher_stopped")
	}
}

// TestReloadDebounce_DispatchesReloadTriggered — when the watcher
// observes a WRITE event, the debounced fire-and-forget timer calls
// Close() AND emits a typed PluginReloadTriggeredEvent. End-to-end
// verifies the fsnotify → debounce → emit pipeline.
func TestReloadDebounce_DispatchesReloadTriggered(t *testing.T) {
	LockDefaultRegistryForTest(t)
	t.Cleanup(ClearPluginWatches)
	_, cap := installCaptureDispatcher(t)

	tmp := t.TempDir()
	binary := filepath.Join(tmp, "fake-plugin")
	require.NoError(t, os.WriteFile(binary, []byte("v1"), 0o755))

	var closeCount atomic.Int32
	stub := &stubReloadable{closeFn: func() { closeCount.Add(1) }}
	require.NoError(t, WatchPluginBinary(binary, stub))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, StartPluginBinaryWatcher(ctx))
	defer StopPluginBinaryWatcher()

	// Trigger a fsnotify WRITE.
	require.NoError(t, os.WriteFile(binary, []byte("v2"), 0o755))

	// Wait for Close() AND the dispatched reload event to land. The 250ms
	// debounce + fsnotify latency budget covered by the 2s outer poll.
	abs, _ := filepath.Abs(binary)
	require.Eventually(t, func() bool {
		if closeCount.Load() == 0 {
			return false
		}
		for _, e := range cap.snapshot() {
			if r, ok := e.(domain.PluginReloadTriggeredEvent); ok && r.Path == abs {
				return true
			}
		}
		return false
	}, 2*time.Second, 20*time.Millisecond,
		"PluginReloadTriggeredEvent must be dispatched after debounced Close()")
}

// TestSetPluginWatcherEventDispatcher_RoundTrip — getter returns what
// setter installed; nil clears.
func TestSetPluginWatcherEventDispatcher_RoundTrip(t *testing.T) {
	prev := pluginWatcherDispatcher.Load()
	t.Cleanup(func() { SetPluginWatcherEventDispatcher(prev) })

	d := domain.NewEventDispatcher()
	SetPluginWatcherEventDispatcher(d)
	assert.Same(t, d, pluginEventBus())

	SetPluginWatcherEventDispatcher(nil)
	assert.Nil(t, pluginEventBus())
}

// TestPluginWatcherAggregateID — per-path events key by path; lifecycle
// events key by the global singleton.
func TestPluginWatcherAggregateID(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "plugin-watcher:/abs/foo",
		domain.PluginWatcherAggregateID("/abs/foo"))
	assert.Equal(t, "plugin-watcher:global",
		domain.PluginWatcherAggregateID(""))
}
