package audit

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// anomaly_cache_events_test.go — Event-source pilot tests for the
// statsCache aggregate. Verifies that every successful mutation
// dispatches a typed domain.AnomalyCache*Event via the shared
// EventDispatcher. The legacy hit-rate / TTL / size-eviction tests in
// anomaly_cache_test.go cover the cache behaviour itself; these
// tests focus on the dispatcher contract: runtime subscribers
// (projector, future consumers) MUST observe a typed event for every
// state-changing operation that succeeds.
//
// Pattern mirrors kc/usecases/watchlist_events_test.go (commit
// aeb3e8c) — the canonical "lift store mutations to typed domain
// events" template inside this codebase.

// captureDispatcher is a tiny helper that records every event passed
// through Dispatch into a slice under a mutex. Avoids re-implementing
// the same plumbing in each test.
type captureDispatcher struct {
	*domain.EventDispatcher
	mu     sync.Mutex
	events []domain.Event
}

func newCaptureDispatcher(t *testing.T) *captureDispatcher {
	t.Helper()
	c := &captureDispatcher{EventDispatcher: domain.NewEventDispatcher()}
	for _, et := range []string{
		"anomaly.baseline_snapshotted",
		"anomaly.cache_invalidated",
		"anomaly.cache_evicted",
	} {
		c.EventDispatcher.Subscribe(et, func(e domain.Event) {
			c.mu.Lock()
			c.events = append(c.events, e)
			c.mu.Unlock()
		})
	}
	return c
}

func (c *captureDispatcher) snapshot() []domain.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]domain.Event, len(c.events))
	copy(out, c.events)
	return out
}

// TestStatsCache_Set_DispatchesBaselineSnapshotted verifies a normal
// Set fires exactly one AnomalyBaselineSnapshottedEvent with the
// payload carrying the email/days/mean/stdev/count and BelowFloor=false
// for above-threshold snapshots.
func TestStatsCache_Set_DispatchesBaselineSnapshotted(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Set("alice@example.com", 30, 1000, 200, 12)

	got := disp.snapshot()
	require.Len(t, got, 1, "Set with non-overflow must dispatch exactly one baseline event")
	ev, ok := got[0].(domain.AnomalyBaselineSnapshottedEvent)
	require.True(t, ok, "expected AnomalyBaselineSnapshottedEvent, got %T", got[0])
	assert.Equal(t, "alice@example.com", ev.UserEmail)
	assert.Equal(t, 30, ev.Days)
	assert.Equal(t, 1000.0, ev.Mean)
	assert.Equal(t, 200.0, ev.Stdev)
	assert.Equal(t, 12.0, ev.Count)
	assert.False(t, ev.BelowFloor, "above-threshold snapshot must not be flagged BelowFloor")
	assert.WithinDuration(t, time.Now(), ev.Timestamp, 2*time.Second)
	assert.Equal(t, "anomaly.baseline_snapshotted", ev.EventType())
}

// TestStatsCache_Set_BelowFloorFlagged verifies that the floor
// sentinel (mean=0, stdev=0, count>0) maps to BelowFloor=true. This
// is what UserOrderStats writes when count<minBaselineOrders.
func TestStatsCache_Set_BelowFloorFlagged(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	// Floor sentinel: count>0 but mean+stdev zeroed.
	c.Set("new@user.com", 30, 0, 0, 3)

	got := disp.snapshot()
	require.Len(t, got, 1)
	ev := got[0].(domain.AnomalyBaselineSnapshottedEvent)
	assert.True(t, ev.BelowFloor, "floor sentinel (mean=0, stdev=0, count>0) must flag BelowFloor=true")
	assert.Equal(t, 3.0, ev.Count)
}

// TestStatsCache_Set_SizeOverflowDispatchesEviction verifies that
// when Set forces a size-overflow eviction (cap=2, third net-new key)
// BOTH events fire: an AnomalyCacheEvictedEvent for the dropped slot
// AND the AnomalyBaselineSnapshottedEvent for the new entry.
func TestStatsCache_Set_SizeOverflowDispatchesEviction(t *testing.T) {
	t.Parallel()
	c := newStatsCacheWithSize(15*time.Minute, 2)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Set("a@x.com", 30, 1, 1, 5) // 1 entry, no overflow
	c.Set("b@x.com", 30, 2, 2, 5) // 2 entries, no overflow
	c.Set("c@x.com", 30, 3, 3, 5) // overflow — one of a/b is evicted

	got := disp.snapshot()
	// 3 baseline snapshots + 1 size-overflow eviction = 4
	assert.Len(t, got, 4, "expected 3 snapshots + 1 size-overflow eviction")

	var evictions, snapshots int
	var sizeOverflowSeen bool
	for _, e := range got {
		switch ev := e.(type) {
		case domain.AnomalyCacheEvictedEvent:
			evictions++
			if ev.Reason == "size_overflow" {
				sizeOverflowSeen = true
				// Whichever email was evicted, it must be one of the two
				// we set earlier (a@x.com or b@x.com), and Days must equal 30.
				assert.Contains(t, []string{"a@x.com", "b@x.com"}, ev.UserEmail,
					"evicted UserEmail must be one of the originally-Set emails")
				assert.Equal(t, 30, ev.Days, "size-overflow event must carry the parsed days component")
			}
		case domain.AnomalyBaselineSnapshottedEvent:
			snapshots++
		}
	}
	assert.Equal(t, 3, snapshots, "exactly 3 baseline snapshots fire (one per Set)")
	assert.Equal(t, 1, evictions, "exactly 1 eviction fires on net-new overflow")
	assert.True(t, sizeOverflowSeen, "eviction must be tagged Reason=size_overflow")
}

// TestStatsCache_Set_ReplaceDoesNotEvict verifies replacing an
// existing key is NOT a net-new entry, so no eviction fires even
// when len==maxEntries. Only the snapshot event fires.
func TestStatsCache_Set_ReplaceDoesNotEvict(t *testing.T) {
	t.Parallel()
	c := newStatsCacheWithSize(15*time.Minute, 2)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Set("a@x.com", 30, 1, 1, 5)
	c.Set("b@x.com", 30, 2, 2, 5)
	disp.mu.Lock()
	disp.events = nil
	disp.mu.Unlock()

	// Replace a@x.com — len stays at 2, no eviction.
	c.Set("a@x.com", 30, 9, 9, 9)

	got := disp.snapshot()
	require.Len(t, got, 1, "replace must dispatch only the snapshot, no eviction")
	_, ok := got[0].(domain.AnomalyBaselineSnapshottedEvent)
	assert.True(t, ok, "expected only AnomalyBaselineSnapshottedEvent on replace")
}

// TestStatsCache_Get_TTLExpiryDispatchesEviction verifies the lazy
// TTL eviction path fires AnomalyCacheEvictedEvent with Reason=
// "ttl_expired" when a stale entry is encountered on Get.
func TestStatsCache_Get_TTLExpiryDispatchesEviction(t *testing.T) {
	t.Parallel()
	c := newStatsCache(5 * time.Millisecond)
	c.Set("ttl@user.com", 30, 500, 100, 7)
	// Snapshot from the Set above is irrelevant for this assertion;
	// attach the dispatcher AFTER the Set so we observe only the
	// eviction.
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	time.Sleep(15 * time.Millisecond)
	_, _, _, ok := c.Get("ttl@user.com", 30)
	require.False(t, ok, "stale entry must miss after TTL")

	got := disp.snapshot()
	require.Len(t, got, 1, "TTL miss must dispatch exactly one eviction event")
	ev, ok := got[0].(domain.AnomalyCacheEvictedEvent)
	require.True(t, ok)
	assert.Equal(t, "ttl@user.com", ev.UserEmail)
	assert.Equal(t, 30, ev.Days)
	assert.Equal(t, "ttl_expired", ev.Reason)
}

// TestStatsCache_Get_FreshHitDoesNotDispatch verifies that a normal
// hit (entry within TTL) emits no event — only state-changing
// operations dispatch, reads stay silent.
func TestStatsCache_Get_FreshHitDoesNotDispatch(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	c.Set("hot@user.com", 30, 100, 50, 8)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	_, _, _, ok := c.Get("hot@user.com", 30)
	require.True(t, ok)

	got := disp.snapshot()
	assert.Empty(t, got, "fresh Get hit must not dispatch any events")
}

// TestStatsCache_Invalidate_DispatchesInvalidatedEvent verifies that
// Invalidate fires exactly one AnomalyCacheInvalidatedEvent (not one
// per evicted key) tagged with the default "manual" reason.
func TestStatsCache_Invalidate_DispatchesInvalidatedEvent(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	c.Set("u@x.com", 30, 1, 1, 5)
	c.Set("u@x.com", 7, 2, 2, 5) // same email, different days window
	c.Set("v@x.com", 30, 3, 3, 5)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Invalidate("u@x.com")

	got := disp.snapshot()
	require.Len(t, got, 1, "Invalidate dispatches one aggregate-level event regardless of purged key count")
	ev, ok := got[0].(domain.AnomalyCacheInvalidatedEvent)
	require.True(t, ok, "expected AnomalyCacheInvalidatedEvent, got %T", got[0])
	assert.Equal(t, "u@x.com", ev.UserEmail)
	assert.Equal(t, "manual", ev.Reason, "Invalidate without reason defaults to 'manual'")
}

// TestStatsCache_InvalidateWithReason_PassesReason verifies the
// reason tag from the typed entry-point reaches the event payload.
// store_worker.go calls InvalidateWithReason("...", "order_recorded").
func TestStatsCache_InvalidateWithReason_PassesReason(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	c.Set("trader@x.com", 30, 1, 1, 5)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.InvalidateWithReason("trader@x.com", "order_recorded")

	got := disp.snapshot()
	require.Len(t, got, 1)
	ev := got[0].(domain.AnomalyCacheInvalidatedEvent)
	assert.Equal(t, "order_recorded", ev.Reason)
}

// TestStatsCache_Invalidate_NoOpStaysSilent verifies the
// "silent on no-op" contract: invalidating an email that has nothing
// in the cache must NOT dispatch (matches TierChangedEvent semantics).
func TestStatsCache_Invalidate_NoOpStaysSilent(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Invalidate("ghost@user.com") // never Set — purges 0 keys

	got := disp.snapshot()
	assert.Empty(t, got, "Invalidate of a never-cached email must stay silent")
}

// TestStatsCache_Invalidate_EmptyEmailStaysSilent verifies an empty
// email argument doesn't get sneaky behaviour (would have purged
// nothing under the old prefix-match anyway, but the explicit guard
// matches the intent).
func TestStatsCache_Invalidate_EmptyEmailStaysSilent(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)
	c.Set("u@x.com", 30, 1, 1, 5)
	disp := newCaptureDispatcher(t)
	c.SetEventDispatcher(disp.EventDispatcher)

	c.Invalidate("")

	got := disp.snapshot()
	assert.Empty(t, got, "empty-email Invalidate must stay silent")
}

// TestStatsCache_NilDispatcherIsSafe verifies the cache still works
// when no dispatcher has been wired (legacy path / older callers).
// All three mutation entry-points (Set, Invalidate, Get-TTL-evict)
// must succeed without panic.
func TestStatsCache_NilDispatcherIsSafe(t *testing.T) {
	t.Parallel()
	c := newStatsCache(5 * time.Millisecond) // no SetEventDispatcher

	c.Set("a@x.com", 30, 1, 1, 5)
	_, _, _, ok := c.Get("a@x.com", 30)
	assert.True(t, ok, "fresh hit must still work without dispatcher")

	time.Sleep(15 * time.Millisecond)
	_, _, _, ok = c.Get("a@x.com", 30) // triggers TTL evict
	assert.False(t, ok)

	c.Set("b@x.com", 30, 2, 2, 5)
	c.Invalidate("b@x.com")
}

// TestStatsCache_NilReceiverIsSafe verifies SetEventDispatcher is a
// no-op on a nil *statsCache, matching the rest of the cache API
// (Get/Set/Invalidate all tolerate nil receivers).
func TestStatsCache_NilReceiverIsSafe(t *testing.T) {
	t.Parallel()
	var c *statsCache
	require.NotPanics(t, func() {
		c.SetEventDispatcher(domain.NewEventDispatcher())
	})
}

// TestStatsCache_SetEventDispatcher_RebindIsIdempotent verifies that
// re-binding the dispatcher (e.g. test cleanup → fresh dispatcher)
// switches subscribers cleanly. The legacy dispatcher must stop
// receiving events and the new one must start.
func TestStatsCache_SetEventDispatcher_RebindIsIdempotent(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	first := newCaptureDispatcher(t)
	c.SetEventDispatcher(first.EventDispatcher)
	c.Set("u@x.com", 30, 1, 1, 5)

	// Rebind — first dispatcher must stop seeing new events.
	second := newCaptureDispatcher(t)
	c.SetEventDispatcher(second.EventDispatcher)
	c.Set("v@x.com", 30, 2, 2, 5)

	assert.Len(t, first.snapshot(), 1, "rebind must stop the previous dispatcher")
	assert.Len(t, second.snapshot(), 1, "rebind must route subsequent events to the new dispatcher")
}

// TestStatsCache_AggregateIDDerivation verifies the AnomalyCacheAggregateID
// helper produces the documented "anomaly:<email>" format. Co-located
// here because it's the single source of truth for app/adapters.go's
// deriveAggregateID anomaly cases.
func TestStatsCache_AggregateIDDerivation(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "anomaly:alice@x.com", domain.AnomalyCacheAggregateID("alice@x.com"))
	assert.Equal(t, "anomaly:unknown", domain.AnomalyCacheAggregateID(""))
}
