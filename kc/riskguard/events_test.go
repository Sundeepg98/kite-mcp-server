package riskguard

import (
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// captureDispatcher returns a fresh EventDispatcher whose every dispatch
// is recorded into the *[]domain.Event mutex-guarded slice. Using
// the real dispatcher instead of a mock keeps the tests honest about
// the "events flow exactly the same way ProductionDispatcher.Dispatch
// runs them" contract — any future regression in the dispatcher (e.g.
// new sync semantics) gets caught here.
func captureDispatcher(t *testing.T) (*domain.EventDispatcher, *[]domain.Event, *sync.Mutex) {
	t.Helper()
	d := domain.NewEventDispatcher()
	var mu sync.Mutex
	captured := make([]domain.Event, 0)
	for _, evType := range []string{
		"riskguard.kill_switch_tripped",
		"riskguard.daily_counter_reset",
		"riskguard.rejection_recorded",
	} {
		d.Subscribe(evType, func(e domain.Event) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, e)
		})
	}
	return d, &captured, &mu
}

// TestSetEventDispatcher_KillSwitchTrip_DispatchesActiveTrue verifies
// that FreezeGlobal emits RiskguardKillSwitchTrippedEvent with Active=true
// on a real off→on transition.
func TestSetEventDispatcher_KillSwitchTrip_DispatchesActiveTrue(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	g.FreezeGlobal("admin@test.com", "scheduled maintenance")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 1, "expected exactly one event on a real freeze transition")
	ev, ok := (*captured)[0].(domain.RiskguardKillSwitchTrippedEvent)
	require.True(t, ok, "event should be RiskguardKillSwitchTrippedEvent")
	assert.True(t, ev.Active, "first trip should be Active=true")
	assert.Equal(t, "admin@test.com", ev.FrozenBy)
	assert.Equal(t, "scheduled maintenance", ev.Reason)
	assert.Empty(t, ev.UserEmail, "global kill-switch event has empty UserEmail")
	assert.False(t, ev.Timestamp.IsZero(), "timestamp must be set")
}

// TestSetEventDispatcher_KillSwitchTrip_IdempotentReEmission verifies
// that a second FreezeGlobal call while already frozen is a no-op for
// dispatch — projection replays should see ONE trip per actual
// off→on lifecycle.
func TestSetEventDispatcher_KillSwitchTrip_IdempotentReEmission(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	g.FreezeGlobal("admin@test.com", "first reason")
	g.FreezeGlobal("admin@test.com", "second reason — should NOT emit")
	g.FreezeGlobal("other-admin@test.com", "third reason — also should NOT emit")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 1, "idempotent FreezeGlobal must emit only on the first trip")
	ev := (*captured)[0].(domain.RiskguardKillSwitchTrippedEvent)
	assert.Equal(t, "first reason", ev.Reason, "first event captures the original trip metadata")
}

// TestSetEventDispatcher_KillSwitchLift_DispatchesActiveFalse verifies
// that UnfreezeGlobal emits RiskguardKillSwitchTrippedEvent with
// Active=false on a real on→off transition.
func TestSetEventDispatcher_KillSwitchLift_DispatchesActiveFalse(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	g.FreezeGlobal("admin@test.com", "incident")
	g.UnfreezeGlobal()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 2)
	trip := (*captured)[0].(domain.RiskguardKillSwitchTrippedEvent)
	lift := (*captured)[1].(domain.RiskguardKillSwitchTrippedEvent)
	assert.True(t, trip.Active, "first event is the trip")
	assert.False(t, lift.Active, "second event is the lift")
}

// TestSetEventDispatcher_KillSwitchLift_NoOpWhenAlreadyUnfrozen verifies
// idempotent unfreeze: calling UnfreezeGlobal when not frozen should not
// emit a spurious lift event.
func TestSetEventDispatcher_KillSwitchLift_NoOpWhenAlreadyUnfrozen(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	// No prior FreezeGlobal — guard starts unfrozen.
	g.UnfreezeGlobal()
	g.UnfreezeGlobal()

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, *captured, "UnfreezeGlobal on already-unfrozen guard must not emit")
}

// TestSetEventDispatcher_DailyCounterReset_DispatchesOnRollover verifies
// that crossing 9:15 AM IST emits RiskguardDailyCounterResetEvent.
func TestSetEventDispatcher_DailyCounterReset_DispatchesOnRollover(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)
	ist, _ := time.LoadLocation("Asia/Kolkata")

	email := "trader@test.com"

	// Seed yesterday's state under the lock.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Date(2026, 4, 7, 10, 0, 0, 0, ist) // yesterday 10 AM
	tracker.DailyOrderCount = 15
	tracker.DailyPlacedValue = domain.NewINR(50000)
	g.mu.Unlock()

	// Clock cross to today 9:30 AM IST → reset should fire.
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 9, 30, 0, 0, ist) })

	// GetUserStatus is the canonical entry point that triggers maybeResetDay.
	status := g.GetUserStatus(email)
	assert.Equal(t, 0, status.DailyOrderCount, "counters should be zeroed by the reset")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 1, "exactly one reset event")
	ev, ok := (*captured)[0].(domain.RiskguardDailyCounterResetEvent)
	require.True(t, ok)
	assert.Equal(t, email, ev.UserEmail)
	assert.Equal(t, "trading_day_boundary", ev.Reason)
	assert.False(t, ev.Timestamp.IsZero())
}

// TestSetEventDispatcher_DailyCounterReset_NoOpWhenNotRolled verifies
// that calls within the same trading day don't emit reset events.
func TestSetEventDispatcher_DailyCounterReset_NoOpWhenNotRolled(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 14, 0, 0, 0, ist) })

	email := "trader@test.com"

	// First read: tracker is created with DayResetAt = clock(), so
	// maybeResetDay sees DayResetAt == today → not before today's 9:15 →
	// no reset.
	_ = g.GetUserStatus(email)
	// Second read: same.
	_ = g.GetUserStatus(email)

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, *captured, "no reset events should fire within the same trading day")
}

// TestSetEventDispatcher_RejectionRecorded_DispatchesWithReason verifies
// that recordRejection emits RiskguardRejectionEvent threading the
// RejectionReason through.
func TestSetEventDispatcher_RejectionRecorded_DispatchesWithReason(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	email := "rejected@test.com"
	g.recordRejection(email, ReasonOrderValue)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 1)
	ev, ok := (*captured)[0].(domain.RiskguardRejectionEvent)
	require.True(t, ok)
	assert.Equal(t, email, ev.UserEmail)
	assert.Equal(t, string(ReasonOrderValue), ev.Reason)
	assert.False(t, ev.Timestamp.IsZero())
}

// TestSetEventDispatcher_RejectionRecorded_MultipleRejectionsAccumulate
// verifies that multiple recordRejection calls produce one event each
// — replaying gives the auto-freeze sliding window's full trajectory.
func TestSetEventDispatcher_RejectionRecorded_MultipleRejectionsAccumulate(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)

	email := "abuser@test.com"
	g.recordRejection(email, ReasonOrderValue)
	g.recordRejection(email, ReasonDailyValueLimit)
	g.recordRejection(email, ReasonAnomalyHigh)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, *captured, 3, "each rejection emits its own event")
	reasons := []string{
		(*captured)[0].(domain.RiskguardRejectionEvent).Reason,
		(*captured)[1].(domain.RiskguardRejectionEvent).Reason,
		(*captured)[2].(domain.RiskguardRejectionEvent).Reason,
	}
	assert.Equal(t, []string{
		string(ReasonOrderValue),
		string(ReasonDailyValueLimit),
		string(ReasonAnomalyHigh),
	}, reasons, "events preserve insertion order and reason")
}

// TestSetEventDispatcher_NilSafety verifies that a Guard constructed
// without SetEventDispatcher behaves identically to the pre-ES code
// path — no panics on the mutation surface.
func TestSetEventDispatcher_NilSafety(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	// No SetEventDispatcher call.

	require.NotPanics(t, func() {
		g.FreezeGlobal("admin", "reason")
		g.UnfreezeGlobal()
		g.recordRejection("user@test.com", ReasonOrderValue)
		_ = g.GetUserStatus("user@test.com")
		g.RecordOrder("user@test.com", OrderCheckRequest{
			Email: "user@test.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
			Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		})
	})
}

// TestSetEventDispatcher_RecordOrder_DispatchesResetEvent verifies that
// RecordOrder also drives the reset emission when it's the first call
// of the trading day (covers the place-order hot path that doesn't go
// through GetUserStatus).
func TestSetEventDispatcher_RecordOrder_DispatchesResetEvent(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	d, captured, mu := captureDispatcher(t)
	g.SetEventDispatcher(d)
	ist, _ := time.LoadLocation("Asia/Kolkata")

	email := "trader@test.com"

	// Seed yesterday's state.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Date(2026, 4, 7, 10, 0, 0, 0, ist)
	tracker.DailyOrderCount = 5
	g.mu.Unlock()

	// Today 10 AM IST.
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 10, 0, 0, 0, ist) })

	g.RecordOrder(email, OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
	})

	mu.Lock()
	defer mu.Unlock()

	// Expect exactly ONE reset event from this RecordOrder call.
	resetCount := 0
	for _, e := range *captured {
		if _, ok := e.(domain.RiskguardDailyCounterResetEvent); ok {
			resetCount++
		}
	}
	assert.Equal(t, 1, resetCount, "RecordOrder triggers the rollover reset event exactly once")
}

// TestSetEventDispatcher_DispatcherReplaceable verifies SetEventDispatcher
// is idempotent: re-calling replaces the dispatcher, so a stale dispatcher
// stops receiving events. Mirrors the billing.Store contract.
func TestSetEventDispatcher_DispatcherReplaceable(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())

	d1, cap1, mu1 := captureDispatcher(t)
	g.SetEventDispatcher(d1)
	g.FreezeGlobal("admin", "reason1")

	d2, cap2, mu2 := captureDispatcher(t)
	g.SetEventDispatcher(d2)
	g.UnfreezeGlobal() // emits Active=false on d2 only

	mu1.Lock()
	mu2.Lock()
	defer mu1.Unlock()
	defer mu2.Unlock()
	assert.Len(t, *cap1, 1, "first dispatcher saw the trip; nothing after replacement")
	assert.Len(t, *cap2, 1, "second dispatcher saw only the lift")
	lift := (*cap2)[0].(domain.RiskguardKillSwitchTrippedEvent)
	assert.False(t, lift.Active)
}

// TestRiskguardCountersAggregateID verifies the natural-key derivation
// for the counters aggregate. Critical for projector replay correctness:
// per-user events sort under "riskguard:<email>", global kill-switch
// events sort under "riskguard:global".
func TestRiskguardCountersAggregateID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{"per-user email", "user@test.com", "riskguard:user@test.com"},
		{"empty email is global", "", "riskguard:global"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, domain.RiskguardCountersAggregateID(tt.email))
		})
	}
}
