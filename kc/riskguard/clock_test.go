package riskguard

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMaybeResetDay_BeforeMarketOpen verifies that daily counters are NOT
// reset when the clock is before 9:15 AM IST on the same day.
func TestMaybeResetDay_BeforeMarketOpen(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")

	// Set clock to 8:00 AM IST on a Wednesday.
	morning := time.Date(2026, 4, 8, 8, 0, 0, 0, ist)
	g.SetClock(func() time.Time { return morning })

	email := "reset@test.com"

	// Manually seed the tracker with state from "yesterday" (well, today's
	// early morning — before 9:15 IST means the reset boundary hasn't
	// crossed yet).
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	// DayResetAt is set to 8:00 AM by getOrCreateTracker because our clock
	// returns that time. Now push DayResetAt backward to simulate yesterday's
	// reset but still after yesterday's 9:15.
	tracker.DayResetAt = time.Date(2026, 4, 7, 10, 0, 0, 0, ist) // yesterday 10 AM
	tracker.DailyOrderCount = 42
	tracker.DailyPlacedValue = 99999
	g.mu.Unlock()

	// GetUserStatus calls maybeResetDay under the hood.
	status := g.GetUserStatus(email)

	// Before 9:15 today, the "reset at" boundary is yesterday's 9:15.
	// Our tracker's DayResetAt (yesterday 10:00 AM) is AFTER yesterday's 9:15,
	// so no reset should occur.
	assert.Equal(t, 42, status.DailyOrderCount, "daily count should NOT be reset before 9:15 AM IST when last reset was after yesterday's 9:15")
	assert.Equal(t, float64(99999), status.DailyPlacedValue, "daily value should NOT be reset before 9:15 AM IST")
}

// TestMaybeResetDay_AfterMarketOpen verifies that daily counters ARE reset
// when the clock crosses 9:15 AM IST.
func TestMaybeResetDay_AfterMarketOpen(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")

	email := "reset@test.com"

	// Seed tracker with yesterday's state.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Date(2026, 4, 7, 10, 0, 0, 0, ist) // yesterday 10 AM
	tracker.DailyOrderCount = 42
	tracker.DailyPlacedValue = 99999
	g.mu.Unlock()

	// Now set clock to 9:30 AM IST today (after market open).
	afterOpen := time.Date(2026, 4, 8, 9, 30, 0, 0, ist)
	g.SetClock(func() time.Time { return afterOpen })

	status := g.GetUserStatus(email)

	// Today's 9:15 is the boundary. DayResetAt (yesterday 10 AM) is before
	// today's 9:15, so counters should reset.
	assert.Equal(t, 0, status.DailyOrderCount, "daily count should be reset after 9:15 AM IST")
	assert.Equal(t, float64(0), status.DailyPlacedValue, "daily value should be reset after 9:15 AM IST")
}

// TestMaybeResetDay_ExactlyAt915 verifies boundary behavior at exactly 9:15 AM IST.
func TestMaybeResetDay_ExactlyAt915(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")

	email := "boundary@test.com"

	// Seed tracker with yesterday's state.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Date(2026, 4, 7, 10, 0, 0, 0, ist)
	tracker.DailyOrderCount = 50
	tracker.DailyPlacedValue = 200000
	g.mu.Unlock()

	// At exactly 9:15 AM IST.
	exactlyOpen := time.Date(2026, 4, 8, 9, 15, 0, 0, ist)
	g.SetClock(func() time.Time { return exactlyOpen })

	status := g.GetUserStatus(email)

	// now == resetTime means now.Before(resetTime) is false, so resetTime
	// stays at today's 9:15. DayResetAt (yesterday 10 AM) is before today's
	// 9:15, so counters should reset.
	assert.Equal(t, 0, status.DailyOrderCount, "daily count should be reset at exactly 9:15 AM IST")
	assert.Equal(t, float64(0), status.DailyPlacedValue, "daily value should be reset at exactly 9:15 AM IST")
}

// TestMaybeResetDay_SameDayNoDoubleReset verifies that once reset, a second
// call within the same day does NOT re-reset counters.
func TestMaybeResetDay_SameDayNoDoubleReset(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")

	email := "noreset@test.com"

	// Clock at 10:00 AM IST.
	morning := time.Date(2026, 4, 8, 10, 0, 0, 0, ist)
	g.SetClock(func() time.Time { return morning })

	// First call: triggers reset (tracker DayResetAt defaults to clock time
	// which is after 9:15, so no immediate reset). Record some orders.
	g.RecordOrder(email, OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 10, Price: 1000, OrderType: "LIMIT",
	})
	g.RecordOrder(email)

	status := g.GetUserStatus(email)
	assert.Equal(t, 2, status.DailyOrderCount)

	// Advance clock to 2 PM same day.
	afternoon := time.Date(2026, 4, 8, 14, 0, 0, 0, ist)
	g.SetClock(func() time.Time { return afternoon })

	// Counters should NOT be reset — same trading day.
	status = g.GetUserStatus(email)
	assert.Equal(t, 2, status.DailyOrderCount, "counters should not reset within the same trading day")
}

// TestSetClock_DefaultIsTimeNow verifies that a fresh Guard uses time.Now
// and that SetClock overrides it.
func TestSetClock_DefaultIsTimeNow(t *testing.T) {
	t.Parallel()
	g := NewGuard(nil)

	// Default clock should return a time close to now.
	diff := time.Since(g.clock())
	assert.True(t, diff < time.Second, "default clock should return approximately time.Now()")

	// Override clock.
	ist, _ := time.LoadLocation("Asia/Kolkata")
	fixed := time.Date(2026, 1, 1, 12, 0, 0, 0, ist)
	g.SetClock(func() time.Time { return fixed })

	assert.Equal(t, fixed, g.clock(), "SetClock should override the clock")
}
