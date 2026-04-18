package riskguard

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestPerSecondRate_Allows9InOneSecond verifies that exactly 9 orders
// submitted inside the same calendar second are all allowed. The defensive
// threshold sits at 9 so the broker-side 10/sec cap always has 1-order
// headroom before Zerodha would reject the 11th order.
func TestPerSecondRate_Allows9InOneSecond(t *testing.T) {
	g := newTestGuard()
	email := "persec9@test.com"

	// Freeze the clock at a specific calendar second so every CheckOrder
	// call lands in the same second bucket.
	fixed := time.Date(2026, 4, 18, 10, 30, 45, 100_000_000, time.UTC) // 10:30:45.100
	g.SetClock(func() time.Time { return fixed })

	baseReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		// Use LIMIT with a tiny value so the per-order cap doesn't trip.
		Quantity: 1, Price: 10, OrderType: "LIMIT",
		Confirmed: true,
	}

	// 9 orders in the same calendar second — all should be allowed by the
	// per-second check. We rotate symbols so the params-based duplicate
	// check doesn't trip on identical (sym, side, qty) within 30s.
	symbols := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"}
	for i, sym := range symbols {
		req := baseReq
		req.Tradingsymbol = sym
		r := g.checkPerSecondRate(req.Email)
		assert.True(t, r.Allowed, "order %d in same second should be allowed (i=%d)", i+1, i)
		// Record so subsequent calls see this one in the counter.
		g.recordPerSecondOrder(email)
	}
}

// TestPerSecondRate_Denies10InOneSecond verifies that the 10th order in
// the same calendar second is rejected. Zerodha's broker-side cap is 10,
// so our defensive cap at 9 reserves one order of headroom.
func TestPerSecondRate_Denies10InOneSecond(t *testing.T) {
	g := newTestGuard()
	email := "persec10@test.com"

	fixed := time.Date(2026, 4, 18, 10, 30, 45, 250_000_000, time.UTC)
	g.SetClock(func() time.Time { return fixed })

	// Seed 9 prior orders in the same second.
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(email)
	}

	// The 10th check must be denied.
	r := g.checkPerSecondRate(email)
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonPerSecondRateExceeded, r.Reason)
	assert.Contains(t, r.Message, "Per-second")
}

// TestPerSecondRate_AllowsAcrossSeconds verifies that the counter is keyed
// by calendar second — an order at T=s and one at T=s+1 both allowed even
// if each second independently hits 9 orders. The spec explicitly says
// "per calendar clock second", not a rolling 1-second window.
func TestPerSecondRate_AllowsAcrossSeconds(t *testing.T) {
	g := newTestGuard()
	email := "persec-cross@test.com"

	// Second 1: put 9 orders in the bucket.
	second1 := time.Date(2026, 4, 18, 10, 30, 45, 500_000_000, time.UTC)
	g.SetClock(func() time.Time { return second1 })
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(email)
	}

	// Still second 1 — the 10th must be denied.
	denied := g.checkPerSecondRate(email)
	assert.False(t, denied.Allowed, "10th order in same second must be denied")

	// Advance to second 2 (new calendar second) — fresh bucket, must allow.
	second2 := time.Date(2026, 4, 18, 10, 30, 46, 100_000_000, time.UTC)
	g.SetClock(func() time.Time { return second2 })

	r := g.checkPerSecondRate(email)
	assert.True(t, r.Allowed, "first order in a new calendar second must be allowed even if the previous second was saturated")

	// Fill second 2 to 9 and confirm 10th denied there too.
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(email)
	}
	r = g.checkPerSecondRate(email)
	assert.False(t, r.Allowed, "second 2 also caps at 9")
	assert.Equal(t, ReasonPerSecondRateExceeded, r.Reason)

	// Advance to second 3 — fresh bucket again.
	second3 := time.Date(2026, 4, 18, 10, 30, 47, 0, time.UTC)
	g.SetClock(func() time.Time { return second3 })
	r = g.checkPerSecondRate(email)
	assert.True(t, r.Allowed, "third calendar second must start fresh")
}

// TestPerSecondRate_IsolatedByEmail verifies that user A exhausting their
// per-second quota does not starve user B. The counter must be keyed by
// (email, second), not just second.
func TestPerSecondRate_IsolatedByEmail(t *testing.T) {
	g := newTestGuard()
	userA := "alice@test.com"
	userB := "bob@test.com"

	fixed := time.Date(2026, 4, 18, 10, 30, 45, 0, time.UTC)
	g.SetClock(func() time.Time { return fixed })

	// Saturate user A to the cap.
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(userA)
	}

	// User A's next check is denied.
	rA := g.checkPerSecondRate(userA)
	assert.False(t, rA.Allowed, "user A at cap should be denied")
	assert.Equal(t, ReasonPerSecondRateExceeded, rA.Reason)

	// User B must still be allowed — isolated counter.
	rB := g.checkPerSecondRate(userB)
	assert.True(t, rB.Allowed, "user B should not be affected by user A's activity in the same second")

	// Fill user B to cap.
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(userB)
	}
	rB = g.checkPerSecondRate(userB)
	assert.False(t, rB.Allowed, "user B at own cap should also be denied")

	// User A and user B share the same wall-clock second — their state
	// must remain independent.
	rA = g.checkPerSecondRate(userA)
	assert.False(t, rA.Allowed, "user A still denied independently of user B")
}

// TestPerSecondRate_NilCounterFailsOpen verifies the defensive nil-guard:
// if a Guard is constructed without going through NewGuard (shouldn't
// happen in production, but possible in tests or if wiring regresses),
// the check must fail open rather than lock everyone out — the broker's
// own 10/sec cap still provides the hard stop.
func TestPerSecondRate_NilCounterFailsOpen(t *testing.T) {
	// Struct-literal construction — bypasses NewGuard, so perSecond is nil.
	g := &Guard{
		trackers: make(map[string]*UserTracker),
		limits:   make(map[string]*UserLimits),
		clock:    time.Now,
	}

	// checkPerSecondRate must allow (fail open on nil).
	r := g.checkPerSecondRate("any@test.com")
	assert.True(t, r.Allowed, "nil counter should fail open, not block")

	// recordPerSecondOrder must be a no-op (no panic on nil).
	assert.NotPanics(t, func() {
		g.recordPerSecondOrder("any@test.com")
	}, "recordPerSecondOrder on nil counter should be a silent no-op")
}

// TestPerSecondRate_IntegratedInCheckOrder_Denies10th verifies the check
// is actually wired into CheckOrder. Same-second 10th place_order must
// fail with the per-second reason, proving the middleware chain consults
// the new gate.
func TestPerSecondRate_IntegratedInCheckOrder_Denies10th(t *testing.T) {
	g := NewGuard(slog.Default())
	email := "integrated@test.com"

	// Turn off auto-freeze so accumulated rejections don't trip kill-switch
	// mid-test and mask the per-second reason.
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:       SystemDefaults.MaxSingleOrderINR,
		MaxOrdersPerDay:         SystemDefaults.MaxOrdersPerDay,
		MaxOrdersPerMinute:      SystemDefaults.MaxOrdersPerMinute,
		DuplicateWindowSecs:     0, // disable 30s dup check — we rotate symbols anyway
		MaxDailyValueINR:        SystemDefaults.MaxDailyValueINR,
		AutoFreezeOnLimitHit:    false,
		RequireConfirmAllOrders: true,
		AllowOffHours:           true, // avoid off-hours false negatives in CI
	}
	g.mu.Unlock()

	fixed := time.Date(2026, 4, 18, 10, 30, 45, 0, time.UTC)
	g.SetClock(func() time.Time { return fixed })

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", TransactionType: "BUY",
		Quantity: 1, Price: 10, OrderType: "LIMIT",
		Confirmed: true,
	}

	// Seed 9 prior recorded orders in the same second directly.
	for i := 0; i < 9; i++ {
		g.recordPerSecondOrder(email)
	}

	// 10th through CheckOrder should be rejected by per-second gate.
	req.Tradingsymbol = "SYM10"
	r := g.CheckOrder(req)
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonPerSecondRateExceeded, r.Reason)
}
