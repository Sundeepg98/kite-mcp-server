// Tests for the anomaly-detection and off-hours checks added on top of the
// existing static riskguard defences. See guard.go for the check methods.
//
// Attack scenario: a user whose historical mean order value is ~Rs 5,000
// suddenly places a Rs 49,000 order. The order is under the Rs 50k static
// cap and therefore not flagged by checkOrderValue — but 49x the user's
// typical trade and >3σ from their mean is a strong signal that either
// (a) their agent was prompt-injected or (b) an account takeover is in
// progress. Block it and demand an admin review.
//
// Complementary off-hours guard: 02:00–06:00 IST is outside market hours
// AND outside the usual human decision window. Any order activity there
// is either automation gone wrong or an adversary betting the owner is
// asleep. Hard-block unless the user explicitly opted in.
package riskguard

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// mockBaseline is a test double for the anomaly baseline provider. It lets
// us pin (mean, stdev, count) without spinning up a real audit store.
type mockBaseline struct {
	mean  float64
	stdev float64
	count float64
}

func (m *mockBaseline) UserOrderStats(_ string, _ int) (float64, float64, float64) {
	return m.mean, m.stdev, m.count
}

// TestCheckAnomalyMultiplier_BlocksFarOutlier: a Rs 60k order against a
// Rs 5k historical mean (σ=Rs 1k) is both > μ+3σ (= 8k) AND > 10×μ (= 50k).
// Must block. We raise the static per-order and daily-value caps so the
// static guards don't pre-empt the anomaly check — we're isolating the
// new behaviour.
func TestCheckAnomalyMultiplier_BlocksFarOutlier(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	g.SetBaselineProvider(&mockBaseline{mean: 5000, stdev: 1000, count: 20})

	g.mu.Lock()
	g.limits["attacker@test.com"] = &UserLimits{
		RequireConfirmAllOrders: false,
		MaxSingleOrderINR:       domain.NewINR(1_000_000), // Rs 10L — lets the anomaly check be decisive
		MaxDailyValueINR:        domain.NewINR(10_000_000),
	}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "attacker@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(60_000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed, "12x mean AND >3σ should trigger anomaly block")
	assert.Equal(t, ReasonAnomalyHigh, r.Reason)
	assert.Contains(t, r.Message, "anomaly")
}

// TestCheckAnomalyMultiplier_AllowsWithinBaseline: an order of 2× the mean
// is below the 10× threshold (even if >3σ away) — allow and let lesser
// checks catch it.
func TestCheckAnomalyMultiplier_AllowsWithinBaseline(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	g.SetBaselineProvider(&mockBaseline{mean: 5000, stdev: 500, count: 20})
	g.mu.Lock()
	g.limits["steady@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	// 2× mean = Rs 10,000. > μ+3σ (= 6500) but NOT > 10×μ (= 50000).
	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "steady@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(10000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "2x mean is within the 10x anomaly ceiling")
}

// TestCheckAnomalyMultiplier_RequiresBothConditions: an order that is >10×
// mean but within μ+3σ (because stdev is huge) must pass — statistical
// noise is not an anomaly. Both conditions must hold.
func TestCheckAnomalyMultiplier_RequiresBothConditions(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	// Huge stdev → μ+3σ is higher than 10×μ.
	g.SetBaselineProvider(&mockBaseline{mean: 5000, stdev: 100000, count: 20})
	g.mu.Lock()
	g.limits["volatile@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	// Rs 60,000: > 10×mean (50k) but < μ+3σ (305k). Should NOT trigger
	// anomaly. It WILL hit the static per-order cap (50k) but that's a
	// separate check — we're asserting the anomaly check specifically
	// lets it through. Use a tiny override to disable the static cap.
	g.mu.Lock()
	g.limits["volatile@test.com"].MaxSingleOrderINR = domain.NewINR(1_000_000) // Rs 10L override
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "volatile@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(60000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "wide-stdev user: 10x mean but within 3σ should not be flagged")
}

// TestCheckAnomalyMultiplier_NoBaselineSkips: a user with fewer than 5
// historical orders has count < minBaselineOrders → mean=0, stdev=0. The
// anomaly check must skip (fail open, allow the order).
func TestCheckAnomalyMultiplier_NoBaselineSkips(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	g.SetBaselineProvider(&mockBaseline{mean: 0, stdev: 0, count: 2}) // below floor
	g.mu.Lock()
	g.limits["newbie@test.com"] = &UserLimits{
		RequireConfirmAllOrders: false,
		MaxSingleOrderINR:       domain.NewINR(10_000_000), // raise static caps so we isolate anomaly check
		MaxDailyValueINR:        domain.NewINR(100_000_000),
	}
	g.mu.Unlock()

	// Big order, no history → anomaly check must not block it.
	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "newbie@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(500_000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "no baseline yet should fail open on anomaly check")
}

// TestCheckAnomalyMultiplier_MarketOrderSkipped: MARKET orders have Price=0
// at submission → order value is unknown → anomaly check must no-op.
func TestCheckAnomalyMultiplier_MarketOrderSkipped(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	g.SetBaselineProvider(&mockBaseline{mean: 5000, stdev: 500, count: 20})
	g.mu.Lock()
	g.limits["mo@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "mo@test.com", ToolName: "place_order",
		Quantity: 1_000_000, Price: domain.Money{}, OrderType: "MARKET",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "MARKET orders have no known value — anomaly check skips")
}

// TestCheckAnomalyMultiplier_NoProviderSkips: if the guard was never given
// a baseline provider (e.g. tests or dev mode without audit store), the
// check must be a silent no-op.
func TestCheckAnomalyMultiplier_NoProviderSkips(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	g.mu.Lock()
	g.limits["np@test.com"] = &UserLimits{
		RequireConfirmAllOrders: false,
		MaxSingleOrderINR:       domain.NewINR(10_000_000),
		MaxDailyValueINR:        domain.NewINR(100_000_000),
	}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "np@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(500_000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "no baseline provider configured → anomaly check is a no-op")
}

// --- Off-hours check ---

// TestCheckOffHours_BlocksAt3AM: 03:00 IST is deep inside the 02:00–06:00
// block window. Must reject with ReasonOffHoursBlocked.
func TestCheckOffHours_BlocksAt3AM(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")
	// 03:00 AM IST on a Wednesday.
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 3, 0, 0, 0, ist) })
	g.mu.Lock()
	g.limits["night@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "night@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed, "3 AM IST is hard-blocked")
	assert.Equal(t, ReasonOffHoursBlocked, r.Reason)
}

// TestCheckOffHours_BlocksAtBoundary0200: the window is [02:00, 06:00), so
// 02:00 IST sharp is blocked and 06:00 IST sharp is allowed.
func TestCheckOffHours_BlocksAtBoundary0200(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 2, 0, 0, 0, ist) })
	g.mu.Lock()
	g.limits["boundary@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "boundary@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonOffHoursBlocked, r.Reason)
}

// TestCheckOffHours_AllowsAtBoundary0600: the window ends at 06:00 exclusive.
// Variety="amo" bypasses the new market_hours check (T1) so this test
// isolates the off_hours decision — at 06:00 IST the market is closed,
// so a non-AMO order would still be rejected by checkMarketHours.
func TestCheckOffHours_AllowsAtBoundary0600(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 6, 0, 0, 0, ist) })
	g.mu.Lock()
	g.limits["b2@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "b2@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Variety:   "amo", // bypass market_hours; we only test off_hours here
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "06:00 IST is outside the off-hours block window")
}

// TestCheckOffHours_AllowsAtMarketHours: 09:30 IST is peak market hours.
func TestCheckOffHours_AllowsAtMarketHours(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 9, 30, 0, 0, ist) })
	g.mu.Lock()
	g.limits["day@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "day@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed)
}

// TestCheckOffHours_AllowOptIn: a power user with AllowOffHours=true can
// bypass the off-hours block. Variety="amo" additionally bypasses the new
// market_hours check (T1) so this test isolates the AllowOffHours opt-in;
// 03:00 IST is well before market open so a non-AMO order would still be
// rejected by checkMarketHours.
func TestCheckOffHours_AllowOptIn(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	ist, _ := time.LoadLocation("Asia/Kolkata")
	g.SetClock(func() time.Time { return time.Date(2026, 4, 8, 3, 0, 0, 0, ist) })
	g.mu.Lock()
	g.limits["owl@test.com"] = &UserLimits{
		RequireConfirmAllOrders: false,
		AllowOffHours:           true,
	}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "owl@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Variety:   "amo", // bypass market_hours; we only test off_hours opt-in here
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "AllowOffHours=true bypasses the off-hours block")
}

// TestCheckOffHours_TimezoneCorrectness: IST is UTC+5:30, so UTC 21:00 the
// previous day is 02:30 IST the next day — must be blocked. This catches
// regressions where someone compares server-local hour instead of IST.
func TestCheckOffHours_TimezoneCorrectness(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	// UTC clock at 21:00 on Apr 7 → IST 02:30 on Apr 8 (well inside block).
	utcTime := time.Date(2026, 4, 7, 21, 0, 0, 0, time.UTC)
	g.SetClock(func() time.Time { return utcTime })
	g.mu.Lock()
	g.limits["tz@test.com"] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "tz@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(1000), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed, "21:00 UTC = 02:30 IST — off-hours block must engage in IST not UTC")
	assert.Equal(t, ReasonOffHoursBlocked, r.Reason)
}
