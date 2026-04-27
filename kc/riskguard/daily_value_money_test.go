package riskguard

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// daily_value_money_test.go — Money-VO behavior of UserTracker.DailyPlacedValue
// + UserStatus.DailyPlacedValue. Pinned invariants for Slice 3:
//   - Both fields are typed Money (currency-aware; not bare float64)
//   - JSON wire format unchanged via custom MarshalJSON emitting float64
//   - RecordOrder increments via Money.Add (not float +=); zero-Money sentinel
//     handled correctly on the first priced increment of the day
//   - Daily reset (9:15 AM IST) zeroes the Money via assignment

// TestUserTracker_DailyPlacedValueIsMoney is the type-level assertion. If the
// field reverts to float64, this stops compiling rather than producing
// silent currency coercion at the headroom-subtraction boundary.
func TestUserTracker_DailyPlacedValueIsMoney(t *testing.T) {
	t.Parallel()
	var tr UserTracker
	tr.DailyPlacedValue = domain.NewINR(50000)
	assert.Equal(t, "INR", tr.DailyPlacedValue.Currency)
	assert.Equal(t, float64(50000), tr.DailyPlacedValue.Float64())
}

// TestUserStatus_DailyPlacedValueIsMoney — same compile-time gate for the
// read-side snapshot.
func TestUserStatus_DailyPlacedValueIsMoney(t *testing.T) {
	t.Parallel()
	var s UserStatus
	s.DailyPlacedValue = domain.NewINR(123.45)
	assert.Equal(t, "INR", s.DailyPlacedValue.Currency)
	assert.Equal(t, 123.45, s.DailyPlacedValue.Float64())
}

// TestUserStatus_JSONWireFormatPreserved — the dashboard SSE feed and admin
// tools see UserStatus marshalled to JSON. The wire contract MUST emit
// `daily_placed_value` as a raw float64; the Money internal type is
// transparent to JSON consumers.
func TestUserStatus_JSONWireFormatPreserved(t *testing.T) {
	t.Parallel()

	s := UserStatus{
		DailyOrderCount:  5,
		DailyPlacedValue: domain.NewINR(12345.67),
		IsFrozen:         false,
	}
	data, err := json.Marshal(s)
	require.NoError(t, err)

	// Round-trip via map[string]any to inspect the wire shape.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	dpv, ok := raw["daily_placed_value"].(float64)
	require.True(t, ok, "daily_placed_value must be a JSON number, got %T", raw["daily_placed_value"])
	assert.Equal(t, 12345.67, dpv)
}

// TestUserStatus_JSONRoundTrip verifies UnmarshalJSON reconstructs the
// Money field correctly — internal logic that round-trips a UserStatus
// through JSON (admin tool fixtures, SSE replay tests) must see the same
// Money value on both sides.
func TestUserStatus_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := UserStatus{
		DailyOrderCount:  3,
		DailyPlacedValue: domain.NewINR(98765.43),
	}
	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded UserStatus
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, "INR", decoded.DailyPlacedValue.Currency)
	assert.Equal(t, 98765.43, decoded.DailyPlacedValue.Float64())
	assert.Equal(t, 3, decoded.DailyOrderCount)
}

// TestRecordOrder_IncrementsViaMoneyAdd: when RecordOrder is called with a
// priced order, the daily-placed-value Money grows by qty * price. This is
// the cumulative tracker that drives the daily-value cap check.
func TestRecordOrder_IncrementsViaMoneyAdd(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	email := "incr@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:       domain.NewINR(10000000),
		MaxDailyValueINR:        domain.NewINR(100000000),
		RequireConfirmAllOrders: false,
	}
	g.mu.Unlock()

	// First order: 10 * 1000 = 10,000 (zero-Money sentinel transitioned
	// to populated via the IsZero() branch of RecordOrder).
	g.RecordOrder(email, OrderCheckRequest{
		Email:    email,
		ToolName: "place_order",
		Quantity: 10,
		Price:    domain.NewINR(1000),
	})
	status := g.GetUserStatus(email)
	assert.Equal(t, "INR", status.DailyPlacedValue.Currency)
	assert.InDelta(t, 10000.0, status.DailyPlacedValue.Float64(), 0.01)

	// Second order: 5 * 200 = 1,000 (Money.Add path). Cumulative = 11,000.
	g.RecordOrder(email, OrderCheckRequest{
		Email:    email,
		ToolName: "place_order",
		Quantity: 5,
		Price:    domain.NewINR(200),
	})
	status = g.GetUserStatus(email)
	assert.InDelta(t, 11000.0, status.DailyPlacedValue.Float64(), 0.01)
}

// TestRecordOrder_MarketOrderSkips: a MARKET order has zero-Money price and
// must NOT increment DailyPlacedValue (price unknown at submission time).
func TestRecordOrder_MarketOrderSkips(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)
	email := "market@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:       domain.NewINR(10000000),
		MaxDailyValueINR:        domain.NewINR(100000000),
		RequireConfirmAllOrders: false,
	}
	g.mu.Unlock()

	// Zero-Money price (MARKET semantics) — no increment.
	g.RecordOrder(email, OrderCheckRequest{
		Email:    email,
		ToolName: "place_order",
		Quantity: 1000,
	})

	status := g.GetUserStatus(email)
	assert.True(t, status.DailyPlacedValue.IsZero(),
		"MARKET order (zero-Money price) must not increment DailyPlacedValue")
}

// TestPnL_NegativeMoneyPreserved verifies sign preservation through Money.
// P&L can be negative (loss); domain.NewINR accepts any sign and Money.Add
// must preserve it. This is the safety check for the briefing P&L
// aggregation paths in kc/alerts/briefing.go.
func TestPnL_NegativeMoneyPreserved(t *testing.T) {
	t.Parallel()

	// Positive + negative -> net negative (loss day).
	gain := domain.NewINR(1500)
	loss := domain.NewINR(-3000)
	net, err := gain.Add(loss)
	require.NoError(t, err)
	assert.True(t, net.IsNegative())
	assert.Equal(t, -1500.0, net.Float64())

	// Pure negative aggregation.
	a := domain.NewINR(-200)
	b := domain.NewINR(-300)
	sum, err := a.Add(b)
	require.NoError(t, err)
	assert.Equal(t, -500.0, sum.Float64())
	assert.Equal(t, "INR", sum.Currency)
}
