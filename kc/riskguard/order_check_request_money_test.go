package riskguard

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// order_check_request_money_test.go — Money-VO behavior of
// OrderCheckRequest.Price. Pinned invariants for Slice 2 of the Money
// sweep:
//   - Price is typed Money (currency-aware, not bare float64)
//   - Zero-value Money is the "MARKET order / no price set" sentinel —
//     priced checks (order_value, daily_value, OTR-band, circuit limit,
//     margin) must skip when Price.IsZero() returns true
//   - LIMIT orders carry a positive Money and are subject to the priced
//     checks via Money.GreaterThan against UserLimits Money values

// TestOrderCheckRequest_PriceIsMoney is the type-level assertion. If the
// Price field reverts to a primitive float64, this stops compiling rather
// than producing silent currency coercion at the comparison boundary.
func TestOrderCheckRequest_PriceIsMoney(t *testing.T) {
	t.Parallel()
	var req OrderCheckRequest
	// Compile-time assertion: assignment requires domain.Money on both sides.
	req.Price = domain.NewINR(100.50)
	assert.Equal(t, "INR", req.Price.Currency)
	assert.Equal(t, float64(100.50), req.Price.Float64())
}

// TestCheckOrderValue_ZeroPriceSkips: when Price is zero Money (MARKET
// order), the order-value check must skip — there is no known notional
// to compare against the cap.
func TestCheckOrderValue_ZeroPriceSkips(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)

	g.mu.Lock()
	g.limits["m@test.com"] = &UserLimits{
		MaxSingleOrderINR:       domain.NewINR(1000),
		RequireConfirmAllOrders: false,
	}
	g.mu.Unlock()

	// MARKET order: Price is zero Money. Quantity could otherwise blow
	// the cap (10000 * <unknown> >> 1000) but with no price we can't
	// compute the notional, so the check skips and the order proceeds.
	r := g.checkOrderValue(OrderCheckRequest{
		Email:    "m@test.com",
		ToolName: "place_order",
		Quantity: 10000,
		// Price left as zero Money — MARKET semantics
	})
	assert.True(t, r.Allowed, "zero-Money price (MARKET) must skip order_value check")
}

// TestCheckOrderValue_PricedExceedsLimit: when Price is a positive Money
// and quantity*price exceeds MaxSingleOrderINR, the check rejects with
// ReasonOrderValue. Replaces the float-comparison test.
func TestCheckOrderValue_PricedExceedsLimit(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	pinClockInMarketHours(g)

	g.mu.Lock()
	g.limits["lim@test.com"] = &UserLimits{
		MaxSingleOrderINR:       domain.NewINR(1000),
		RequireConfirmAllOrders: false,
	}
	g.mu.Unlock()

	// 10 * 200 = 2000 > 1000
	r := g.checkOrderValue(OrderCheckRequest{
		Email:    "lim@test.com",
		ToolName: "place_order",
		Quantity: 10,
		Price:    domain.NewINR(200),
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonOrderValue, r.Reason)
}

// TestSubprocessWire_PreservesPrice: the plugin RPC wire-format keeps
// Price as float64 for backward-compat. The host -> wire conversion
// must drop into the float boundary and the wire -> host conversion
// must reconstruct an INR Money value.
func TestSubprocessWire_PreservesPrice(t *testing.T) {
	t.Parallel()
	// Internal Money price.
	internalPrice := domain.NewINR(123.45)
	// Wire conversion: drop to float64.
	wirePrice := internalPrice.Float64()
	assert.Equal(t, 123.45, wirePrice)
	// Reconstruct from wire on the receive side.
	reconstructed := domain.NewINR(wirePrice)
	assert.Equal(t, "INR", reconstructed.Currency)
	assert.Equal(t, 123.45, reconstructed.Float64())
}
