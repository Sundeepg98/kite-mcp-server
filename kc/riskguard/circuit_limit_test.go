package riskguard

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// stubCircuitLookup is the test double for CircuitLookup. Maps a key
// "exchange|tradingsymbol" to (lower, upper) circuit pair.
type stubCircuitLookup struct {
	limits map[string][2]float64
}

func newStubCircuit(limits map[string][2]float64) *stubCircuitLookup {
	return &stubCircuitLookup{limits: limits}
}

func (s *stubCircuitLookup) GetCircuitLimits(exchange, tradingsymbol string) (lower, upper float64, found bool) {
	pair, ok := s.limits[exchange+"|"+tradingsymbol]
	if !ok {
		return 0, 0, false
	}
	return pair[0], pair[1], true
}

func newGuardWithCircuit(lookup CircuitLookup) *Guard {
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SetCircuitLookup(lookup)
	pinClockInMarketHours(g)
	return g
}

// TestCircuitLimit_AllowsWithinBand — order at ₹100 with circuit
// (₹95, ₹105) passes through.
func TestCircuitLimit_AllowsWithinBand(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{
		"NSE|RELIANCE": {95, 105},
	}))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 1, OrderType: "LIMIT", Price: 100, Confirmed: true,
	})
	assert.True(t, res.Allowed)
}

// TestCircuitLimit_RejectsAboveUpper — order at ₹120 with upper ₹105
// hits the rejection.
func TestCircuitLimit_RejectsAboveUpper(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{
		"NSE|RELIANCE": {95, 105},
	}))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 1, OrderType: "LIMIT", Price: 120, Confirmed: true,
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonCircuitBreached, res.Reason)
	assert.Contains(t, res.Message, "circuit")
}

// TestCircuitLimit_RejectsBelowLower — symmetric: order at ₹80 below
// lower ₹95.
func TestCircuitLimit_RejectsBelowLower(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{
		"NSE|RELIANCE": {95, 105},
	}))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 1, OrderType: "LIMIT", Price: 80, Confirmed: true,
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonCircuitBreached, res.Reason)
}

// TestCircuitLimit_AllowsAtBoundary — exact match on lower / upper is
// permitted (Kite's exchange match engine accepts orders at the band).
func TestCircuitLimit_AllowsAtBoundary(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{
		"NSE|RELIANCE": {95, 105},
	}))
	for _, p := range []float64{95, 105} {
		res := g.CheckOrder(OrderCheckRequest{
			Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
			Quantity: 1, OrderType: "LIMIT", Price: p, Confirmed: true,
		})
		assert.True(t, res.Allowed, "boundary price %.2f must be permitted", p)
	}
}

// TestCircuitLimit_AllowsMarket — MARKET orders skip the price check
// (no price specified ≠ no order; the broker will fill at the
// prevailing match price which is by definition inside the band).
func TestCircuitLimit_AllowsMarket(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{
		"NSE|RELIANCE": {95, 105},
	}))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 1, OrderType: "MARKET", Price: 0, Confirmed: true,
	})
	assert.True(t, res.Allowed)
}

// TestCircuitLimit_NoLookupConfigured — no lookup wired = no rejection
// reason ever fires (DevMode / tests where circuit data is unavailable).
func TestCircuitLimit_NoLookupConfigured(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 1, OrderType: "LIMIT", Price: 99999, Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonCircuitBreached, res.Reason,
			"missing lookup must NOT trigger circuit rejection")
	}
}

// TestCircuitLimit_LookupMissBypasses — lookup wired but specific
// instrument has no data. Fail open (the order may still hit other
// rejections, but circuit is not the one).
func TestCircuitLimit_LookupMissBypasses(t *testing.T) {
	t.Parallel()
	g := newGuardWithCircuit(newStubCircuit(map[string][2]float64{}))
	res := g.CheckOrder(OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "UNKNOWN",
		Quantity: 1, OrderType: "LIMIT", Price: 500, Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonCircuitBreached, res.Reason,
			"unknown instrument must NOT trigger circuit rejection")
	}
}

// TestCircuitLimit_RecordOnRejection — circuit breaches DO count
// toward auto-freeze. A user repeatedly trying to slam through the
// circuit is either fat-fingered or hostile; either way deserves
// rate-limit pressure.
func TestCircuitLimit_RecordOnRejection(t *testing.T) {
	t.Parallel()
	c := &circuitLimitCheck{}
	assert.True(t, c.RecordOnRejection())
}

// TestCircuitLimit_OrderConstantPlacement — circuit slot sits between
// order_value (300) and quantity_limit (400) — the position-cap
// rejections fire before the circuit lookup so we don't hit the
// LTP cache for orders that would already be blocked.
func TestCircuitLimit_OrderConstantPlacement(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 350, OrderCircuitLimit)
	assert.Less(t, OrderOrderValue, OrderCircuitLimit)
	assert.Less(t, OrderCircuitLimit, OrderQuantityLimit)
}
