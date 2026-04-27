package riskguard

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// stubMarginLookup returns canned available-margin values for tests.
type stubMarginLookup struct {
	margins map[string]float64
}

func newStubMargin(margins map[string]float64) *stubMarginLookup {
	return &stubMarginLookup{margins: margins}
}

func (s *stubMarginLookup) GetAvailableMargin(email string) (float64, bool) {
	v, ok := s.margins[email]
	return v, ok
}

func newGuardWithMargin(lookup MarginLookup, enabled bool) *Guard {
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SetMarginLookup(lookup)
	g.SetMarginCheckEnabled(enabled)
	pinClockInMarketHours(g)
	return g
}

// TestMarginCheck_AllowsSufficientMargin — order notional ₹50k under
// available ₹100k passes.
func TestMarginCheck_AllowsSufficientMargin(t *testing.T) {
	t.Parallel()
	g := newGuardWithMargin(newStubMargin(map[string]float64{
		"trader@test.com": 100000,
	}), true)
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(500), Confirmed: true,
	})
	assert.True(t, res.Allowed)
}

// TestMarginCheck_RejectsInsufficientMargin — order notional ₹100k
// against available ₹50k → rejected with required + available
// embedded in Message so the user sees the gap.
func TestMarginCheck_RejectsInsufficientMargin(t *testing.T) {
	t.Parallel()
	g := newGuardWithMargin(newStubMargin(map[string]float64{
		"trader@test.com": 50000,
	}), true)
	// Raise the per-user single-order cap so order_value (chain order 300)
	// does not preempt the margin check (chain order 325) we are isolating.
	// The tightened Free-tier default of Rs 50,000 would otherwise reject
	// our Rs 100,000 notional before margin sees it.
	g.mu.Lock()
	g.limits["trader@test.com"] = &UserLimits{
		MaxSingleOrderINR:       domain.NewINR(1000000),
		RequireConfirmAllOrders: false,
	}
	g.mu.Unlock()
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(1000), Confirmed: true,
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonInsufficientMargin, res.Reason)
	// Required notional + available margin both present in message.
	assert.Contains(t, res.Message, "100000", "required notional must appear")
	assert.Contains(t, res.Message, "50000", "available margin must appear")
}

// TestMarginCheck_DisabledByDefault — fresh Guard with no
// SetMarginCheckEnabled(true) MUST NOT consult the lookup. Wiring
// the lookup is the simple step; flipping the flag is the user's
// opt-in (per-tier or global config).
func TestMarginCheck_DisabledByDefault(t *testing.T) {
	t.Parallel()
	// Lookup wired but check disabled.
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SetMarginLookup(newStubMargin(map[string]float64{
		"trader@test.com": 0, // would reject if check ran
	}))
	// NO SetMarginCheckEnabled call.
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(500), Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonInsufficientMargin, res.Reason,
			"disabled-by-default: margin must NOT trigger rejection")
	}
}

// TestMarginCheck_AllowsAtBoundary — required exactly equal to
// available passes (Kite's margin engine is inclusive on equality).
func TestMarginCheck_AllowsAtBoundary(t *testing.T) {
	t.Parallel()
	g := newGuardWithMargin(newStubMargin(map[string]float64{
		"trader@test.com": 50000,
	}), true)
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(500), Confirmed: true,
	})
	assert.True(t, res.Allowed, "required ₹50k against available ₹50k must pass")
}

// TestMarginCheck_AllowsMarketOrder — MARKET orders skip the check
// (Price=0 so notional can't be computed; broker-side margin gate
// handles it).
func TestMarginCheck_AllowsMarketOrder(t *testing.T) {
	t.Parallel()
	g := newGuardWithMargin(newStubMargin(map[string]float64{
		"trader@test.com": 0,
	}), true)
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "MARKET", Price: domain.Money{}, Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonInsufficientMargin, res.Reason,
			"MARKET orders must NOT trigger margin rejection (no Price = no notional)")
	}
}

// TestMarginCheck_NoLookupConfigured — enabled but no lookup wired
// = no rejection (fail-open, can't infer "out of margin" from
// missing data).
func TestMarginCheck_NoLookupConfigured(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SetMarginCheckEnabled(true)
	// NO SetMarginLookup.
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "trader@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(500), Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonInsufficientMargin, res.Reason)
	}
}

// TestMarginCheck_LookupMissBypasses — enabled + lookup wired but
// user not in cache. Fail open (no margin data ≠ no margin).
func TestMarginCheck_LookupMissBypasses(t *testing.T) {
	t.Parallel()
	g := newGuardWithMargin(newStubMargin(map[string]float64{}), true)
	res := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: "unknown@test.com", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 100, OrderType: "LIMIT", Price: domain.NewINR(500), Confirmed: true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonInsufficientMargin, res.Reason)
	}
}

// TestMarginCheck_RecordOnRejection — false. Insufficient margin is
// a USER STATE issue, not a fat-finger or hostile-script signal.
// Counting toward auto-freeze would punish someone who legitimately
// ran out of margin from prior fills. Same posture as
// confirmation_required (policy gate, not limit violation).
func TestMarginCheck_RecordOnRejection(t *testing.T) {
	t.Parallel()
	c := &marginCheck{}
	assert.False(t, c.RecordOnRejection(),
		"insufficient margin = user state, not abuse pattern")
}

// TestMarginCheck_OrderConstantPlacement — slot 325, between
// order_value (300) and circuit_limit (350).
func TestMarginCheck_OrderConstantPlacement(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 325, OrderMarginCheck)
	assert.Less(t, OrderOrderValue, OrderMarginCheck)
	assert.Less(t, OrderMarginCheck, OrderCircuitLimit)
}
