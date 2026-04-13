package kc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

func TestIsBrokerUnavailable(t *testing.T) {
	cases := map[string]bool{
		// Trigger fallback
		"rate limit exceeded":          true,
		"Rate Limit Exceeded":          true,
		"too many requests":            true,
		"HTTP 429":                     true,
		"HTTP 503":                     true,
		"service unavailable":          true,
		"connection refused":           true,
		"connection reset by peer":     true,
		"dial tcp: lookup api.kite.trade: no such host": true,
		"unexpected EOF":               true,
		"context deadline exceeded (timeout)": true,
		"bad gateway":                  true,

		// Do NOT trigger fallback — auth/validation errors must propagate
		"invalid access token":     false,
		"403 forbidden":            false,
		"user not found":           false,
		"missing required field":   false,
		"expired":                  false, // token expired — re-auth needed
	}
	for msg, want := range cases {
		t.Run(msg, func(t *testing.T) {
			got := isBrokerUnavailable(errors.New(msg))
			assert.Equal(t, want, got, "isBrokerUnavailable(%q)", msg)
		})
	}
	// Nil check.
	assert.False(t, isBrokerUnavailable(nil))
}

func TestOrderAggregateToBrokerOrder_FlattensState(t *testing.T) {
	// Build aggregate state via the public event dispatcher (same path
	// the projector uses) so the test doesn't depend on internal event
	// constructors or private state setters.
	proj := eventsourcing.NewProjector()
	disp := domain.NewEventDispatcher()
	proj.Subscribe(disp)

	qty, _ := domain.NewQuantity(10)
	disp.Dispatch(domain.OrderPlacedEvent{
		Email:           "alice@example.com",
		OrderID:         "ORD-123",
		Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
		TransactionType: "BUY",
		Qty:             qty,
		Price:           domain.NewINR(2500.0),
	})
	disp.Dispatch(domain.OrderFilledEvent{
		Email:       "alice@example.com",
		OrderID:     "ORD-123",
		FilledQty:   qty,
		FilledPrice: domain.NewINR(2505.5),
	})

	agg, ok := proj.GetOrder("ORD-123")
	assert.True(t, ok)
	out := orderAggregateToBrokerOrder(agg)

	assert.Equal(t, "ORD-123", out.OrderID)
	assert.Equal(t, "NSE", out.Exchange)
	assert.Equal(t, "RELIANCE", out.Tradingsymbol)
	assert.Equal(t, "BUY", out.TransactionType)
	assert.Equal(t, 10, out.Quantity)
	assert.Equal(t, 10, out.FilledQuantity)
	assert.InDelta(t, 2500.0, out.Price, 0.01)
	assert.InDelta(t, 2505.5, out.AveragePrice, 0.01) // filled price used when available
	assert.Equal(t, eventsourcing.OrderStatusFilled, out.Status)
}

func TestProjectionOrdersForEmail_EmptyWhenNoProjector(t *testing.T) {
	m := &Manager{}
	out := m.projectionOrdersForEmail("nobody@example.com")
	assert.Empty(t, out)
}

func TestProjectionOrdersForEmail_ReturnsMatchingAggregates(t *testing.T) {
	proj := eventsourcing.NewProjector()
	m := &Manager{projector: proj}

	// Seed the projector with events via the public dispatcher path.
	disp := domain.NewEventDispatcher()
	proj.Subscribe(disp)

	qty, _ := domain.NewQuantity(5)
	disp.Dispatch(domain.OrderPlacedEvent{
		Email:           "alice@example.com",
		OrderID:         "ORD-ALICE-1",
		Instrument:      domain.NewInstrumentKey("NSE", "HDFC"),
		TransactionType: "BUY",
		Qty:             qty,
		Price:           domain.NewINR(1500.0),
	})
	disp.Dispatch(domain.OrderPlacedEvent{
		Email:           "bob@example.com",
		OrderID:         "ORD-BOB-1",
		Instrument:      domain.NewInstrumentKey("NSE", "INFY"),
		TransactionType: "SELL",
		Qty:             qty,
		Price:           domain.NewINR(0),
	})

	alice := m.projectionOrdersForEmail("alice@example.com")
	assert.Len(t, alice, 1)
	assert.Equal(t, "ORD-ALICE-1", alice[0].OrderID)
	assert.Equal(t, "HDFC", alice[0].Tradingsymbol)

	bob := m.projectionOrdersForEmail("bob@example.com")
	assert.Len(t, bob, 1)
	assert.Equal(t, "ORD-BOB-1", bob[0].OrderID)

	// A user with no projected orders gets an empty slice, not an error.
	none := m.projectionOrdersForEmail("stranger@example.com")
	assert.Empty(t, none)
}

// Ensure the unused broker import stays used; will be removed if nothing
// above references broker.Order (belt-and-suspenders for import discipline).
var _ = broker.Order{}
