package domain

// holding_test.go — unit tests for the rich Holding domain entity
// (Slice 6b of the Money VO sweep). Mirrors position_test.go in
// shape: type-level checks + Money accessor coverage + cross-
// currency rejection on the accessor.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
)

// TestHolding_PnL pins the canonical accessor: the broker DTO's
// pre-computed PnL float lifts to INR-tagged Money.
func TestHolding_PnL(t *testing.T) {
	t.Parallel()

	h := NewHoldingFromBroker(broker.Holding{PnL: 1234.5})
	got := h.PnL()
	assert.InDelta(t, 1234.5, got.Amount, 0.001,
		"TestHolding_PnL: want=%v got=%v", 1234.5, got.Amount, 0.001)
	assert.Equal(t, "INR", got.Currency,
		"all broker-sourced Holding PnL is INR-denominated")
}

// TestHolding_PnL_NegativeIsLoss pins the loss-day path: a holding
// with negative PnL (when LTP has dropped below average price)
// surfaces as IsNegative Money. Investors care a lot about the
// sign — losing positions are an explicit dashboard / Telegram
// notification trigger.
func TestHolding_PnL_NegativeIsLoss(t *testing.T) {
	t.Parallel()

	h := NewHoldingFromBroker(broker.Holding{PnL: -250.5})
	got := h.PnL()
	assert.Equal(t, -250.5, got.Float64())
	assert.True(t, got.IsNegative())
	assert.False(t, got.IsZero())
	assert.False(t, got.IsPositive())
	assert.Equal(t, "INR", got.Currency)
}

// TestHolding_PnL_ZeroIsSentinel pins the zero-Money sentinel: a
// holding with no realised gain (just-bought, no price movement)
// returns the zero Money. Same IsZero() sentinel established in
// Slices 1+5 for "unset / no data".
func TestHolding_PnL_ZeroIsSentinel(t *testing.T) {
	t.Parallel()

	h := NewHoldingFromBroker(broker.Holding{PnL: 0})
	got := h.PnL()
	assert.True(t, got.IsZero(),
		"zero PnL surfaces as zero Money (sentinel)")
	assert.Equal(t, "INR", got.Currency,
		"zero Money still carries the INR currency tag for "+
			"consistent cross-currency Add semantics")
}

// TestHolding_PnL_RejectsCrossCurrencyAdd is the type-safety win
// for Slice 6b: once a Holding's PnL is read through the accessor,
// attempting to Add a non-INR Money returns an error rather than
// silently coercing. Same property Slices 1-6 surface for limits,
// prices, daily values, tier amounts, paper cash, and Position
// PnL — extended here to per-Holding PnL.
func TestHolding_PnL_RejectsCrossCurrencyAdd(t *testing.T) {
	t.Parallel()

	h := NewHoldingFromBroker(broker.Holding{PnL: 1000})
	pnl := h.PnL()

	usd := Money{Amount: 12, Currency: "USD"}
	_, err := pnl.Add(usd)
	require.Error(t, err,
		"Holding.PnL().Add(USD) must reject; cross-currency math "+
			"on broker holding PnL may not silently coerce")

	_, err = pnl.GreaterThan(usd)
	require.Error(t, err,
		"Holding.PnL().GreaterThan(USD) must reject for the same reason")
}

// TestHolding_DTO verifies the round-trip identity: NewHoldingFromBroker
// followed by .DTO() returns the original DTO unchanged. Crucial for
// adapter passthrough where existing code that consumes broker.Holding
// directly stays unaffected by the lift.
func TestHolding_DTO(t *testing.T) {
	t.Parallel()

	dto := broker.Holding{
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		ISIN:          "INE002A01018",
		Quantity:      10,
		AveragePrice:  2500.0,
		LastPrice:     2600.0,
		PnL:           1000.0,
		DayChangePct:  2.5,
		Product:       "CNC",
	}
	h := NewHoldingFromBroker(dto)
	assert.Equal(t, dto, h.DTO())
}

// TestHolding_InstrumentKey pins the canonical instrument key:
// (exchange, tradingsymbol) — same shape Position uses, so a
// joined holdings + positions LTP map keys consistently.
func TestHolding_InstrumentKey(t *testing.T) {
	t.Parallel()

	h := NewHoldingFromBroker(broker.Holding{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	k := h.InstrumentKey()
	assert.Equal(t, "NSE", k.Exchange)
	assert.Equal(t, "RELIANCE", k.Tradingsymbol)
	assert.Equal(t, "NSE:RELIANCE", k.String())
}

// TestHolding_IsHeld covers the held-vs-unwound flag: a Holding
// with quantity > 0 is "held" (positive position in the user's
// demat account); zero quantity is no longer held even if the
// row appears (e.g. just sold today, T+1 settlement still shows
// the residual). Mirrors Position.IsOpen for the holding context.
func TestHolding_IsHeld(t *testing.T) {
	t.Parallel()

	held := NewHoldingFromBroker(broker.Holding{Quantity: 10})
	assert.True(t, held.IsHeld())

	unheld := NewHoldingFromBroker(broker.Holding{Quantity: 0})
	assert.False(t, unheld.IsHeld())
}

// TestHolding_InvestedValue computes (averagePrice * quantity)
// as a Money — the cost basis. Useful for portfolio summary
// computations that previously did inline float multiplication.
func TestHolding_InvestedValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		quantity     int
		averagePrice float64
		want         float64
	}{
		{"long position", 10, 1500.0, 15000.0},
		{"single share", 1, 2500.0, 2500.0},
		{"fractional avg price", 5, 100.55, 502.75},
		{"zero quantity", 0, 1500.0, 0},
		{"zero avg price (free shares?)", 10, 0, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewHoldingFromBroker(broker.Holding{
				Quantity:     tc.quantity,
				AveragePrice: tc.averagePrice,
			})
			got := h.InvestedValue()
			assert.InDelta(t, tc.want, got.Float64(), 0.001)
			assert.Equal(t, "INR", got.Currency)
		})
	}
}

// TestHolding_CurrentValue computes (lastPrice * quantity) as a
// Money — the mark-to-market value of the holding right now.
func TestHolding_CurrentValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		quantity  int
		lastPrice float64
		want      float64
	}{
		{"long position", 10, 1600.0, 16000.0},
		{"single share", 1, 2600.0, 2600.0},
		{"fractional last price", 5, 110.30, 551.5},
		{"zero quantity", 0, 1500.0, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewHoldingFromBroker(broker.Holding{
				Quantity:  tc.quantity,
				LastPrice: tc.lastPrice,
			})
			got := h.CurrentValue()
			assert.InDelta(t, tc.want, got.Float64(), 0.001)
			assert.Equal(t, "INR", got.Currency)
		})
	}
}

// TestToDomainHolding mirrors TestToDomainPosition — alias
// converter for ergonomic adapter-boundary use.
func TestToDomainHolding(t *testing.T) {
	t.Parallel()

	bh := broker.Holding{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Quantity:      5,
		AveragePrice:  1500,
		LastPrice:     1520,
		PnL:           100,
	}
	d := ToDomainHolding(bh)
	assert.True(t, d.IsHeld())
	assert.Equal(t, 100.0, d.PnL().Float64())
	assert.Equal(t, "INR", d.PnL().Currency)
	assert.Equal(t, 7500.0, d.InvestedValue().Float64()) // 1500*5
	assert.Equal(t, 7600.0, d.CurrentValue().Float64())  // 1520*5
}
