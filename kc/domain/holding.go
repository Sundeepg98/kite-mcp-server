package domain

import "github.com/zerodha/kite-mcp-server/broker"

// Holding is the rich domain entity for a broker portfolio holding.
// It wraps a broker.Holding DTO and exposes the same Money-aware
// accessor pattern Position uses (Slice 6) — PnL() returns
// INR-tagged Money, plus convenience computations (InvestedValue,
// CurrentValue) that previously lived as inline float
// multiplication at consumer sites.
//
// The wrapped DTO is the source of truth; existing broker /
// persistence code continues to use broker.Holding directly. Use
// ToDomainHolding or NewHoldingFromBroker at the adapter boundary.
//
// Slice 6b of the Money VO sweep: this wrapper is the keystone for
// migrating Holding.PnL consumers (currently bare-float reads in
// kc/usecases/widget_usecases.go and mcp/plugin_widget_returns_matrix.go)
// to type-tagged Money at the JSON-emit boundary. Mirrors the
// Position wrapper added in commits a926f8a / 5ce3eb0.
type Holding struct {
	dto broker.Holding
}

// NewHoldingFromBroker lifts a broker.Holding DTO into the rich
// domain entity. Identity-preserving — DTO() returns the original
// DTO unchanged.
func NewHoldingFromBroker(b broker.Holding) Holding {
	return Holding{dto: b}
}

// ToDomainHolding is a converter alias — identical to
// NewHoldingFromBroker, named for ergonomic use at adapter
// boundaries (matches the ToDomainPosition naming convention).
func ToDomainHolding(b broker.Holding) Holding {
	return NewHoldingFromBroker(b)
}

// DTO returns the underlying broker DTO for passthrough to code
// that still consumes broker.Holding directly. Used by adapters
// and JSON-emit boundaries that need the bare-float wire shape.
func (h Holding) DTO() broker.Holding {
	return h.dto
}

// PnL returns the broker-reported holding P&L as a Money value in
// INR. This is the pre-computed figure that brokers populate based
// on (LastPrice - AveragePrice) * Quantity at snapshot time.
//
// Sign is preserved: a winning position returns positive Money, a
// losing position returns negative Money. The zero Money is the
// "no movement / freshly bought" sentinel — callers that branch
// on win-vs-loss should use IsPositive / IsNegative / IsZero
// rather than comparing the raw Float64() against zero.
func (h Holding) PnL() Money {
	return NewINR(h.dto.PnL)
}

// IsHeld reports whether the holding has non-zero quantity. A
// holding row with Quantity == 0 may still appear (T+1 settlement
// quirks, recently-sold residuals) but is not "held" in the
// active-portfolio sense. Mirrors Position.IsOpen.
func (h Holding) IsHeld() bool {
	return h.dto.Quantity != 0
}

// InvestedValue returns the cost basis as Money — averagePrice
// times quantity, INR-tagged. Useful for portfolio summary
// computations that need the cost basis as a typed value (and
// for downstream Money.Add aggregation across multiple holdings
// when the consumer wants typed totals).
func (h Holding) InvestedValue() Money {
	return NewINR(h.dto.AveragePrice * float64(h.dto.Quantity))
}

// CurrentValue returns the mark-to-market value as Money —
// lastPrice times quantity, INR-tagged. The Slice 1 boundary
// pattern: aggregations of CurrentValue across many holdings can
// now flow through Money.Add (currency-aware) rather than the
// bare-float `total += h.LastPrice * float64(h.Quantity)` idiom.
func (h Holding) CurrentValue() Money {
	return NewINR(h.dto.LastPrice * float64(h.dto.Quantity))
}

// InstrumentKey returns the canonical (EXCHANGE:SYMBOL) identifier
// for this holding's instrument. Useful when joining holdings
// with LTP maps keyed by instrument key. Same shape Position uses
// so a unified holdings+positions LTP fetch can key consistently.
func (h Holding) InstrumentKey() InstrumentKey {
	return NewInstrumentKey(h.dto.Exchange, h.dto.Tradingsymbol)
}
