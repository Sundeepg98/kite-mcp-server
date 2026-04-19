package domain

import (
	"strings"

	"github.com/zerodha/kite-mcp-server/broker"
)

// --- Position direction constants ---
//
// Direction is exposed as a stringly-typed value (not a domain.Direction,
// which is already taken by alerts). The values are display-friendly
// identifiers used in dashboards and debug logs.
const (
	// PositionLong means the position quantity is > 0 — the user owns the
	// instrument / is net-long.
	PositionLong = "LONG"
	// PositionShort means the position quantity is < 0 — the user has sold
	// more than bought / is net-short.
	PositionShort = "SHORT"
	// PositionFlat means the position quantity is exactly 0 — the position
	// is closed out but may still show residual P&L from the day's activity.
	PositionFlat = "FLAT"
)

// Position is the rich domain entity for a broker trading position. It wraps
// a broker.Position DTO and exposes behaviour that was previously duplicated:
// IsIntraday (product == "MIS"), Direction (LONG/SHORT/FLAT), RealizedPnL,
// UnrealizedPnL, and InstrumentKey projection.
//
// The wrapped DTO is the source of truth; existing broker / persistence code
// continues to use broker.Position directly. Use ToDomainPosition or
// NewPositionFromBroker at the adapter boundary.
type Position struct {
	dto broker.Position
}

// NewPositionFromBroker lifts a broker.Position DTO into the rich domain entity.
func NewPositionFromBroker(b broker.Position) Position {
	return Position{dto: b}
}

// ToDomainPosition is a converter alias — identical to NewPositionFromBroker,
// named for ergonomic use at adapter boundaries.
func ToDomainPosition(b broker.Position) Position {
	return NewPositionFromBroker(b)
}

// DTO returns the underlying broker DTO for passthrough to code that still
// consumes broker.Position directly.
func (p Position) DTO() broker.Position {
	return p.dto
}

// IsIntraday reports whether the position is intraday-only (MIS product).
// MIS positions are force-squared-off at market close unless converted to NRML/CNC.
func (p Position) IsIntraday() bool {
	return strings.EqualFold(strings.TrimSpace(p.dto.Product), ProductMIS)
}

// Direction returns "LONG" when quantity > 0, "SHORT" when quantity < 0,
// and "FLAT" when quantity == 0.
func (p Position) Direction() string {
	switch {
	case p.dto.Quantity > 0:
		return PositionLong
	case p.dto.Quantity < 0:
		return PositionShort
	default:
		return PositionFlat
	}
}

// IsOpen reports whether the position still has non-zero quantity.
// A flat position (Quantity == 0) may still appear in the broker's position
// list because it carried realized P&L earlier in the session, but it is not
// "open" in the sense of carrying market exposure.
func (p Position) IsOpen() bool {
	return p.dto.Quantity != 0
}

// PnL returns the broker-reported net P&L as a Money value in INR.
// This is the pre-computed figure that brokers typically populate; prefer
// UnrealizedPnL when you want to compute P&L at a specific LTP that may
// differ from the broker's last-seen LTP.
func (p Position) PnL() Money {
	return NewINR(p.dto.PnL)
}

// UnrealizedPnL computes the mark-to-market P&L at the given LTP as
// (ltp - averagePrice) * quantity, wrapped in a Money value.
//
// For a long position (quantity > 0), profit accrues when ltp rises above
// averagePrice. For a short position (quantity < 0), the sign flips naturally
// because the quantity factor is negative — no special-casing required.
//
// If ltp is in a different currency than INR, the result carries the
// LTP's currency. Callers may normalise via Money.Add error handling.
func (p Position) UnrealizedPnL(ltp Money) Money {
	diff := ltp.Amount - p.dto.AveragePrice
	pnl := diff * float64(p.dto.Quantity)
	return Money{Amount: pnl, Currency: ltp.Currency}
}

// InstrumentKey returns the canonical (EXCHANGE:SYMBOL) identifier for
// this position's instrument. Useful when joining positions with LTP maps
// keyed by instrument key.
func (p Position) InstrumentKey() InstrumentKey {
	return NewInstrumentKey(p.dto.Exchange, p.dto.Tradingsymbol)
}
