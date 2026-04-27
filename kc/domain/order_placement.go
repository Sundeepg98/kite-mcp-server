package domain

import "fmt"

// ValidateIceberg enforces the "disclosed ≤ total" invariant for iceberg
// orders on Kite. Iceberg variety splits a large order into visible chunks
// of `disclosed` quantity at a time; disclosed > total is logically
// impossible, and zero/negative values are nonsensical for a chunked order.
//
// This is a free function rather than a value-object constructor because
// iceberg is a property of the order placement request, not of the order
// itself after acceptance — the broker stores the expanded legs, not the
// configuration.
func ValidateIceberg(total, disclosed int) error {
	if total <= 0 {
		return fmt.Errorf("domain: iceberg total quantity must be positive, got %d", total)
	}
	if disclosed <= 0 {
		return fmt.Errorf("domain: iceberg disclosed quantity must be positive, got %d", disclosed)
	}
	if disclosed > total {
		return fmt.Errorf("domain: iceberg disclosed quantity %d exceeds total %d", disclosed, total)
	}
	return nil
}

// OrderPlacement is the DDD aggregate root for a not-yet-submitted order.
// It binds validated value objects (instrument, qty, price) with the
// transaction/order-type strings and enforces placement-time invariants
// at construction: price must be positive for non-MARKET orders, and
// transaction type must be BUY or SELL.
//
// Service/use-case code constructs one of these and reads the validated
// fields back rather than re-checking primitives inline. Follow-on code
// (riskguard, broker call) operates on a known-good placement or an
// error — the placement cannot be in a halfway-valid state.
type OrderPlacement struct {
	instrument      InstrumentKey
	qty             Quantity
	price           Money
	transactionType string // BUY or SELL
	orderType       string // MARKET, LIMIT, SL, SL-M
}

// NewOrderPlacement constructs a validated OrderPlacement. All value objects
// are checked for validity; transaction type must be BUY or SELL; and for
// non-MARKET orders the price must be positive (Money.IsPositive). MARKET /
// SL-M orders carry a zero-value Money by convention — those are accepted.
func NewOrderPlacement(
	instrument InstrumentKey,
	qty Quantity,
	price Money,
	transactionType string,
	orderType string,
) (OrderPlacement, error) {
	if instrument.IsZero() || instrument.Exchange == "" || instrument.Tradingsymbol == "" {
		return OrderPlacement{}, fmt.Errorf("domain: order placement requires a valid instrument")
	}
	if !qty.IsValid() {
		return OrderPlacement{}, fmt.Errorf("domain: order placement requires a positive quantity")
	}
	if transactionType != "BUY" && transactionType != "SELL" {
		return OrderPlacement{}, fmt.Errorf("domain: transaction_type must be BUY or SELL, got %q", transactionType)
	}
	needsPrice := orderType != "MARKET" && orderType != "SL-M"
	if needsPrice && !price.IsPositive() {
		return OrderPlacement{}, fmt.Errorf("domain: %s order requires a positive price", orderType)
	}
	return OrderPlacement{
		instrument:      instrument,
		qty:             qty,
		price:           price,
		transactionType: transactionType,
		orderType:       orderType,
	}, nil
}

// Instrument returns the validated instrument key.
func (p OrderPlacement) Instrument() InstrumentKey { return p.instrument }

// Quantity returns the validated quantity value object.
func (p OrderPlacement) Quantity() Quantity { return p.qty }

// Price returns the placement's price. May be zero-value Money for MARKET /
// SL-M orders — check with Price().IsPositive() before use.
func (p OrderPlacement) Price() Money { return p.price }

// TransactionType returns BUY or SELL.
func (p OrderPlacement) TransactionType() string { return p.transactionType }

// OrderType returns MARKET, LIMIT, SL, or SL-M.
func (p OrderPlacement) OrderType() string { return p.orderType }

// Notional returns the placement's price × quantity as a Money value in the
// price's currency. For MARKET / SL-M orders the price is zero-Money by
// convention; Notional in those cases returns a zero-Money in the SAME
// currency as the configured price (which is INR by default for unset
// prices). Callers that need a meaningful notional for MARKET orders must
// estimate from LTP separately — this aggregate intentionally does not
// reach for live market data.
func (p OrderPlacement) Notional() Money {
	return p.price.Multiply(float64(p.qty.Int()))
}
