package domain

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// tickEpsilon is the tolerance used when checking whether a float64 price
// is aligned to a given tick size. Floats of the form 2500.45 = 2500 + 9*0.05
// do not round-trip exactly in IEEE-754, so a naive `remainder == 0` check
// rejects legitimate prices. 1e-9 is tight enough to reject off-by-one-paise
// mistakes while tolerating float representation drift.
const tickEpsilon = 1e-9

// ValidateLotSize enforces that an order's total quantity is a positive
// integer multiple of the instrument's lot size. Equity typically has
// lotSize = 1 so any positive qty passes; derivatives (F&O) enforce the
// contract size (NIFTY futures lotSize = 50 at time of writing).
//
// lotSize <= 0 is treated as bad configuration — legitimate equity rows
// report lotSize = 1, never 0.
func ValidateLotSize(qty, lotSize int) error {
	if qty <= 0 {
		return fmt.Errorf("domain: order quantity must be positive, got %d", qty)
	}
	if lotSize <= 0 {
		return fmt.Errorf("domain: lot size must be positive, got %d", lotSize)
	}
	if qty%lotSize != 0 {
		return fmt.Errorf("domain: quantity %d is not a multiple of lot size %d", qty, lotSize)
	}
	return nil
}

// ValidateTickSize enforces that an order's price is aligned to the
// instrument's tick size. NSE equity ticks are typically 0.05; some
// indices / MF entries have tickSize = 0, which we treat as "no tick
// rule" (the broker accepts arbitrary precision).
//
// Uses a 1e-9 epsilon because float remainders on decimal-rational tick
// sizes drift (2500.45 mod 0.05 is not exactly zero in IEEE-754).
func ValidateTickSize(price, tickSize float64) error {
	if price <= 0 {
		return fmt.Errorf("domain: order price must be positive, got %v", price)
	}
	if tickSize < 0 {
		return fmt.Errorf("domain: tick size cannot be negative, got %v", tickSize)
	}
	if tickSize == 0 {
		return nil // no alignment rule for this instrument
	}
	remainder := math.Mod(price, tickSize)
	// Accept both "remainder ≈ 0" and "remainder ≈ tickSize" (the latter
	// happens when math.Mod reports -ε + tickSize for some inputs).
	if remainder > tickEpsilon && (tickSize-remainder) > tickEpsilon {
		return fmt.Errorf("domain: price %v is not aligned to tick size %v", price, tickSize)
	}
	return nil
}

// ValidateTradingsymbolFormat enforces that a tradingsymbol is non-empty
// and contains only printable, non-whitespace ASCII-ish characters. Kite's
// tradingsymbol convention is uppercase alphanumerics plus a few separators
// like "-" and "&" (e.g. "M&M"); we don't enforce the exact charset — just
// reject clearly bad inputs (empty, whitespace, control chars) so invalid
// rows fail fast at the domain boundary instead of surfacing as opaque
// Kite API errors later.
func ValidateTradingsymbolFormat(symbol string) error {
	if symbol == "" {
		return fmt.Errorf("domain: tradingsymbol must not be empty")
	}
	if strings.TrimSpace(symbol) != symbol {
		return fmt.Errorf("domain: tradingsymbol %q must not have surrounding whitespace", symbol)
	}
	for _, r := range symbol {
		if unicode.IsSpace(r) {
			return fmt.Errorf("domain: tradingsymbol %q must not contain whitespace", symbol)
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("domain: tradingsymbol %q contains non-printable character", symbol)
		}
	}
	return nil
}

// InstrumentRules bundles the lot-size and tick-size metadata for one
// instrument so a caller can run the two related checks without
// threading the primitives through every call site.
//
// Construct with NewInstrumentRules; the Exchange + Tradingsymbol fields
// are informational (used in error messages) — actual whitelist validation
// lives on InstrumentKey.NewInstrumentKeyStrict.
type InstrumentRules struct {
	exchange      string
	tradingsymbol string
	lotSize       int
	tickSize      float64
}

// NewInstrumentRules constructs an InstrumentRules bundle. Called from
// the order-placement pipeline once the instrument metadata has been
// resolved via instruments.Manager.Find.
func NewInstrumentRules(exchange, tradingsymbol string, lotSize int, tickSize float64) InstrumentRules {
	return InstrumentRules{
		exchange:      exchange,
		tradingsymbol: tradingsymbol,
		lotSize:       lotSize,
		tickSize:      tickSize,
	}
}

// Exchange returns the exchange code (for error messages / diagnostics).
func (r InstrumentRules) Exchange() string { return r.exchange }

// Tradingsymbol returns the symbol (for error messages / diagnostics).
func (r InstrumentRules) Tradingsymbol() string { return r.tradingsymbol }

// CheckQuantity reports whether qty satisfies the instrument's lot-size
// rule. Returns a descriptive error otherwise.
func (r InstrumentRules) CheckQuantity(qty int) error {
	return ValidateLotSize(qty, r.lotSize)
}

// CheckPrice reports whether price is aligned to the instrument's tick
// size. Returns a descriptive error otherwise.
func (r InstrumentRules) CheckPrice(price float64) error {
	return ValidateTickSize(price, r.tickSize)
}
