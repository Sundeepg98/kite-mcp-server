// Package money is the leaf-layer Money value object.
//
// Why a separate package: the existing Slice 1-6d Money sweep placed
// the type in kc/domain. That worked for in-process consumers but
// blocked Slice 6e (broker.Holding.PnL / broker.Position.PnL elevated
// to Money) — the broker package can't import kc/domain because
// kc/domain itself imports broker for its Holding / Position / Order
// wrapper entities, and Go forbids the resulting cycle.
//
// Extracting Money to a leaf package (zero internal repo deps) lets
// both kc/domain and broker import it freely. kc/domain.Money is now
// a type alias to money.Money so the 65+ existing consumer files
// (372+ constructor sites, struct literals, method calls) continue
// to compile unchanged. The alias is structural, not behavioural —
// downstream code observes identical semantics.
//
// Wire-format choice (MarshalJSON / UnmarshalJSON):
//
//   - INR Money serializes as a bare JSON number (1234.56). This is
//     the pre-Slice-6e wire shape for broker.Holding.PnL etc.; keeping
//     it bare-float means external Kite-API-shaped consumers see no
//     schema break.
//   - Non-INR Money serializes as {"amount":N,"currency":"S"}. The
//     cross-currency case is rare in practice (gokiteconnect emits
//     INR-only) but the explicit shape removes ambiguity for forward-
//     compat multi-currency accounts.
//   - UnmarshalJSON accepts BOTH shapes symmetrically: a bare number
//     rehydrates as INR; an object preserves the currency tag.
//
// Empty Currency on a zero-value Money is the "no money set" sentinel
// — IsZero() / IsPositive() / IsNegative() are the canonical predicates.
// Empty Currency does NOT auto-INR at construction (zero-value safety),
// but bare-float JSON DOES auto-INR on unmarshal (wire-compat).
package money

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Money is a value object representing a monetary amount with currency.
// The default and primary currency is INR.
type Money struct {
	Amount   float64
	Currency string
}

// NewINR creates a Money value in Indian Rupees without validation.
// Kept for existing callers that intentionally pass zero/negative values
// (adjustments, PnL deltas). New call sites that must reject invalid
// amounts should prefer NewMoney.
func NewINR(amount float64) Money {
	return Money{Amount: amount, Currency: "INR"}
}

// NewMoney creates a validated Money value in INR. Rejects amounts that are
// not strictly positive — the canonical "price must be > 0" invariant for
// LIMIT/SL orders. Zero is rejected so that the zero-value Money can be
// detected as "no price set" via IsPositive.
func NewMoney(amount float64) (Money, error) {
	if amount <= 0 {
		return Money{}, fmt.Errorf("money: amount must be positive, got %v", amount)
	}
	return Money{Amount: amount, Currency: "INR"}, nil
}

// Add returns a new Money that is the sum of m and other.
// Returns an error if the currencies differ.
func (m Money) Add(other Money) (Money, error) {
	if m.Currency != other.Currency {
		return Money{}, fmt.Errorf("money: cannot add %s to %s", other.Currency, m.Currency)
	}
	return Money{Amount: m.Amount + other.Amount, Currency: m.Currency}, nil
}

// Sub returns a new Money that is m minus other.
// Returns an error if the currencies differ.
func (m Money) Sub(other Money) (Money, error) {
	if m.Currency != other.Currency {
		return Money{}, fmt.Errorf("money: cannot subtract %s from %s", other.Currency, m.Currency)
	}
	return Money{Amount: m.Amount - other.Amount, Currency: m.Currency}, nil
}

// Multiply returns a new Money scaled by the given factor.
func (m Money) Multiply(factor float64) Money {
	return Money{Amount: m.Amount * factor, Currency: m.Currency}
}

// IsPositive returns true if the amount is greater than zero.
func (m Money) IsPositive() bool {
	return m.Amount > 0
}

// GreaterThan reports whether m's amount is strictly greater than other's.
// Returns an error if the currencies differ — silent cross-currency
// comparison would defeat the type's purpose (e.g. comparing a USD limit
// against an INR order value would silently coerce). The riskguard
// per-user MaxSingleOrderINR / MaxDailyValueINR caps use this method.
func (m Money) GreaterThan(other Money) (bool, error) {
	if m.Currency != other.Currency {
		return false, fmt.Errorf("money: cannot compare %s to %s", m.Currency, other.Currency)
	}
	return m.Amount > other.Amount, nil
}

// Float64 returns the underlying amount. Boundary accessor for JSON
// serialization, log fields, and SQLite REAL bindings — call sites that
// invoke this are deliberately crossing out of the domain layer. New
// in-domain code should keep working with Money values directly.
func (m Money) Float64() float64 {
	return m.Amount
}

// IsZero returns true if the amount is exactly zero.
func (m Money) IsZero() bool {
	return m.Amount == 0
}

// IsNegative returns true if the amount is less than zero.
func (m Money) IsNegative() bool {
	return m.Amount < 0
}

// String formats the money for display.
// INR is rendered as "₹1,234.56"; other currencies use the ISO code prefix.
func (m Money) String() string {
	if m.Currency == "INR" {
		return "₹" + formatIndian(m.Amount)
	}
	if m.Currency == "" {
		// Empty currency is the zero-value sentinel — render as bare
		// rupee since callers that build Money via NewINR always
		// land in the INR branch above. The fallback here is for
		// the explicit zero-value Money{} case (test fixtures,
		// uninitialised fields) where rendering "INR" would falsely
		// imply currency tagging.
		return formatIndian(m.Amount)
	}
	return m.Currency + " " + fmt.Sprintf("%.2f", m.Amount)
}

// MarshalJSON implements json.Marshaler. Wire-compat choice (Slice 6e
// precondition): INR Money + zero-value Money serialize as a bare JSON
// number to match the pre-Money-typed broker DTO wire shape; non-INR
// Money serializes as an explicit {"amount", "currency"} object so
// cross-currency cases are unambiguous on the wire.
//
// Justification: 372+ constructor call sites currently emit Money via
// the kc/domain package. Those that cross JSON boundaries (broker DTOs
// post-Slice-6e, billing.Subscription) use INR almost exclusively
// (gokiteconnect emits INR; billing tiers are INR by tier table).
// Bare-float emission means downstream consumers see no schema break.
// The non-INR object shape is reserved for the small future multi-
// currency surface.
func (m Money) MarshalJSON() ([]byte, error) {
	if m.Currency == "" || m.Currency == "INR" {
		return json.Marshal(m.Amount)
	}
	return json.Marshal(struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
	}{Amount: m.Amount, Currency: m.Currency})
}

// UnmarshalJSON implements json.Unmarshaler symmetric to MarshalJSON:
// a bare JSON number rehydrates as an INR Money (matches the bare-float
// emission); an object with "amount" + "currency" keys preserves the
// currency tag. This is the read-side guarantee that historical rows
// (pre-Slice-6e, all bare floats) round-trip correctly into the new
// Money-typed broker DTOs.
func (m *Money) UnmarshalJSON(data []byte) error {
	// Try bare number first — the common case.
	var amount float64
	if err := json.Unmarshal(data, &amount); err == nil {
		m.Amount = amount
		m.Currency = "INR"
		return nil
	}
	// Fall back to object shape.
	var obj struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("money: unmarshal: %w", err)
	}
	m.Amount = obj.Amount
	m.Currency = obj.Currency
	return nil
}

// formatIndian formats a float with the Indian numbering system
// (12,34,567.89 — groups of 2 after the initial group of 3).
func formatIndian(v float64) string {
	negative := v < 0
	if negative {
		v = -v
	}

	// Split into integer and decimal parts.
	whole := int64(v)
	frac := v - float64(whole)
	decimal := fmt.Sprintf("%.2f", frac)[1:] // ".XX"

	// Format integer part with Indian grouping.
	s := fmt.Sprintf("%d", whole)
	n := len(s)

	var parts []string
	if n <= 3 {
		parts = append(parts, s)
	} else {
		// Last 3 digits are the first group.
		parts = append(parts, s[n-3:])
		s = s[:n-3]
		// Remaining digits in groups of 2, right to left.
		for len(s) > 2 {
			parts = append(parts, s[len(s)-2:])
			s = s[:len(s)-2]
		}
		if len(s) > 0 {
			parts = append(parts, s)
		}
	}

	// Reverse parts so most significant comes first.
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	result := strings.Join(parts, ",") + decimal
	if negative {
		result = "-" + result
	}
	return result
}
