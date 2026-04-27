// Package domain contains DDD value objects and domain events for the trading platform.
// These are pure domain types with zero external dependencies — they model the
// ubiquitous language of Indian equity trading (Money in INR, Quantities,
// InstrumentKeys like "NSE:RELIANCE") and domain events that capture what
// happened in the system.
package domain

import (
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
		return Money{}, fmt.Errorf("domain: money amount must be positive, got %v", amount)
	}
	return Money{Amount: amount, Currency: "INR"}, nil
}

// Add returns a new Money that is the sum of m and other.
// Returns an error if the currencies differ.
func (m Money) Add(other Money) (Money, error) {
	if m.Currency != other.Currency {
		return Money{}, fmt.Errorf("domain: cannot add %s to %s", other.Currency, m.Currency)
	}
	return Money{Amount: m.Amount + other.Amount, Currency: m.Currency}, nil
}

// Sub returns a new Money that is m minus other.
// Returns an error if the currencies differ.
func (m Money) Sub(other Money) (Money, error) {
	if m.Currency != other.Currency {
		return Money{}, fmt.Errorf("domain: cannot subtract %s from %s", other.Currency, m.Currency)
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
		return false, fmt.Errorf("domain: cannot compare %s to %s", m.Currency, other.Currency)
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
	return m.Currency + " " + fmt.Sprintf("%.2f", m.Amount)
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
