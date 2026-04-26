package domain

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// ---------------------------------------------------------------------------
// Property-based tests for the Money value object.
//
// Money wraps a float64 amount + currency. Float arithmetic is not associative
// in general, so we use a small relative tolerance (epsilon) when comparing
// algebraic results. Magnitudes are bounded by Generate to avoid overflow
// noise from extreme values that would dominate the rounding error.
// ---------------------------------------------------------------------------

// epsilon is the relative tolerance used for float equality in algebraic laws.
// 1e-9 is comfortably above IEEE-754 double-precision noise for the magnitudes
// the Generate method below produces (|amount| <= 1e9).
const moneyEpsilon = 1e-9

// approxEqual reports whether two amounts are equal within a relative tolerance.
// Falls back to an absolute tolerance for amounts near zero.
func approxEqual(a, b float64) bool {
	if a == b {
		return true
	}
	diff := math.Abs(a - b)
	if diff < 1e-9 {
		return true
	}
	largest := math.Max(math.Abs(a), math.Abs(b))
	return diff/largest < moneyEpsilon
}

// Generate implements quick.Generator for Money so testing/quick can
// produce arbitrary INR Money values with bounded magnitude. We restrict
// to a single currency (INR) for the algebraic-law tests because cross-currency
// operations are *errors* by contract, not algebraic operations.
//
// Magnitudes are capped at +/-1e9 so that the sum of three values
// (a+b+c in associativity tests) cannot overflow or lose all precision.
func (Money) Generate(rng *rand.Rand, _ int) reflect.Value {
	// Bound magnitude to avoid float noise dominating equality checks.
	// Range: [-1e9, +1e9].
	amount := (rng.Float64()*2 - 1) * 1e9
	return reflect.ValueOf(Money{Amount: amount, Currency: "INR"})
}

// ---------------------------------------------------------------------------
// Algebraic laws
// ---------------------------------------------------------------------------

// TestPropertyMoneyAddAssociativity: (a + b) + c == a + (b + c)
func TestPropertyMoneyAddAssociativity(t *testing.T) {
	t.Parallel()
	f := func(a, b, c Money) bool {
		ab, err := a.Add(b)
		if err != nil {
			return false
		}
		left, err := ab.Add(c)
		if err != nil {
			return false
		}

		bc, err := b.Add(c)
		if err != nil {
			return false
		}
		right, err := a.Add(bc)
		if err != nil {
			return false
		}

		if left.Currency != right.Currency {
			t.Logf("currency mismatch: %s vs %s", left.Currency, right.Currency)
			return false
		}
		if !approxEqual(left.Amount, right.Amount) {
			t.Logf("associativity violated: (%.6f + %.6f) + %.6f = %.6f vs %.6f + (%.6f + %.6f) = %.6f",
				a.Amount, b.Amount, c.Amount, left.Amount,
				a.Amount, b.Amount, c.Amount, right.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneyAddCommutativity: a + b == b + a
func TestPropertyMoneyAddCommutativity(t *testing.T) {
	t.Parallel()
	f := func(a, b Money) bool {
		ab, err := a.Add(b)
		if err != nil {
			return false
		}
		ba, err := b.Add(a)
		if err != nil {
			return false
		}
		if ab.Currency != ba.Currency {
			return false
		}
		if !approxEqual(ab.Amount, ba.Amount) {
			t.Logf("commutativity violated: %.6f + %.6f = %.6f vs %.6f + %.6f = %.6f",
				a.Amount, b.Amount, ab.Amount, b.Amount, a.Amount, ba.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneyAddIdentity: a + Zero == a, where Zero is the identity
// element for INR addition (Money{Amount: 0, Currency: "INR"}).
func TestPropertyMoneyAddIdentity(t *testing.T) {
	t.Parallel()
	zero := Money{Amount: 0, Currency: "INR"}
	f := func(a Money) bool {
		sum, err := a.Add(zero)
		if err != nil {
			return false
		}
		if sum.Currency != a.Currency {
			return false
		}
		if !approxEqual(sum.Amount, a.Amount) {
			t.Logf("identity violated: %.6f + 0 = %.6f", a.Amount, sum.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneySubInverse: (a + b) - b == a — subtraction undoes addition.
func TestPropertyMoneySubInverse(t *testing.T) {
	t.Parallel()
	f := func(a, b Money) bool {
		sum, err := a.Add(b)
		if err != nil {
			return false
		}
		back, err := sum.Sub(b)
		if err != nil {
			return false
		}
		if back.Currency != a.Currency {
			return false
		}
		if !approxEqual(back.Amount, a.Amount) {
			t.Logf("sub-inverse violated: (%.6f + %.6f) - %.6f = %.6f, want %.6f",
				a.Amount, b.Amount, b.Amount, back.Amount, a.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneyMulByOne: a * 1 == a — multiplicative identity.
func TestPropertyMoneyMulByOne(t *testing.T) {
	t.Parallel()
	f := func(a Money) bool {
		got := a.Multiply(1.0)
		if got.Currency != a.Currency {
			return false
		}
		if !approxEqual(got.Amount, a.Amount) {
			t.Logf("mul-by-1 violated: %.6f * 1 = %.6f", a.Amount, got.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneyMulByZero: a * 0 == Zero (in same currency).
func TestPropertyMoneyMulByZero(t *testing.T) {
	t.Parallel()
	f := func(a Money) bool {
		got := a.Multiply(0.0)
		if got.Currency != a.Currency {
			t.Logf("mul-by-0 currency mismatch: got %q want %q", got.Currency, a.Currency)
			return false
		}
		// 0 * NaN == NaN in float; Generate caps magnitude so this is fine,
		// but we still defensively reject NaN to keep the law clean.
		if math.IsNaN(got.Amount) {
			return false
		}
		if got.Amount != 0 {
			t.Logf("mul-by-0 violated: %.6f * 0 = %.6f, want 0", a.Amount, got.Amount)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Currency invariant — different currencies must error, not silently combine.
// This pins down the contract that exists today; we're testing the existing
// behaviour, not changing it.
// ---------------------------------------------------------------------------

// TestPropertyMoneyCurrencyInvariantAdd: Add between two different-currency
// Moneys returns a non-nil error (it does NOT panic, does NOT silently coerce).
func TestPropertyMoneyCurrencyInvariantAdd(t *testing.T) {
	t.Parallel()
	f := func(amountA, amountB float64) bool {
		// Cap magnitudes so we don't pollute the failure log with huge numbers.
		if math.Abs(amountA) > 1e9 {
			amountA = math.Mod(amountA, 1e9)
		}
		if math.Abs(amountB) > 1e9 {
			amountB = math.Mod(amountB, 1e9)
		}
		inr := Money{Amount: amountA, Currency: "INR"}
		usd := Money{Amount: amountB, Currency: "USD"}

		_, err := inr.Add(usd)
		if err == nil {
			t.Logf("expected error adding INR+USD, got nil")
			return false
		}
		_, err = usd.Add(inr)
		if err == nil {
			t.Logf("expected error adding USD+INR, got nil")
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// TestPropertyMoneyCurrencyInvariantSub: same as Add but for Sub.
func TestPropertyMoneyCurrencyInvariantSub(t *testing.T) {
	t.Parallel()
	f := func(amountA, amountB float64) bool {
		if math.Abs(amountA) > 1e9 {
			amountA = math.Mod(amountA, 1e9)
		}
		if math.Abs(amountB) > 1e9 {
			amountB = math.Mod(amountB, 1e9)
		}
		inr := Money{Amount: amountA, Currency: "INR"}
		usd := Money{Amount: amountB, Currency: "USD"}

		_, err := inr.Sub(usd)
		if err == nil {
			t.Logf("expected error subtracting INR-USD, got nil")
			return false
		}
		_, err = usd.Sub(inr)
		if err == nil {
			t.Logf("expected error subtracting USD-INR, got nil")
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
