package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// money_test.go — example-based unit tests for Money. The property-based
// tests in money_property_test.go cover algebraic laws (associativity etc.);
// this file targets the boundary-crossing accessors and the currency-aware
// comparison methods used by riskguard's per-user limit enforcement.

// ---------------------------------------------------------------------------
// Float64 — boundary-crossing accessor used by JSON serialization, log fields,
// and any other primitive-only consumer (e.g. SQLite REAL bindings).
// ---------------------------------------------------------------------------

func TestMoney_Float64(t *testing.T) {
	t.Parallel()
	t.Run("returns the underlying amount", func(t *testing.T) {
		m := NewINR(50000)
		assert.Equal(t, float64(50000), m.Float64())
	})
	t.Run("zero-value Money returns 0", func(t *testing.T) {
		var m Money
		assert.Equal(t, float64(0), m.Float64())
	})
	t.Run("negative amount preserved", func(t *testing.T) {
		m := NewINR(-1234.56)
		assert.Equal(t, float64(-1234.56), m.Float64())
	})
}

// ---------------------------------------------------------------------------
// GreaterThan — currency-aware comparison. The riskguard order-value cap
// uses this to reject orders that exceed the user's MaxSingleOrderINR limit.
// Cross-currency comparison must error out — the security goal is to make
// silent INR↔USD coercion impossible.
// ---------------------------------------------------------------------------

func TestMoney_GreaterThan(t *testing.T) {
	t.Parallel()

	t.Run("same currency, lhs greater", func(t *testing.T) {
		got, err := NewINR(100000).GreaterThan(NewINR(50000))
		require.NoError(t, err)
		assert.True(t, got)
	})
	t.Run("same currency, lhs equal", func(t *testing.T) {
		got, err := NewINR(50000).GreaterThan(NewINR(50000))
		require.NoError(t, err)
		assert.False(t, got)
	})
	t.Run("same currency, lhs less", func(t *testing.T) {
		got, err := NewINR(10000).GreaterThan(NewINR(50000))
		require.NoError(t, err)
		assert.False(t, got)
	})
	t.Run("cross-currency rejected", func(t *testing.T) {
		usd := Money{Amount: 100, Currency: "USD"}
		_, err := NewINR(50000).GreaterThan(usd)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "INR")
		assert.Contains(t, err.Error(), "USD")
	})
}
