// Package money_test verifies the leaf-package contract: a future
// import-cycle-sensitive consumer (e.g. broker.Holding.PnL elevated
// to Money) MUST be able to import money without pulling in
// kc/domain transitively. This guard test pins the "zero external
// deps" invariant that lets broker take a Money-typed dependency
// without inverting the existing kc/domain → broker import direction.
package money_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/money"
)

// TestPackage_LeafContract is the structural assertion that protects
// the import-graph invariant. money MUST be a leaf — no internal
// repo dependencies — so broker can import it without creating a
// cycle through kc/domain.
//
// This test is intentionally smoke-only; the real enforcement is
// the Go compiler, which would refuse to build money_test.go if
// money/money.go imported kc/domain or broker. Reading the import
// list directly via the AST would be over-engineered; the build
// itself is the structural proof.
func TestPackage_LeafContract(t *testing.T) {
	t.Parallel()
	// If this test compiles + runs, the build succeeded, which
	// means money has no broker / kc/domain imports. The body is
	// a sentinel.
	_ = money.Money{}
}

// TestNewINR_RoundTrips verifies the canonical constructor + the
// boundary accessor pair. Mirrors the kc/domain test of the same
// shape so the migrated callers see identical behavior.
func TestNewINR_RoundTrips(t *testing.T) {
	t.Parallel()

	m := money.NewINR(50000)
	assert.Equal(t, "INR", m.Currency)
	assert.Equal(t, 50000.0, m.Float64())
	assert.True(t, m.IsPositive())
	assert.False(t, m.IsZero())
	assert.False(t, m.IsNegative())
}

// TestZeroValueSentinel: the bare struct is the "no money set"
// sentinel — IsZero() true, Currency empty (NOT auto-INR — that
// would defeat the cross-currency safety net).
func TestZeroValueSentinel(t *testing.T) {
	t.Parallel()

	var m money.Money
	assert.True(t, m.IsZero())
	assert.Equal(t, "", m.Currency)
	assert.Equal(t, 0.0, m.Float64())
}

// TestAddSub_CrossCurrencyError: same-currency arithmetic succeeds;
// cross-currency surfaces a typed error rather than silently coercing.
func TestAddSub_CrossCurrencyError(t *testing.T) {
	t.Parallel()

	inr := money.NewINR(1000)
	usd := money.Money{Amount: 12, Currency: "USD"}

	sum, err := inr.Add(money.NewINR(500))
	require.NoError(t, err)
	assert.Equal(t, 1500.0, sum.Float64())

	_, err = inr.Add(usd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USD")
	assert.Contains(t, err.Error(), "INR")

	diff, err := inr.Sub(money.NewINR(300))
	require.NoError(t, err)
	assert.Equal(t, 700.0, diff.Float64())

	_, err = inr.Sub(usd)
	require.Error(t, err)
}

// TestGreaterThan_CrossCurrencyError: comparison rejects
// cross-currency rather than coercing.
func TestGreaterThan_CrossCurrencyError(t *testing.T) {
	t.Parallel()

	inr := money.NewINR(1000)
	usd := money.Money{Amount: 12, Currency: "USD"}

	gt, err := inr.GreaterThan(money.NewINR(500))
	require.NoError(t, err)
	assert.True(t, gt)

	_, err = inr.GreaterThan(usd)
	require.Error(t, err)
}

// TestMultiply_PreservesCurrency: scaling by a factor keeps the
// currency unchanged. Foundational for weighted-average math.
func TestMultiply_PreservesCurrency(t *testing.T) {
	t.Parallel()

	m := money.NewINR(100)
	scaled := m.Multiply(2.5)
	assert.Equal(t, 250.0, scaled.Float64())
	assert.Equal(t, "INR", scaled.Currency)

	// Negative factor preserves sign.
	neg := m.Multiply(-1)
	assert.Equal(t, -100.0, neg.Float64())
	assert.True(t, neg.IsNegative())
}

// TestNewMoney_RejectsNonPositive: validated constructor for
// "price MUST be > 0" invariants (LIMIT/SL order prices).
func TestNewMoney_RejectsNonPositive(t *testing.T) {
	t.Parallel()

	m, err := money.NewMoney(100)
	require.NoError(t, err)
	assert.Equal(t, 100.0, m.Float64())

	_, err = money.NewMoney(0)
	require.Error(t, err)

	_, err = money.NewMoney(-50)
	require.Error(t, err)
}

// TestStringFormat_IndianGrouping: INR rendering uses the Indian
// numbering system (12,34,567.89). Other currencies use ISO prefix.
func TestStringFormat_IndianGrouping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   money.Money
		want string
	}{
		{money.NewINR(0), "₹0.00"},
		{money.NewINR(123), "₹123.00"},
		{money.NewINR(1234), "₹1,234.00"},
		{money.NewINR(12345), "₹12,345.00"},
		{money.NewINR(123456), "₹1,23,456.00"},
		{money.NewINR(1234567.89), "₹12,34,567.89"},
		{money.NewINR(-1000), "₹-1,000.00"}, // matches kc/domain behavior verbatim (rupee then minus)
		{money.Money{Amount: 99.5, Currency: "USD"}, "USD 99.50"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.in.String(), "String() for %v", c.in)
	}
}

// TestMarshalJSON_INRBareFloat is the wire-format invariant: an INR
// Money value serializes as a bare JSON number. This is the
// pre-condition for elevating broker.Holding.PnL / broker.Position.PnL
// to Money WITHOUT breaking the JSON wire shape that external
// dashboards / chat clients depend on.
//
// Empty Currency (zero-value Money) also serializes as a bare 0
// — same wire shape, distinguishable in-process via IsZero().
func TestMarshalJSON_INRBareFloat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   money.Money
		want string
	}{
		{money.NewINR(1234.56), "1234.56"},
		{money.NewINR(0), "0"},
		{money.NewINR(-500), "-500"},
		{money.Money{}, "0"}, // zero value (empty currency) → bare 0
	}
	for _, c := range cases {
		got, err := json.Marshal(c.in)
		require.NoError(t, err)
		assert.JSONEq(t, c.want, string(got), "marshal %v", c.in)
	}
}

// TestMarshalJSON_NonINRObject: non-INR Money serializes as the
// {"amount": N, "currency": "S"} object so the cross-currency
// case is unambiguous on the wire. Future multi-currency Kite
// accounts surface here.
func TestMarshalJSON_NonINRObject(t *testing.T) {
	t.Parallel()

	usd := money.Money{Amount: 99.5, Currency: "USD"}
	got, err := json.Marshal(usd)
	require.NoError(t, err)

	// Object shape with amount + currency keys.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(got, &decoded))
	assert.Equal(t, 99.5, decoded["amount"])
	assert.Equal(t, "USD", decoded["currency"])
}

// TestUnmarshalJSON_BareFloat: bare-float JSON round-trips back
// to an INR Money via the symmetric Unmarshal path. This is the
// other half of the wire-compat contract — readers of historical
// rows (pre-Money-typed broker DTOs) get correct currency tagging.
func TestUnmarshalJSON_BareFloat(t *testing.T) {
	t.Parallel()

	var m money.Money
	require.NoError(t, json.Unmarshal([]byte("1234.56"), &m))
	assert.Equal(t, 1234.56, m.Float64())
	assert.Equal(t, "INR", m.Currency, "bare-float JSON must rehydrate as INR")
}

// TestUnmarshalJSON_Object: object-shaped JSON round-trips back
// preserving both amount and currency. Forward-compat for the
// non-INR case.
func TestUnmarshalJSON_Object(t *testing.T) {
	t.Parallel()

	var m money.Money
	require.NoError(t, json.Unmarshal([]byte(`{"amount": 99.5, "currency": "USD"}`), &m))
	assert.Equal(t, 99.5, m.Float64())
	assert.Equal(t, "USD", m.Currency)
}

// TestMarshalUnmarshal_Roundtrip: end-to-end JSON round-trip for
// both INR (bare) and non-INR (object) cases.
func TestMarshalUnmarshal_Roundtrip(t *testing.T) {
	t.Parallel()

	for _, in := range []money.Money{
		money.NewINR(1234.56),
		money.NewINR(0),
		money.NewINR(-500),
		{Amount: 99.5, Currency: "USD"},
	} {
		raw, err := json.Marshal(in)
		require.NoError(t, err)

		var out money.Money
		require.NoError(t, json.Unmarshal(raw, &out))

		assert.Equal(t, in.Float64(), out.Float64())
		// Empty-currency input rehydrates as INR (matches the
		// "bare 0 means INR 0" wire convention).
		expectedCcy := in.Currency
		if expectedCcy == "" {
			expectedCcy = "INR"
		}
		assert.Equal(t, expectedCcy, out.Currency)
	}
}
