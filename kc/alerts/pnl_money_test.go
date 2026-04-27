package alerts

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// TestDailyPnLEntry_HasCurrencyFields is the type-level assertion for the
// DailyPnLEntry currency-aware migration: the struct MUST carry sibling
// Currency string fields alongside each PnL float64 column. Empty string
// is the "INR default" sentinel — the SQL boundary normalizes it to "INR".
//
// Design choice: 3 sibling string fields rather than swapping the float64
// PnL fields to domain.Money keeps the JSON wire shape unchanged for
// kc/ops/api_alerts.go (chart points consume e.NetPnL as a float numeric)
// AND preserves SQLite native SUM()/AVG() aggregation. Money construction
// happens on-demand via the *Money() accessors below.
func TestDailyPnLEntry_HasCurrencyFields(t *testing.T) {
	t.Parallel()

	stringType := reflect.TypeOf("")
	e := DailyPnLEntry{}

	for _, name := range []string{"HoldingsPnLCurrency", "PositionsPnLCurrency", "NetPnLCurrency"} {
		f, ok := reflect.TypeOf(e).FieldByName(name)
		if !ok {
			t.Fatalf("DailyPnLEntry missing %s field", name)
		}
		if f.Type != stringType {
			t.Fatalf("DailyPnLEntry.%s must be string, got %s", name, f.Type)
		}
		// Currency fields stay off the JSON wire — chart consumers
		// (kc/ops/api_alerts.go) read NetPnL as a primitive number.
		if tag := f.Tag.Get("json"); tag != "-" {
			t.Errorf("DailyPnLEntry.%s json tag must be \"-\" to keep wire compat, got %q", name, tag)
		}
	}
}

// TestDailyPnLEntry_MoneyAccessors verifies the helper methods that
// construct domain.Money on-demand from the float + currency pair.
// Empty currency string defaults to INR (broker contract — current
// emitter is gokiteconnect which only ships INR).
func TestDailyPnLEntry_MoneyAccessors(t *testing.T) {
	t.Parallel()

	// Empty currency → INR default.
	e := &DailyPnLEntry{HoldingsPnL: 100, PositionsPnL: 200, NetPnL: 300}
	assert.Equal(t, "INR", e.HoldingsPnLMoney().Currency)
	assert.Equal(t, "INR", e.PositionsPnLMoney().Currency)
	assert.Equal(t, "INR", e.NetPnLMoney().Currency)
	assert.InDelta(t, 100.0, e.HoldingsPnLMoney().Float64(), 0.001)
	assert.InDelta(t, 200.0, e.PositionsPnLMoney().Float64(), 0.001)
	assert.InDelta(t, 300.0, e.NetPnLMoney().Float64(), 0.001)

	// Explicit currency carried through.
	e.HoldingsPnLCurrency = "USD"
	assert.Equal(t, "USD", e.HoldingsPnLMoney().Currency)
	assert.InDelta(t, 100.0, e.HoldingsPnLMoney().Float64(), 0.001)
}

// TestSaveDailyPnL_DefaultsCurrencyToINR verifies the SQL write path:
// when the struct's Currency fields are empty, SaveDailyPnL persists
// 'INR' to the new sibling columns. Existing tests construct
// DailyPnLEntry without currency fields — the default keeps them green.
func TestSaveDailyPnL_DefaultsCurrencyToINR(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	entry := &DailyPnLEntry{
		Date:         "2026-04-27",
		Email:        "user@example.com",
		HoldingsPnL:  1000,
		PositionsPnL: 500,
		NetPnL:       1500,
	}
	require.NoError(t, db.SaveDailyPnL(entry))

	loaded, err := db.LoadDailyPnL("user@example.com", "2026-04-27", "2026-04-27")
	require.NoError(t, err)
	require.Len(t, loaded, 1)

	// Round-trip: empty currencies on write became 'INR' on read.
	assert.Equal(t, "INR", loaded[0].HoldingsPnLCurrency)
	assert.Equal(t, "INR", loaded[0].PositionsPnLCurrency)
	assert.Equal(t, "INR", loaded[0].NetPnLCurrency)
	assert.InDelta(t, 1000.0, loaded[0].HoldingsPnL, 0.01)
	assert.InDelta(t, 500.0, loaded[0].PositionsPnL, 0.01)
	assert.InDelta(t, 1500.0, loaded[0].NetPnL, 0.01)
}

// TestSaveDailyPnL_PreservesExplicitCurrency verifies that an entry
// with explicit non-INR currencies round-trips through SQLite intact
// — the currency columns are NOT clobbered by the write-path default.
// Forward-compat for future multi-currency Kite accounts.
func TestSaveDailyPnL_PreservesExplicitCurrency(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	entry := &DailyPnLEntry{
		Date:                 "2026-04-27",
		Email:                "user@example.com",
		HoldingsPnL:          120,
		HoldingsPnLCurrency:  "USD",
		PositionsPnL:         50,
		PositionsPnLCurrency: "USD",
		NetPnL:               170,
		NetPnLCurrency:       "USD",
	}
	require.NoError(t, db.SaveDailyPnL(entry))

	loaded, err := db.LoadDailyPnL("user@example.com", "2026-04-27", "2026-04-27")
	require.NoError(t, err)
	require.Len(t, loaded, 1)

	assert.Equal(t, "USD", loaded[0].HoldingsPnLCurrency)
	assert.Equal(t, "USD", loaded[0].PositionsPnLCurrency)
	assert.Equal(t, "USD", loaded[0].NetPnLCurrency)
}

// TestGetJournal_RejectsCrossCurrencyAggregation verifies the canonical
// "no silent coercion" invariant from Slice 1: when a user's daily P&L
// stream mixes currencies (rare in practice, but possible if a user
// switches Kite accounts across currencies), GetJournal must surface
// the mismatch rather than silently summing INR + USD as a bare number.
//
// Acceptance criterion: the aggregation returns a typed error containing
// "currency" when entries with conflicting NetPnLCurrency are summed.
func TestGetJournal_RejectsCrossCurrencyAggregation(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	// Day 1: INR. Day 2: USD. Same user.
	require.NoError(t, db.SaveDailyPnL(&DailyPnLEntry{
		Date: "2026-04-26", Email: "user@example.com",
		NetPnL: 1500, NetPnLCurrency: "INR",
	}))
	require.NoError(t, db.SaveDailyPnL(&DailyPnLEntry{
		Date: "2026-04-27", Email: "user@example.com",
		NetPnL: 50, NetPnLCurrency: "USD",
	}))

	_, err := svc.GetJournal("user@example.com", "2026-04-26", "2026-04-27")
	require.Error(t, err, "cross-currency aggregation must error rather than silently sum")
	assert.Contains(t, err.Error(), "currency", "error must name the currency mismatch")
}

// TestGetJournal_SameCurrencyAggregationSucceeds is the green-path twin:
// when all entries share INR (the production default), GetJournal
// computes cumulative + best/worst day stats without error.
func TestGetJournal_SameCurrencyAggregationSucceeds(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	require.NotNil(t, svc)

	for _, e := range []*DailyPnLEntry{
		{Date: "2026-04-25", Email: "user@example.com", NetPnL: 1000, NetPnLCurrency: "INR"},
		{Date: "2026-04-26", Email: "user@example.com", NetPnL: -500, NetPnLCurrency: "INR"},
		{Date: "2026-04-27", Email: "user@example.com", NetPnL: 200, NetPnLCurrency: "INR"},
	} {
		require.NoError(t, db.SaveDailyPnL(e))
	}

	result, err := svc.GetJournal("user@example.com", "2026-04-25", "2026-04-27")
	require.NoError(t, err)
	assert.InDelta(t, 700.0, result.CumulativePnL, 0.01)
	assert.Equal(t, 3, result.TotalDays)
}

// TestBuildPnLEntry_DefaultsToINR verifies the broker-data → struct
// boundary: gokiteconnect emits INR-priced floats; buildPnLEntry must
// stamp the Currency fields with "INR" so persisted rows are
// unambiguously INR (not "" → ambiguous "could be anything").
//
// This is the upstream invariant that makes the cross-currency
// rejection test meaningful — without it, every persisted row would
// match every other persisted row (empty == INR default), defeating
// the safety net.
func TestBuildPnLEntry_DefaultsToINR(t *testing.T) {
	t.Parallel()

	entry := buildPnLEntry("2026-04-27", "user@example.com", nil, nil, kiteconnect.Positions{}, nil)
	require.NotNil(t, entry)

	assert.Equal(t, "INR", entry.HoldingsPnLCurrency)
	assert.Equal(t, "INR", entry.PositionsPnLCurrency)
	assert.Equal(t, "INR", entry.NetPnLCurrency)
}

// TestPnLMoneyAccessors_ReturnTypedMoney verifies that calling the
// *Money() accessors yields a domain.Money value object compatible
// with the rest of the Money pipeline — Add, Sub, GreaterThan all work.
func TestPnLMoneyAccessors_ReturnTypedMoney(t *testing.T) {
	t.Parallel()

	a := &DailyPnLEntry{NetPnL: 1000, NetPnLCurrency: "INR"}
	b := &DailyPnLEntry{NetPnL: 500, NetPnLCurrency: "INR"}

	sum, err := a.NetPnLMoney().Add(b.NetPnLMoney())
	require.NoError(t, err)
	assert.InDelta(t, 1500.0, sum.Float64(), 0.01)

	// Cross-currency: USD vs INR → typed error from domain.Money.Add.
	// Error message format is "domain: cannot add USD to INR" — assert
	// on the currency code presence rather than the literal word
	// "currency", since the domain package's wording is the canonical
	// surface and shouldn't be coupled to test phrasing.
	c := &DailyPnLEntry{NetPnL: 50, NetPnLCurrency: "USD"}
	_, err = a.NetPnLMoney().Add(c.NetPnLMoney())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USD")
	assert.Contains(t, err.Error(), "INR")

	// Sanity: type IS domain.Money (not bare float).
	assert.IsType(t, domain.Money{}, a.NetPnLMoney())
}
