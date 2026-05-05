package sectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStockSectors_KnownSymbols verifies a sample of canonical NSE
// symbols resolves to expected sector buckets. This locks the public
// API contract: external consumers (mcp/portfolio, kc/ops, scanner)
// rely on these mappings being stable.
func TestStockSectors_KnownSymbols(t *testing.T) {
	t.Parallel()
	cases := []struct {
		symbol string
		sector string
	}{
		// Banking
		{"HDFCBANK", "Banking"},
		{"SBIN", "Banking"},
		// IT
		{"TCS", "IT"},
		{"INFY", "IT"},
		// FMCG
		{"HINDUNILVR", "FMCG"},
		{"ITC", "FMCG"},
		// Pharma / Healthcare distinction
		{"SUNPHARMA", "Pharma"},
		{"APOLLOHOSP", "Healthcare"},
		// Auto
		{"MARUTI", "Auto"},
		// Energy
		{"RELIANCE", "Energy"},
		// Conglomerate carve-out (ADANIENT specifically; not the rest of Adani)
		{"ADANIENT", "Conglomerate"},
		{"ADANIPORTS", "Infra"},
	}
	for _, tc := range cases {
		got, ok := StockSectors[tc.symbol]
		assert.True(t, ok, "StockSectors[%q] should exist", tc.symbol)
		assert.Equal(t, tc.sector, got, "StockSectors[%q]", tc.symbol)
	}
}

// TestStockSectors_NoEmptyValues asserts that every entry in the map has
// a non-empty key AND non-empty value. Mirrors the property test in
// mcp/portfolio/sector_tool_property_test.go but lives here to catch
// drift if entries are added directly to this package without going
// through the helper.
func TestStockSectors_NoEmptyValues(t *testing.T) {
	t.Parallel()
	for symbol, sector := range StockSectors {
		assert.NotEmpty(t, symbol, "empty symbol key found")
		assert.NotEmpty(t, sector, "StockSectors[%q] is empty", symbol)
	}
}

// TestStockSectors_MinimumCoverage verifies the package ships a
// reasonable sector universe — defends against accidental truncation
// during refactors.
func TestStockSectors_MinimumCoverage(t *testing.T) {
	t.Parallel()
	// Canonical map has ~150+ symbols; require >=120 to absorb minor
	// edits without locking the count.
	assert.GreaterOrEqual(t, len(StockSectors), 120,
		"StockSectors should map >=120 symbols (got %d)", len(StockSectors))
}

// TestNormalizeSymbol_StripsKnownSuffixes verifies the canonical
// suffixes documented at .research/abc-100pct-complete-paths.md are
// stripped during normalization for sector lookup.
func TestNormalizeSymbol_StripsKnownSuffixes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in  string
		out string
	}{
		{"SBIN-EQ", "SBIN"},
		{"HDFCBANK-BE", "HDFCBANK"},
		{"TCS-BZ", "TCS"},
		{"INFY-BL", "INFY"},
		{"reliance", "RELIANCE"}, // lowercase → uppercase
		{"  ITC  ", "ITC"},       // whitespace trimmed
		{"M&M", "M&M"},           // no suffix; idempotent
	}
	for _, tc := range cases {
		assert.Equal(t, tc.out, NormalizeSymbol(tc.in), "NormalizeSymbol(%q)", tc.in)
	}
}

// TestNormalizeSymbol_Idempotent — applying NormalizeSymbol twice
// equals applying it once. Property-test invariant from the canonical
// suite at mcp/portfolio/sector_tool_property_test.go.
func TestNormalizeSymbol_Idempotent(t *testing.T) {
	t.Parallel()
	samples := []string{"HDFCBANK-EQ", "  TCS-BE  ", "infy", "RELIANCE", ""}
	for _, s := range samples {
		first := NormalizeSymbol(s)
		second := NormalizeSymbol(first)
		assert.Equal(t, first, second, "NormalizeSymbol not idempotent for %q", s)
	}
}

// TestLookup_NormalizesBeforeMatch verifies the helper Lookup() does
// the normalize+lookup in one step, matching the canonical pattern
// used by mcp/portfolio/sector_tool.go and kc/ops/api_portfolio.go.
func TestLookup_NormalizesBeforeMatch(t *testing.T) {
	t.Parallel()
	// SBIN-EQ should normalize to SBIN and resolve to Banking.
	sector, ok := Lookup("SBIN-EQ")
	assert.True(t, ok, "Lookup should find SBIN via SBIN-EQ")
	assert.Equal(t, "Banking", sector)

	// Lowercase + whitespace should also resolve.
	sector, ok = Lookup("  hdfcbank  ")
	assert.True(t, ok)
	assert.Equal(t, "Banking", sector)

	// Unknown symbol returns false.
	_, ok = Lookup("UNKNOWNXYZ")
	assert.False(t, ok)
}
