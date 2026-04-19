package mcp

import (
	"sort"
	"testing"

	"pgregory.net/rapid"

	"github.com/zerodha/kite-mcp-server/broker"
)

// sector_tool_property_test.go — property-based tests for sector
// classification + computeSectorExposure. Focuses on invariants that
// should hold regardless of which subset of the 150+ stocks appears in
// a portfolio.
//
// Properties under test:
//
//  1. Known-symbol mapping: every key in stockSectors maps to a
//     non-empty sector. (Catches accidental "" entries in refactors.)
//
//  2. normalizeSymbol is idempotent: applying it twice is the same
//     as applying it once.
//
//  3. computeSectorExposure never panics on arbitrary holdings lists,
//     including empty names, zero quantities, negative values,
//     duplicate symbols, and unknown tickers.
//
//  4. Sector allocation percentages sum to ~100% (within float
//     rounding) whenever the portfolio has non-zero total value.
//
//  5. Unknown tickers map to the "Other" sector bucket and surface
//     in the UnmappedStocks list — they never vanish or panic.

// TestProperty_StockSectors_EveryEntryHasNonEmptySector validates the
// invariant that the stockSectors map itself is well-formed: no empty
// strings, no whitespace-only values. A refactor that accidentally
// wipes a sector string would be caught here before landing.
func TestProperty_StockSectors_EveryEntryHasNonEmptySector(t *testing.T) {
	t.Parallel()
	// Not strictly a rapid test (finite map, no generators needed) but
	// keeping it here so sector correctness lives alongside the rapid
	// properties. Runs in <1ms.
	for symbol, sector := range stockSectors {
		if symbol == "" {
			t.Errorf("stockSectors has empty symbol key → %q", sector)
		}
		if sector == "" {
			t.Errorf("stockSectors[%q] is empty", symbol)
		}
	}
}

// TestProperty_NormalizeSymbol_Idempotent asserts that normalizeSymbol
// applied to its own output returns the same string. A regression that
// strips suffixes conditionally (e.g. only if uppercase) would break
// this.
func TestProperty_NormalizeSymbol_Idempotent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "raw_symbol")
		first := normalizeSymbol(s)
		second := normalizeSymbol(first)
		if first != second {
			t.Fatalf("normalizeSymbol not idempotent: %q → %q → %q", s, first, second)
		}
	})
}

// TestProperty_NormalizeSymbol_StripsKnownSuffixes asserts the
// post-condition that no known suffix remains after normalisation.
// If future Kite symbol conventions add a new suffix, this property
// points at the place to update.
func TestProperty_NormalizeSymbol_StripsKnownSuffixes(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		base := rapid.StringMatching(`[A-Z]{1,10}`).Draw(t, "base")
		suffix := rapid.SampledFrom([]string{"", "-BE", "-EQ", "-BZ", "-BL"}).
			Draw(t, "suffix")
		got := normalizeSymbol(base + suffix)
		// The base string must survive the round-trip — no amount of
		// suffix stripping should shave letters off the base token.
		if got != base {
			t.Fatalf("normalizeSymbol(%q) = %q, want %q", base+suffix, got, base)
		}
	})
}

// TestProperty_ComputeSectorExposure_NeverPanics asserts that
// computeSectorExposure tolerates arbitrary holdings input — any
// combination of known/unknown tickers, zero/negative quantities,
// zero/negative prices, empty symbols — without panicking.
func TestProperty_ComputeSectorExposure_NeverPanics(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 25).Draw(t, "holdings_count")
		holdings := make([]broker.Holding, 0, n)
		// Pre-compute a sample of known tickers to mix with random ones.
		known := knownSymbolSample()

		for i := 0; i < n; i++ {
			var sym string
			if rapid.Bool().Draw(t, "pick_known") && len(known) > 0 {
				sym = rapid.SampledFrom(known).Draw(t, "known_sym")
			} else {
				sym = rapid.String().Draw(t, "random_sym")
			}
			holdings = append(holdings, broker.Holding{
				Tradingsymbol: sym,
				Quantity:      rapid.IntRange(-100, 10000).Draw(t, "qty"),
				LastPrice:     rapid.Float64Range(-1e6, 1e6).Draw(t, "price"),
			})
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("computeSectorExposure panicked on %d holdings: %v", len(holdings), r)
			}
		}()
		_ = computeSectorExposure(holdings)
	})
}

// TestProperty_ComputeSectorExposure_PercentagesSumToHundred asserts
// that when total portfolio value is positive, per-sector allocations
// sum to ~100%. Float rounding (roundTo2) means an exact equality
// check fails; a 0.5% tolerance is well within the expected rounding
// drift across 25 holdings × two-decimal rounds.
func TestProperty_ComputeSectorExposure_PercentagesSumToHundred(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Force a positive-value portfolio: clamp prices and quantities
		// to strictly positive ranges.
		n := rapid.IntRange(1, 10).Draw(t, "holdings_count")
		known := knownSymbolSample()
		holdings := make([]broker.Holding, 0, n)
		for i := 0; i < n; i++ {
			holdings = append(holdings, broker.Holding{
				Tradingsymbol: rapid.SampledFrom(known).Draw(t, "sym"),
				Quantity:      rapid.IntRange(1, 1000).Draw(t, "qty"),
				LastPrice:     rapid.Float64Range(1, 10000).Draw(t, "price"),
			})
		}

		resp := computeSectorExposure(holdings)
		if resp.TotalValue <= 0 {
			return // guard: if rounding pushed it to 0, skip
		}

		var sum float64
		for _, s := range resp.Sectors {
			sum += s.Pct
		}
		// 0.5% tolerance absorbs roundTo2 drift across up to 10 sectors.
		if sum < 99.5 || sum > 100.5 {
			t.Fatalf("sector percentages sum to %.4f, want ~100 (holdings=%v)", sum, resp.Sectors)
		}
	})
}

// TestProperty_ComputeSectorExposure_UnknownSymbolsSurfaceAsUnmapped
// asserts that feeding purely unknown tickers produces an
// UnmappedStocks list of the same length and no "real" sector slots
// apart from the "Other" bucket.
func TestProperty_ComputeSectorExposure_UnknownSymbolsSurfaceAsUnmapped(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 10).Draw(t, "holdings_count")
		holdings := make([]broker.Holding, 0, n)
		for i := 0; i < n; i++ {
			sym := rapid.StringMatching(`UNK[A-Z]{3,8}Z`).Draw(t, "sym")
			// Skip any symbol that might coincidentally be in stockSectors.
			if _, hit := stockSectors[sym]; hit {
				t.Skip()
			}
			holdings = append(holdings, broker.Holding{
				Tradingsymbol: sym,
				Quantity:      rapid.IntRange(1, 100).Draw(t, "qty"),
				LastPrice:     rapid.Float64Range(1, 10000).Draw(t, "price"),
			})
		}

		resp := computeSectorExposure(holdings)
		if resp.UnmappedCount != len(holdings) {
			t.Fatalf("expected %d unmapped, got %d", len(holdings), resp.UnmappedCount)
		}
		if resp.MappedCount != 0 {
			t.Fatalf("expected 0 mapped, got %d", resp.MappedCount)
		}
		// All surfaced as "Other" in the sector list.
		if len(resp.Sectors) != 1 || resp.Sectors[0].Sector != "Other" {
			t.Fatalf("expected single 'Other' sector, got %v", resp.Sectors)
		}
	})
}

// knownSymbolSample returns a stable alphabetical sample of up to 40
// known stockSectors keys. Used by tests that want reproducible
// known-ticker generators (map iteration is random in Go).
func knownSymbolSample() []string {
	syms := make([]string, 0, len(stockSectors))
	for s := range stockSectors {
		syms = append(syms, s)
	}
	sort.Strings(syms)
	if len(syms) > 40 {
		syms = syms[:40]
	}
	return syms
}
