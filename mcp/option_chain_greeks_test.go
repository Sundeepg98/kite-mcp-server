package mcp

import (
	"math"
	"testing"
	"time"
)

// TestTimeToExpiryYearsFromKiteDate covers the date parser we call before
// the Black-Scholes loop. Key cases:
//   - YYYY-MM-DD (canonical Kite format) parses correctly.
//   - Timestamps with suffixes truncate to the date.
//   - Empty / malformed input returns (0, 0) so the caller skips Greeks.
//   - A date in the past returns (0, 0).
func TestTimeToExpiryYearsFromKiteDate(t *testing.T) {
	t.Parallel()
	ist := time.FixedZone("IST", 5*3600+30*60)
	tomorrow := time.Now().In(ist).Add(24 * time.Hour).Format("2006-01-02")
	future := time.Now().In(ist).Add(30 * 24 * time.Hour).Format("2006-01-02")
	past := time.Now().In(ist).Add(-48 * time.Hour).Format("2006-01-02")

	tests := []struct {
		name      string
		in        string
		wantYears bool // true if expected > 0
		wantDays  int  // 0 means "any value is fine"
	}{
		{"empty", "", false, 0},
		{"malformed", "not-a-date", false, 0},
		{"past", past, false, 0},
		{"tomorrow", tomorrow, true, 0},
		{"far future", future, true, 0},
		{"with timestamp suffix", tomorrow + "T00:00:00+05:30", true, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			years, days := timeToExpiryYearsFromKiteDate(tc.in)
			if tc.wantYears {
				if years <= 0 {
					t.Fatalf("expected positive years, got %v", years)
				}
				if days <= 0 {
					t.Fatalf("expected positive days, got %d", days)
				}
			} else {
				if years != 0 || days != 0 {
					t.Fatalf("expected (0,0), got (%v, %d)", years, days)
				}
			}
		})
	}
}

// TestFillGreeks_CEAndPE verifies fillGreeks populates the correct side of
// the entry and leaves the other side untouched. Uses a realistic ATM NIFTY
// setup so IV solver converges and numbers are sane.
func TestFillGreeks_CEAndPE(t *testing.T) {
	t.Parallel()
	const (
		spot    = 22000.0
		strike  = 22000.0
		t30d    = 30.0 / 365.25 // 30 days
		r       = 0.07
		cePrice = 200.0
		pePrice = 200.0
	)

	// CE path
	ce := &optionChainEntry{Strike: strike, CELTP: cePrice}
	fillGreeks(ce, spot, strike, t30d, r, cePrice, true)
	if ce.CEDelta <= 0 || ce.CEDelta > 1 {
		t.Errorf("CE delta out of bounds: %v", ce.CEDelta)
	}
	if ce.CEGamma <= 0 {
		t.Errorf("CE gamma expected positive: %v", ce.CEGamma)
	}
	if ce.CEIV <= 0 || ce.CEIV > 500 {
		t.Errorf("CE IV%% implausible: %v", ce.CEIV)
	}
	// PE side must be untouched by a CE call.
	if ce.PEDelta != 0 || ce.PEIV != 0 {
		t.Errorf("CE call should not populate PE fields: %+v", ce)
	}

	// PE path on a separate entry
	pe := &optionChainEntry{Strike: strike, PELTP: pePrice}
	fillGreeks(pe, spot, strike, t30d, r, pePrice, false)
	if pe.PEDelta >= 0 || pe.PEDelta < -1 {
		t.Errorf("PE delta out of bounds (expected [-1, 0)): %v", pe.PEDelta)
	}
	if pe.PEIV <= 0 {
		t.Errorf("PE IV%% expected positive: %v", pe.PEIV)
	}
	if pe.CEDelta != 0 || pe.CEIV != 0 {
		t.Errorf("PE call should not populate CE fields: %+v", pe)
	}
}

// TestFillGreeks_ZeroWhenIVFails simulates a price below intrinsic. The
// solver should bail and leave Greek fields at zero so the widget renders
// an em-dash rather than a nonsense number.
func TestFillGreeks_ZeroWhenIVFails(t *testing.T) {
	t.Parallel()
	const (
		spot   = 22000.0
		strike = 20000.0 // deep ITM call
		t30d   = 30.0 / 365.25
		r      = 0.07
		// Price well below intrinsic (2000) -> solver rejects.
		cePrice = 100.0
	)
	ce := &optionChainEntry{Strike: strike, CELTP: cePrice}
	fillGreeks(ce, spot, strike, t30d, r, cePrice, true)
	if ce.CEIV != 0 || ce.CEDelta != 0 {
		t.Errorf("expected zero Greeks when price < intrinsic, got %+v", ce)
	}
}

// TestFillGreeks_IVPercentIsHumanReadable confirms IV is returned as a
// percent in [0, 500] for typical inputs — the widget renders it with "%".
func TestFillGreeks_IVPercentIsHumanReadable(t *testing.T) {
	t.Parallel()
	const (
		spot    = 22000.0
		strike  = 22200.0
		t30d    = 30.0 / 365.25
		r       = 0.07
		cePrice = 180.0
	)
	ce := &optionChainEntry{Strike: strike, CELTP: cePrice}
	fillGreeks(ce, spot, strike, t30d, r, cePrice, true)
	if ce.CEIV <= 0 || ce.CEIV > 500 {
		t.Errorf("expected IV percent in (0, 500], got %v", ce.CEIV)
	}
	// Sanity: internal sigma reconstructed from percent should be close to
	// what Black-Scholes would give back with the same price.
	sigma := ce.CEIV / 100
	priceBack := blackScholesPrice(spot, strike, t30d, r, sigma, true)
	if math.Abs(priceBack-cePrice) > 1.0 {
		t.Errorf("IV round-trip off: priceBack=%v expected close to %v", priceBack, cePrice)
	}
}
