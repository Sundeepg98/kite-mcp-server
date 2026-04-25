package riskguard

// otr_band.go — SEBI Order-to-Trade band check (Apr 2026).
//
// Rule (SEBI circular Feb 2026, effective Apr 6, 2026)
// =====================================================
// Order-to-Trade Ratio surveillance assigns each order a "band" based
// on price distance from LTP. Orders priced WITHIN the exemption band
// are excluded from OTR computation. Orders OUTSIDE the band count
// against the user's OTR ratio and can trigger broker-side throttles
// or compliance flags.
//
// Exemption bands (asset-class dependent):
//   - Equity options:  ±40% of LTP
//   - Cash + futures:  ±0.75% of LTP
//
// We don't enforce OTR globally (that's the broker's job), but we DO
// pre-block orders priced obviously outside the band. Two reasons:
//
//  1. Prevents fat-finger trades (operator types ₹100 instead of ₹1000).
//  2. Keeps the user's OTR ratio in good standing automatically.
//
// MARKET orders carry Price=0 and bypass the check (no price specified
// = no band to validate). LIMIT/SL/SL-M with explicit Price get checked.
//
// LTPLookup port
// ==============
// The check needs a "current LTP for this instrument" oracle. The port
// is intentionally narrow so the production wiring (instruments cache
// or live broker quote) and test wiring (in-memory map) share the same
// surface. nil LTPLookup or a missing instrument returns ok=false; the
// check then PASSES (we'd rather not block on a missing oracle than
// false-positive a valid order).

// LTPLookup is the narrow port the OTR band check needs to fetch the
// last-traded-price for a given instrument. Production binds this to
// the instruments-cache or paper-trading LTP provider. nil-implementation
// is allowed; the check no-ops in that case rather than block valid
// orders on missing infrastructure.
type LTPLookup interface {
	// GetLTP returns the last traded price for the given instrument
	// and a found-flag. found=false signals "no quote available" —
	// the check will pass through without rejecting.
	GetLTP(exchange, tradingsymbol string) (price float64, found bool)
}

// OrderOTRBand is the Check.Order slot for the band check. Sits after
// the daily-value cap and before the anomaly detector — placed late so
// cheap reject-paths short-circuit ahead of the LTP lookup.
const OrderOTRBand = 1050

// OTR exemption band thresholds. Single source of truth for the SEBI
// rule values; tests and production both read these constants.
const (
	OTRBandOptionsPct      = 0.40   // ±40% for equity options
	OTRBandCashFuturesPct  = 0.0075 // ±0.75% for cash + futures
)

// otrBandCheck implements the SEBI OTR band rule as a Check.
//
// RecordOnRejection is true: the rejection counts toward auto-freeze.
// A user repeatedly placing wildly off-band orders is either a fat-
// fingered operator or a hostile script; neither should keep the
// kill switch un-tripped.
//
// Holds a *Guard pointer rather than a captured LTPLookup so callers
// can wire the lookup AFTER NewGuard via SetLTPLookup. Reads g.ltpLookup
// at evaluation time under mu.RLock — the same pattern other built-in
// checks use to avoid stale-binding issues.
type otrBandCheck struct {
	g *Guard
}

func (c *otrBandCheck) Name() string             { return "otr_band" }
func (c *otrBandCheck) Order() int               { return OrderOTRBand }
func (c *otrBandCheck) RecordOnRejection() bool  { return true }

// Evaluate enforces the band. Skips MARKET orders (Price=0), missing
// LTP (lookup returned !found), and the case where no lookup has been
// wired (DevMode / tests).
func (c *otrBandCheck) Evaluate(req OrderCheckRequest) CheckResult {
	c.g.mu.RLock()
	lookup := c.g.ltpLookup
	c.g.mu.RUnlock()
	if lookup == nil || req.Price <= 0 {
		return CheckResult{Allowed: true}
	}
	ltp, found := lookup.GetLTP(req.Exchange, req.Tradingsymbol)
	if !found || ltp <= 0 {
		// No quote available — fail open. Better to pass a real order
		// than reject one because the LTP cache hasn't warmed.
		return CheckResult{Allowed: true}
	}
	bandPct := bandForExchange(req.Exchange, req.Tradingsymbol)
	low := ltp * (1.0 - bandPct)
	high := ltp * (1.0 + bandPct)
	if req.Price < low || req.Price > high {
		return CheckResult{
			Allowed: false,
			Reason:  ReasonOTRBand,
			Message: formatBandRejection(req.Price, ltp, bandPct),
		}
	}
	return CheckResult{Allowed: true}
}

// bandForExchange returns the SEBI-defined exemption band as a fractional
// multiplier (0.40 for options, 0.0075 for cash/futures).
//
// Heuristic: NSE/BSE options carry symbols ending in "CE" or "PE"
// (call-european / put-european). Anything else falls under cash + futures.
// Mirrors the lookup the broker performs when computing OTR.
func bandForExchange(exchange, tradingsymbol string) float64 {
	if isOptionSymbol(exchange, tradingsymbol) {
		return OTRBandOptionsPct
	}
	return OTRBandCashFuturesPct
}

// isOptionSymbol detects equity options by their NSE/BSE option-suffix
// convention. F&O options end in "CE" or "PE"; futures end in "FUT".
// Underlying cash equities don't have a suffix.
func isOptionSymbol(exchange, tradingsymbol string) bool {
	if exchange != "NFO" && exchange != "BFO" && exchange != "MCX" {
		return false
	}
	if len(tradingsymbol) < 2 {
		return false
	}
	suf := tradingsymbol[len(tradingsymbol)-2:]
	return suf == "CE" || suf == "PE"
}

// formatBandRejection renders a human-readable rejection message naming
// the LTP, the order's price, and the band percent. Operators see this
// in MCP responses and audit logs — concise but enough to debug.
func formatBandRejection(price, ltp, bandPct float64) string {
	pct := bandPct * 100
	return formatPriceMsg(price, ltp, pct)
}

// formatPriceMsg builds the rejection text. Extracted so tests can verify
// shape without re-deriving the percentage math.
func formatPriceMsg(price, ltp, bandPct float64) string {
	return "Order price " + fmtRupees(price) +
		" is outside the SEBI OTR exemption band (" +
		fmtPct(bandPct) + " around LTP " + fmtRupees(ltp) + ")"
}

// fmtRupees formats a value as "Rs <int>" — keeps the rejection message
// short. Rounds half-away-from-zero.
func fmtRupees(v float64) string {
	rounded := int64(v + 0.5)
	if v < 0 {
		rounded = int64(v - 0.5)
	}
	return "Rs " + itoa(rounded)
}

// fmtPct formats a percentage with one decimal place ("0.8%").
func fmtPct(p float64) string {
	whole := int64(p)
	frac := int64((p-float64(whole))*10 + 0.5)
	if frac >= 10 {
		whole++
		frac = 0
	}
	return itoa(whole) + "." + itoa(frac) + "%"
}

// itoa is a tiny inline integer-to-string helper that avoids the strconv
// import where the only use is a single integer formatter. Negative
// numbers keep their sign.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
