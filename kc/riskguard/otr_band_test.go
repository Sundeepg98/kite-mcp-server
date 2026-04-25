package riskguard

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// stubLTPLookup is a minimal in-memory LTPLookup for tests. Maps a key
// "exchange|tradingsymbol" to its current LTP. Missing keys → not found.
type stubLTPLookup struct {
	prices map[string]float64
}

func newStubLookup(prices map[string]float64) *stubLTPLookup {
	return &stubLTPLookup{prices: prices}
}

func (s *stubLTPLookup) GetLTP(exchange, tradingsymbol string) (float64, bool) {
	p, ok := s.prices[exchange+"|"+tradingsymbol]
	return p, ok
}

func newGuardWithLookup(lookup LTPLookup) *Guard {
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.SetLTPLookup(lookup)
	return g
}

func TestOTRBand_AllowsMarketOrder(t *testing.T) {
	t.Parallel()
	g := newGuardWithLookup(newStubLookup(map[string]float64{"NSE|RELIANCE": 1000}))
	res := g.CheckOrder(OrderCheckRequest{
		Email:           "trader@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        1,
		OrderType:       "MARKET",
		Price:           0, // MARKET — no price set
		Confirmed:       true,
	})
	assert.True(t, res.Allowed, "MARKET orders bypass band check")
}

func TestOTRBand_AllowsCashOrderWithinBand(t *testing.T) {
	t.Parallel()
	// LTP 1000, ±0.75% band = 992.5 .. 1007.5
	g := newGuardWithLookup(newStubLookup(map[string]float64{"NSE|RELIANCE": 1000}))
	res := g.CheckOrder(OrderCheckRequest{
		Email:           "trader@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        1,
		OrderType:       "LIMIT",
		Price:           1005.0,
		Confirmed:       true,
	})
	assert.True(t, res.Allowed)
}

func TestOTRBand_RejectsCashOrderAboveBand(t *testing.T) {
	t.Parallel()
	// LTP 1000, ±0.75% upper = 1007.5; 1010 is outside (above) but
	// stays under the order_value cap so we hit the band check.
	g := newGuardWithLookup(newStubLookup(map[string]float64{"NSE|RELIANCE": 1000}))
	res := g.CheckOrder(OrderCheckRequest{
		Email:           "trader@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        1,
		OrderType:       "LIMIT",
		Price:           1010.0,
		Confirmed:       true,
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonOTRBand, res.Reason)
	assert.Contains(t, res.Message, "outside the SEBI OTR exemption band")
}

func TestOTRBand_RejectsCashOrderBelowBand(t *testing.T) {
	t.Parallel()
	g := newGuardWithLookup(newStubLookup(map[string]float64{"NSE|RELIANCE": 1000}))
	res := g.CheckOrder(OrderCheckRequest{
		Email:           "trader@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "SELL",
		Quantity:        1,
		OrderType:       "LIMIT",
		Price:           980.0, // -2% — below the 0.75% band but inside order_value cap
		Confirmed:       true,
	})
	assert.False(t, res.Allowed)
	assert.Equal(t, ReasonOTRBand, res.Reason)
}

func TestOTRBand_OptionsBandIs40Percent(t *testing.T) {
	t.Parallel()
	// NFO option (suffix CE) gets the 40% band: 100 * 0.6 .. 100 * 1.4
	// = 60 .. 140. Order at 130 should pass; at 200 should fail.
	g := newGuardWithLookup(newStubLookup(map[string]float64{"NFO|NIFTY24DEC25000CE": 100}))
	pass := g.CheckOrder(OrderCheckRequest{
		Email:         "trader@test.com",
		Exchange:      "NFO",
		Tradingsymbol: "NIFTY24DEC25000CE",
		Quantity:      50,
		OrderType:     "LIMIT",
		Price:         130,
		Confirmed:     true,
	})
	assert.True(t, pass.Allowed, "130 is within the 40%% options band around LTP 100")

	fail := g.CheckOrder(OrderCheckRequest{
		Email:         "trader@test.com",
		Exchange:      "NFO",
		Tradingsymbol: "NIFTY24DEC25000CE",
		Quantity:      50,
		OrderType:     "LIMIT",
		Price:         200,
		Confirmed:     true,
	})
	assert.False(t, fail.Allowed, "200 is outside the 40%% options band around LTP 100")
}

func TestOTRBand_NoLookupConfigured_AllowsAll(t *testing.T) {
	t.Parallel()
	// No SetLTPLookup called → check no-ops, all orders pass through.
	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	res := g.CheckOrder(OrderCheckRequest{
		Email:         "trader@test.com",
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
		Quantity:      1,
		OrderType:     "LIMIT",
		Price:         5000, // wildly off — but no lookup means no rejection
		Confirmed:     true,
	})
	// May or may not be Allowed (other checks could fire) — the assert is
	// that the OTR band specifically isn't the rejection reason.
	if !res.Allowed {
		assert.NotEqual(t, ReasonOTRBand, res.Reason,
			"missing lookup must NOT trigger band rejection")
	}
}

func TestOTRBand_LookupMissBypasses(t *testing.T) {
	t.Parallel()
	// Lookup wired but the specific instrument has no quote → band check
	// fails open. (Other checks may still reject.)
	g := newGuardWithLookup(newStubLookup(map[string]float64{}))
	res := g.CheckOrder(OrderCheckRequest{
		Email:         "trader@test.com",
		Exchange:      "NSE",
		Tradingsymbol: "UNKNOWN",
		Quantity:      1,
		OrderType:     "LIMIT",
		Price:         500,
		Confirmed:     true,
	})
	if !res.Allowed {
		assert.NotEqual(t, ReasonOTRBand, res.Reason,
			"missing instrument quote must NOT trigger band rejection")
	}
}

func TestOTRBand_RecordOnRejection(t *testing.T) {
	t.Parallel()
	c := &otrBandCheck{}
	assert.True(t, c.RecordOnRejection(),
		"band violations count toward auto-freeze — fat-finger trades shouldn't keep kill switch un-tripped")
}

func TestOTRBand_OrderConstantPlacement(t *testing.T) {
	t.Parallel()
	// Sits between dailyValue (1000) and anomaly (1100).
	assert.Equal(t, 1050, OrderOTRBand)
	assert.Less(t, OrderDailyValue, OrderOTRBand)
	assert.Less(t, OrderOTRBand, OrderAnomalyMultiplier)
}

func TestIsOptionSymbol(t *testing.T) {
	t.Parallel()
	assert.True(t, isOptionSymbol("NFO", "NIFTY24DEC25000CE"))
	assert.True(t, isOptionSymbol("NFO", "BANKNIFTY24DEC50000PE"))
	assert.False(t, isOptionSymbol("NFO", "NIFTY24DECFUT"), "futures get cash band")
	assert.False(t, isOptionSymbol("NSE", "RELIANCE"), "cash equity gets cash band")
	assert.False(t, isOptionSymbol("NFO", "X"), "too-short symbol")
}
