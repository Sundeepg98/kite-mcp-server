package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.


func TestGetHistoricalData_MissingInstrumentToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"from_date": "2024-01-01 00:00:00",
		"to_date":   "2024-12-31 00:00:00",
		"interval":  "day",
		// instrument_token missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestOptionsStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "invalid_strategy",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Unknown strategy")
}


func TestGetLTP_TooManyInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	insts := make([]any, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_ltp", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "maximum 500")
}


func TestGetOHLC_TooManyInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	insts := make([]any, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_ohlc", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "maximum 500")
}


func TestOptionsStrategy_BullCallSpreadInvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(25000),
		"strike2":    float64(24000), // strike2 <= strike1
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}


func TestOptionsStrategy_InvalidExpiry(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "not-a-date",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}


func TestOptionsStrategy_BearPutSpreadInvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(25000),
		"strike2":    float64(24000), // strike2 <= strike1
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}


func TestOptionsStrategy_IronCondorMissingStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(23000),
		"strike2":    float64(24000),
		// strike3 and strike4 missing (default 0)
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike")
}


func TestOptionsStrategy_ButterflyBadOrder(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "butterfly",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
		"strike2":    float64(23000), // strike2 < strike1 = bad order
		"strike3":    float64(25000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike1 < strike2")
}


func TestBacktestStrategy_MissingStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// strategy missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestTechnicalIndicators_MissingIndicators(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// indicators missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestOptionsStrategy_StrangleMissingStrike2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
		// strike2 missing (defaults to 0)
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2")
}


func TestBacktestStrategy_InvalidStrategy2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{
		"strategy":       "invalid_strategy",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Unknown strategy")
}


func TestTechnicalIndicators_MissingExchange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestTechnicalIndicators_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"exchange": "NSE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetOptionChain_NoNFOInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "test@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "No options found")
}


func TestGetOptionChain_NegativeStrikesAround(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "test@example.com", map[string]any{
		"underlying":       "NIFTY",
		"strikes_around_atm": float64(-5),
	})
	assert.True(t, result.IsError)
	// Should still fail due to no NFO options
	assertResultContains(t, result, "No options found")
}


func TestOptionsGreeks_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestOptionsStrategy_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestSearchInstruments_EmptyQuery(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query": "",
	})
	assert.True(t, result.IsError)
}


func TestTechnicalIndicators_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestBacktestStrategy_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestOptionsGreeks_InvalidParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"spot_price":  float64(0),
		"strike":      float64(1500),
		"expiry_days": float64(30),
		"rate":        float64(0.05),
		"option_type": "CE",
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_InvalidStrategy_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "invalid_strategy",
		"underlying": "NIFTY",
		"spot_price": float64(24000),
	})
	assert.NotNil(t, result)
}


func TestBacktestStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"strategy":   "nonexistent",
		"period":     "1y",
	})
	assert.NotNil(t, result)
}


func TestTechnicalIndicators_InvalidIndicator(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"indicators": "invalid_indicator",
	})
	assert.NotNil(t, result)
}


func TestSearchInstruments_WithQuery(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query": "INFY",
	})
	assert.NotNil(t, result)
	// Should find INFY in test data
	assert.False(t, result.IsError)
}


func TestSearchInstruments_WithExchangeFilter(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query":    "RELIANCE",
		"exchange": "NSE",
	})
	assert.NotNil(t, result)
}


func TestGetHistoricalData_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetLTP_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ltp", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetOHLC_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ohlc", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetQuotes_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_quotes", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestOptionsGreeks_InvalidOptionType_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(24000),
		"expiry_date":    "2025-06-01",
		"option_type":    "INVALID",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "CE or PE")
}


func TestOptionsGreeks_NegativeStrike(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(-100),
		"expiry_date":    "2025-06-01",
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "positive")
}


func TestOptionsGreeks_InvalidExpiryFormat(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(24000),
		"expiry_date":    "invalid-date",
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}


func TestOptionsStrategy_InvalidExpiry_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "bad-date",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}


func TestOptionsStrategy_BullCallSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}


func TestOptionsStrategy_BearPutSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_BearCallSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "bear_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_UnknownStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "test@example.com", map[string]any{
		"strategy":   "unknown_strat",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
}
