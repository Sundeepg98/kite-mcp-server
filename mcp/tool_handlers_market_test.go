package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Market tools: parameter validation
// ---------------------------------------------------------------------------
func TestGetQuotes_RequiresInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_quotes", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_quotes without instruments should fail")
	assertResultContains(t, result, "is required")
}


func TestGetLTP_RequiresInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ltp", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_ltp without instruments should fail")
	assertResultContains(t, result, "is required")
}


func TestGetQuotes_TooManyInstruments(t *testing.T) {
	mgr := newTestManager(t)
	// Create more than 500 instruments
	insts := make([]any, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError, "get_quotes with >500 instruments should fail")
	assertResultContains(t, result, "maximum 500")
}


// ---------------------------------------------------------------------------
// Options tools: pre-session validation
// ---------------------------------------------------------------------------
func TestGetOptionChain_MissingUnderlying(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_option_chain without underlying should fail")
	assertResultContains(t, result, "is required")
}


func TestOptionsGreeks_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "options_greeks with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestOptionsGreeks_MissingStrikePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2440324000CE",
		"expiry_date":    "2024-04-03",
		"option_type":    "CE",
		// strike_price missing
	})
	assert.True(t, result.IsError, "options_greeks without strike_price should fail")
	assertResultContains(t, result, "strike_price")
}


func TestOptionsGreeks_InvalidOptionType(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(24000),
		"expiry_date":   "2024-04-03",
		"option_type":   "INVALID",
	})
	assert.True(t, result.IsError, "options_greeks with invalid option_type should fail")
	assertResultContains(t, result, "option_type must be CE or PE")
}


func TestOptionsGreeks_NegativeStrikePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(-100),
		"expiry_date":   "2024-04-03",
		"option_type":   "CE",
	})
	assert.True(t, result.IsError, "options_greeks with negative strike_price should fail")
	assertResultContains(t, result, "strike_price must be positive")
}


func TestOptionsGreeks_InvalidExpiryDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(24000),
		"expiry_date":   "not-a-date",
		"option_type":   "CE",
	})
	assert.True(t, result.IsError, "options_greeks with invalid expiry_date should fail")
	assertResultContains(t, result, "YYYY-MM-DD")
}


func TestOptionsStrategy_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "options_payoff_builder with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestOptionsStrategy_MissingStrike1(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		// strike1 missing
	})
	assert.True(t, result.IsError, "options_payoff_builder without strike1 should fail")
	assertResultContains(t, result, "strike1")
}


// ---------------------------------------------------------------------------
// Backtest and indicators: pre-session validation
// ---------------------------------------------------------------------------
func TestBacktestStrategy_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "historical_price_analyzer with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestTechnicalIndicators_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "technical_indicators with no params should fail validation")
	assertResultContains(t, result, "is required")
}


// ---------------------------------------------------------------------------
// search_instruments: full handler test (no broker session needed!)
// ---------------------------------------------------------------------------
func TestSearchInstruments_MissingQuery(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "search_instruments without query should fail")
	assertResultContains(t, result, "is required")
}


func TestSearchInstruments_ByID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "NSE:INFY",
	})
	assert.False(t, result.IsError, "search_instruments by ID should succeed")
}


func TestSearchInstruments_ByName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "INFOSYS",
		"filter_on": "name",
	})
	assert.False(t, result.IsError, "search_instruments by name should succeed")
}


func TestSearchInstruments_ByTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "RELIANCE",
		"filter_on": "tradingsymbol",
	})
	assert.False(t, result.IsError, "search_instruments by tradingsymbol should succeed")
}


func TestSearchInstruments_WithPagination(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "NSE",
		"limit": float64(1),
	})
	assert.False(t, result.IsError, "search_instruments with pagination should succeed")
}


func TestSearchInstruments_NoResults(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "ZZZNONEXISTENT",
	})
	assert.False(t, result.IsError, "search_instruments with no results should still succeed (empty array)")
}


func TestSearchInstruments_UnderlyingWithColon(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "NFO:NIFTY",
		"filter_on": "underlying",
	})
	// May return empty but should not error
	assert.False(t, result.IsError, "search_instruments underlying with colon should succeed")
}


func TestSearchInstruments_UnderlyingWithoutColon(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "NIFTY",
		"filter_on": "underlying",
	})
	assert.False(t, result.IsError, "search_instruments underlying without colon should succeed")
}


// ---------------------------------------------------------------------------
// get_historical_data: pre-session validation
// ---------------------------------------------------------------------------
func TestGetHistoricalData_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_historical_data with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestGetHistoricalData_InvalidFromDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "not-a-date",
		"to_date":          "2024-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "invalid from_date should fail")
	assertResultContains(t, result, "from_date")
}


func TestGetHistoricalData_InvalidToDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-01-01 00:00:00",
		"to_date":          "bad-date",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "invalid to_date should fail")
	assertResultContains(t, result, "to_date")
}


func TestGetHistoricalData_FromAfterTo(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-12-01 00:00:00",
		"to_date":          "2024-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "from_date after to_date should fail")
	assertResultContains(t, result, "from_date must be before to_date")
}


// ---------------------------------------------------------------------------
// get_ohlc: pre-session validation
// ---------------------------------------------------------------------------
func TestGetOHLC_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ohlc", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_ohlc without instruments should fail")
	assertResultContains(t, result, "is required")
}


// ---------------------------------------------------------------------------
// get_option_chain: pre-session validation (additional)
// ---------------------------------------------------------------------------
func TestGetOptionChain_EmptyUnderlying(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "trader@example.com", map[string]any{
		"underlying": "",
	})
	assert.True(t, result.IsError, "get_option_chain with empty underlying should fail")
}


// ---------------------------------------------------------------------------
// options_payoff_builder: additional validation
// ---------------------------------------------------------------------------
func TestOptionsStrategy_MissingExpiry(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"strike1":    float64(24000),
		// expiry missing
	})
	assert.True(t, result.IsError, "options_payoff_builder without expiry should fail")
	assertResultContains(t, result, "expiry")
}


// ---------------------------------------------------------------------------
// historical_price_analyzer: additional validation
// ---------------------------------------------------------------------------
func TestBacktestStrategy_MissingInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{
		"strategy": "sma_crossover",
		// instrument missing
	})
	assert.True(t, result.IsError, "historical_price_analyzer without instrument should fail")
	assertResultContains(t, result, "is required")
}


// ---------------------------------------------------------------------------
// technical_indicators: additional validation
// ---------------------------------------------------------------------------
func TestTechnicalIndicators_MissingInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"indicators": []any{"RSI"},
		// instrument missing
	})
	assert.True(t, result.IsError, "technical_indicators without instrument should fail")
	assertResultContains(t, result, "is required")
}


// ── Market tools — instrument limits ─────────────────────────────────────
func TestGetLTP_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}


func TestGetOHLC_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}


func TestGetQuotes_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}


// ── Search instruments edge cases ────────────────────────────────────────
func TestSearchInstruments_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query": "NSE", "filter_on": "id",
		"from": float64(0), "limit": float64(1),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}
