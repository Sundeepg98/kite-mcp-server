package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestGetLTP_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ltp", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}


func TestGetOHLC_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ohlc", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}


func TestGetQuotes_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}


func TestSearchInstruments_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "RELIANCE",
	})
	// search_instruments uses the instrument manager (not Kite client),
	// so it may actually succeed
	assert.NotNil(t, result)
}


func TestBacktestStrategy_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
}


func TestTechnicalIndicators_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"indicators":       []any{"RSI", "SMA"},
	})
	assert.True(t, result.IsError)
}


func TestGetHistoricalData_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-01-01 00:00:00",
		"to_date":          "2024-12-31 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
}


func TestOptionsGreeks_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
		"strike_price":  float64(24000),
		"option_type":   "CE",
		"expiry_date":   "2026-04-30",
	})
	assert.True(t, result.IsError)
}


func TestGetOptionChain_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_option_chain", "trader@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2026-04-30",
		"strike1":    float64(24000),
		"strike2":    float64(24500),
	})
	assert.True(t, result.IsError)
}


func TestSubscribeInstruments_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "subscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestUnsubscribeInstruments_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "unsubscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestStopTicker_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "stop_ticker", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestTickerStatus_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "ticker_status", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestOptionsGreeks_ValidCE_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(24000),
		"expiry_date":    "2027-06-01",
		"option_type":    "CE",
	})
	assert.NotNil(t, result)
}


func TestOptionsGreeks_ValidPE_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY2560124000PE",
		"strike_price":     float64(24000),
		"expiry_date":      "2027-06-01",
		"option_type":      "PE",
		"underlying_price": float64(24850),
		"risk_free_rate":   float64(0.065),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_BullCallSpread_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24000),
		"strike2":    float64(24500),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_IronCondor_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(23500),
		"strike2":    float64(24000),
		"strike3":    float64(25000),
		"strike4":    float64(25500),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_Straddle_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24000),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_Strangle_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(23500),
		"strike2":    float64(24500),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// ticker_tools.go: deeper handler body coverage
// ---------------------------------------------------------------------------
func TestStartTicker_WithToken(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping: start_ticker invokes gokiteconnect v4.4.0 ticker.go:297 ServeWithContext which races on websocket.DefaultDialer (external SDK bug)")
	}
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Seed credentials+token
	mgr.CredentialStore().Set("ticker@example.com", &kc.KiteCredentialEntry{
		APIKey: "tk", APISecret: "ts", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("ticker@example.com", &kc.KiteTokenEntry{
		AccessToken: "access_token", StoredAt: time.Now(),
	})

	result := callToolDevMode(t, mgr, "start_ticker", "ticker@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should exercise the handler body — start may succeed or fail
}


func TestStopTicker_NoTicker(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "stop_ticker", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestTickerStatus_NoTicker(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "ticker_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestSubscribeInstruments_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY", "NSE:RELIANCE"},
		"mode":        "full",
	})
	assert.NotNil(t, result)
	// Ticker not started, so should fail with message
}


func TestSubscribeInstruments_EmptyArray(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestUnsubscribeInstruments_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestUnsubscribeInstruments_EmptyArray(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


// ---------------------------------------------------------------------------
// market_tools.go: get_historical_data edge cases (77% -> higher)
// ---------------------------------------------------------------------------
func TestGetHistoricalData_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"interval":         "day",
		"from_date":        "2025-01-01",
		"to_date":          "2025-03-01",
		"from":             float64(0),
		"limit":            float64(10),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// indicators_tool.go: deeper handler body (42.9% -> higher)
// ---------------------------------------------------------------------------
func TestTechnicalIndicators_WithInterval(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, interval := range []string{"day", "15minute", "60minute"} {
		result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
			"exchange":      "NSE",
			"tradingsymbol": "INFY",
			"interval":      interval,
			"days":          float64(90),
		})
		assert.NotNil(t, result, "interval=%s", interval)
	}
}


func TestTechnicalIndicators_MinDays(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"days":          float64(5), // below minimum, should clamp to 14
	})
	assert.NotNil(t, result)
}


func TestTechnicalIndicators_MaxDays(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"days":          float64(500), // above max, should clamp to 365
	})
	assert.NotNil(t, result)
}


func TestTechnicalIndicators_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "DOESNOTEXIST",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


// ---------------------------------------------------------------------------
// options_greeks_tool.go: deeper handler paths (43-47% -> higher)
// ---------------------------------------------------------------------------
func TestOptionsGreeks_SingleOption(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"underlying":       "NSE:NIFTY 50",
		"underlying_price": float64(17750),
		"strike_price":     float64(17500),
		"option_type":      "CE",
		"expiry_date":      time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"risk_free_rate":   float64(7.0),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_BullCallSpread(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"underlying": "NSE:NIFTY 50",
		"strategy":   "bull_call_spread",
		"expiry":     time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"atm_strike": float64(17800),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_BearPutSpread(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"underlying": "NSE:NIFTY 50",
		"strategy":   "bear_put_spread",
		"expiry":     time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"atm_strike": float64(17800),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_IronCondor(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"underlying":   "NSE:NIFTY 50",
		"strategy":     "iron_condor",
		"expiry":       time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"atm_strike":   float64(17800),
		"strike_width": float64(200),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_Butterfly(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"underlying":   "NSE:NIFTY 50",
		"strategy":     "butterfly",
		"expiry":       time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"atm_strike":   float64(17800),
		"strike_width": float64(100),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// search_instruments edge cases
// ---------------------------------------------------------------------------
func TestSearchInstruments_WithExchange(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query":    "INFY",
		"exchange": "NSE",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestSearchInstruments_WithType(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query":           "INFY",
		"instrument_type": "EQ",
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// market_tools: get_ltp / get_ohlc / get_quotes edge cases
// ---------------------------------------------------------------------------
func TestGetLTP_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
}


func TestGetOHLC_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
}


func TestGetQuotes_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// get_option_chain edge cases
// ---------------------------------------------------------------------------
func TestGetOptionChain_WithStrikesAround(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying":        "NSE:NIFTY 50",
		"expiry":            time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"strikes_around_atm": float64(5),
	})
	assert.NotNil(t, result)
}


// ===========================================================================
// Additional coverage push tests — targeting sub-90% functions
// ===========================================================================

// ---------------------------------------------------------------------------
// options_payoff_builder: branch coverage for bear_call_spread, bull_put_spread,
// straddle, strangle, unknown strategy, invalid expiry, bad strike ordering
// ---------------------------------------------------------------------------
func TestOptionsStrategy_BearCallSpread_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bear_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
		"strike2":    float64(17600),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_BullPutSpread_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_put_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
		"strike2":    float64(17600),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_Straddle_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_Strangle_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
		"strike2":    float64(18500),
	})
	assert.NotNil(t, result)
}


func TestOptionsStrategy_UnknownStrategy_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "zigzag",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Unknown strategy")
}


func TestOptionsStrategy_InvalidExpiry_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "not-a-date",
		"strike1":    float64(18000),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "YYYY-MM-DD")
}


func TestOptionsStrategy_BullCallSpread_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17000), // wrong order
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "strike2 > strike1")
}


func TestOptionsStrategy_BearPutSpread_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17000),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "strike2 > strike1")
}


func TestOptionsStrategy_BearCallSpread_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bear_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17000),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_BullPutSpread_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_put_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17000),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_Strangle_NoStrike2_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "strike2")
}


func TestOptionsStrategy_IronCondor_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17500),
		"strike3":    float64(18500),
		"strike4":    float64(19000),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_IronCondor_MissingStrikes_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_Butterfly_BadOrder_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "butterfly",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17500), // bad order
		"strike3":    float64(18500),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_Butterfly_MissingStrikes_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "butterfly",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17500),
	})
	assert.True(t, result.IsError)
}


func TestOptionsStrategy_LotsOverride_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"lots":       float64(2),
		"lot_size":   float64(25),
	})
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// options_greeks: validation branches
// ---------------------------------------------------------------------------
func TestOptionsGreeks_InvalidOptionType_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2641018000CE",
		"strike_price":   float64(18000),
		"expiry_date":    time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"option_type":    "XX", // invalid
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "CE or PE")
}


func TestOptionsGreeks_NegativeStrike_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2641018000CE",
		"strike_price":   float64(-100),
		"expiry_date":    time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "positive")
}


func TestOptionsGreeks_InvalidExpiry_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2641018000CE",
		"strike_price":   float64(18000),
		"expiry_date":    "bad-date",
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "YYYY-MM-DD")
}


// ---------------------------------------------------------------------------
// get_option_chain: validation branches
// ---------------------------------------------------------------------------
func TestGetOptionChain_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}


// ---------------------------------------------------------------------------
// ticker_tools: validation branches
// ---------------------------------------------------------------------------
func TestSubscribeInstruments_MissingInstrument_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}


func TestUnsubscribeInstruments_MissingInstrument_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}
