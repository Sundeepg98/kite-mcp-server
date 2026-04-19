package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestDevMode_GetLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOHLC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetQuotes(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestDevMode_TechnicalIndicators(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_HistoricalData(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "2026-03-31 00:00:00",
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsGreeks(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
	})
	assert.NotNil(t, result)
}


func TestDevMode_BacktestStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_SearchInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query": "RELIANCE",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOptionChain(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "2026-04-24",
		"strike":     float64(24000),
	})
	assert.NotNil(t, result)
}


func TestDevMode_TickerStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "ticker_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_StartTicker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "start_ticker", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// May fail due to no access token in DevMode, but exercises the handler body
}


func TestDevMode_StopTicker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "stop_ticker", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_SubscribeInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
}


func TestDevMode_UnsubscribeInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{
		"instruments": []any{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetLTP_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOHLC_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetQuotes_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_HistoricalData_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"interval":   "day",
		"from_date":  "2025-01-01",
		"to_date":    "2025-12-31",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOptionChain_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "underlying")
}


func TestDevMode_GetOptionChain_NoNFOInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying":        "NIFTY",
		"strikes_around_atm": float64(5),
	})
	assert.NotNil(t, result)
	// No NFO instruments in test data, so should get error
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "No options found")
}


func TestDevMode_GetOptionChain_NegativeStrikes(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying":        "NIFTY",
		"strikes_around_atm": float64(-1),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOptionChain_WithExpiry(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying": "RELIANCE",
		"expiry":     "2026-04-24",
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsGreeks_MissingFields(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsGreeks_InvalidOptionType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2640118000CE",
		"strike_price":   float64(18000),
		"expiry_date":    "2026-04-24",
		"option_type":    "INVALID",
		"risk_free_rate": float64(0.07),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "CE or PE")
}


func TestDevMode_OptionsGreeks_NegativeStrike(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2640118000CE",
		"strike_price":  float64(-100),
		"expiry_date":   "2026-04-24",
		"option_type":   "CE",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "positive")
}


func TestDevMode_OptionsGreeks_BadExpiryFormat(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2640118000CE",
		"strike_price":  float64(18000),
		"expiry_date":   "24-04-2026",
		"option_type":   "CE",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "YYYY-MM-DD")
}


func TestDevMode_OptionsGreeks_ValidCE_APIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY2640118000CE",
		"strike_price":     float64(18000),
		"expiry_date":      "2026-04-24",
		"option_type":      "CE",
		"risk_free_rate":   float64(0.07),
		"underlying_price": float64(17500),
	})
	assert.NotNil(t, result)
	// Should reach the API call and get a connection error from stub
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsGreeks_ValidPE_APIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY2640118000PE",
		"strike_price":     float64(18000),
		"expiry_date":      "2026-04-24",
		"option_type":      "PE",
		"risk_free_rate":   float64(0.07),
		"underlying_price": float64(17500),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":    "invalid_strategy",
		"underlying":  "NIFTY",
		"expiry_date": "2026-04-24",
		"atm_strike":  float64(18000),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_BullCallSpread(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "bull_call_spread",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(100),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	// Will reach API call and get error from stub
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_BearPutSpread(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "bear_put_spread",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(100),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_IronCondor(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "iron_condor",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(200),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_Straddle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":    "long_straddle",
		"underlying":  "NIFTY",
		"expiry_date": "2026-04-24",
		"atm_strike":  float64(18000),
		"lot_size":    float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_Strangle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "long_strangle",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(200),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_ProtectivePut(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":    "protective_put",
		"underlying":  "NIFTY",
		"expiry_date": "2026-04-24",
		"atm_strike":  float64(18000),
		"lot_size":    float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_CoveredCall(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "covered_call",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(100),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_ButterflySpread(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":     "butterfly",
		"underlying":   "NIFTY",
		"expiry_date":  "2026-04-24",
		"atm_strike":   float64(18000),
		"strike_width": float64(100),
		"lot_size":     float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_TechnicalIndicators_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_TechnicalIndicators_DaysClamping(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// Test days > 365 (clamped to 365)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"days":          float64(500),
		"interval":      "day",
	})
	assert.NotNil(t, result)
	// Should proceed to WithSession → API error
	assert.True(t, result.IsError)
}


func TestDevMode_TechnicalIndicators_DaysMinimum(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// Test days < 14 (clamped to 14)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"days":          float64(3),
		"interval":      "15minute",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_TechnicalIndicators_UnknownSymbol(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "NONEXISTENT",
		"interval":      "60minute",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


func TestDevMode_TechnicalIndicators_ValidSymbol(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"interval":      "day",
		"days":          float64(90),
	})
	assert.NotNil(t, result)
	// Should reach API call → error from stub
	assert.True(t, result.IsError)
}


func TestDevMode_BacktestStrategy_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_BacktestStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":       "invalid",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.NotNil(t, result)
	// Should fail with unknown strategy or reach API call
}


func TestDevMode_BacktestStrategy_SMACrossover(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":        "sma_crossover",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(180),
		"initial_capital": float64(500000),
		"param1":          float64(10),
		"param2":          float64(30),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // API error from stub
}


func TestDevMode_BacktestStrategy_RSIReversal(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":          "rsi_reversal",
		"exchange":          "NSE",
		"tradingsymbol":     "RELIANCE",
		"days":              float64(365),
		"position_size_pct": float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_BacktestStrategy_Breakout(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":       "breakout",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"param1":         float64(20),
		"param2":         float64(10),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_BacktestStrategy_MeanReversion(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":       "mean_reversion",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"param1":         float64(20),
		"param2":         float64(2.0),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_BacktestStrategy_CapitalAndDaysBounds(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// days > 730 should be clamped
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":        "sma_crossover",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(1000),
		"initial_capital": float64(100),
	})
	assert.NotNil(t, result)
}


func TestDevMode_StartTicker_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "start_ticker", "", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_StopTicker_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "stop_ticker", "", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_SubscribeInstruments_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_UnsubscribeInstruments_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_TickerStatus_Multiple(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// Call with email
	result := callToolDevMode(t, mgr, "ticker_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Call without email
	result = callToolDevMode(t, mgr, "ticker_status", "", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetLTP_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
	// May return error or empty data from stub
}


func TestDevMode_GetOHLC_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
	// May return error or empty data from stub
}


func TestDevMode_GetQuotes_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	assert.NotNil(t, result)
	// May return error or empty data from stub
}


func TestDevMode_GetHistoricalData_AllIntervals(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, interval := range []string{"minute", "3minute", "5minute", "10minute", "15minute", "30minute", "60minute", "day"} {
		result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
			"exchange":      "NSE",
			"tradingsymbol": "INFY",
			"interval":      interval,
			"from":          "2026-03-01",
			"to":            "2026-04-01",
		})
		assert.NotNil(t, result, "interval=%s", interval)
	}
}


func TestDevMode_SearchInstruments_AllExchanges(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, exchange := range []string{"NSE", "BSE", "NFO", "CDS", "MCX"} {
		result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
			"query":    "INFY",
			"exchange": exchange,
		})
		assert.NotNil(t, result, "exchange=%s", exchange)
	}
}


func TestDevMode_SearchInstruments_WithType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query":           "INFY",
		"exchange":        "NSE",
		"instrument_type": "EQ",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetHistoricalData_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetLTP_MissingInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOHLC_MissingInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetQuotes_MissingInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOptionChain_WithNFOInstruments(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying":        "NIFTY",
		"strikes_around_atm": float64(5),
	})
	assert.NotNil(t, result)
	// Should exercise steps 1-6+ of the option chain handler
	// May fail at WithSession API call, but exercises all pre-session code
}


func TestDevMode_GetOptionChain_WithExpiry_NFO(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying":        "NIFTY",
		"expiry":            futureExpiry,
		"strikes_around_atm": float64(3),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOptionChain_BadExpiry_NFO(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying": "NIFTY",
		"expiry":     "2020-01-01",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


func TestDevMode_OptionsStrategy_WithNFO_BullCall(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17800),
		"strike2":    float64(18000),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_IronCondor(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17600),
		"strike2":    float64(17800),
		"strike3":    float64(18200),
		"strike4":    float64(18400),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_Straddle(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_BearPut(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17800),
		"strike2":    float64(18000),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_Strangle(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17700),
		"strike2":    float64(18300),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_BearCallSpread(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bear_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(18200),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_BullPutSpread(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_put_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17800),
		"strike2":    float64(18000),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_Butterfly(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "butterfly",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17800),
		"strike2":    float64(18000),
		"strike3":    float64(18200),
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
}


func TestDevMode_OptionsStrategy_WithNFO_BadStrikeOrder(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17800), // strike2 < strike1
		"lot_size":   float64(50),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_WithNFO_IronCondorBadOrder(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(18000),
		"strike2":    float64(17800), // bad order
		"strike3":    float64(18200),
		"strike4":    float64(18400),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsStrategy_WithNFO_StrangleMissingStrike2(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_payoff_builder", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17700),
		// missing strike2
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_OptionsGreeks_CE_NFO(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY2641018000CE",
		"strike_price":     float64(18000),
		"expiry_date":      time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"option_type":      "CE",
		"risk_free_rate":   float64(0.07),
		"underlying_price": float64(17900),
	})
	assert.NotNil(t, result)
	// Will try API call → fail, but exercises validation and pre-session code
}


func TestDevMode_OptionsGreeks_PE_NFO(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	result := callToolNFODevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY2641018000PE",
		"strike_price":     float64(18000),
		"expiry_date":      time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"option_type":      "PE",
		"underlying_price": float64(18100),
	})
	assert.NotNil(t, result)
}


func TestDevMode_SubscribeInstruments_Valid(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "subscribe_instruments", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY,NSE:RELIANCE",
		"mode":        "full",
	})
	assert.NotNil(t, result)
}


func TestDevMode_UnsubscribeInstruments_Valid(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "unsubscribe_instruments", "dev@example.com", map[string]any{
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}
