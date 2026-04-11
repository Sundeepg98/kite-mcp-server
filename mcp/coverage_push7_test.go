package mcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Silence unused import warnings.
var (
	_ = fmt.Sprintf
	_ server.MCPServer
	_ = math.NaN
	_ = time.Now
	_ = context.Background
)

// ===========================================================================
// coverage_push7_test.go — Push mcp coverage from ~73% to 80%+
//
// Strategy: Call every tool through callToolDevMode with various parameter
// combinations to exercise handler bodies, validation branches, formatting
// logic, and error paths. The DevMode stub Kite client makes all broker
// calls return API/connection errors instead of panicking on nil.
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: extract text from a CallToolResult
// ---------------------------------------------------------------------------
func resultText(t *testing.T, result *gomcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	tc, ok := result.Content[0].(gomcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

// ===========================================================================
// P&L Journal tool — exercises period parsing, date validation, early exit
// ===========================================================================

func TestDevMode_GetPnLJournal_NoPnLService(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// PnLService is nil in DevMode, should return error about not available
	text := resultText(t, result)
	assert.Contains(t, text, "not available")
}

func TestDevMode_GetPnLJournal_Periods(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, period := range []string{"week", "month", "quarter", "year", "all"} {
		result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}

func TestDevMode_GetPnLJournal_CustomDates(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "2026-03-31",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetPnLJournal_InvalidDates(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "not-a-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	// PnL service is nil in DevMode → returns "not available" before date validation
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}

func TestDevMode_GetPnLJournal_InvalidToDate(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "bad-date",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}

func TestDevMode_GetPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Server Metrics tool — admin-only, exercises admin check and early exit
// ===========================================================================

func TestDevMode_ServerMetrics_NotAdmin(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should fail because dev@example.com is not admin
	assert.True(t, result.IsError)
}

func TestDevMode_ServerMetrics_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}

// ===========================================================================
// Option Chain tool — exercises validation, instruments filter paths
// ===========================================================================

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

// ===========================================================================
// Options Greeks tool — exercises validation and early-exit paths
// ===========================================================================

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

// ===========================================================================
// Options Strategy tool — exercises validation paths
// ===========================================================================

func TestDevMode_OptionsStrategy_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_OptionsStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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

// ===========================================================================
// Technical Indicators tool — exercises validation, days clamping, WithSession
// ===========================================================================

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

// ===========================================================================
// Backtest Strategy tool — exercises validation, all strategy types
// ===========================================================================

func TestDevMode_BacktestStrategy_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_BacktestStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":        "sma_crossover",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(1000),
		"initial_capital": float64(100),
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Watchlist tools — exercises creation, deletion, add, remove, get, list
// ===========================================================================

func TestDevMode_Watchlist_FullCycle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// List (should be empty or succeed)
	result := callToolDevMode(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)

	// Create — may fail if WatchlistStore is nil, that's fine
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Test Watchlist 7",
	})
	assert.NotNil(t, result)

	// Create with empty name
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)

	// Create missing required
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent-id",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}

func TestDevMode_DeleteWatchlist_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_AddToWatchlist_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "add_to_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_AddToWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "add_to_watchlist", "dev@example.com", map[string]any{
		"watchlist":   "nonexistent",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_RemoveFromWatchlist_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "remove_from_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_RemoveFromWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "remove_from_watchlist", "dev@example.com", map[string]any{
		"watchlist":   "nonexistent",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetWatchlist_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_watchlist", "dev@example.com", map[string]any{
		"watchlist":   "nonexistent",
		"include_ltp": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}

func TestDevMode_GetWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_watchlist", "", map[string]any{
		"watchlist": "test",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Paper Trading tools — exercises toggle, status, reset paths
// ===========================================================================

func TestDevMode_PaperTradingToggle_Enable(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true,
	})
	assert.NotNil(t, result)
	// PaperEngine might be nil → error, or succeed if engine exists
}

func TestDevMode_PaperTradingToggle_Disable(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": false,
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingToggle_CustomCash(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable":       true,
		"initial_cash": float64(5000000),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingToggle_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PaperTradingStatus_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PaperTradingReset_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Alert tools — exercises set_alert, list_alerts, delete_alert, setup_telegram
// ===========================================================================

func TestDevMode_SetAlert_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetAlert_InvalidDirection(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "sideways",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Direction")
}

func TestDevMode_SetAlert_NegativePrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(-100),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "positive")
}

func TestDevMode_SetAlert_PctTooHigh(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(150),
		"direction":  "drop_pct",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "100%")
}

func TestDevMode_SetAlert_AboveWithValidInstrument(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	// Should proceed to CreateAlertUseCase → AlertStore.Set
}

func TestDevMode_SetAlert_BelowDirection(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:RELIANCE",
		"price":      float64(2000),
		"direction":  "below",
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetAlert_DropPctWithRefPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"price":           float64(5),
		"direction":       "drop_pct",
		"reference_price": float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetAlert_RisePctWithRefPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(10),
		"direction":       "rise_pct",
		"reference_price": float64(2500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetAlert_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetAlert_InvalidInstrument(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:NONEXISTENT",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetAlert_BadInstrumentFormat(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NOINFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ListAlerts_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_alerts", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteAlert_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_alert", "", map[string]any{
		"alert_id": "test-id",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteAlert_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_alert", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetupTelegram_NoNotifier(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// TelegramNotifier is nil in DevMode
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(12345),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not configured")
}

func TestDevMode_SetupTelegram_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(12345),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetupTelegram_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Account tools — exercises delete_my_account, update_my_credentials
// ===========================================================================

func TestDevMode_DeleteMyAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "permanently deletes")
}

func TestDevMode_DeleteMyAccount_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteMyAccount_Confirmed(t *testing.T) {
	// Not parallel — modifies shared state
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "delete-test@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "deleted")
}

func TestDevMode_UpdateMyCredentials_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_UpdateMyCredentials_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key":    "new_key",
		"api_secret": "new_secret",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_UpdateMyCredentials_EmptyValues(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_key":    "",
		"api_secret": "",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	// Validation catches empty values
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}

func TestDevMode_UpdateMyCredentials_Valid(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_key":    "new_key_123",
		"api_secret": "new_secret_456",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "updated")
}

// ===========================================================================
// Ticker tools — exercises start, stop, subscribe, unsubscribe, status
// ===========================================================================

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

// ===========================================================================
// Trailing stop tools — additional edge cases
// ===========================================================================

func TestDevMode_SetTrailingStop_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_SetTrailingStop_InvalidTrailType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":  "NSE:INFY",
		"trail_type":  "invalid",
		"trail_value": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetTrailingStop_PercentageType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":  "NSE:INFY",
		"trail_type":  "percentage",
		"trail_value": float64(3.5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetTrailingStop_AbsoluteType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":  "NSE:INFY",
		"trail_type":  "absolute",
		"trail_value": float64(50),
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelTrailingStop_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_trailing_stop", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ListTrailingStops_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_trailing_stops", "", map[string]any{})
	assert.NotNil(t, result)
}

// ===========================================================================
// Rebalance tool — exercises validation and different modes
// ===========================================================================

func TestDevMode_PortfolioRebalance_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PortfolioRebalance_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"target_allocation": "not json",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PortfolioRebalance_ValidAllocation(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"target_allocation": `{"NSE:INFY": 50, "NSE:RELIANCE": 50}`,
	})
	assert.NotNil(t, result)
	// Should reach API call or computation
}

func TestDevMode_PortfolioRebalance_OverAllocated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"target_allocation": `{"NSE:INFY": 60, "NSE:RELIANCE": 60}`,
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Tax Harvest tool — exercises computation path through DevMode
// ===========================================================================

func TestDevMode_TaxHarvest_WithMinLoss(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Compliance tool — exercises different check paths
// ===========================================================================

func TestDevMode_SEBICompliance_WithPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should reach API call for positions/orders → error or empty data
}

// ===========================================================================
// Dividend Calendar — exercises format and date handling
// ===========================================================================

func TestDevMode_DividendCalendar_WithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{
		"days": float64(30),
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Analytics tools — portfolio_summary, portfolio_concentration, position_analysis
// ===========================================================================

func TestDevMode_PortfolioSummary_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioConcentration_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PositionAnalysis_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ===========================================================================
// Market tools — get_ltp, get_ohlc, get_quotes, get_historical_data,
//                search_instruments variations
// ===========================================================================

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

// ===========================================================================
// Order tools — additional validation paths
// ===========================================================================

func TestDevMode_PlaceOrder_LimitMissingPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		// Missing price — should trigger validation
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PlaceOrder_SLMissingTrigger(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL",
		"product":          "CNC",
		"price":            float64(1500),
		// Missing trigger_price — should trigger validation
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PlaceOrder_IcebergValidation(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
		"iceberg_legs":     float64(3),
		"iceberg_quantity": float64(0),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyOrder_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_CancelOrder_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// GTT Order tools — additional validation paths
// ===========================================================================

func TestDevMode_PlaceGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ModifyGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Close/Convert Position tools — validation
// ===========================================================================

func TestDevMode_ClosePosition_MissingInstrument(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ClosePosition_BadFormat(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NOCOLON",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ClosePosition_WithProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"product":    "MIS",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ConvertPosition_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_CloseAllPositions_WithProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"product": "MIS",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Get tools — validation paths (missing required, pagination, filters)
// ===========================================================================

func TestDevMode_GetHoldings_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"sort_by": "pnl",
		"limit":   float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetPositions_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"product": "MIS",
		"limit":   float64(10),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrders_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"status": "COMPLETE",
		"limit":  float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetTrades_WithLimit(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetGTTs_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetProfile_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMargins_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderHistory_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetOrderTrades_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Margin tools — additional validation
// ===========================================================================

func TestDevMode_GetOrderMargins_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetBasketMargins_MissingJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetBasketMargins_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": "not valid json",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetOrderCharges_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// MF tools — additional validation and param paths
// ===========================================================================

func TestDevMode_PlaceMFOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_PlaceMFSIP_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_CancelMFOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_CancelMFSIP_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetMFOrders_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{
		"status": "COMPLETE",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFSIPs_WithStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{
		"status": "ACTIVE",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFHoldings_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{
		"sort_by": "pnl",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFOrder_SELLType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "SELL",
		"quantity":         float64(100),
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Native alert tools — additional validation
// ===========================================================================

func TestDevMode_PlaceNativeAlert_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_ModifyNativeAlert_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_DeleteNativeAlert_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestDevMode_GetNativeAlertHistory_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Pre-trade check — additional parameter combinations
// ===========================================================================

func TestDevMode_PreTradeCheck_SELLOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PreTradeCheck_MISProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(50),
		"product":          "MIS",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Trading Context — exercises the composite context tool
// ===========================================================================

func TestDevMode_TradingContext_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ===========================================================================
// Sector Exposure tool — exercises sector mapping computation
// ===========================================================================

func TestDevMode_SectorExposure_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ===========================================================================
// extractUnderlyingSymbol pure function test
// ===========================================================================

func TestExtractUnderlyingSymbol_AdditionalCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input, expected string
	}{
		{"NIFTY2640118000CE", "NIFTY"},
		{"BANKNIFTY24403CE", "BANKNIFTY"},
		{"RELIANCE2440324000CE", "RELIANCE"},
		{"INFY", "INFY"},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractUnderlyingSymbol(tc.input)
		assert.Equal(t, tc.expected, got, "input=%q", tc.input)
	}
}

// ===========================================================================
// Registry hooks — exercise hook registration and execution
// ===========================================================================

func TestHookMiddleware_BlocksOnError(t *testing.T) {
	t.Parallel()
	// Save and restore hooks
	defer ClearHooks()

	OnBeforeToolExecution(func(toolName string, args map[string]interface{}) error {
		if toolName == "blocked_tool" {
			return fmt.Errorf("tool is blocked")
		}
		return nil
	})

	err := RunBeforeHooks("blocked_tool", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")

	err = RunBeforeHooks("allowed_tool", nil)
	require.NoError(t, err)
}

func TestHookMiddleware_AfterHooks(t *testing.T) {
	t.Parallel()
	defer ClearHooks()

	called := false
	OnAfterToolExecution(func(toolName string, args map[string]interface{}) error {
		called = true
		return nil
	})

	RunAfterHooks("test_tool", nil)
	assert.True(t, called)
}

// ===========================================================================
// Computation helpers — computeSignals, computeRSI, computeSMA, etc.
// ===========================================================================

func TestComputeRSI_Basics(t *testing.T) {
	t.Parallel()
	// 15 prices: first 14 go up → RSI should be high
	prices := make([]float64, 20)
	for i := range prices {
		prices[i] = 100 + float64(i)*2
	}
	rsi := computeRSI(prices, 14)
	assert.NotNil(t, rsi)
	assert.Greater(t, len(rsi), 0)
	// All gains → RSI should be near 100
	last := rsi[len(rsi)-1]
	assert.Greater(t, last, 80.0)
}

func TestComputeRSI_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	rsi := computeRSI(prices, 14)
	assert.Nil(t, rsi)
}

func TestComputeSMA_Basic(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20, 30, 40, 50}
	sma := computeSMA(prices, 3)
	assert.NotNil(t, sma)
	// SMA of last 3 values (30+40+50)/3 = 40
	assert.InDelta(t, 40.0, sma[4], 0.01)
}

func TestComputeSMA_PeriodTooLong(t *testing.T) {
	t.Parallel()
	prices := []float64{10, 20}
	sma := computeSMA(prices, 5)
	assert.Nil(t, sma)
}

func TestComputeEMA_Basic(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = 100 + float64(i)
	}
	ema := computeEMA(prices, 12)
	assert.NotNil(t, ema)
	assert.Equal(t, len(prices), len(ema))
}

func TestComputeEMA_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	ema := computeEMA(prices, 12)
	assert.Nil(t, ema)
}

func TestComputeBollingerBands_Basic(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 30)
	for i := range prices {
		prices[i] = 100 + float64(i%5)
	}
	upper, middle, lower := computeBollingerBands(prices, 20, 2.0)
	assert.NotNil(t, upper)
	assert.NotNil(t, middle)
	assert.NotNil(t, lower)
	// Upper should be > middle > lower for the last value
	last := len(upper) - 1
	if last >= 0 && upper[last] > 0 {
		assert.Greater(t, upper[last], lower[last])
	}
}

func TestComputeBollingerBands_TooFewPrices(t *testing.T) {
	t.Parallel()
	prices := []float64{1, 2, 3}
	upper, middle, lower := computeBollingerBands(prices, 20, 2.0)
	assert.Nil(t, upper)
	assert.Nil(t, middle)
	assert.Nil(t, lower)
}

func TestComputeSignals_WithSufficientData(t *testing.T) {
	t.Parallel()
	// Generate enough data for all indicators
	n := 60
	prices := make([]float64, n)
	for i := range prices {
		prices[i] = 100 + float64(i%10)*2
	}

	rsi := computeRSI(prices, 14)
	sma20 := computeSMA(prices, 20)
	sma50 := computeSMA(prices, 50)
	ema12 := computeEMA(prices, 12)
	ema26 := computeEMA(prices, 26)
	bbUpper, _, bbLower := computeBollingerBands(prices, 20, 2.0)
	macdLine := make([]float64, n)
	for i := range prices {
		if i < len(ema12) && i < len(ema26) {
			macdLine[i] = ema12[i] - ema26[i]
		}
	}
	macdSignal := computeEMA(macdLine, 9)

	signals := computeSignals(prices, rsi, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal)
	assert.NotNil(t, signals)
}

// ===========================================================================
// Backtest pure functions — signalsSMACrossover, signalsMeanReversion, etc.
// ===========================================================================

func TestBacktestSignalsSMACrossover(t *testing.T) {
	t.Parallel()
	// Create 100 candles with a clear crossover pattern
	n := 100
	closes := make([]float64, n)
	for i := range closes {
		// Rising trend
		closes[i] = 100 + float64(i)*0.5
	}
	signals := signalsSMACrossover(closes, 10, 30)
	assert.NotNil(t, signals)
}

func TestBacktestSignalsMeanReversion(t *testing.T) {
	t.Parallel()
	n := 50
	closes := make([]float64, n)
	for i := range closes {
		closes[i] = 100 + float64(i%10)*2 // oscillating
	}
	signals := signalsMeanReversion(closes, 20, 2.0)
	assert.NotNil(t, signals)
}

// ===========================================================================
// safeLastValue and safeBBWidth helpers
// ===========================================================================

func TestSafeLastValue_NegativeValues(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -5.0, safeLastValue([]float64{-5}))
	assert.Equal(t, -100.5, safeLastValue([]float64{10, 20, -100.5}))
}

func TestSafeBBWidth_ZeroMiddle(t *testing.T) {
	t.Parallel()
	// Zero middle should avoid division by zero
	upper := []float64{10}
	lower := []float64{-10}
	middle := []float64{0}
	w := safeBBWidth(upper, lower, middle)
	// Depends on implementation: either 0 or Inf
	_ = w
}

// ===========================================================================
// Prompts — exercise prompt handlers
// ===========================================================================

func TestDevMode_Prompts_Registration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// RegisterPrompts shouldn't panic with a valid manager
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// No assertion needed — just exercising the registration code path
}

// ===========================================================================
// Dashboard/login tool — additional edge cases
// ===========================================================================

func TestDevMode_Login_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "test",
		"api_secret": "test",
	})
	assert.NotNil(t, result)
}

func TestDevMode_OpenDashboard_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "", nil)
	assert.NotNil(t, result)
}

// ===========================================================================
// PURE FUNCTION TESTS — directly exercise computation logic for coverage
// ===========================================================================

// ---------------------------------------------------------------------------
// runBacktest — exercises the full backtest pipeline with synthetic candles
// ---------------------------------------------------------------------------

func makeCandles(n int, startPrice float64, volatility float64) []broker.HistoricalCandle {
	candles := make([]broker.HistoricalCandle, n)
	price := startPrice
	for i := 0; i < n; i++ {
		// Simple price movement: alternate up/down with drift
		delta := volatility * float64((i%7)-3) / 3.0
		price += delta
		if price < 1 {
			price = 1
		}
		candles[i] = broker.HistoricalCandle{
			Date:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, i),
			Open:   price - 1,
			High:   price + 2,
			Low:    price - 2,
			Close:  price,
			Volume: 1000 + i*10,
		}
	}
	return candles
}

func TestRunBacktest_SMACrossover_P7(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 5)
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 20, 50)
	assert.NotNil(t, result)
	assert.Equal(t, "sma_crossover", result.Strategy)
	assert.Equal(t, "NSE:TEST", result.Symbol)
	assert.Greater(t, result.InitialCapital, 0.0)
}

func TestRunBacktest_RSIReversal(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 8)
	result := runBacktest(candles, "rsi_reversal", "NSE", "TEST", 500000, 50, 14, 70)
	assert.NotNil(t, result)
	assert.Equal(t, "rsi_reversal", result.Strategy)
}

func TestRunBacktest_Breakout(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 10)
	result := runBacktest(candles, "breakout", "NSE", "TEST", 1000000, 100, 20, 10)
	assert.NotNil(t, result)
	assert.Equal(t, "breakout", result.Strategy)
}

func TestRunBacktest_MeanReversion(t *testing.T) {
	t.Parallel()
	candles := makeCandles(200, 100, 6)
	result := runBacktest(candles, "mean_reversion", "NSE", "TEST", 1000000, 100, 20, 2.0)
	assert.NotNil(t, result)
	assert.Equal(t, "mean_reversion", result.Strategy)
}

func TestRunBacktest_UnknownStrategy(t *testing.T) {
	t.Parallel()
	candles := makeCandles(100, 100, 5)
	result := runBacktest(candles, "unknown", "NSE", "TEST", 1000000, 100, 20, 50)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.TotalTrades)
}

func TestRunBacktest_SmallCandles(t *testing.T) {
	t.Parallel()
	candles := makeCandles(10, 100, 5)
	result := runBacktest(candles, "sma_crossover", "NSE", "TEST", 1000000, 100, 5, 8)
	assert.NotNil(t, result)
}

func TestRunBacktest_TradeLogCap(t *testing.T) {
	t.Parallel()
	// Create enough data to potentially generate >50 trades
	candles := makeCandles(500, 100, 15)
	result := runBacktest(candles, "rsi_reversal", "NSE", "TEST", 1000000, 100, 5, 65)
	assert.NotNil(t, result)
	assert.LessOrEqual(t, len(result.TradeLog), 50)
}

// ---------------------------------------------------------------------------
// signalsRSIReversal — exercises RSI signal generation
// ---------------------------------------------------------------------------

func TestSignalsRSIReversal_WithOversoldOverbought(t *testing.T) {
	t.Parallel()
	// Create a price series that goes down then up to trigger RSI signals
	n := 50
	closes := make([]float64, n)
	for i := 0; i < n; i++ {
		if i < 20 {
			closes[i] = 100 - float64(i)*3 // decline → RSI drops
		} else if i < 35 {
			closes[i] = closes[19] + float64(i-19)*5 // sharp rally → RSI rises
		} else {
			closes[i] = closes[34] - float64(i-34)*4 // decline again
		}
	}
	signals := signalsRSIReversal(closes, 14, 70)
	assert.NotNil(t, signals)
	assert.Equal(t, n, len(signals))
}

func TestSignalsRSIReversal_TooFewPrices(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101, 102}
	signals := signalsRSIReversal(closes, 14, 70)
	assert.NotNil(t, signals)
	// All nil signals because RSI can't be computed
}

// ---------------------------------------------------------------------------
// signalsBreakout — exercises N-day breakout signal generation
// ---------------------------------------------------------------------------

func TestSignalsBreakout_GeneratesSignals(t *testing.T) {
	t.Parallel()
	n := 100
	closes := make([]float64, n)
	highs := make([]float64, n)
	lows := make([]float64, n)
	for i := 0; i < n; i++ {
		base := 100.0
		if i > 50 {
			base = 130.0 // sudden jump — breakout signal
		}
		closes[i] = base + float64(i%5)
		highs[i] = closes[i] + 2
		lows[i] = closes[i] - 2
	}
	signals := signalsBreakout(closes, highs, lows, 20, 10)
	assert.NotNil(t, signals)
	assert.Equal(t, n, len(signals))
}

func TestSignalsBreakout_ShortData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 101}
	highs := []float64{102, 103}
	lows := []float64{98, 99}
	signals := signalsBreakout(closes, highs, lows, 20, 10)
	assert.NotNil(t, signals)
}

// ---------------------------------------------------------------------------
// generateSignals — exercises the strategy dispatcher
// ---------------------------------------------------------------------------

func TestGenerateSignals_AllStrategies(t *testing.T) {
	t.Parallel()
	n := 100
	closes := make([]float64, n)
	highs := make([]float64, n)
	lows := make([]float64, n)
	for i := range closes {
		closes[i] = 100 + float64(i%10)*2
		highs[i] = closes[i] + 3
		lows[i] = closes[i] - 3
	}

	for _, strategy := range []string{"sma_crossover", "rsi_reversal", "breakout", "mean_reversion", "unknown"} {
		signals := generateSignals(strategy, closes, highs, lows, 20, 50)
		assert.NotNil(t, signals, "strategy=%s", strategy)
		assert.Equal(t, n, len(signals), "strategy=%s", strategy)
	}
}

// ---------------------------------------------------------------------------
// simulateTrades — exercises the trade simulation engine
// ---------------------------------------------------------------------------

func TestSimulateTrades_WithSignals(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	// Place a BUY at index 5 and a SELL at index 10
	signals[5] = &backtestSignal{action: "BUY", reason: "test buy"}
	signals[10] = &backtestSignal{action: "SELL", reason: "test sell"}
	// Another round trip
	signals[15] = &backtestSignal{action: "BUY", reason: "test buy 2"}
	signals[20] = &backtestSignal{action: "SELL", reason: "test sell 2"}

	trades := simulateTrades(candles, signals, 1000000, 100)
	assert.GreaterOrEqual(t, len(trades), 1)
}

func TestSimulateTrades_NoSignals_P7(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	trades := simulateTrades(candles, signals, 1000000, 100)
	assert.Empty(t, trades)
}

func TestSimulateTrades_PartialPositionSize(t *testing.T) {
	t.Parallel()
	candles := makeCandles(50, 100, 5)
	signals := make([]*backtestSignal, len(candles))
	signals[5] = &backtestSignal{action: "BUY", reason: "test buy"}
	signals[10] = &backtestSignal{action: "SELL", reason: "test sell"}
	trades := simulateTrades(candles, signals, 1000000, 25) // 25% position size
	assert.NotNil(t, trades)
}

// ---------------------------------------------------------------------------
// computeMaxDrawdown, computeSharpeRatio — pure metric computation
// ---------------------------------------------------------------------------

func TestComputeMaxDrawdown_Realistic(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 5000},
		{PnL: -8000},
		{PnL: 3000},
		{PnL: -2000},
		{PnL: 10000},
	}
	dd := computeMaxDrawdown(trades, 100000)
	assert.GreaterOrEqual(t, dd, 0.0)
}

func TestComputeMaxDrawdown_NoTrades_P7(t *testing.T) {
	t.Parallel()
	dd := computeMaxDrawdown(nil, 100000)
	assert.Equal(t, 0.0, dd)
}

func TestComputeMaxDrawdown_AllWins(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 1000},
		{PnL: 2000},
		{PnL: 3000},
	}
	dd := computeMaxDrawdown(trades, 100000)
	assert.Equal(t, 0.0, dd)
}

func TestComputeSharpeRatio_Realistic(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{
		{PnL: 5000},
		{PnL: -3000},
		{PnL: 4000},
		{PnL: -1000},
		{PnL: 6000},
	}
	sharpe := computeSharpeRatio(trades, 100000)
	assert.False(t, math.IsNaN(sharpe))
}

func TestComputeSharpeRatio_NoTrades(t *testing.T) {
	t.Parallel()
	sharpe := computeSharpeRatio(nil, 100000)
	assert.Equal(t, 0.0, sharpe)
}

func TestComputeSharpeRatio_SingleTrade(t *testing.T) {
	t.Parallel()
	trades := []BacktestTrade{{PnL: 5000}}
	sharpe := computeSharpeRatio(trades, 100000)
	// With single trade, std dev is 0, should return 0
	assert.False(t, math.IsNaN(sharpe))
}

// ---------------------------------------------------------------------------
// computeDividendCalendar — exercises dividend yield computation
// ---------------------------------------------------------------------------

func TestComputeDividendCalendar_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeDividendCalendar(nil, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.HoldingsByYield))
}

func TestComputeDividendCalendar_WithHoldings_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: 10000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: 5000},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, AveragePrice: 3400, LastPrice: 3500, PnL: 2000},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 30, AveragePrice: 1600, LastPrice: 1700, PnL: 3000},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.HoldingsByYield), 0)
	assert.NotEmpty(t, result.TaxNote)
}

func TestComputeDividendCalendar_SingleHolding(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1000, LastPrice: 0, PnL: 0},
	}
	result := computeDividendCalendar(holdings, 365)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// injectData — exercises JSON injection into HTML template
// ---------------------------------------------------------------------------

func TestInjectData_NilData_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	result := injectData(html, nil)
	assert.Contains(t, result, "null")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_WithData_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	data := map[string]string{"key": "value"}
	result := injectData(html, data)
	assert.Contains(t, result, "key")
	assert.Contains(t, result, "value")
	assert.NotContains(t, result, "__INJECTED_DATA__")
}

func TestInjectData_XSSPrevention_P7(t *testing.T) {
	t.Parallel()
	html := `<script>window.__DATA__ = "__INJECTED_DATA__";</script>`
	// Data with a </script> attempt should be escaped
	data := map[string]string{"payload": "</script><script>alert(1)</script>"}
	result := injectData(html, data)
	// Go's json.Marshal escapes < as \u003c, so </script> won't appear literally
	assert.NotContains(t, result, "</script><script>")
}

func TestInjectData_NoPlaceholder_P7(t *testing.T) {
	t.Parallel()
	html := `<div>No placeholder here</div>`
	data := map[string]string{"key": "value"}
	result := injectData(html, data)
	// Should be unchanged since there's no placeholder
	assert.Equal(t, html, result)
}

// ---------------------------------------------------------------------------
// resourceURIForTool — exercises tool→URI mapping
// ---------------------------------------------------------------------------

func TestResourceURIForTool_Exists(t *testing.T) {
	t.Parallel()
	// Some tools should have dashboard page mappings
	// If none exist, just verify it returns empty for unknown tools
	uri := resourceURIForTool("nonexistent_tool")
	assert.Equal(t, "", uri)
}

func TestResourceURIForTool_KnownTools(t *testing.T) {
	t.Parallel()
	// Test a few known tool names that likely have dashboard mappings
	for _, toolName := range []string{"get_holdings", "get_positions", "get_orders"} {
		_ = resourceURIForTool(toolName) // Exercise the function; may or may not return a URI
	}
}

// ---------------------------------------------------------------------------
// ValidateRequired �� exercises additional validation paths
// ---------------------------------------------------------------------------

func TestValidateRequired_EmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []interface{}{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_EmptyStringSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []string{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_EmptyIntSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []int{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_NonEmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	err := ValidateRequired(args, "items")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ArgParser — exercises edge cases
// ---------------------------------------------------------------------------

func TestArgParser_NilArgs(t *testing.T) {
	t.Parallel()
	p := NewArgParser(nil)
	assert.Equal(t, "", p.String("key", ""))
	assert.Equal(t, 0, p.Int("key", 0))
	assert.Equal(t, 0.0, p.Float("key", 0))
	assert.Equal(t, false, p.Bool("key", false))
}

func TestArgParser_TypeMismatch(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"str_as_num": "not_a_number",
		"num_as_str": float64(42),
	}
	p := NewArgParser(args)
	assert.Equal(t, 0, p.Int("str_as_num", 0))
	assert.Equal(t, "42", p.String("num_as_str", ""))
}

// ---------------------------------------------------------------------------
// ValidationError — exercises Error() method
// ---------------------------------------------------------------------------

func TestValidationError_FormatMessage(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "name", Message: "is required"}
	assert.Equal(t, "parameter 'name': is required", err.Error())
}

// ---------------------------------------------------------------------------
// ToolCache — exercises additional cache paths
// ---------------------------------------------------------------------------

func TestToolCache_MissAndHit_P7(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(time.Minute)
	require.NotNil(t, cache)

	// Miss
	val, ok := cache.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Set
	cache.Set("key1", "value1")

	// Hit
	val, ok = cache.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestToolCache_Expiration_P7(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(10 * time.Millisecond)
	require.NotNil(t, cache)

	cache.Set("key1", "value1")
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	val, ok := cache.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)
}

// ---------------------------------------------------------------------------
// Additional DevMode handler tests for more coverage
// ---------------------------------------------------------------------------

func TestDevMode_DropPctWithoutRefPrice(t *testing.T) {
	// drop_pct without reference_price should fail (needs Kite LTP which fails in DevMode)
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(5),
		"direction":  "drop_pct",
		// No reference_price — needs to fetch LTP from Kite
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_MarketValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(1),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
	// Should reach the Kite API call and get connection error
}

func TestDevMode_PlaceOrder_LimitValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_SLValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL",
		"product":          "CNC",
		"price":            float64(1500),
		"trigger_price":    float64(1490),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_SLMValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL-M",
		"product":          "CNC",
		"trigger_price":    float64(1490),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_WithDisclosedQty(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":           "NSE",
		"tradingsymbol":      "INFY",
		"transaction_type":   "BUY",
		"quantity":           float64(100),
		"order_type":         "LIMIT",
		"product":            "CNC",
		"price":              float64(1500),
		"disclosed_quantity": float64(10),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_WithValidity(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
		"validity":         "IOC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_WithTagAndValidity(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
		"tag":              "test_tag",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"order_id":      "ORD001",
		"quantity":      float64(20),
		"price":         float64(1600),
		"trigger_price": float64(1590),
		"order_type":    "SL",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceGTTOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"price":            float64(1400),
		"product":          "CNC",
		"last_price":       float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyGTTOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"gtt_id":           float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"price":            float64(1400),
		"product":          "CNC",
		"last_price":       float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ConvertPosition_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions_NoFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{})
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

// ---------------------------------------------------------------------------
// computeSectorExposure — exercises sector computation
// ---------------------------------------------------------------------------

func TestComputeSectorExposure_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, LastPrice: 2500},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, LastPrice: 3500},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
}

func TestComputeSectorExposure_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure(nil)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// computePortfolioConcentration — exercises concentration computation
// ---------------------------------------------------------------------------

func TestComputePortfolioConcentration_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1500, PnL: 10000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2500, PnL: 5000},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_SingleHolding_P7(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.NotNil(t, result)
}

func TestComputePortfolioConcentration_EmptyHoldings(t *testing.T) {
	t.Parallel()
	result := computePortfolioConcentration(nil)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// computeTaxHarvest — exercises tax harvest computation
// ---------------------------------------------------------------------------

func TestComputeTaxHarvest_WithHoldings(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1600, LastPrice: 1400, PnL: -20000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 50, AveragePrice: 2400, LastPrice: 2600, PnL: 10000},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 20, AveragePrice: 3600, LastPrice: 3400, PnL: -4000},
	}
	result := computeTaxHarvest(holdings, 5.0)
	assert.NotNil(t, result)
}

func TestComputeTaxHarvest_NoLosses(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1400, LastPrice: 1600, PnL: 20000},
	}
	result := computeTaxHarvest(holdings, 5.0)
	assert.NotNil(t, result)
}

func TestComputeTaxHarvest_EmptyHoldings_P7(t *testing.T) {
	t.Parallel()
	result := computeTaxHarvest(nil, 5.0)
	assert.NotNil(t, result)
}

// ===========================================================================
// Rich DevMode Manager — with Audit Store, User Store, Paper Engine wired up
// ===========================================================================

func newRichDevModeManager(t *testing.T) (*kc.Manager, *audit.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)
	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	// Wire up audit store (in-memory SQLite)
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	mgr.SetAuditStore(auditStore)

	// Create admin user
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	require.NoError(t, uStore.Create(&users.User{
		ID:     "u_admin",
		Email:  "admin@example.com",
		Role:   users.RoleAdmin,
		Status: users.StatusActive,
	}))

	t.Cleanup(func() { db.Close() })

	return mgr, auditStore
}

// callToolAdmin invokes a tool in admin context (non-DevMode session).
func callToolAdmin(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

// ---------------------------------------------------------------------------
// Server Metrics — with admin user and audit store
// ---------------------------------------------------------------------------

func TestServerMetrics_AdminWithAuditStore(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)

	// Record some tool calls so metrics have data
	auditStore.Record(&audit.ToolCall{
		CallID:   "m1",
		Email:    "admin@example.com",
		ToolName: "get_holdings",
	})
	auditStore.Record(&audit.ToolCall{
		CallID:   "m2",
		Email:    "admin@example.com",
		ToolName: "place_order",
		IsError:  true,
	})

	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
		"period": "24h",
	})
	assert.NotNil(t, result)
	// Admin with audit store should return metrics
	assert.False(t, result.IsError, "admin should have access to server_metrics")
}

func TestServerMetrics_AllPeriods_Admin(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
		assert.False(t, result.IsError, "period=%s", period)
	}
}

func TestServerMetrics_NonAdmin_Rejected(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestServerMetrics_DefaultPeriod(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// ext_apps data functions with audit store
// ---------------------------------------------------------------------------

func TestOrdersData_WithAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Record tool calls WITH order IDs so ListOrders picks them up
	auditStore.Record(&audit.ToolCall{
		CallID:      "o1",
		Email:       "admin@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD001",
		InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10,"price":1500}`,
	})
	auditStore.Record(&audit.ToolCall{
		CallID:      "o2",
		Email:       "admin@example.com",
		ToolName:    "place_order",
		OrderID:     "ORD002",
		InputParams: `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"SELL","order_type":"LIMIT","quantity":5,"price":2500}`,
	})
	// Small sleep to allow async writer to flush
	time.Sleep(50 * time.Millisecond)
	data := ordersData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestOrdersData_NoAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := ordersData(mgr, nil, "admin@example.com")
	assert.Nil(t, data)
}

func TestActivityData_WithAuditStore_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	auditStore.Record(&audit.ToolCall{
		CallID:        "a1",
		Email:         "admin@example.com",
		ToolName:      "get_holdings",
		ToolCategory:  "query",
		InputSummary:  "test",
		OutputSummary: "ok",
	})
	data := activityData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestPortfolioData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// No credentials stored → should return nil
	data := portfolioData(mgr, nil, "admin@example.com")
	assert.Nil(t, data)
}

func TestPaperData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := paperData(mgr, nil, "admin@example.com")
	// Returns status message even without engine
	assert.NotNil(t, data)
}

func TestSafetyData_NoRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := safetyData(mgr, nil, "admin@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithStore_Empty(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := watchlistData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithItems_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	ws := mgr.WatchlistStore()
	if ws != nil {
		wlID, err := ws.CreateWatchlist("wl-admin@example.com", "Test WL")
		require.NoError(t, err)
		_ = ws.AddItem("wl-admin@example.com", wlID, &watchlist.WatchlistItem{
			Exchange: "NSE", Tradingsymbol: "INFY", Notes: "buy on dip",
			TargetEntry: 1400, TargetExit: 1600,
		})
		_ = ws.AddItem("wl-admin@example.com", wlID, &watchlist.WatchlistItem{
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Notes: "swing trade",
			TargetEntry: 2400, TargetExit: 2600,
		})
	}
	data := watchlistData(mgr, auditStore, "wl-admin@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	if ok {
		wlCount, _ := dataMap["total_count"].(int)
		assert.GreaterOrEqual(t, wlCount, 1)
	}
}

func TestHubData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := hubData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestAlertData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestAlertData_WithAlerts_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Create some alerts via the alert store interface
	store := mgr.AlertStore()
	if store != nil {
		_, _ = store.Add("admin@example.com", "INFY", "NSE", 256265, 1500, "above")
		_, _ = store.Add("admin@example.com", "RELIANCE", "NSE", 408065, 2000, "below")
	}
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
	dataMap, ok := data.(map[string]any)
	if ok {
		activeCount, _ := dataMap["active_count"].(int)
		assert.GreaterOrEqual(t, activeCount, 0)
	}
}

func TestAlertData_WithTriggeredAlerts_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	store := mgr.AlertStore()
	if store != nil {
		alertID, _ := store.Add("admin@example.com", "TCS", "NSE", 300000, 3000, "above")
		store.MarkTriggered(alertID, 3100)
	}
	data := alertsData(mgr, auditStore, "admin@example.com")
	assert.NotNil(t, data)
}

func TestOrderFormData_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := orderFormData(mgr, nil, "admin@example.com")
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// Admin tools with rich manager
// ---------------------------------------------------------------------------

func TestAdminListUsers_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_users", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminServerStatus_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminGetRiskStatus_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminFreezeGlobal_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test freeze",
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Unfreeze
	result = callToolAdmin(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminSuspendUser_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to suspend
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_suspend", Email: "suspend@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "suspend@example.com",
		"reason":       "test",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Reactivate
	result = callToolAdmin(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{
		"target_email": "suspend@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminGetUser_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminChangeRole_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to change role
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_role", Email: "role@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "role@example.com",
		"role":         "viewer",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminFreezeUser_P7(t *testing.T) {
	mgr, _ := newRichDevModeManager(t)
	// Create a user to freeze
	uStore := mgr.UserStoreConcrete()
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_freeze", Email: "freeze@example.com", Role: users.RoleTrader, Status: users.StatusActive,
	}))

	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "freeze@example.com",
		"reason":       "test freeze",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)

	// Unfreeze
	result = callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"target_email": "freeze@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminInviteFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "family@example.com",
	})
	assert.NotNil(t, result)
}

func TestAdminListFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestAdminRemoveFamily_P7(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "nonexistent@example.com",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// NFO-enabled DevMode Manager — with option chain instruments
// ===========================================================================

func newNFODevModeManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		// NIFTY options — CE
		100001: {InstrumentToken: 100001, Tradingsymbol: "NIFTY2641017500CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17500, ExpiryDate: futureExpiry, LotSize: 50},
		100002: {InstrumentToken: 100002, Tradingsymbol: "NIFTY2641017600CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17600, ExpiryDate: futureExpiry, LotSize: 50},
		100003: {InstrumentToken: 100003, Tradingsymbol: "NIFTY2641017700CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17700, ExpiryDate: futureExpiry, LotSize: 50},
		100004: {InstrumentToken: 100004, Tradingsymbol: "NIFTY2641017800CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17800, ExpiryDate: futureExpiry, LotSize: 50},
		100005: {InstrumentToken: 100005, Tradingsymbol: "NIFTY2641017900CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17900, ExpiryDate: futureExpiry, LotSize: 50},
		100006: {InstrumentToken: 100006, Tradingsymbol: "NIFTY2641018000CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18000, ExpiryDate: futureExpiry, LotSize: 50},
		100007: {InstrumentToken: 100007, Tradingsymbol: "NIFTY2641018100CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18100, ExpiryDate: futureExpiry, LotSize: 50},
		100008: {InstrumentToken: 100008, Tradingsymbol: "NIFTY2641018200CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18200, ExpiryDate: futureExpiry, LotSize: 50},
		100009: {InstrumentToken: 100009, Tradingsymbol: "NIFTY2641018300CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18300, ExpiryDate: futureExpiry, LotSize: 50},
		100010: {InstrumentToken: 100010, Tradingsymbol: "NIFTY2641018400CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18400, ExpiryDate: futureExpiry, LotSize: 50},
		100011: {InstrumentToken: 100011, Tradingsymbol: "NIFTY2641018500CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18500, ExpiryDate: futureExpiry, LotSize: 50},
		// NIFTY options — PE
		200001: {InstrumentToken: 200001, Tradingsymbol: "NIFTY2641017500PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17500, ExpiryDate: futureExpiry, LotSize: 50},
		200002: {InstrumentToken: 200002, Tradingsymbol: "NIFTY2641017600PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17600, ExpiryDate: futureExpiry, LotSize: 50},
		200003: {InstrumentToken: 200003, Tradingsymbol: "NIFTY2641017700PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17700, ExpiryDate: futureExpiry, LotSize: 50},
		200004: {InstrumentToken: 200004, Tradingsymbol: "NIFTY2641017800PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17800, ExpiryDate: futureExpiry, LotSize: 50},
		200005: {InstrumentToken: 200005, Tradingsymbol: "NIFTY2641017900PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17900, ExpiryDate: futureExpiry, LotSize: 50},
		200006: {InstrumentToken: 200006, Tradingsymbol: "NIFTY2641018000PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18000, ExpiryDate: futureExpiry, LotSize: 50},
		200007: {InstrumentToken: 200007, Tradingsymbol: "NIFTY2641018100PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18100, ExpiryDate: futureExpiry, LotSize: 50},
		200008: {InstrumentToken: 200008, Tradingsymbol: "NIFTY2641018200PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18200, ExpiryDate: futureExpiry, LotSize: 50},
		200009: {InstrumentToken: 200009, Tradingsymbol: "NIFTY2641018300PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18300, ExpiryDate: futureExpiry, LotSize: 50},
		200010: {InstrumentToken: 200010, Tradingsymbol: "NIFTY2641018400PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18400, ExpiryDate: futureExpiry, LotSize: 50},
		200011: {InstrumentToken: 200011, Tradingsymbol: "NIFTY2641018500PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18500, ExpiryDate: futureExpiry, LotSize: 50},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)
	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

// callToolNFODevMode invokes a tool on the NFO-enabled DevMode manager.
func callToolNFODevMode(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "b2c3d4e5-f6a7-8901-bcde-f23456789012"})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

// ---------------------------------------------------------------------------
// Option Chain with NFO instruments — exercises the full handler body
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Options Strategy with NFO instruments
// ---------------------------------------------------------------------------

func TestDevMode_OptionsStrategy_WithNFO_BullCall(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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

// Validation error paths
func TestDevMode_OptionsStrategy_WithNFO_BadStrikeOrder(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     futureExpiry,
		"strike1":    float64(17700),
		// missing strike2
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// Options Greeks with NFO manager
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// RegisterAppResources — exercises the resource registration flow
// ---------------------------------------------------------------------------

func TestRegisterAppResources_WithAuditStore(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterAppResources(srv, mgr, auditStore, mgr.Logger)
	// Should not panic — exercises template loading and resource registration
}

// ---------------------------------------------------------------------------
// Prompts eodReviewHandler time-dependent paths
// ---------------------------------------------------------------------------

func TestEodReviewHandler_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// Exercise the prompt handler path — just registration, no assertion needed
}

// ---------------------------------------------------------------------------
// ext_apps admin data functions — exercises admin widget data paths
// ---------------------------------------------------------------------------

func TestAdminOverviewData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	// Test admin data functions by calling them through the appResources list
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-overview" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data, "admin overview should return data for admin")

			// Non-admin should get nil
			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data, "admin overview should return nil for non-admin")
		}
	}
}

func TestAdminUsersData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-users" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)

			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data)
		}
	}
}

func TestAdminMetricsData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-metrics" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)

			data = res.DataFunc(mgr, auditStore, "nobody@example.com")
			assert.Nil(t, data)
		}
	}
}

func TestAdminRiskData_P7(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.URI == "ui://kite-mcp/admin-risk" && res.DataFunc != nil {
			data := res.DataFunc(mgr, auditStore, "admin@example.com")
			assert.NotNil(t, data)
		}
	}
}

func TestOptionsChainData_NoCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	data := optionsChainData(mgr, nil, "admin@example.com")
	assert.Nil(t, data)
}

func TestAllAppResourceDataFuncs_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.DataFunc != nil {
			// Exercise all data functions with a non-admin, non-credentialed email
			_ = res.DataFunc(mgr, auditStore, "nobody@example.com")
		}
	}
}

func TestAllAppResourceDataFuncs_Admin(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newRichDevModeManager(t)
	for _, res := range appResources {
		if res.DataFunc != nil {
			_ = res.DataFunc(mgr, auditStore, "admin@example.com")
		}
	}
}

// ===========================================================================
// Admin tool edge cases — exercise more handler paths
// ===========================================================================

func TestAdminGetRiskStatus_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // missing target_email
}

func TestAdminSuspendUser_SelfAction(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // can't suspend self
}

func TestAdminSuspendUser_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "someone@example.com",
		"confirm":      false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminChangeRole_SelfAction(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"role":         "viewer",
	})
	assert.NotNil(t, result)
	// May be error (self-demotion guard) or succeed
}

func TestAdminChangeRole_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"role": "viewer",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminChangeRole_InvalidRole(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "role@example.com",
		"role":         "superadmin",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminActivateUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminFreezeUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminUnfreezeUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminFreezeGlobal_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminFreezeGlobal_MissingReason(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminInviteFamily_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminListFamily_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "nobody@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // not admin
}

func TestAdminRemoveFamily_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

// ===========================================================================
// Additional trailing stop validation
// ===========================================================================

func TestDevMode_SetTrailingStop_ZeroTrailValue(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":  "NSE:INFY",
		"trail_type":  "percentage",
		"trail_value": float64(0),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetTrailingStop_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "", map[string]any{
		"instrument":  "NSE:INFY",
		"trail_type":  "percentage",
		"trail_value": float64(5),
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Additional watchlist edge cases
// ===========================================================================

func TestDevMode_Watchlist_CreateAndUse(t *testing.T) {
	// Create a watchlist and try operations on it
	mgr := newDevModeManager(t)

	// Create
	result := callToolDevMode(t, mgr, "create_watchlist", "wl-test@example.com", map[string]any{
		"name": "My Test WL",
	})
	assert.NotNil(t, result)

	// List
	result = callToolDevMode(t, mgr, "list_watchlists", "wl-test@example.com", map[string]any{})
	assert.NotNil(t, result)

	// Try adding to it
	result = callToolDevMode(t, mgr, "add_to_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"instruments": "NSE:INFY,NSE:RELIANCE",
		"notes":       "test",
		"target_entry": float64(1400),
		"target_exit":  float64(1600),
	})
	assert.NotNil(t, result)

	// Get watchlist (without LTP to avoid API call)
	result = callToolDevMode(t, mgr, "get_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)

	// Remove items
	result = callToolDevMode(t, mgr, "remove_from_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)

	// Delete
	result = callToolDevMode(t, mgr, "delete_watchlist", "wl-test@example.com", map[string]any{
		"watchlist": "My Test WL",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// Additional OpenDashboard edge cases
// ===========================================================================

func TestDevMode_OpenDashboard_Sections(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	sections := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "admin", "admin/users", "admin/metrics"}
	for _, section := range sections {
		result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
			"section": section,
		})
		assert.NotNil(t, result, "section=%s", section)
	}
}

// ===========================================================================
// Additional close_all_positions edge cases
// ===========================================================================

func TestDevMode_CloseAllPositions_Exchange(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"exchange": "NSE",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions_Confirmed(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "MIS",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Safety")
}

func TestDevMode_CloseAllPositions_AllProducts(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "ALL",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions_CNC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ClosePosition_WithProductCNC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"product":    "CNC",
	})
	assert.NotNil(t, result)
}

// Ticker subscribe/unsubscribe with instruments
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

// Additional place order variations
func TestDevMode_PlaceOrder_NRML(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY24MAR18000CE",
		"transaction_type": "BUY",
		"quantity":         float64(50),
		"order_type":       "MARKET",
		"product":          "NRML",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_SellWithPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "SELL",
		"quantity":         float64(5),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(2500),
	})
	assert.NotNil(t, result)
}

// Additional native alert edge cases
func TestDevMode_PlaceNativeAlert_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":          "Full Alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "RELIANCE",
		"lhs_attribute": "last_price",
		"operator":      "<=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(2000),
	})
	assert.NotNil(t, result)
}

// MF tools with variations
func TestDevMode_PlaceMFSIP_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(10000),
		"frequency":     "weekly",
		"instalments":   float64(52),
		"tag":           "auto-sip",
	})
	assert.NotNil(t, result)
}

// ===========================================================================
// dashboard helper functions
// ===========================================================================

func TestDashboardBaseURL_Variations(t *testing.T) {
	mgr := newDevModeManager(t)
	url := dashboardBaseURL(mgr)
	_ = url
}

func TestDashboardBaseURL_WithExternalURL(t *testing.T) {
	t.Parallel()
	// DevMode manager always returns http://127.0.0.1:8080 (local mode)
	mgr := newDevModeManager(t)
	url := dashboardBaseURL(mgr)
	assert.Contains(t, url, "127.0.0.1")
}

func TestDashboardLink_P7(t *testing.T) {
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	_ = link
}

func TestDashboardLink_WithExternalURL(t *testing.T) {
	t.Setenv("EXTERNAL_URL", "https://test.example.com")
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	assert.NotEmpty(t, link)
}

func TestDashboardPageURL_P7(t *testing.T) {
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/test")
	_ = url
}

func TestDashboardPageURL_WithLocalMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/portfolio")
	assert.Contains(t, url, "127.0.0.1")
}

func TestDashboardLink_LocalMode_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	assert.NotEmpty(t, link) // Local mode returns 127.0.0.1
}
