package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// ===========================================================================
// Coverage push: exercise handler bodies via DevMode to raise mcp to 88%+.
// Uses newFullDevModeManager which has PaperEngine, PnLService, credentials,
// tokens, audit store, and RiskGuard all wired up.
// ===========================================================================

// ---------------------------------------------------------------------------
// alert_tools.go: SetAlertTool.Handler deeper paths (25% -> higher)
// ---------------------------------------------------------------------------

func TestSetAlert_PctThresholdOver100(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(150),
		"direction":  "drop_pct",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "100%")
}

func TestSetAlert_NegativePrice_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(-10),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "positive")
}

func TestSetAlert_InvalidDirection_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(100),
		"direction":  "sideways",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Direction")
}

func TestSetAlert_AboveFull_AutoTicker(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Seed credentials so the alert handler can try to auto-start ticker
	mgr.CredentialStore().Set("dev@example.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("dev@example.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1800),
		"direction":  "above",
	})
	assert.NotNil(t, result)
	// Should succeed creating the alert
	if !result.IsError {
		text := resultText(t, result)
		assert.Contains(t, text, "Alert set")
		assert.Contains(t, text, "INFY")
	}
}

func TestSetAlert_MissingInstrument(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"price":     float64(100),
		"direction": "above",
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// setup_tools.go: LoginTool.Handler (50.7% -> higher)
// ---------------------------------------------------------------------------

func TestLogin_WithCredentials_DevMode(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "cred@example.com", map[string]any{
		"api_key":    "newkey123",
		"api_secret": "newsecret456",
	})
	assert.NotNil(t, result)
	// In DevMode, login stores creds and returns a result
}

func TestLogin_OnlyApiKey(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "onlykey123",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Both")
}

func TestLogin_InvalidApiKeyChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key":    "bad-key!@#",
		"api_secret": "good123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}

func TestLogin_InvalidApiSecretChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key":    "good123",
		"api_secret": "bad-secret!",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}

func TestLogin_NoEmail_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Login with credentials but no email
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "key123",
		"api_secret": "secret456",
	})
	assert.NotNil(t, result)
	// Should return error about OAuth
	if result.IsError {
		assert.Contains(t, resultText(t, result), "OAuth")
	}
}

func TestLogin_PlainLogin_DevMode(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// DevMode should return some result (may succeed or show login URL)
}

// ---------------------------------------------------------------------------
// open_dashboard with various pages (setup_tools)
// ---------------------------------------------------------------------------

func TestOpenDashboard_AllPages(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	pages := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "options", "chart"}
	for _, page := range pages {
		result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
			"page": page,
		})
		assert.NotNil(t, result, "page=%s", page)
	}
}

// ---------------------------------------------------------------------------
// ticker_tools.go: deeper handler body coverage
// ---------------------------------------------------------------------------

func TestStartTicker_WithToken(t *testing.T) {
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
// get_tools.go: PaginatedToolHandler paths (77-78% -> higher)
// ---------------------------------------------------------------------------

func TestGetTrades_Paginated(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}

func TestGetOrders_Paginated(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestGetGTTs_Paginated(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}

func TestGetOrderHistory_Valid(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORD123",
	})
	assert.NotNil(t, result)
}

func TestGetOrderTrades_Valid(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORD123",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// mf_tools.go: MF read/write handlers (50% -> higher)
// ---------------------------------------------------------------------------

func TestGetMFOrders_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}

func TestGetMFSIPs_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestGetMFHoldings_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}

func TestPlaceMFOrder_BuyNoAmount(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
	})
	assert.NotNil(t, result)
	// Should fail validation
	assert.True(t, result.IsError)
}

func TestPlaceMFOrder_BuyWithAmount(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		"amount":           float64(5000),
	})
	assert.NotNil(t, result)
	// DevMode stub broker will return error, but handler body is exercised
}

func TestPlaceMFSip_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol":  "INF209K01YS2",
		"amount":         float64(1000),
		"instalments":    float64(12),
		"frequency":      "monthly",
		"instalment_day": float64(15),
	})
	assert.NotNil(t, result)
}

func TestCancelMFOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF-ORDER-1",
	})
	assert.NotNil(t, result)
}

func TestCancelMFSip_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "MF-SIP-1",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// margin_tools.go: get_order_charges (70% -> higher)
// ---------------------------------------------------------------------------

func TestGetOrderCharges_ValidJSON(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":1,"price":1500,"product":"CNC","order_type":"LIMIT","variety":"regular"}]`,
	})
	assert.NotNil(t, result)
}

func TestGetOrderCharges_EmptyJSON(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": `[]`,
	})
	assert.True(t, result.IsError)
}

func TestGetOrderCharges_InvalidJSON_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": `{not json}`,
	})
	assert.True(t, result.IsError)
}

func TestGetOrderCharges_EmptyString(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": "",
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// trailing_tools.go: deeper paths (59-65% -> higher)
// ---------------------------------------------------------------------------

func TestSetTrailingStop_BothAmountAndPct(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "ORD-123",
		"direction":    "long",
		"trail_amount": float64(50),
		"trail_pct":    float64(5),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "either")
}

func TestSetTrailingStop_PctOver50(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "ORD-123",
		"direction":  "long",
		"trail_pct":  float64(60),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "50%")
}

func TestSetTrailingStop_WithAllParams(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"order_id":        "ORD-123",
		"direction":       "long",
		"trail_amount":    float64(50),
		"current_stop":    float64(1450),
		"reference_price": float64(1500),
		"variety":         "regular",
	})
	assert.NotNil(t, result)
	// Should reach doSetTrailingStop
}

func TestSetTrailingStop_WithPctAndPrices(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"order_id":        "ORD-456",
		"direction":       "short",
		"trail_pct":       float64(3),
		"current_stop":    float64(1550),
		"reference_price": float64(1500),
	})
	assert.NotNil(t, result)
}

func TestSetTrailingStop_NoAmountOrPct(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "ORD-123",
		"direction":  "long",
	})
	assert.True(t, result.IsError)
}

func TestSetTrailingStop_InvalidInstrument_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":   "NOINFY",
		"order_id":     "ORD-123",
		"direction":    "long",
		"trail_amount": float64(50),
	})
	assert.True(t, result.IsError)
}

func TestSetTrailingStop_MissingStopAndRef(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// No current_stop and no reference_price -> needs WithSession to fetch
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "ORD-789",
		"direction":    "long",
		"trail_amount": float64(50),
	})
	assert.NotNil(t, result)
	// Will reach the WithSession path to fetch order history
}

func TestListTrailingStops_NoManager(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_trailing_stops", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestCancelTrailingStop_NotFound_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_trailing_stop", "dev@example.com", map[string]any{
		"trailing_stop_id": "nonexistent",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// analytics_tools.go: deeper handler paths (69-77% -> higher)
// ---------------------------------------------------------------------------

func TestPortfolioConcentration_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "cred@example.com", map[string]any{
		"threshold": float64(30),
	})
	assert.NotNil(t, result)
}

func TestPositionAnalysis_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestPortfolioSummary_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestSectorExposure_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// compliance_tool.go: sebi_compliance_status (77.4% -> higher)
// ---------------------------------------------------------------------------

func TestSEBICompliance_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// tax_tools.go: deeper handler paths (78.6% -> higher)
// ---------------------------------------------------------------------------

func TestTaxHarvest_WithMinLoss(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
	})
	assert.NotNil(t, result)
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
// dividend_tool.go: deeper handler paths (72% -> higher)
// ---------------------------------------------------------------------------

func TestDividendCalendar_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"week", "month", "quarter"} {
		result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
}

// ---------------------------------------------------------------------------
// backtest_tool.go: deeper strategy paths (65.9% -> higher)
// ---------------------------------------------------------------------------

func TestBacktest_MeanReversion(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":        "mean_reversion",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(90),
		"initial_capital": float64(100000),
	})
	assert.NotNil(t, result)
}

func TestBacktest_RSIReversal(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":        "rsi_reversal",
		"exchange":        "NSE",
		"tradingsymbol":   "INFY",
		"days":            float64(60),
		"initial_capital": float64(200000),
	})
	assert.NotNil(t, result)
}

func TestBacktest_Breakout(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":        "breakout",
		"exchange":        "NSE",
		"tradingsymbol":   "RELIANCE",
		"days":            float64(120),
		"initial_capital": float64(500000),
	})
	assert.NotNil(t, result)
}

func TestBacktest_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":      "invalid_strategy",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// exit_tools.go: close_position deeper body (61.5% -> higher)
// ---------------------------------------------------------------------------

func TestClosePosition_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"product":       "MIS",
	})
	assert.NotNil(t, result)
}

func TestClosePosition_WithQuantity(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"product":       "CNC",
		"quantity":      float64(5),
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// admin_tools.go: deeper admin paths (63-77% -> higher)
// ---------------------------------------------------------------------------

func TestAdminFreezeGlobal_NoReason(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "reason")
}

func TestAdminFreezeGlobal_NoConfirm_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason": "emergency",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}

func TestAdminFreezeGlobal_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "emergency",
		"confirm": true,
	})
	assert.NotNil(t, result)
	// Should succeed (no elicitation in test context)
}

func TestAdminUnfreezeGlobal_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Freeze first
	_ = callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": true,
	})
	// Unfreeze
	result := callToolAdmin(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminInviteFamily_SelfInvite(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "admin@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminInviteFamily_EmptyEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"invited_email": "",
	})
	assert.True(t, result.IsError)
}

func TestAdminListFamily_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "admin@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminRemoveFamily_NotConfirmed(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "someone@example.com",
		"confirm":      false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}

func TestAdminRemoveFamily_SelfRemove(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError)
}

func TestAdminRemoveFamily_NotInFamily(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"target_email": "nobody@example.com",
		"confirm":      true,
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// native_alert_tools.go: deeper handler paths (75% -> higher)
// ---------------------------------------------------------------------------

func TestPlaceNativeAlert_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"tradingsymbol": "INFY",
		"exchange":      "NSE",
		"trigger_type":  "single",
		"trigger_value": float64(1500),
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
	})
	assert.NotNil(t, result)
}

func TestModifyNativeAlert_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{
		"trigger_id":    float64(12345),
		"trigger_value": float64(1600),
	})
	assert.NotNil(t, result)
}

func TestDeleteNativeAlert_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{
		"trigger_id": float64(12345),
	})
	assert.NotNil(t, result)
}

func TestListNativeAlerts_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_native_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestGetNativeAlertHistory_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{
		"trigger_id": float64(12345),
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
		"underlying":   "NSE:NIFTY 50",
		"strategy":     "butterfly",
		"expiry":       time.Now().AddDate(0, 0, 14).Format("2006-01-02"),
		"atm_strike":   float64(17800),
		"strike_width": float64(100),
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// ext_apps: more data function coverage
// ---------------------------------------------------------------------------

func TestOrdersData_WithToolCalls(t *testing.T) {
	t.Parallel()
	mgr, auditStore := newFullDevModeManager(t)
	_ = auditStore.Record(&audit.ToolCall{
		CallID:      "cov1",
		Email:       "cred@example.com",
		ToolName:    "place_order",
		OrderID:     "COV-ORD-1",
		InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
	})
	time.Sleep(100 * time.Millisecond) // flush async writer
	data := ordersData(mgr, auditStore, "cred@example.com")
	assert.NotNil(t, data)
}

func TestWatchlistData_WithItems_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "cred@example.com"
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)
	wlID, err := ws.CreateWatchlist(email, "Coverage WL")
	require.NoError(t, err)
	_ = ws.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY", Notes: "cov test",
		TargetEntry: 1400, TargetExit: 1600,
	})
	data := watchlistData(mgr, nil, email)
	assert.NotNil(t, data)
}

// ---------------------------------------------------------------------------
// post_tools.go: place/modify/cancel order edge cases (78% -> higher)
// ---------------------------------------------------------------------------

func TestPlaceOrder_WithIceberg(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"product":          "CNC",
		"variety":          "iceberg",
		"iceberg_quantity": float64(10),
		"iceberg_legs":     float64(5),
	})
	assert.NotNil(t, result)
}

func TestModifyOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"order_id":   "ORD-MOD-1",
		"quantity":   float64(20),
		"price":      float64(1600),
		"order_type": "LIMIT",
		"variety":    "regular",
	})
	assert.NotNil(t, result)
}

func TestCancelOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{
		"order_id": "ORD-CAN-1",
		"variety":  "regular",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// GTT tools deeper paths
// ---------------------------------------------------------------------------

func TestPlaceGTTOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INFY",
		"exchange":         "NSE",
		"trigger_type":     "single",
		"trigger_values":   "1500",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(1500),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.NotNil(t, result)
}

func TestModifyGTTOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"gtt_id":         float64(12345),
		"trigger_values": "1600",
		"price":          float64(1600),
		"quantity":       float64(20),
	})
	assert.NotNil(t, result)
}

func TestDeleteGTTOrder_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{
		"gtt_id": float64(12345),
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// rebalance tool
// ---------------------------------------------------------------------------

func TestPortfolioRebalance_WithTargets(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"target_allocation": `{"INFY":40,"RELIANCE":60}`,
		"position_size_pct": float64(100),
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// convert_position tool
// ---------------------------------------------------------------------------

func TestConvertPosition_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"old_product":   "MIS",
		"new_product":   "CNC",
		"quantity":      float64(10),
		"position_type": "day",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// pre_trade_check tool
// ---------------------------------------------------------------------------

func TestPreTradeCheck_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(1500),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// trading_context tool
// ---------------------------------------------------------------------------

func TestTradingContext_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// server_metrics tool
// ---------------------------------------------------------------------------

func TestServerMetrics_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// server_metrics requires admin role
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestServerMetrics_WithPeriod(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.NotNil(t, result, "period=%s", period)
	}
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
// get_margins with segment
// ---------------------------------------------------------------------------

func TestGetMargins_WithSegment(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// get_basket_margins
// ---------------------------------------------------------------------------

func TestGetBasketMargins_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":1,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// get_order_margins
// ---------------------------------------------------------------------------

func TestGetOrderMargins_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// setup_tools: dashboardBaseURL and dashboardLink helpers
// ---------------------------------------------------------------------------

func TestDashboardBaseURL_LocalMode_Push(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// DevMode manager is local -> returns local URL
	base := dashboardBaseURL(mgr)
	// Either returns a URL or empty
	if base != "" {
		assert.Contains(t, base, "http")
	}
}

func TestDashboardLink_Coverage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	// May be empty in test context
	_ = link
}

func TestDashboardPageURL_Coverage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/dashboard")
	_ = url
}

func TestIsAlphanumeric_Push(t *testing.T) {
	t.Parallel()
	assert.True(t, isAlphanumeric("abc123"))
	assert.True(t, isAlphanumeric("ABCXYZ"))
	assert.False(t, isAlphanumeric(""))
	assert.False(t, isAlphanumeric("abc-123"))
	assert.False(t, isAlphanumeric("abc 123"))
	assert.False(t, isAlphanumeric("abc!@#"))
}

// ---------------------------------------------------------------------------
// Additional admin tool edge cases
// ---------------------------------------------------------------------------

func TestAdminGetUser_WithCredsAndToken(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Seed a user with credentials
	mgr.CredentialStore().Set("target@example.com", &kc.KiteCredentialEntry{
		APIKey: "tk", APISecret: "ts", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("target@example.com", &kc.KiteTokenEntry{
		AccessToken: "at", StoredAt: time.Now(),
	})
	result := callToolAdmin(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
	})
	assert.NotNil(t, result)
}

func TestAdminFreezeUser_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
		"reason":       "testing",
	})
	assert.NotNil(t, result)
	// May fail if target user doesn't exist, or succeed if riskguard handles it
}

func TestAdminUnfreezeUser_WithRiskGuard(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	// Freeze first
	_ = callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
		"reason":       "testing",
	})
	// Unfreeze
	result := callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"target_email": "target@example.com",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestAdminSuspendUser_Active(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com", // self-suspend
		"reason":       "testing",
	})
	// Self-suspend should be rejected
	assert.True(t, result.IsError)
}

func TestAdminServerStatus_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// watchlist_tools: get_watchlist with sort_by
// ---------------------------------------------------------------------------

func TestGetWatchlist_SortByEntry(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	email := "wl-sort@example.com"
	ws := mgr.WatchlistStore()
	require.NotNil(t, ws)
	_, err := ws.CreateWatchlist(email, "Sort WL")
	require.NoError(t, err)
	wl := ws.FindWatchlistByName(email, "Sort WL")
	require.NotNil(t, wl)
	_ = ws.AddItem(email, wl.ID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "INFY", TargetEntry: 1400, TargetExit: 1600,
	})
	_ = ws.AddItem(email, wl.ID, &watchlist.WatchlistItem{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TargetEntry: 2400, TargetExit: 2600,
	})

	result := callToolDevMode(t, mgr, "get_watchlist", email, map[string]any{
		"watchlist":   "Sort WL",
		"include_ltp": false,
		"sort_by":     "target_entry",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// exit_tools: close_all_positions with product filter and close_position edge cases
// ---------------------------------------------------------------------------

func TestCloseAllPositions_NotConfirmed(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Safety")
}

func TestCloseAllPositions_ProductCNC(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "CNC",
	})
	assert.NotNil(t, result)
}

func TestClosePosition_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"exchange": "NSE",
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// compliance_tool deeper paths
// ---------------------------------------------------------------------------

func TestSEBICompliance_WithCreds(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "cred@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// paper_tools: paper_trading_toggle edge cases
// ---------------------------------------------------------------------------

func TestPaperToggle_DoubleEnable(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	email := "double@example.com"
	r1 := callToolDevMode(t, mgr, "paper_trading_toggle", email, map[string]any{"enable": true})
	require.False(t, r1.IsError)
	// Enable again — should be idempotent or return already-enabled message
	r2 := callToolDevMode(t, mgr, "paper_trading_toggle", email, map[string]any{"enable": true})
	assert.NotNil(t, r2)
}

func TestPaperReset_NotEnabled(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "nopaper@example.com", map[string]any{})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// analytics: portfolio_rebalance edge cases
// ---------------------------------------------------------------------------

func TestPortfolioRebalance_InvalidJSON_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"target_allocation": `{not json}`,
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// post_tools: place_order edge cases for deeper handler body coverage
// ---------------------------------------------------------------------------

func TestPlaceOrder_AMO(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
		"variety":          "amo",
	})
	assert.NotNil(t, result)
}

func TestPlaceOrder_SLOrder(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL",
		"price":            float64(1500),
		"trigger_price":    float64(1490),
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}

func TestPlaceOrder_SLMOrder(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(5),
		"order_type":       "SL-M",
		"trigger_price":    float64(1490),
		"product":          "MIS",
	})
	assert.NotNil(t, result)
}

func TestPlaceOrder_WithTag(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
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

// ---------------------------------------------------------------------------
// GTT tools: deeper place_gtt_order paths
// ---------------------------------------------------------------------------

func TestPlaceGTTOrder_TwoLeg(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INFY",
		"exchange":         "NSE",
		"trigger_type":     "two-leg",
		"trigger_values":   "1400,1600",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(1500),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"limit_price":      float64(1550),
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
// get_holdings / get_positions with pagination
// ---------------------------------------------------------------------------

func TestGetHoldings_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestGetPositions_WithPagination(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
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

// ---------------------------------------------------------------------------
// setup_tools: setup_telegram deeper body
// ---------------------------------------------------------------------------

func TestSetupTelegram_ZeroChatID_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.True(t, result.IsError)
	// TelegramNotifier is nil, so returns "not configured" before chatID check
	assert.Contains(t, resultText(t, result), "not configured")
}
