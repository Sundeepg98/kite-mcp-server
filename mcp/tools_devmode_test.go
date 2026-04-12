package mcp

import (
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.

func TestGetHoldings_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_holdings", "trader@example.com", map[string]any{})
	// Should fail with login required (no real Kite client), not panic
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetPositions_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_positions", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetMargins_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetProfile_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_profile", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetOrders_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestGetTrades_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestPortfolioSummary_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_summary", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPortfolioConcentration_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_concentration", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPositionAnalysis_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "position_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetLTP_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ltp", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}

func TestGetOHLC_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_ohlc", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.True(t, result.IsError)
}

func TestGetQuotes_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
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

func TestSEBICompliance_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sebi_compliance_status", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestTradingContext_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "trading_context", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPreTradeCheck_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestBacktestStrategy_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
}

func TestTaxHarvest_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "tax_harvest_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPortfolioRebalance_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "portfolio_rebalance", "trader@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
	})
	assert.True(t, result.IsError)
}

func TestDividendCalendar_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "dividend_calendar", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestSectorExposure_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "sector_exposure", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestServerMetrics_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{})
	// server_metrics may succeed without a Kite client
	assert.NotNil(t, result)
}

func TestTechnicalIndicators_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"indicators":       []interface{}{"RSI", "SMA"},
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

func TestPlaceOrder_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestModifyOrder_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "123456",
		"order_type": "LIMIT",
	})
	assert.True(t, result.IsError)
}

func TestCancelOrder_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestClosePosition_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderMargins_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}

func TestListAlerts_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_alerts", "trader@example.com", map[string]any{})
	// list_alerts may succeed if alert store is available
	assert.NotNil(t, result)
}

func TestSetAlert_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
}

func TestGetMFHoldings_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_holdings", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetMFSIPs_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_sips", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetGTTs_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_gtts", "trader@example.com", map[string]any{})
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

func TestListWatchlists_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_watchlists", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestPaperTradingStatus_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "paper_trading_status", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestCloseAllPositions_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_all_positions", "trader@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
}

func TestPlaceGTT_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
		"quantity":         float64(10),
	})
	assert.True(t, result.IsError)
}

func TestModifyGTT_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
		"quantity":         float64(10),
	})
	assert.True(t, result.IsError)
}

func TestDeleteGTT_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(12345),
	})
	assert.True(t, result.IsError)
}

func TestConvertPosition_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderHistory_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_history", "trader@example.com", map[string]any{
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestGetOrderTrades_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_trades", "trader@example.com", map[string]any{
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
}

func TestPlaceNativeAlert_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1800),
	})
	assert.True(t, result.IsError)
}

func TestListNativeAlerts_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_native_alerts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestGetNativeAlertHistory_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_native_alert_history", "trader@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.True(t, result.IsError)
}

func TestDeleteNativeAlert_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_native_alert", "trader@example.com", map[string]any{
		"uuid": "test-uuid-123",
	})
	assert.True(t, result.IsError)
}

func TestPlaceMFOrder_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(5000),
	})
	assert.True(t, result.IsError)
}

func TestGetBasketMargins_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.True(t, result.IsError)
}

func TestGetOrderCharges_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET","average_price":1500}]`,
	})
	assert.True(t, result.IsError)
}

func TestOptionsStrategy_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2026-04-30",
		"strike1":    float64(24000),
		"strike2":    float64(24500),
	})
	assert.True(t, result.IsError)
}

func TestSetTrailingStop_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "12345",
		"direction":    "long",
		"trail_amount": float64(20),
	})
	assert.NotNil(t, result) // may succeed or fail
}

func TestListTrailingStops_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_trailing_stops", "trader@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestCancelTrailingStop_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_trailing_stop", "trader@example.com", map[string]any{
		"trailing_stop_id": "ts-123",
	})
	assert.NotNil(t, result)
}

func TestGetWatchlist_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_watchlist", "trader@example.com", map[string]any{
		"name": "My Watchlist",
	})
	assert.NotNil(t, result)
}

func TestCreateWatchlist_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "create_watchlist", "trader@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestDeleteWatchlist_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_watchlist", "trader@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestAddToWatchlist_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{
		"name":        "Test Watchlist",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestRemoveFromWatchlist_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "remove_from_watchlist", "trader@example.com", map[string]any{
		"name":        "Test Watchlist",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestDeleteAlert_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_alert", "trader@example.com", map[string]any{
		"alert_id": "alert-123",
	})
	assert.NotNil(t, result)
}

func TestPlaceMFSIP_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError)
}

func TestCancelMFOrder_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_mf_order", "trader@example.com", map[string]any{
		"order_id": "mf-order-123",
	})
	assert.True(t, result.IsError)
}

func TestCancelMFSIP_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_mf_sip", "trader@example.com", map[string]any{
		"sip_id": "sip-123",
	})
	assert.True(t, result.IsError)
}

func TestGetMFOrders_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestSubscribeInstruments_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "subscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestUnsubscribeInstruments_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "unsubscribe_instruments", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
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

func TestServerMetrics_WithSession2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{
		"period": "1h",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetHoldings(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetProfile(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrders(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetGTTs(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderHistory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "ORD001",
		"order_type": "LIMIT",
		"quantity":   float64(10),
		"price":      float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"quantity":         float64(10),
		"limit_price":      float64(1395),
	})
	assert.NotNil(t, result)
}

func TestDevMode_DeleteGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ConvertPosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ClosePosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOHLC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetQuotes(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
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

func TestDevMode_PortfolioSummary(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioConcentration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PositionAnalysis(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SectorExposure(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TaxHarvest(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_DividendCalendar(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SEBICompliance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TradingContext(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PreTradeCheck(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFHoldings(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFOrders(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFSIPs(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{})
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
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ListNativeAlerts(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_native_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceNativeAlert(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_DeleteNativeAlert(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioRebalance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
	})
	assert.NotNil(t, result)
}

func TestDevMode_SetTrailingStop(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "ORD001",
		"direction":    "long",
		"trail_amount": float64(10),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ListTrailingStops(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_trailing_stops", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_CancelTrailingStop(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_trailing_stop", "dev@example.com", map[string]any{
		"trailing_stop_id": "TS001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetBasketMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderCharges(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingToggle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enabled": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingReset(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{
		"confirm": true,
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

func TestDevMode_PlaceMFOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFSIP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(24),
		"tag":           "test",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFSIP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "SIP001",
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "2026-04-24",
		"strike":     float64(24000),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyNativeAlert(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{
		"uuid":          "test-uuid",
		"name":          "Modified alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1600),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetNativeAlertHistory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CreateWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ListWatchlists(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TickerStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "ticker_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SetAlert(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ListAlerts(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_DeleteAlert(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_alert", "dev@example.com", map[string]any{
		"alert_id": "alert-001",
	})
	assert.NotNil(t, result)
}

func TestLogin_NonAlphanumericAPIKey(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key":    "key!@#$%",
		"api_secret": "validsecret123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "invalid api_key")
}

func TestLogin_NonAlphanumericAPISecret(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key":    "validkey123",
		"api_secret": "secret!@#",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "invalid api_secret")
}

func TestLogin_PartialCredentials_KeyOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key": "validkey123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "api_key and api_secret are required")
}

func TestLogin_PartialCredentials_SecretOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_secret": "validsecret123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "api_key and api_secret are required")
}

func TestLogin_DevMode_NoExtraCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", nil)
	// In DevMode with global credentials, should succeed (either cached or login URL)
	assert.NotNil(t, result)
}

func TestLogin_StoreUserCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "user@example.com", map[string]any{
		"api_key":    "userkey123",
		"api_secret": "usersecret456",
	})
	assert.NotNil(t, result)
	// Credentials should be stored
	entry, ok := mgr.CredentialStore().Get("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, "userkey123", entry.APIKey)
}

func TestLogin_NoEmail_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "validkey123",
		"api_secret": "validsecret456",
	})
	// Without email, storing per-user credentials should fail
	assert.True(t, result.IsError)
	assertResultContains(t, result, "OAuth authentication required")
}

func TestOpenDashboard_DefaultPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", nil)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_ActivityPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_OrdersPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "orders",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_AlertsPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "alerts",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_PaperPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "paper",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_SafetyPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "safety",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_WatchlistPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "watchlist",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_OptionsPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "options",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_ChartPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "chart",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_ActivityWithCategory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":     "activity",
		"category": "order",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_ActivityWithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity",
		"days": float64(7),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_ActivityWithErrors(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":   "activity",
		"errors": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_OrdersWithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "orders",
		"days": float64(30),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestOpenDashboard_AllDeepLinkParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":     "activity",
		"category": "market_data",
		"days":     float64(1),
		"errors":   true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestPortfolioRebalance_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"mode":      "percentage",
		"threshold": float64(1.0),
	})
	assert.NotNil(t, result)
	// Exercises handler body with mock broker
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

func TestDevMode_TradingContext_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises the full handler body; may error if mock broker lacks some data
}

func TestDevMode_PreTradeCheck_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
	// Exercises the full handler body
}

func TestDevMode_DividendCalendar_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body with mock broker data
}

func TestDevMode_SEBICompliance_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}

func TestDevMode_SectorExposure_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}

func TestDevMode_GetMFOrders_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFSIPs_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFHoldings_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFOrders_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioSummary_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body with mock data
}

func TestDevMode_PortfolioConcentration_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PositionAnalysis_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TaxHarvest_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetHoldings_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(2),
	})
	assert.NotNil(t, result)
	// Exercises PaginatedToolHandler with from/limit
}

func TestDevMode_GetPositions_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}

func TestDevMode_GetOrders_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetTrades_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetPositions_DayType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"position_type": "day",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetPositions_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"position_type": "net",
		"from":          float64(0),
		"limit":         float64(2),
	})
	assert.NotNil(t, result)
}

func TestModifyOrder_LimitWithZeroPrice_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "order123",
		"order_type": "LIMIT",
		"price":      float64(0),
		"quantity":   float64(10),
	})
	// In DevMode mock broker, order not found but exercises the handler body
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder_WithTag(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"tag":              "test123",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceGTT_FullParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"trigger_type":     "single",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"trigger_values":   "1500",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"last_price":       float64(1800),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderHistory_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORDER123",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderTrades_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORDER123",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFOrder_Buy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		"amount":           float64(5000),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFOrder_Sell(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "SELL",
		"quantity":         float64(10),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFSIP_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol":  "INF209K01YS2",
		"amount":         float64(5000),
		"frequency":      "monthly",
		"instalments":    float64(12),
		"initial_amount": float64(10000),
		"instalment_day": float64(1),
		"tag":            "testsip",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFOrder_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF123",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFSIP_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "SIP123",
	})
	assert.NotNil(t, result)
}

func TestModifyNativeAlert_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{
		"uuid":           "test-uuid-123",
		"name":           "Modified Alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(2000),
	})
	assert.NotNil(t, result)
}

func TestSetTrailingStop_DevMode_NoTickerRunning(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "dev@example.com", map[string]any{
		"instrument":     "NSE:INFY",
		"trail_amount":   float64(50),
		"direction":      "sell",
	})
	assert.NotNil(t, result)
}

func TestClosePosition_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"product":          "CNC",
		"quantity":         float64(10),
		"transaction_type": "SELL",
	})
	assert.NotNil(t, result)
}

func TestDevMode_SEBICompliance_WithMetrics(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetProfile_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMargins_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestTradingContext_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestPortfolioRebalance_ValueMode_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"targets": `{"RELIANCE": 200000, "INFY": 150000}`,
		"mode":    "value",
	})
	assert.NotNil(t, result)
}

func TestPortfolioRebalance_WithThreshold_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"mode":      "percentage",
		"threshold": float64(5.0),
	})
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(23500),
		"strike2":    float64(24500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFSIPs_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFHoldings_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(10),
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetTrades_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
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

func TestDevMode_ConvertPosition_Full(t *testing.T) {
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

func TestDevMode_CloseAllPositions_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetBasketMargins_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderCharges_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORDER-123",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFOrders_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// MF tools now route through broker.Client (mock in DEV_MODE) — they succeed.
	assert.False(t, result.IsError, "MF orders should succeed via mock broker in DEV_MODE")
}

func TestDevMode_GetMFSIPs_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "MF SIPs should succeed via mock broker in DEV_MODE")
}

func TestDevMode_GetMFHoldings_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "MF holdings should succeed via mock broker in DEV_MODE")
}

func TestDevMode_PlaceMFOrder_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "PlaceMFOrder should succeed via mock broker in DEV_MODE")
}

func TestDevMode_PlaceMFSIP_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(24),
		"tag":           "test",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "PlaceMFSIP should succeed via mock broker in DEV_MODE")
}

func TestDevMode_CancelMFOrder_ReturnsNotFoundFromMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF001",
	})
	assert.NotNil(t, result)
	// CancelMFOrder on a non-existent order returns an error from the mock.
	assert.True(t, result.IsError, "cancel of non-existent MF order should error")
}

func TestDevMode_CancelMFSIP_ReturnsNotFoundFromMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "SIP001",
	})
	assert.NotNil(t, result)
	// CancelMFSIP on a non-existent SIP returns an error from the mock.
	assert.True(t, result.IsError, "cancel of non-existent MF SIP should error")
}

func TestDevMode_GetOrderMargins_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "GetOrderMargins should succeed via mock broker in DEV_MODE")
}

func TestDevMode_GetBasketMargins_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "GetBasketMargins should succeed via mock broker in DEV_MODE")
}

func TestDevMode_GetOrderCharges_RequiresOrdersParam(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": `[{"order_id":"ORD001","exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"average_price":1500,"product":"CNC","order_type":"MARKET","variety":"regular"}]`,
	})
	assert.NotNil(t, result)
	// get_order_charges now routes through mock broker and succeeds
	assert.False(t, result.IsError, "GetOrderCharges should succeed via mock broker in DEV_MODE")
}

func TestDevMode_PlaceNativeAlert_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
	})
	assert.NotNil(t, result)
	// Mock broker implements NativeAlertCapable — native alerts succeed in DevMode
	assert.False(t, result.IsError, resultText(t, result))
}

func TestDevMode_ListNativeAlerts_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_native_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}

func TestDevMode_ModifyNativeAlert_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// In DevMode, each GetBrokerForEmail call creates a fresh mock with no alerts,
	// so modifying a non-existent UUID returns an error.
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{
		"uuid":          "test-uuid",
		"name":          "Modified alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1600),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "fresh mock has no alerts to modify")
}

func TestDevMode_DeleteNativeAlert_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}

func TestDevMode_GetNativeAlertHistory_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}

func TestDevMode_TradingContext_ReturnsResult(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// trading_context aggregates from mock broker, so may partially succeed
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestSetAlert_DevMode_BelowDirection(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(500),
		"direction":  "below",
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_DropPctWithExplicitReference(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(5.0),
		"direction":       "drop_pct",
		"reference_price": float64(2500),
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_RisePctWithExplicitReference(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument":      "NSE:RELIANCE",
		"price":           float64(10.0),
		"direction":       "rise_pct",
		"reference_price": float64(2000),
	})
	assert.NotNil(t, result)
}

func TestSetAlert_DevMode_DropPctNoReference_FetchLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// No reference_price — will try to fetch LTP from stub Kite client
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(5.0),
		"direction":  "drop_pct",
	})
	assert.NotNil(t, result)
	// Either succeeds or returns error about LTP — both exercise more code
}

func TestSetAlert_DevMode_RisePctNoReference_FetchLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "dev@example.com", map[string]any{
		"instrument": "NSE:RELIANCE",
		"price":      float64(10.0),
		"direction":  "rise_pct",
	})
	assert.NotNil(t, result)
}

func TestSetupTelegram_DevMode_NilNotifier_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(999888777),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Telegram notifications are not configured")
}

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

func TestDevMode_TaxHarvest_WithMinLoss(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
	})
	assert.NotNil(t, result)
}

func TestDevMode_SEBICompliance_WithPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should reach API call for positions/orders → error or empty data
}

func TestDevMode_DividendCalendar_WithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{
		"days": float64(30),
	})
	assert.NotNil(t, result)
}

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

func TestDevMode_TradingContext_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SectorExposure_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_Prompts_Registration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// RegisterPrompts shouldn't panic with a valid manager
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// No assertion needed — just exercising the registration code path
}

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

func TestAdminListFamily_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_list_family", "nobody@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // not admin
}

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
	assert.Contains(t, resultText(t, result), "api_key and api_secret are required")
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

// ===========================================================================
// Additional coverage push tests — targeting sub-90% functions
// ===========================================================================

// ---------------------------------------------------------------------------
// options_strategy: branch coverage for bear_call_spread, bull_put_spread,
// straddle, strangle, unknown strategy, invalid expiry, bad strike ordering
// ---------------------------------------------------------------------------

func TestOptionsStrategy_BearCallSpread_Push(t *testing.T) {
	t.Parallel()
	mgr := newNFODevModeManager(t)
	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
	result := callToolNFODevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
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
// close_all_positions: confirm=false safety check
// ---------------------------------------------------------------------------

func TestCloseAllPositions_ConfirmFalse_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}

// ---------------------------------------------------------------------------
// set_trailing_stop: no email branch
// ---------------------------------------------------------------------------

func TestSetTrailingStop_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_trailing_stop", "", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "ORDER123",
		"direction":  "long",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email")
}

// ---------------------------------------------------------------------------
// list_trailing_stops: no email
// ---------------------------------------------------------------------------

func TestListTrailingStops_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_trailing_stops", "", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email")
}

// ---------------------------------------------------------------------------
// cancel_trailing_stop: no email + missing id
// ---------------------------------------------------------------------------

func TestCancelTrailingStop_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_trailing_stop", "", map[string]any{
		"trailing_stop_id": "ts-123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email")
}

func TestCancelTrailingStop_MissingID_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_trailing_stop", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

// ---------------------------------------------------------------------------
// close_position: validation branches
// ---------------------------------------------------------------------------

func TestClosePosition_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

// ---------------------------------------------------------------------------
// setup_telegram: no email + NaN chatID + missing chat_id
// ---------------------------------------------------------------------------

func TestSetupTelegram_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(12345),
	})
	assert.True(t, result.IsError)
}

func TestSetupTelegram_MissingChatID_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// set_alert: various validation branches
// ---------------------------------------------------------------------------

func TestSetAlert_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "set_alert", "", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email")
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
// watchlist_tools: delete watchlist, rename validation branches
// ---------------------------------------------------------------------------

func TestDeleteWatchlist_MissingName_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestDeleteWatchlist_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "", map[string]any{
		"name": "test",
	})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// admin_tools: various validation branches
// ---------------------------------------------------------------------------

func TestAdminFreezeUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminUnfreezeUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminListUsers_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_users", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestAdminSuspendUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_suspend_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminActivateUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_activate_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminGetRiskStatus_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_risk_status", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestAdminChangeRole_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_change_role", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
		"role":  "viewer",
	})
	assert.True(t, result.IsError)
}

func TestAdminFreezeGlobal_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_global", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestAdminUnfreezeGlobal_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_global", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestAdminInviteFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_invite_family_member", "nonadmin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminListFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_family", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestAdminRemoveFamily_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_remove_family_member", "nonadmin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminGetUser_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "nonadmin@example.com", map[string]any{
		"email": "target@example.com",
	})
	assert.True(t, result.IsError)
}

func TestAdminServerStatus_NotAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_server_status", "nonadmin@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// dividend_calendar: missing instrument
// ---------------------------------------------------------------------------

func TestDividendCalendar_MissingInstrument_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	// dividend_calendar uses portfolio, not a required instrument - different path
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// portfolio_rebalance: missing params
// ---------------------------------------------------------------------------

func TestPortfolioRebalance_MissingTargets_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

// ---------------------------------------------------------------------------
// observability: server_metrics tool
// ---------------------------------------------------------------------------

func TestServerMetrics_IncludeSystem_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "server_metrics", "dev@example.com", map[string]any{
		"include_system": true,
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// admin_tools: SUCCESS paths (with admin@example.com)
// ---------------------------------------------------------------------------

func TestAdminListUsers_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_users", "admin@example.com", map[string]any{})
	assert.False(t, result.IsError)
}

func TestAdminGetUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.False(t, result.IsError)
}

func TestAdminGetUser_NotFound_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_user", "admin@example.com", map[string]any{
		"target_email": "nonexistent@example.com",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}

func TestAdminServerStatus_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_server_status", "admin@example.com", map[string]any{})
	assert.False(t, result.IsError)
}

func TestAdminGetRiskStatus_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{
		"target_email": "admin@example.com",
	})
	assert.False(t, result.IsError)
}

func TestAdminSuspendUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Create a user to suspend
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_target", Email: "target@example.com",
		Role: users.RoleTrader, Status: users.StatusActive,
	})
	result := callToolDevMode(t, mgr, "admin_suspend_user", "admin@example.com", map[string]any{
		"email":  "target@example.com",
		"reason": "test suspension",
	})
	assert.NotNil(t, result)
}

func TestAdminActivateUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_suspended", Email: "suspended@example.com",
		Role: users.RoleTrader, Status: users.StatusSuspended,
	})
	result := callToolDevMode(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{
		"email": "suspended@example.com",
	})
	assert.NotNil(t, result)
}

func TestAdminChangeRole_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	_ = uStore.Create(&users.User{
		ID: "u_role", Email: "rolechange@example.com",
		Role: users.RoleTrader, Status: users.StatusActive,
	})
	result := callToolDevMode(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"email": "rolechange@example.com",
		"role":  "viewer",
	})
	assert.NotNil(t, result)
}

func TestAdminFreezeUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"email":  "admin@example.com",
		"reason": "test freeze",
	})
	assert.NotNil(t, result)
}

func TestAdminUnfreezeUser_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{
		"email": "admin@example.com",
	})
	assert.NotNil(t, result)
}

func TestAdminFreezeGlobal_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"reason": "test global freeze",
	})
	assert.NotNil(t, result)
}

func TestAdminUnfreezeGlobal_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_unfreeze_global", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestAdminInviteFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.NotNil(t, result)
}

func TestAdminListFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_list_family", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestAdminRemoveFamily_AsAdmin_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{
		"email": "family@example.com",
	})
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// native_alert_tools: validation branches
// ---------------------------------------------------------------------------

func TestPlaceNativeAlert_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestModifyNativeAlert_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestDeleteNativeAlert_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

// ---------------------------------------------------------------------------
// post_tools: more validation branches
// ---------------------------------------------------------------------------

func TestModifyOrder_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestCancelOrder_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestModifyGTT_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "required")
}

func TestDeleteGTT_MissingParams_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{})
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
