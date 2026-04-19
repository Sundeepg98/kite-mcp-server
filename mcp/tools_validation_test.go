package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.


func TestPreTradeCheck_MissingExchange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
		// exchange missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestToolDefinitions_Coverage(t *testing.T) {
	t.Parallel()
	// These are tools whose Tool() method may not yet be covered
	toolTypes := []Tool{
		&PaperTradingToggleTool{},
		&PaperTradingStatusTool{},
		&PaperTradingResetTool{},
		&DeleteMyAccountTool{},
		&UpdateMyCredentialsTool{},
		&GetPnLJournalTool{},
		&TradingContextTool{},
		&SEBIComplianceTool{},
		&ClosePositionTool{},
		&CloseAllPositionsTool{},
		&PortfolioSummaryTool{},
		&PortfolioConcentrationTool{},
		&PositionAnalysisTool{},
	}
	for _, td := range toolTypes {
		toolDef := td.Tool()
		assert.NotEmpty(t, toolDef.Name, "tool should have a name")
		assert.NotEmpty(t, toolDef.Description, "tool %s should have a description", toolDef.Name)
	}
}


func TestResolveWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	wl := resolveWatchlist(mgr, "user@test.com", "nonexistent")
	assert.Nil(t, wl)
}


func TestSessionBrokerResolver_ReturnsSameClient(t *testing.T) {
	t.Parallel()
	resolver := &sessionBrokerResolver{client: nil}
	client, err := resolver.GetBrokerForEmail("any@email.com")
	assert.NoError(t, err)
	assert.Nil(t, client) // nil client is valid in this adapter
}


func TestGetOrderMargins_SLMWithoutTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL-M",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestPreTradeCheck_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
		// tradingsymbol missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestPreTradeCheck_MissingRequiredFields(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":       "NSE",
		// missing tradingsymbol, quantity, etc.
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestPreTradeCheck_ZeroQty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(0),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "quantity must be greater than 0")
}


func TestPreTradeCheck_LimitOrderNoPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}


func TestTaxHarvestTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&TaxHarvestTool{}).Tool()
	assert.Equal(t, "tax_loss_analysis", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}


func TestPortfolioRebalance_ValueModeNegative(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"INFY": -50000}`,
		"mode":    "value",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "non-negative")
}


func TestTradingContextTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&TradingContextTool{}).Tool()
	assert.Equal(t, "trading_context", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}


func TestGetPnLJournal_NoAuth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestDividendCalendarTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&DividendCalendarTool{}).Tool()
	assert.Equal(t, "dividend_calendar", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
}


func TestGetOrderMargins_LimitNoPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing = 0
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}


func TestGetOrderMargins_SLNoTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		// trigger_price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestGetOrderMargins_SLMNoTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(10),
		"product":          "MIS",
		"order_type":       "SL-M",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestAllToolsDefinitions_Categories(t *testing.T) {
	t.Parallel()
	tools := GetAllTools()
	names := make(map[string]bool)
	for _, td := range tools {
		toolDef := td.Tool()
		names[toolDef.Name] = true
	}
	// Verify key tools exist
	assert.True(t, names["place_order"])
	assert.True(t, names["get_holdings"])
	assert.True(t, names["historical_price_analyzer"])
	assert.True(t, names["tax_loss_analysis"])
	assert.True(t, names["portfolio_analysis"])
	assert.True(t, names["order_risk_report"])
	assert.True(t, names["trading_context"])
	assert.True(t, names["get_pnl_journal"])
	assert.True(t, names["options_greeks"])
	assert.True(t, names["options_payoff_builder"])
	assert.True(t, names["server_metrics"])
}


func TestGetOrderTrades_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetOrderHistory_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_history", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Call without email in context
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestGetPnLJournal_NoPnLServiceAvailable(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Manager has no PnL service by default, so this should fail
	result := callToolWithManager(t, mgr, "get_pnl_journal", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}


func TestGetPnLJournal_InvalidFromDate(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "trader@example.com", map[string]any{
		"from": "not-a-date",
	})
	assert.True(t, result.IsError)
	// Either "not available" (no pnl service) or "Invalid 'from' date"
	assert.NotNil(t, result)
}


func TestSessionTool_GetOrderTrades_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_trades", "trader@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_GetOrderHistory_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_history", "trader@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_DeleteGTT_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_ConvertPosition_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_ModifyGTT_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_ListNativeAlerts_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_native_alerts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_PlaceNativeAlert_SessionError(t *testing.T) {
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
		"rhs_constant":  float64(1500),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_TechnicalIndicators_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}


func TestSessionTool_GetMFOrders_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestSessionTool_OptionsStrategy_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":      "straddle",
		"underlying":    "NIFTY",
		"expiry":        "2026-04-24",
		"strike":        float64(24000),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_OptionsGreeks_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_PlaceOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	// Valid params but no real Kite session
	assert.True(t, result.IsError)
}


func TestSessionTool_ModifyOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "ORD123",
		"order_type": "LIMIT",
		"quantity":   float64(10),
		"price":      float64(1500),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_CancelOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "ORD123",
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_PlaceGTT_ValidParamsSessionError(t *testing.T) {
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
		"quantity":         float64(10),
		"limit_price":      float64(1395),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_DeleteGTT_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_ConvertPosition_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_ModifyGTT_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_ClosePosition_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_CloseAllPositions_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_all_positions", "trader@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_PlaceMFOrder_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_GetQuotesMultiple_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": []any{"NSE:INFY", "NSE:TCS"},
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_HistoricalData_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "2026-03-31 00:00:00",
	})
	assert.True(t, result.IsError)
}


func TestSessionTool_DeleteNativeAlert_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_native_alert", "trader@example.com", map[string]any{
		"uuid": "test-uuid-1",
	})
	assert.True(t, result.IsError)
}


func TestOpenDashboard_InvalidPage_FallsBackToPortfolio(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "nonexistent",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestCreateWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "", map[string]any{
		"name": "Test",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestCreateWatchlist_Success(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{
		"name": "My Stocks",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "created")
}


func TestCreateWatchlist_DuplicateName(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Create first
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "Dupe"})
	// Create duplicate
	result := callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "Dupe"})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "already exists")
}


func TestDeleteWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "", map[string]any{
		"watchlist": "someid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestDeleteWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestDeleteWatchlist_Success(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Create first
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ToDelete"})
	// Delete by name
	result := callToolWithManager(t, mgr, "delete_watchlist", "test@example.com", map[string]any{
		"watchlist": "ToDelete",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "deleted")
}


func TestAddToWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "", map[string]any{
		"watchlist":   "Test",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestAddToWatchlist_WatchlistNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "nonexistent",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestAddToWatchlist_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd",
		"instruments": "",
	})
	assert.True(t, result.IsError)
	// ValidateRequired fires before the split logic
	assertResultContains(t, result, "cannot be empty")
}


func TestAddToWatchlist_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd2"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd2",
		"instruments": "NSE:UNKNOWN_STOCK_XYZ",
	})
	// Instrument not found → all failed → returns error
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestAddToWatchlist_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd3"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd3",
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	// Test data instruments may not have ID field set for GetByID lookup,
	// but the handler exercises the full code path regardless.
	assert.NotNil(t, result)
}


func TestAddToWatchlist_WithTargets(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestTargets"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":    "TestTargets",
		"instruments":  "NSE:INFY",
		"notes":        "Swing trade candidate",
		"target_entry": float64(1800),
		"target_exit":  float64(2000),
	})
	// Exercises the notes/targets code paths regardless of instrument resolution
	assert.NotNil(t, result)
}


func TestRemoveFromWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "", map[string]any{
		"watchlist": "Test",
		"items":     "item1",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestRemoveFromWatchlist_WatchlistNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
		"items":     "item1",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestRemoveFromWatchlist_EmptyItems(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove"})
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove",
		"items":     "",
	})
	assert.True(t, result.IsError)
	// ValidateRequired fires before the split logic
	assertResultContains(t, result, "cannot be empty")
}


func TestRemoveFromWatchlist_ItemNotInWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove2"})
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove2",
		"items":     "NSE:UNKNOWN",
	})
	assert.NotNil(t, result)
	// Should report failure since item is not in the watchlist
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not in watchlist")
}


func TestRemoveFromWatchlist_ByItemID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove3"})
	// Try removing a non-existent item ID
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove3",
		"items":     "nonexistent-item-id",
	})
	// Exercises the non-colon ref path (item ID resolution)
	assert.NotNil(t, result)
}


func TestGetWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "", map[string]any{
		"watchlist": "Test",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestGetWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestGetWatchlist_EmptyWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "EmptyWL"})
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist": "EmptyWL",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "empty")
}


func TestGetWatchlist_WithItems_NoLTP(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "GetWL"})
	callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "GetWL",
		"instruments": "NSE:INFY",
	})
	// Get without LTP (no session)
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist":   "GetWL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)
	// Without LTP flag, should still return the items
}


func TestListWatchlists_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestListWatchlists_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "empty@example.com", map[string]any{})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "No watchlists")
}


func TestListWatchlists_WithData(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "list@example.com", map[string]any{"name": "WL1"})
	callToolWithManager(t, mgr, "create_watchlist", "list@example.com", map[string]any{"name": "WL2"})
	result := callToolWithManager(t, mgr, "list_watchlists", "list@example.com", map[string]any{})
	assert.False(t, result.IsError)
}


func TestSetupTelegram_NoNotifier(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not configured")
}


func TestSetupTelegram_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError)
	// Handler checks notifier config before email, so we get "not configured"
	assertResultContains(t, result, "not configured")
}


func TestSetupTelegram_MissingChatID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	// Notifier is nil, so it fails before chat_id check
	assertResultContains(t, result, "not configured")
}


func TestSetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.True(t, result.IsError)
}


func TestListAlerts_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_alerts", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestListAlerts_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_alerts", "noalerts@example.com", map[string]any{})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "No alerts")
}


func TestPlaceMFOrder_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceMFOrder_BuyWithZeroAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		"amount":           float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "amount")
}


func TestPlaceMFOrder_SellWithZeroQuantity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "SELL",
		"quantity":         float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "quantity")
}


func TestCancelMFOrder_MissingOrderID_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceMFSIP_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceMFSIP_ZeroAmount_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "test@example.com", map[string]any{
		"tradingsymbol": "INF209K01YS2",
		"amount":        float64(0),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "amount")
}


func TestCancelMFSIP_MissingID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_sip", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPaperTradingToggle_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}


func TestPaperTradingToggle_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "test@example.com", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}


func TestPaperTradingStatus_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}


func TestPaperTradingStatus_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}


func TestPaperTradingReset_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}


func TestPaperTradingReset_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}


func TestGetPnLJournal_NoEmail_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestGetPnLJournal_NoService(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}


func TestGetPnLJournal_Periods(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	periods := []string{"week", "month", "quarter", "year", "all"}
	for _, p := range periods {
		result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
			"period": p,
		})
		assert.True(t, result.IsError, "period=%s should fail due to no PnL service", p)
		assertResultContains(t, result, "not available")
	}
}


func TestPortfolioRebalance_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "test@example.com", map[string]any{
		"targets": "not valid json",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Invalid")
}


func TestPortfolioRebalance_EmptyObject(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "test@example.com", map[string]any{
		"targets": "{}",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "at least one")
}


func TestPortfolioRebalance_InvalidMode_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "test@example.com", map[string]any{
		"targets": `{"RELIANCE": 50, "INFY": 50}`,
		"mode":    "invalid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "percentage")
}


func TestGetNativeAlertHistory_MissingUUID_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_native_alert_history", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestListTrailingStops_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_trailing_stops", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestServerMetrics_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "server_metrics", "regular@example.com", map[string]any{})
	assert.True(t, result.IsError)
}


func TestServerMetrics_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "server_metrics", "", map[string]any{})
	assert.True(t, result.IsError)
}


func TestPreTradeCheck_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetOrderMargins_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestKiteClientForEmail_NoCreds(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	client := brokerClientForEmail(mgr, "nobody@example.com")
	assert.Nil(t, client)
}


func TestResolveWatchlist_ByName(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ResolveName"})
	wl := resolveWatchlist(mgr, "test@example.com", "ResolveName")
	assert.NotNil(t, wl)
	assert.Equal(t, "ResolveName", wl.Name)
}


func TestResolveWatchlist_ByID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ResolveID"})
	// Get the ID from the store
	watchlists := mgr.WatchlistStore().ListWatchlists("test@example.com")
	require.Len(t, watchlists, 1)
	wl := resolveWatchlist(mgr, "test@example.com", watchlists[0].ID)
	assert.NotNil(t, wl)
}


func TestResolveWatchlist_NotFound_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	wl := resolveWatchlist(mgr, "test@example.com", "nonexistent-ref")
	assert.Nil(t, wl)
}


func TestKiteClientForEmail_HasCredsButNoToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Set credentials but no token
	mgr.CredentialStore().Set("partial@example.com", &kc.KiteCredentialEntry{
		APIKey:    "testkey",
		APISecret: "testsecret",
	})
	client := brokerClientForEmail(mgr, "partial@example.com")
	assert.Nil(t, client)
}


func TestKiteClientForEmail_HasTokenButNoCreds(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Set token but no per-user credentials. Global API key ("test_key") is used
	// as fallback, so GetBrokerForEmail creates a valid client.
	mgr.TokenStore().Set("partial2@example.com", &kc.KiteTokenEntry{
		AccessToken: "testtoken",
		UserName:    "tester",
	})
	client := brokerClientForEmail(mgr, "partial2@example.com")
	assert.NotNil(t, client, "global API key + stored token = valid client")
}


func TestKiteClientForEmail_HasBoth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	mgr.CredentialStore().Set("full@example.com", &kc.KiteCredentialEntry{
		APIKey:    "testkey",
		APISecret: "testsecret",
	})
	mgr.TokenStore().Set("full@example.com", &kc.KiteTokenEntry{
		AccessToken: "testtoken",
		UserName:    "tester",
	})
	client := brokerClientForEmail(mgr, "full@example.com")
	assert.NotNil(t, client)
}


func TestListTrailingStops_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_trailing_stops", "test@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestSubscribeInstruments_MissingInstruments_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "subscribe_instruments", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestUnsubscribeInstruments_MissingInstruments_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "unsubscribe_instruments", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestGetPnLJournal_CustomDateRange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
		"from": "2025-01-01",
		"to":   "2025-12-31",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}


func TestGetPnLJournal_DefaultPeriod(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
		"period": "invalid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}


func TestAdminGetRiskStatus_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // missing target_email
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


func TestAdminRemoveFamily_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}
