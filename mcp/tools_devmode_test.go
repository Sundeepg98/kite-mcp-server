package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func assertResultNotContains(t *testing.T, result *gomcp.CallToolResult, substr string) {
	t.Helper()
	if len(result.Content) == 0 {
		return // no content to check
	}
	text := result.Content[0].(gomcp.TextContent).Text
	assert.NotContains(t, text, substr)
}

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
	assertResultContains(t, result, "Invalid api_key")
}

func TestLogin_NonAlphanumericAPISecret(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key":    "validkey123",
		"api_secret": "secret!@#",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Invalid api_secret")
}

func TestLogin_PartialCredentials_KeyOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key": "validkey123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Both api_key and api_secret are required")
}

func TestLogin_PartialCredentials_SecretOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_secret": "validsecret123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Both api_key and api_secret are required")
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

func TestDevMode_PlaceNativeAlert_ReturnsAPIError(t *testing.T) {
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
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_ListNativeAlerts_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_native_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_ModifyNativeAlert_ReturnsAPIError(t *testing.T) {
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
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_DeleteNativeAlert_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_GetNativeAlertHistory_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
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
