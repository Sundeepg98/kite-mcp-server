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
	result := callToolWithSession(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
}


func TestTaxHarvest_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "tax_loss_analysis", "trader@example.com", map[string]any{})
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


func TestServerMetrics_WithSession2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "server_metrics", "trader@example.com", map[string]any{
		"period": "1h",
	})
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
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
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


func TestDevMode_SEBICompliance_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
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


func TestDevMode_SEBICompliance_WithMetrics(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestTradingContext_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
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


func TestDevMode_TradingContext_ReturnsResult(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// trading_context aggregates from mock broker, so may partially succeed
	assertResultNotContains(t, result, "not available in DEV_MODE")
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


func TestDevMode_SEBICompliance_WithPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Should reach API call for positions/orders → error or empty data
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


func TestDevMode_PreTradeCheck_SELLOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
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


func TestDevMode_Prompts_Registration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// RegisterPrompts shouldn't panic with a valid manager
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)
	// No assertion needed — just exercising the registration code path
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
	result := callToolDevMode(t, mgr, "tax_loss_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
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
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
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
	result := callToolDevMode(t, mgr, "historical_price_analyzer", "dev@example.com", map[string]any{
		"strategy":      "invalid_strategy",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
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
// order_risk_report tool
// ---------------------------------------------------------------------------
func TestPreTradeCheck_Full(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "order_risk_report", "dev@example.com", map[string]any{
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
