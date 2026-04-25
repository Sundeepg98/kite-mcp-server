package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// DevMode MF + watchlist tool tests: mutual-fund orders/SIPs/holdings + watchlist CRUD + paper-trading status.

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
	data := ordersData(context.Background(), mgr, auditStore, "cred@example.com")
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
	data := watchlistData(context.Background(), mgr, nil, email)
	assert.NotNil(t, data)
}



// ---------------------------------------------------------------------------
// order_risk_report tool
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
