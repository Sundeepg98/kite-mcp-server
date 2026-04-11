package mcp

import (
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

// ===========================================================================
// coverage_push5_test.go — Verify DevMode stub Kite client
//
// These tests confirm that DevMode sessions have a non-nil session.Kite
// with a stub kiteconnect.Client pointing to a dead endpoint. Handler bodies
// execute and return API/connection errors (not the old "not available in
// DEV_MODE" panic-guard message).
// ===========================================================================

// assertResultNotContains verifies the tool result text does NOT contain substr.
func assertResultNotContains(t *testing.T, result *gomcp.CallToolResult, substr string) {
	t.Helper()
	if len(result.Content) == 0 {
		return // no content to check
	}
	text := result.Content[0].(gomcp.TextContent).Text
	assert.NotContains(t, text, substr)
}

// ---------------------------------------------------------------------------
// MF tools: previously panicked on session.Kite.Client nil dereference
// ---------------------------------------------------------------------------

func TestDevMode_GetMFOrders_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	// Should NOT contain the old panic-guard message
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_GetMFSIPs_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_GetMFHoldings_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_PlaceMFOrder_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_PlaceMFSIP_ReturnsAPIError(t *testing.T) {
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
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_CancelMFOrder_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF001",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_CancelMFSIP_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "SIP001",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

// ---------------------------------------------------------------------------
// Margin tools: previously panicked on session.Kite.Client nil dereference
// ---------------------------------------------------------------------------

func TestDevMode_GetOrderMargins_ReturnsAPIError(t *testing.T) {
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
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_GetBasketMargins_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError, "expected error from stub Kite client")
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

func TestDevMode_GetOrderCharges_ReturnsAPIError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
	// get_order_charges may or may not error depending on mock fallback
	assertResultNotContains(t, result, "not available in DEV_MODE")
}

// ---------------------------------------------------------------------------
// Native alert tools: previously panicked on session.Kite.Client nil dereference
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Context tool: uses session.Kite.Client for profile in some paths
// ---------------------------------------------------------------------------

func TestDevMode_TradingContext_ReturnsResult(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// trading_context aggregates from mock broker, so may partially succeed
	assertResultNotContains(t, result, "not available in DEV_MODE")
}
