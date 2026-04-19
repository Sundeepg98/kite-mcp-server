package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Write tools: pre-session validation (param validation before broker call)
// ---------------------------------------------------------------------------
func TestPlaceOrder_MissingRequiredParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestPlaceOrder_LimitOrderRequiresPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price is missing → should error
	})
	assert.True(t, result.IsError, "LIMIT order without price should fail")
	assertResultContains(t, result, "price must be greater than 0 for LIMIT orders")
}


func TestPlaceOrder_SLOrderRequiresTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		"price":            float64(1500),
		// trigger_price missing → should error
	})
	assert.True(t, result.IsError, "SL order without trigger_price should fail")
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestPlaceOrder_SLMOrderRequiresTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(5),
		"product":          "MIS",
		"order_type":       "SL-M",
		// trigger_price missing
	})
	assert.True(t, result.IsError, "SL-M order without trigger_price should fail")
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestPlaceOrder_IcebergRequiresLegsAndQty(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "iceberg",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		// iceberg_legs and iceberg_quantity missing
	})
	assert.True(t, result.IsError, "iceberg order without legs/qty should fail")
	assertResultContains(t, result, "iceberg_legs and iceberg_quantity must be greater than 0")
}


func TestPlaceOrder_DisclosedQtyCannotExceedQuantity(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":            "regular",
		"exchange":           "NSE",
		"tradingsymbol":      "INFY",
		"transaction_type":   "BUY",
		"quantity":           float64(10),
		"product":            "CNC",
		"order_type":         "LIMIT",
		"price":              float64(1500),
		"disclosed_quantity": float64(20), // > quantity
	})
	assert.True(t, result.IsError, "disclosed_quantity > quantity should fail")
	assertResultContains(t, result, "disclosed_quantity cannot exceed quantity")
}


func TestCancelOrder_MissingRequiredParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestCancelOrder_MissingOrderID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety": "regular",
		// order_id missing
	})
	assert.True(t, result.IsError, "cancel_order without order_id should fail")
	assertResultContains(t, result, "order_id")
}


func TestModifyOrder_MissingRequiredParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "modify_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestModifyOrder_MissingOrderID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_type": "LIMIT",
		// order_id missing
	})
	assert.True(t, result.IsError, "modify_order without order_id should fail")
	assertResultContains(t, result, "order_id")
}


// ---------------------------------------------------------------------------
// Close position: parameter validation
// ---------------------------------------------------------------------------
func TestClosePosition_RequiresInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "close_position without instrument should fail")
	assertResultContains(t, result, "is required")
}


func TestClosePosition_InvalidInstrumentFormat(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "NOINFY", // missing colon separator
	})
	assert.True(t, result.IsError, "close_position with invalid instrument format should fail")
	assertResultContains(t, result, "Invalid instrument format")
}


// ---------------------------------------------------------------------------
// Close position: additional validation cases
// ---------------------------------------------------------------------------
func TestClosePosition_EmptyInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "",
	})
	assert.True(t, result.IsError, "close_position with empty instrument should fail")
}


// ── Validation edge cases for post tools ─────────────────────────────────
func TestPlaceOrder_SLWithZeroTrigger(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety": "regular", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10), "product": "CNC",
		"order_type": "SL", "price": float64(1500), "trigger_price": float64(0),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "trigger_price must be greater than 0")
}


func TestPlaceOrder_SLMWithZeroTrigger(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety": "regular", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10), "product": "CNC",
		"order_type": "SL-M", "trigger_price": float64(0),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "trigger_price must be greater than 0")
}


func TestPlaceOrder_IcebergMissingParams(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety": "iceberg", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(100), "product": "CNC",
		"order_type": "LIMIT", "price": float64(1500),
		"iceberg_legs": float64(0), "iceberg_quantity": float64(0),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "iceberg")
}


func TestPlaceOrder_DisclosedQtyExceedsQty(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety": "regular", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10), "product": "CNC",
		"order_type": "MARKET", "disclosed_quantity": float64(20),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "disclosed_quantity")
}


func TestPlaceOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety": "regular",
	})
	assert.True(t, result.IsError)
}


// ── Close position edge cases ────────────────────────────────────────────
func TestClosePosition_InvalidFormat(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "INFY", // missing exchange prefix
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Invalid instrument format")
}


func TestCloseAllPositions_NotConfirmed_Push100(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Safety check")
}
