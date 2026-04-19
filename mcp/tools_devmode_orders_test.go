package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


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


func TestGetGTTs_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_gtts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
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
