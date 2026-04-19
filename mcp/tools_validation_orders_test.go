package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.


func TestPlaceOrder_IcebergWithLegsButNoQty(t *testing.T) {
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
		"iceberg_legs":     float64(3),
		// iceberg_quantity missing
	})
	assert.True(t, result.IsError, "iceberg with legs but no qty should fail")
	assertResultContains(t, result, "iceberg_legs and iceberg_quantity must be greater than 0")
}


func TestModifyOrder_MissingVariety(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"order_id":   "123456",
		"order_type": "LIMIT",
		// variety missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "variety")
}


func TestModifyOrder_MissingOrderType(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "123456",
		// order_type missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "order_type")
}


func TestCloseAllPositions_MissingConfirm(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_all_positions", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "confirm")
}


func TestCancelOrder_MissingVariety(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"order_id": "12345",
		// variety missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "variety")
}


func TestPlaceGTTOrder_TwoLegMissingLowerTrigger(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"upper_trigger_value": float64(1600),
		// lower_trigger_value missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "lower_trigger_value must be greater than 0")
}


func TestConvertPosition_MissingNewProduct(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"position_type":    "day",
		// new_product missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}


func TestPlaceOrder_LimitWithZeroPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}


func TestPlaceOrder_SLWithZeroTriggerPrice(t *testing.T) {
	t.Parallel()
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
		"trigger_price":    float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestPlaceOrder_SLMWithZeroTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL-M",
		"trigger_price":    float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestPlaceOrder_DisclosedQtyExceedsQuantity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":             "regular",
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"transaction_type":    "BUY",
		"quantity":            float64(10),
		"product":             "CNC",
		"order_type":          "MARKET",
		"disclosed_quantity":  float64(20),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "disclosed_quantity cannot exceed quantity")
}


func TestPlaceOrder_MissingExchange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceOrder_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceOrder_MissingTransactionType(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":       "regular",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"quantity":      float64(10),
		"product":       "CNC",
		"order_type":    "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestModifyOrder_MissingOrderIDParam(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_type": "LIMIT",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestCancelOrder_MissingOrderIDOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety": "regular",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestCancelOrder_MissingVarietyOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"order_id": "123456",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceGTT_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceGTT_SingleTriggerValueZero(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_value must be greater than 0")
}


func TestPlaceGTT_TwoLegMissingUpperTrigger(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"upper_trigger_value": float64(0),
		"lower_trigger_value": float64(1400),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "upper_trigger_value must be greater than 0")
}


func TestPlaceGTT_TwoLegMissingLowerTrigger(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"upper_trigger_value": float64(1600),
		"lower_trigger_value": float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "lower_trigger_value must be greater than 0")
}


func TestPlaceGTT_InvalidTriggerType(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "triple-leg",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "single")
}


func TestModifyGTT_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestModifyGTT_InvalidTriggerType(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "invalid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "single")
}


func TestModifyGTT_SingleTriggerValueZero(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_value must be greater than 0")
}


func TestModifyGTT_TwoLegMissingUpperTrigger(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":          float64(1001),
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"upper_trigger_value": float64(0),
		"lower_trigger_value": float64(1400),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "upper_trigger_value must be greater than 0")
}


func TestModifyGTT_TwoLegMissingLowerTrigger(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":          float64(1001),
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"upper_trigger_value": float64(1600),
		"lower_trigger_value": float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "lower_trigger_value must be greater than 0")
}


func TestDeleteGTT_MissingTriggerID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestConvertPosition_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestConvertPosition_MissingOldProduct(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestClosePosition_MissingInstrument(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestClosePosition_InvalidInstrumentFormatNoColon(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "INFY", // missing exchange prefix
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Invalid instrument format")
}


func TestClosePosition_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_position", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestCloseAllPositions_MissingConfirm_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_all_positions", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "confirm")
}


func TestModifyOrder_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestConvertPosition_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceGTT_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestModifyGTT_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestDeleteGTT_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_gtt_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestCancelOrder_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceOrder_IcebergQtyExceedsQuantity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "test@example.com", map[string]any{
		"variety":          "iceberg",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"iceberg_legs":     float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "iceberg_legs")
}


func TestPlaceOrder_IcebergWithNonLimitOrder(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_order", "test@example.com", map[string]any{
		"variety":          "iceberg",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"product":          "CNC",
		"order_type":       "MARKET",
		"iceberg_legs":     float64(5),
	})
	assert.True(t, result.IsError)
}
