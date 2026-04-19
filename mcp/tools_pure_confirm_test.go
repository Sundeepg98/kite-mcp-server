package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestBuildOrderConfirmMessage_ClosePosition(t *testing.T) {
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:RELIANCE",
		"product":    "MIS",
	})
	assert.Contains(t, msg, "NSE:RELIANCE")
}


func TestBuildOrderConfirmMessage_ModifyGTT(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_gtt_order", map[string]any{
		"trigger_id":       float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.Contains(t, msg, "GTT")
}


func TestBuildOrderConfirmMessage_PlaceNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":          "Test alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"operator":      ">=",
	})
	assert.NotEmpty(t, msg)
}


func TestBuildOrderConfirmMessage_ModifyNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_native_alert", map[string]any{
		"uuid": "test-uuid",
		"name": "Modified alert",
	})
	assert.NotEmpty(t, msg)
}


func TestBuildOrderConfirmMessage_AllConfirmableTools(t *testing.T) {
	for toolName := range confirmableTools {
		msg := buildOrderConfirmMessage(toolName, map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"quantity":         float64(10),
			"order_type":       "MARKET",
			"product":          "CNC",
			"order_id":         "123",
			"confirm":          true,
			"trigger_type":     "single",
			"trigger_value":    float64(1400),
			"amount":           float64(5000),
			"frequency":        "monthly",
			"instalments":      float64(12),
			"instrument":       "NSE:INFY",
			"name":             "Test",
			"type":             "ato",
			"operator":         ">=",
			"uuid":             "test-uuid",
		})
		assert.NotEmpty(t, msg, "confirm message for %s should not be empty", toolName)
	}
}


func TestBuildOrderConfirmMessage_PlaceOrder_Market(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.Contains(t, msg, "BUY")
	assert.Contains(t, msg, "100")
	assert.Contains(t, msg, "NSE:RELIANCE")
	assert.Contains(t, msg, "MARKET")
}


func TestBuildOrderConfirmMessage_PlaceOrder_Limit(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "SELL",
		"quantity":         float64(50),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"price":            float64(1500.50),
	})
	assert.Contains(t, msg, "1500.50")
	assert.Contains(t, msg, "LIMIT")
}


func TestBuildOrderConfirmMessage_PlaceOrder_SL(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"order_type":       "SL",
		"product":          "CNC",
		"trigger_price":    float64(3200),
	})
	assert.Contains(t, msg, "trigger 3200")
}


func TestBuildOrderConfirmMessage_PlaceOrder_SLM(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_order", map[string]any{
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"order_type":       "SL-M",
		"product":          "CNC",
		"trigger_price":    float64(3200),
	})
	assert.Contains(t, msg, "trigger 3200")
	assert.Contains(t, msg, "SL-M")
}


func TestBuildOrderConfirmMessage_ModifyOrder_WithTrigger(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("modify_order", map[string]any{
		"order_id":      "ORD123",
		"order_type":    "LIMIT",
		"quantity":      float64(25),
		"price":         float64(1450),
		"trigger_price": float64(1400),
	})
	assert.Contains(t, msg, "ORD123")
	assert.Contains(t, msg, "qty 25")
	assert.Contains(t, msg, "price 1450")
	assert.Contains(t, msg, "trigger 1400")
}


func TestBuildOrderConfirmMessage_CloseAllPositions(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("close_all_positions", map[string]any{
		"product": "MIS",
	})
	assert.Contains(t, msg, "ALL")
	assert.Contains(t, msg, "MIS")
}


func TestBuildOrderConfirmMessage_ClosePosition_NoProduct(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:HDFC",
	})
	assert.Contains(t, msg, "NSE:HDFC")
	assert.Contains(t, msg, "MARKET")
}


func TestBuildOrderConfirmMessage_PlaceGTT(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_gtt_order", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"limit_price":      float64(1405),
	})
	assert.Contains(t, msg, "GTT")
	assert.Contains(t, msg, "BUY")
	assert.Contains(t, msg, "1400")
	assert.Contains(t, msg, "1405")
}


func TestBuildOrderConfirmMessage_PlaceMFOrder_Amount(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.Contains(t, msg, "MF")
	assert.Contains(t, msg, "10000")
}


func TestBuildOrderConfirmMessage_PlaceMFOrder_Quantity(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "SELL",
		"quantity":         float64(50),
	})
	assert.Contains(t, msg, "50 units")
}


func TestBuildOrderConfirmMessage_PlaceMFSIP(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_mf_sip", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(24),
	})
	assert.Contains(t, msg, "SIP")
	assert.Contains(t, msg, "5000")
	assert.Contains(t, msg, "monthly")
	assert.Contains(t, msg, "24")
}


func TestBuildOrderConfirmMessage_PlaceNativeAlert_InstrumentRHS(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":              "Cross alert",
		"type":              "simple",
		"exchange":          "NSE",
		"tradingsymbol":     "INFY",
		"operator":          ">=",
		"rhs_type":          "instrument",
		"rhs_exchange":      "NSE",
		"rhs_tradingsymbol": "TCS",
	})
	assert.Contains(t, msg, "NSE:TCS")
}


func TestBuildOrderConfirmMessage_PlaceNativeAlert_ConstantRHS(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":          "Price alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1800),
	})
	assert.Contains(t, msg, "1800")
}


func TestBuildOrderConfirmMessage_ModifyNativeAlert_Details(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("modify_native_alert", map[string]any{
		"uuid":          "test-uuid-123",
		"name":          "Modified alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "TCS",
		"operator":      "<=",
	})
	assert.Contains(t, msg, "test-uuid-123")
	assert.Contains(t, msg, "Modified alert")
	assert.Contains(t, msg, "ato")
}


func TestBuildOrderConfirmMessage_Default(t *testing.T) {
	t.Parallel()
	msg := buildOrderConfirmMessage("unknown_tool", map[string]any{})
	assert.Contains(t, msg, "Execute unknown_tool")
}
