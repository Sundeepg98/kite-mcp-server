package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// GTT tools: pre-session validation
// ---------------------------------------------------------------------------
func TestPlaceGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// No params at all → should fail on required fields
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_gtt_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestPlaceGTTOrder_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		// tradingsymbol missing
	})
	assert.True(t, result.IsError, "place_gtt_order without tradingsymbol should fail")
	assertResultContains(t, result, "tradingsymbol")
}


func TestPlaceGTTOrder_SingleLegMissingTriggerValue(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		// trigger_value missing → should error
	})
	assert.True(t, result.IsError, "place_gtt_order single without trigger_value should fail")
	assertResultContains(t, result, "trigger_value must be greater than 0")
}


func TestPlaceGTTOrder_TwoLegMissingUpperTrigger(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":            "NSE",
		"tradingsymbol":       "INFY",
		"last_price":          float64(1500),
		"transaction_type":    "BUY",
		"product":             "CNC",
		"trigger_type":        "two-leg",
		"lower_trigger_value": float64(1400),
		// upper_trigger_value missing
	})
	assert.True(t, result.IsError, "place_gtt_order two-leg without upper_trigger_value should fail")
	assertResultContains(t, result, "upper_trigger_value must be greater than 0")
}


func TestPlaceGTTOrder_InvalidTriggerType(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "invalid",
	})
	assert.True(t, result.IsError, "place_gtt_order with invalid trigger_type should fail")
	assertResultContains(t, result, "Invalid trigger_type")
}


func TestDeleteGTTOrder_MissingTriggerID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_gtt_order without trigger_id should fail")
	assertResultContains(t, result, "is required")
}


func TestModifyGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "modify_gtt_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestModifyGTTOrder_MissingTriggerID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		// trigger_id missing
	})
	assert.True(t, result.IsError, "modify_gtt_order without trigger_id should fail")
	assertResultContains(t, result, "trigger_id")
}
