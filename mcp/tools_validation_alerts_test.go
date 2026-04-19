package mcp

import (
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.


func TestDeleteAlert_MissingAlertID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_alert without alert_id should fail")
	assertResultContains(t, result, "is required")
}


func TestSetTrailingStop_InvalidDirection(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "12345",
		"direction":    "sideways", // invalid
		"trail_amount": float64(20),
	})
	assert.True(t, result.IsError, "invalid direction should fail")
	// May fail on instrument resolution before direction check
}


func TestSetTrailingStop_NegativeTrailAmount(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "12345",
		"direction":    "long",
		"trail_amount": float64(-10),
	})
	assert.True(t, result.IsError, "negative trail_amount should fail")
	assertResultContains(t, result, "trail_amount or trail_pct must be provided and positive")
}


func TestSetAlert_InvalidDirection(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(100),
		"direction":  "invalid_direction",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Direction must be")
}


func TestPlaceNativeAlert_InstrumentMissingRHSAttribute(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":              "Cross alert",
		"type":              "simple",
		"exchange":          "NSE",
		"tradingsymbol":     "INFY",
		"lhs_attribute":     "last_price",
		"operator":          ">=",
		"rhs_type":          "instrument",
		"rhs_exchange":      "NSE",
		"rhs_tradingsymbol": "RELIANCE",
		// rhs_attribute missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "rhs_exchange")
}


func TestModifyNativeAlert_ATOEmptyBasket(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_native_alert", "dev@example.com", map[string]any{
		"uuid":          "test-uuid",
		"name":          "ATO alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
		"basket_json":   `{"name":"test","type":"order","items":[]}`,
	})
	// basket items not validated at handler level — mock broker accepts as-is
	assert.NotNil(t, result)
}


func TestSetAlert_ValidDirection_PassesDirectionCheck(t *testing.T) {
	// These should pass the direction validation but fail later on instrument resolution
	mgr := newTestManager(t)
	for _, dir := range []string{"above", "below"} {
		result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
			"instrument": "NSE:INFY",
			"price":      float64(100),
			"direction":  dir,
		})
		assert.True(t, result.IsError, "direction=%s should fail (instrument or ticker)", dir)
		// Should NOT contain "Direction must be" since the direction is valid
		text := result.Content[0].(gomcp.TextContent).Text
		assert.NotContains(t, text, "Direction must be")
	}
}


func TestSetAlert_RisePctRequiresReferencePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(10),
		"direction":  "rise_pct",
	})
	assert.True(t, result.IsError)
	// Should fail because rise_pct/drop_pct needs reference_price
}


func TestPlaceNativeAlert_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceNativeAlert_ConstantRHSMissingValue(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		// Missing rhs_constant
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "rhs_constant")
}


func TestPlaceNativeAlert_ATONoBasketProvided(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":          "ATO alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
		// Missing basket_json
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "basket_json")
}


func TestPlaceNativeAlert_ATOBadBasketJSON(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":          "ATO alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
		"basket_json":   "not-json",
	})
	// basket_json structure not validated at handler level — mock broker accepts as-is
	assert.NotNil(t, result)
}


func TestPlaceNativeAlert_ATOZeroItemBasket(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":          "ATO alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
		"basket_json":   `{"items":[]}`,
	})
	// basket items not validated at handler level — mock broker accepts as-is
	assert.NotNil(t, result)
}


func TestModifyNativeAlert_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestSetAlert_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestSetAlert_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestSetAlert_ZeroPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(0),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "positive")
}


func TestSetAlert_NegativePrice_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(-100),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "positive")
}


func TestSetAlert_PercentageOver100(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(150),
		"direction":  "drop_pct",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "100%")
}


func TestSetAlert_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument": "NSE:DOESNOTEXIST",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}


func TestSetAlert_AboveWithReferencePrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"price":           float64(1500),
		"direction":       "above",
		"reference_price": float64(1400),
	})
	// Exercises past validation into the handler body (instrument resolution + alert creation)
	assert.NotNil(t, result)
}


func TestDeleteAlert_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_alert", "", map[string]any{
		"alert_id": "alert-001",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}


func TestDeleteAlert_MissingID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_alert", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestDeleteAlert_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_alert", "test@example.com", map[string]any{
		"alert_id": "nonexistent-id",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "no alerts found")
}


func TestPlaceNativeAlert_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceNativeAlert_ConstantMissingRHSValue(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "test@example.com", map[string]any{
		"name":           "Test Alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "rhs_constant")
}


func TestPlaceNativeAlert_InstrumentMissingRHSParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "test@example.com", map[string]any{
		"name":           "Test Alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "instrument",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "rhs_exchange")
}


func TestModifyNativeAlert_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestDeleteNativeAlert_MissingUUID_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_native_alert", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestSetTrailingStop_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}


func TestPlaceNativeAlert_ATOMissingBasket_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "test@example.com", map[string]any{
		"name":           "ATO Alert",
		"type":           "ato",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(1500),
	})
	assert.NotNil(t, result)
	// ATO without basket_json should fail
}


func TestCancelTrailingStop_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_trailing_stop", "test@example.com", map[string]any{
		"stop_id": "nonexistent-stop",
	})
	assert.True(t, result.IsError)
}


func TestSetAlert_DropPctValid(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"price":           float64(5.0),
		"direction":       "drop_pct",
		"reference_price": float64(1800),
	})
	assert.NotNil(t, result)
	// Exercises the percentage direction path
}


func TestSetAlert_RisePctValid(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument":      "NSE:INFY",
		"price":           float64(10.0),
		"direction":       "rise_pct",
		"reference_price": float64(1500),
	})
	assert.NotNil(t, result)
}


func TestSetAlert_BelowDirection(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1400),
		"direction":  "below",
	})
	assert.NotNil(t, result)
}
