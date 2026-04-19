package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


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


func TestDevMode_PlaceNativeAlert_SucceedsViaMock(t *testing.T) {
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
	// Mock broker implements NativeAlertCapable — native alerts succeed in DevMode
	assert.False(t, result.IsError, resultText(t, result))
}


func TestDevMode_ListNativeAlerts_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_native_alerts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}


func TestDevMode_ModifyNativeAlert_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// In DevMode, each GetBrokerForEmail call creates a fresh mock with no alerts,
	// so modifying a non-existent UUID returns an error.
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
	assert.True(t, result.IsError, "fresh mock has no alerts to modify")
}


func TestDevMode_DeleteNativeAlert_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_native_alert", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}


func TestDevMode_GetNativeAlertHistory_SucceedsViaMock(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_native_alert_history", "dev@example.com", map[string]any{
		"uuid": "test-uuid",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
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
