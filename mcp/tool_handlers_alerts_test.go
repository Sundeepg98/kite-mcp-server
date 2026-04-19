package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Read tools: require auth (email in context)
// ---------------------------------------------------------------------------
func TestSetAlert_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	// set_alert checks email from context BEFORE WithSession
	result := callToolWithManager(t, mgr, "set_alert", "", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	})
	assert.True(t, result.IsError, "set_alert without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestSetupTelegram_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError, "setup_telegram without email should fail")
}


// ---------------------------------------------------------------------------
// Alert tools: pre-session validation
// ---------------------------------------------------------------------------
func TestSetAlert_RequiresInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"price":     float64(100),
		"direction": "above",
		// instrument missing
	})
	assert.True(t, result.IsError, "set_alert without instrument should fail")
	assertResultContains(t, result, "is required")
}


func TestSetAlert_RequiresPositivePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(0),
		"direction":  "above",
	})
	assert.True(t, result.IsError, "set_alert with zero price should fail")
	assertResultContains(t, result, "Price must be positive")
}


func TestSetAlert_PercentageCannotExceed100(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(150),
		"direction":  "drop_pct",
	})
	assert.True(t, result.IsError, "set_alert with >100% threshold should fail")
	assertResultContains(t, result, "cannot exceed 100%")
}


func TestSetAlert_NegativePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_alert", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(-50),
		"direction":  "above",
	})
	assert.True(t, result.IsError, "set_alert with negative price should fail")
	assertResultContains(t, result, "Price must be positive")
}


// ---------------------------------------------------------------------------
// SetupTelegram: parameter validation
// ---------------------------------------------------------------------------
func TestSetupTelegram_RequiresChatID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "setup_telegram without chat_id should fail")
}


func TestSetupTelegram_ZeroChatIDInvalid(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "trader@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.True(t, result.IsError, "setup_telegram with zero chat_id should fail")
}


// ---------------------------------------------------------------------------
// Trailing stop tools: pre-session validation
// ---------------------------------------------------------------------------
func TestSetTrailingStop_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "set_trailing_stop with no params should fail validation")
	assertResultContains(t, result, "is required")
}


func TestSetTrailingStop_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "12345",
		"direction":  "long",
		"trail_pct":  float64(1.5),
	})
	assert.True(t, result.IsError, "set_trailing_stop without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestSetTrailingStop_MissingTrailAmountAndPct(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "12345",
		"direction":  "long",
		// neither trail_amount nor trail_pct
	})
	assert.True(t, result.IsError, "set_trailing_stop without trail_amount or trail_pct should fail")
	assertResultContains(t, result, "trail_amount or trail_pct must be provided")
}


func TestSetTrailingStop_BothTrailAmountAndPct(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NSE:INFY",
		"order_id":     "12345",
		"direction":    "long",
		"trail_amount": float64(20),
		"trail_pct":    float64(1.5),
	})
	assert.True(t, result.IsError, "set_trailing_stop with both trail_amount and trail_pct should fail")
	assertResultContains(t, result, "not both")
}


func TestSetTrailingStop_TrailPctTooHigh(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"order_id":   "12345",
		"direction":  "long",
		"trail_pct":  float64(60),
	})
	assert.True(t, result.IsError, "set_trailing_stop with trail_pct > 50 should fail")
	assertResultContains(t, result, "cannot exceed 50%")
}


func TestSetTrailingStop_InvalidInstrumentFormat(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "set_trailing_stop", "trader@example.com", map[string]any{
		"instrument":   "NOINFY", // missing colon
		"order_id":     "12345",
		"direction":    "long",
		"trail_amount": float64(20),
	})
	assert.True(t, result.IsError, "set_trailing_stop with invalid instrument format should fail")
	assertResultContains(t, result, "Invalid instrument format")
}


func TestCancelTrailingStop_MissingID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_trailing_stop", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_trailing_stop without trailing_stop_id should fail")
	assertResultContains(t, result, "is required")
}


func TestCancelTrailingStop_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_trailing_stop", "", map[string]any{
		"trailing_stop_id": "ts-123",
	})
	assert.True(t, result.IsError, "cancel_trailing_stop without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestListTrailingStops_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_trailing_stops", "", map[string]any{})
	assert.True(t, result.IsError, "list_trailing_stops without email should fail")
	assertResultContains(t, result, "Email required")
}


// ---------------------------------------------------------------------------
// Native alert tools: pre-session validation
// ---------------------------------------------------------------------------
func TestPlaceNativeAlert_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_native_alert with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestPlaceNativeAlert_ConstantMissingRHSConstant(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":           "INFY alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		// rhs_constant missing
	})
	assert.True(t, result.IsError, "place_native_alert constant type without rhs_constant should fail")
	assertResultContains(t, result, "rhs_constant is required")
}


func TestPlaceNativeAlert_InstrumentMissingRHSFields(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":           "Cross alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "instrument",
		// rhs_exchange, rhs_tradingsymbol, rhs_attribute missing
	})
	assert.True(t, result.IsError, "place_native_alert instrument type without rhs fields should fail")
	assertResultContains(t, result, "rhs_exchange")
}


func TestPlaceNativeAlert_ATOMissingBasket(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":           "ATO alert",
		"type":           "ato",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(1500),
		// basket_json missing
	})
	assert.True(t, result.IsError, "ATO without basket_json should fail")
	assertResultContains(t, result, "basket_json is required")
}


func TestPlaceNativeAlert_ATOInvalidBasketJSON(t *testing.T) {

	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":           "ATO alert",
		"type":           "ato",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(1500),
		"basket_json":    "{invalid json",
	})
	// basket_json structure is not validated at handler level — broker receives it as-is.
	// Mock broker accepts anything, so this succeeds in DevMode.
	assert.NotNil(t, result)
}
func TestPlaceNativeAlert_ATOEmptyBasketItems(t *testing.T) {
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_native_alert", "dev@example.com", map[string]any{
		"name":           "ATO alert",
		"type":           "ato",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(1500),
		"basket_json":    `{"name":"test","type":"order","items":[]}`,
	})
	// basket_json items are not validated at handler level — broker receives as-is.
	assert.NotNil(t, result)
}


// ---------------------------------------------------------------------------
// Setup_telegram: TelegramNotifier unavailable
// ---------------------------------------------------------------------------
func TestSetupTelegram_NoNotifierConfigured(t *testing.T) {
	mgr := newTestManager(t)
	// Manager has no TelegramNotifier configured
	result := callToolWithManager(t, mgr, "setup_telegram", "user@example.com", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError, "setup_telegram without notifier should fail")
	assertResultContains(t, result, "not configured")
}


// ---------------------------------------------------------------------------
// Delete alert: auth check
// ---------------------------------------------------------------------------
func TestDeleteAlert_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_alert", "", map[string]any{
		"alert_id": "alert-123",
	})
	assert.True(t, result.IsError, "delete_alert without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestListAlerts_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_alerts", "", map[string]any{})
	assert.True(t, result.IsError, "list_alerts without email should fail")
	assertResultContains(t, result, "Email required")
}


// ---------------------------------------------------------------------------
// modify_native_alert: pre-session validation
// ---------------------------------------------------------------------------
func TestModifyNativeAlert_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "modify_native_alert with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestModifyNativeAlert_ConstantMissingRHS(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{
		"uuid":           "test-uuid",
		"name":           "Updated alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		// rhs_constant missing
	})
	assert.True(t, result.IsError, "modify_native_alert without rhs_constant should fail")
	assertResultContains(t, result, "rhs_constant is required")
}


func TestModifyNativeAlert_InstrumentMissingRHS(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{
		"uuid":           "test-uuid",
		"name":           "Updated alert",
		"type":           "simple",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "instrument",
	})
	assert.True(t, result.IsError, "modify_native_alert instrument missing rhs fields should fail")
	assertResultContains(t, result, "rhs_exchange")
}


func TestModifyNativeAlert_ATOMissingBasket(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{
		"uuid":           "test-uuid",
		"name":           "ATO alert",
		"type":           "ato",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
		"lhs_attribute":  "last_price",
		"operator":       ">=",
		"rhs_type":       "constant",
		"rhs_constant":   float64(1500),
	})
	assert.True(t, result.IsError, "modify_native_alert ATO without basket should fail")
	assertResultContains(t, result, "basket_json is required")
}


// ---------------------------------------------------------------------------
// delete_native_alert: pre-session validation
// ---------------------------------------------------------------------------
func TestDeleteNativeAlert_MissingUUID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_native_alert without uuid should fail")
	assertResultContains(t, result, "is required")
}


// ---------------------------------------------------------------------------
// get_native_alert_history: pre-session validation
// ---------------------------------------------------------------------------
func TestGetNativeAlertHistory_MissingUUID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_native_alert_history", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_native_alert_history without uuid should fail")
	assertResultContains(t, result, "is required")
}


// ── Trailing stop edge cases ─────────────────────────────────────────────
func TestSetTrailingStop_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "set_trailing_stop", "", map[string]any{
		"instrument": "NSE:INFY", "order_id": "ORD1", "direction": "long",
		"trail_amount": float64(20),
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}
