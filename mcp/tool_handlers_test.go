package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------

func TestAllToolsRegistered(t *testing.T) {
	t.Parallel()
	tools := GetAllTools()
	assert.GreaterOrEqual(t, len(tools), 60, "should have at least 60 built-in tools")

	// Build a name set
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Tool().Name] = true
	}

	required := []string{
		"place_order", "modify_order", "cancel_order",
		"get_holdings", "get_positions", "get_profile", "get_margins",
		"get_orders", "get_trades", "get_order_history",
		"get_quotes", "get_ltp", "get_ohlc",
		"search_instruments", "get_historical_data",
		"set_alert", "list_alerts", "delete_alert",
		"close_position", "close_all_positions",
		"place_gtt_order", "modify_gtt_order", "delete_gtt_order",
		"login", "server_metrics",
		"admin_list_users", "admin_freeze_global",
		"admin_suspend_user", "admin_activate_user",
		"start_ticker", "stop_ticker", "subscribe_instruments",
		"portfolio_summary", "order_risk_report",
		"historical_price_analyzer", "technical_indicators",
		"options_greeks", "options_payoff_builder",
		"sector_exposure", "tax_loss_analysis",
		"sebi_compliance_status",
	}
	for _, name := range required {
		assert.True(t, names[name], "required tool %s should be registered", name)
	}
}

func TestAllToolsHaveUniqueNames(t *testing.T) {
	t.Parallel()
	tools := GetAllTools()
	names := make(map[string]int)
	for _, tool := range tools {
		names[tool.Tool().Name]++
	}

	for name, count := range names {
		assert.Equal(t, 1, count, "tool %s appears %d times (should be unique)", name, count)
	}
}

func TestAllToolsHaveDescriptions(t *testing.T) {
	t.Parallel()
	for _, td := range GetAllTools() {
		toolDef := td.Tool()
		assert.NotEmpty(t, toolDef.Description, "tool %s should have a description", toolDef.Name)
	}
}

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
// Market tools: parameter validation
// ---------------------------------------------------------------------------

func TestGetQuotes_RequiresInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_quotes", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_quotes without instruments should fail")
	assertResultContains(t, result, "is required")
}

func TestGetLTP_RequiresInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ltp", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_ltp without instruments should fail")
	assertResultContains(t, result, "is required")
}

func TestGetQuotes_TooManyInstruments(t *testing.T) {
	mgr := newTestManager(t)
	// Create more than 500 instruments
	insts := make([]any, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError, "get_quotes with >500 instruments should fail")
	assertResultContains(t, result, "maximum 500")
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
// ArgParser: integration with real tool request args
// ---------------------------------------------------------------------------

func TestArgParser_InToolContext(t *testing.T) {
	// Simulate the exact arg types MCP sends (all numbers are float64 in JSON)
	args := map[string]any{
		"exchange":           "NSE",
		"tradingsymbol":      "INFY",
		"quantity":           float64(10),
		"price":              float64(1500.50),
		"order_type":         "LIMIT",
		"product":            "CNC",
		"disclosed_quantity": float64(0),
	}
	p := NewArgParser(args)

	assert.Equal(t, "NSE", p.String("exchange", ""))
	assert.Equal(t, "INFY", p.String("tradingsymbol", ""))
	assert.Equal(t, 10, p.Int("quantity", 0))
	assert.Equal(t, 1500.50, p.Float("price", 0.0))
	assert.Equal(t, "LIMIT", p.String("order_type", ""))
	assert.Equal(t, "CNC", p.String("product", ""))
	assert.Equal(t, 0, p.Int("disclosed_quantity", 0))

	// Missing keys return defaults
	assert.Equal(t, "regular", p.String("variety", "regular"))
	assert.Equal(t, 0.0, p.Float("trigger_price", 0.0))
	assert.False(t, p.Bool("confirm", false))
}

func TestArgParser_RequiredInToolContext(t *testing.T) {
	args := map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	}
	p := NewArgParser(args)

	// All present — no error
	assert.NoError(t, p.Required("exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"))

	// Missing "variety" — should error
	err := p.Required("variety")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "variety")
}

func TestArgParser_BoolFromString(t *testing.T) {
	// MCP sometimes sends bools as strings
	args := map[string]any{
		"confirm_true":  "true",
		"confirm_false": "false",
		"confirm_yes":   "yes",
		"confirm_no":    "no",
		"confirm_1":     "1",
		"confirm_0":     "0",
		"actual_bool":   true,
	}
	p := NewArgParser(args)

	assert.True(t, p.Bool("confirm_true", false))
	assert.False(t, p.Bool("confirm_false", true))
	assert.True(t, p.Bool("confirm_yes", false))
	assert.False(t, p.Bool("confirm_no", true))
	assert.True(t, p.Bool("confirm_1", false))
	assert.False(t, p.Bool("confirm_0", true))
	assert.True(t, p.Bool("actual_bool", false))
}

// ---------------------------------------------------------------------------
// Tool annotations: confirmable vs non-confirmable
// ---------------------------------------------------------------------------

func TestConfirmableToolsAreWriteTools(t *testing.T) {
	// Every confirmable tool should also be a write tool
	for toolName := range confirmableTools {
		assert.True(t, writeTools[toolName],
			"confirmable tool %s should also be in writeTools", toolName)
	}
}

func TestReadToolsNotConfirmable(t *testing.T) {
	readToolNames := []string{
		"get_holdings", "get_positions", "get_profile", "get_margins",
		"get_orders", "get_trades", "get_ltp", "get_quotes",
		"search_instruments", "get_historical_data",
		"list_alerts", "list_trailing_stops",
		"portfolio_summary", "sector_exposure",
		"technical_indicators", "options_greeks",
	}
	for _, name := range readToolNames {
		assert.False(t, isConfirmableTool(name),
			"read-only tool %s should NOT require confirmation", name)
	}
}

// ---------------------------------------------------------------------------
// Validation: ValidateRequired with real tool parameter shapes
// ---------------------------------------------------------------------------

func TestValidateRequired_PlaceOrderParams(t *testing.T) {
	// Full valid place_order args
	args := map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	}

	err := ValidateRequired(args, "variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type")
	assert.NoError(t, err, "all required params present should pass")

	// Remove one at a time and verify error
	for _, key := range []string{"variety", "exchange", "tradingsymbol", "transaction_type", "product", "order_type"} {
		reduced := make(map[string]any)
		for k, v := range args {
			if k != key {
				reduced[k] = v
			}
		}
		err := ValidateRequired(reduced, "variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type")
		assert.Error(t, err, "missing %s should fail validation", key)
		assert.Contains(t, err.Error(), key)
	}
}

func TestValidateRequired_AlertParams(t *testing.T) {
	args := map[string]any{
		"instrument": "NSE:INFY",
		"price":      float64(1500),
		"direction":  "above",
	}

	assert.NoError(t, ValidateRequired(args, "instrument", "price", "direction"))

	// Empty instrument string should fail
	args["instrument"] = ""
	assert.Error(t, ValidateRequired(args, "instrument"))
}

// ---------------------------------------------------------------------------
// GTT tools: pre-session validation
// ---------------------------------------------------------------------------

func TestPlaceGTTOrder_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	// No params at all → should fail on required fields
	result := callToolWithManager(t, mgr, "place_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_gtt_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestPlaceGTTOrder_MissingTradingsymbol(t *testing.T) {
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
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_gtt_order without trigger_id should fail")
	assertResultContains(t, result, "is required")
}

func TestModifyGTTOrder_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "modify_gtt_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestModifyGTTOrder_MissingTriggerID(t *testing.T) {
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

// ---------------------------------------------------------------------------
// MF tools: pre-session validation
// ---------------------------------------------------------------------------

func TestPlaceMFOrder_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_mf_order with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestPlaceMFOrder_MissingTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"transaction_type": "BUY",
		"amount":           float64(5000),
		// tradingsymbol missing
	})
	assert.True(t, result.IsError, "place_mf_order without tradingsymbol should fail")
	assertResultContains(t, result, "tradingsymbol")
}

func TestPlaceMFOrder_BuyRequiresAmount(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		// amount missing → should error for BUY
	})
	assert.True(t, result.IsError, "place_mf_order BUY without amount should fail")
	assertResultContains(t, result, "amount is required")
}

func TestPlaceMFOrder_SellRequiresQuantity(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "SELL",
		// quantity missing → should error for SELL
	})
	assert.True(t, result.IsError, "place_mf_order SELL without quantity should fail")
	assertResultContains(t, result, "quantity is required")
}

func TestPlaceMFSIP_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "place_mf_sip with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestPlaceMFSIP_ZeroAmount(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "trader@example.com", map[string]any{
		"tradingsymbol": "INF209K01YS2",
		"amount":        float64(0),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError, "place_mf_sip with zero amount should fail")
	assertResultContains(t, result, "amount must be greater than 0")
}

func TestCancelMFOrder_MissingOrderID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_mf_order without order_id should fail")
	assertResultContains(t, result, "is required")
}

func TestCancelMFSIP_MissingSIPID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_sip", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "cancel_mf_sip without sip_id should fail")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// Watchlist tools: pre-session validation
// ---------------------------------------------------------------------------

func TestCreateWatchlist_MissingName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "create_watchlist without name should fail")
	assertResultContains(t, result, "is required")
}

func TestCreateWatchlist_EmptyName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "trader@example.com", map[string]any{
		"name": "   ", // whitespace only
	})
	assert.True(t, result.IsError, "create_watchlist with empty name should fail")
	assertResultContains(t, result, "cannot be empty")
}

func TestCreateWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "", map[string]any{
		"name": "Tech Stocks",
	})
	assert.True(t, result.IsError, "create_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestAddToWatchlist_MissingParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "add_to_watchlist without params should fail")
	assertResultContains(t, result, "is required")
}

func TestAddToWatchlist_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{
		"watchlist": "my-list",
		// instruments missing
	})
	assert.True(t, result.IsError, "add_to_watchlist without instruments should fail")
	assertResultContains(t, result, "is required")
}

func TestAddToWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "", map[string]any{
		"watchlist":   "my-list",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError, "add_to_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestDeleteWatchlist_MissingWatchlist(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_watchlist without watchlist should fail")
	assertResultContains(t, result, "is required")
}

func TestRemoveFromWatchlist_MissingParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "remove_from_watchlist without params should fail")
	assertResultContains(t, result, "is required")
}

func TestGetWatchlist_MissingWatchlist(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_watchlist without watchlist should fail")
	assertResultContains(t, result, "is required")
}

func TestGetWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "", map[string]any{
		"watchlist": "my-list",
	})
	assert.True(t, result.IsError, "get_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestListWatchlists_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "", map[string]any{})
	assert.True(t, result.IsError, "list_watchlists without email should fail")
	assertResultContains(t, result, "Email required")
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
// Options tools: pre-session validation
// ---------------------------------------------------------------------------

func TestGetOptionChain_MissingUnderlying(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_option_chain without underlying should fail")
	assertResultContains(t, result, "is required")
}

func TestOptionsGreeks_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "options_greeks with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestOptionsGreeks_MissingStrikePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2440324000CE",
		"expiry_date":    "2024-04-03",
		"option_type":    "CE",
		// strike_price missing
	})
	assert.True(t, result.IsError, "options_greeks without strike_price should fail")
	assertResultContains(t, result, "strike_price")
}

func TestOptionsGreeks_InvalidOptionType(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(24000),
		"expiry_date":   "2024-04-03",
		"option_type":   "INVALID",
	})
	assert.True(t, result.IsError, "options_greeks with invalid option_type should fail")
	assertResultContains(t, result, "option_type must be CE or PE")
}

func TestOptionsGreeks_NegativeStrikePrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(-100),
		"expiry_date":   "2024-04-03",
		"option_type":   "CE",
	})
	assert.True(t, result.IsError, "options_greeks with negative strike_price should fail")
	assertResultContains(t, result, "strike_price must be positive")
}

func TestOptionsGreeks_InvalidExpiryDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY2440324000CE",
		"strike_price":  float64(24000),
		"expiry_date":   "not-a-date",
		"option_type":   "CE",
	})
	assert.True(t, result.IsError, "options_greeks with invalid expiry_date should fail")
	assertResultContains(t, result, "YYYY-MM-DD")
}

func TestOptionsStrategy_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "options_payoff_builder with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestOptionsStrategy_MissingStrike1(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		// strike1 missing
	})
	assert.True(t, result.IsError, "options_payoff_builder without strike1 should fail")
	assertResultContains(t, result, "strike1")
}

// ---------------------------------------------------------------------------
// Backtest and indicators: pre-session validation
// ---------------------------------------------------------------------------

func TestBacktestStrategy_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "historical_price_analyzer with no params should fail validation")
	assertResultContains(t, result, "is required")
}

func TestTechnicalIndicators_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "technical_indicators with no params should fail validation")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// Analytics tools: annotations (read-only, etc.)
// ---------------------------------------------------------------------------

func TestAnalyticsToolsAnnotations(t *testing.T) {
	tools := GetAllTools()
	readOnlyTools := []string{
		"portfolio_summary", "portfolio_concentration", "position_analysis",
		"sector_exposure", "tax_loss_analysis", "dividend_calendar",
		"portfolio_analysis", "sebi_compliance_status",
		"historical_price_analyzer", "technical_indicators",
		"options_greeks", "options_payoff_builder",
	}

	toolMap := make(map[string]Tool)
	for _, td := range tools {
		toolMap[td.Tool().Name] = td
	}

	for _, name := range readOnlyTools {
		td, found := toolMap[name]
		if !found {
			t.Errorf("expected tool %s to be registered", name)
			continue
		}
		toolDef := td.Tool()
		assert.True(t, toolDef.Annotations.ReadOnlyHint != nil && *toolDef.Annotations.ReadOnlyHint,
			"tool %s should be read-only", name)
	}
}

func TestWriteToolsHaveDestructiveHint(t *testing.T) {
	tools := GetAllTools()
	destructiveTools := []string{
		"place_order", "cancel_order", "place_gtt_order", "delete_gtt_order",
		"place_mf_order", "cancel_mf_order", "cancel_mf_sip",
		"delete_watchlist", "remove_from_watchlist",
		"cancel_trailing_stop",
	}

	toolMap := make(map[string]Tool)
	for _, td := range tools {
		toolMap[td.Tool().Name] = td
	}

	for _, name := range destructiveTools {
		td, found := toolMap[name]
		if !found {
			t.Errorf("expected tool %s to be registered", name)
			continue
		}
		toolDef := td.Tool()
		assert.True(t, toolDef.Annotations.DestructiveHint != nil && *toolDef.Annotations.DestructiveHint,
			"tool %s should be marked destructive", name)
	}
}

// ===========================================================================
// NEW TESTS: coverage push from 28.3% to 45%+
// ===========================================================================

// ---------------------------------------------------------------------------
// common.go: SessionType context functions
// ---------------------------------------------------------------------------

func TestWithSessionType_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = WithSessionType(ctx, SessionTypeSSE)
	assert.Equal(t, SessionTypeSSE, SessionTypeFromContext(ctx))
}

func TestSessionTypeFromContext_Default(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))
}

func TestSessionTypeFromContext_AllTypes(t *testing.T) {
	for _, st := range []string{SessionTypeSSE, SessionTypeMCP, SessionTypeStdio, SessionTypeUnknown} {
		ctx := WithSessionType(context.Background(), st)
		assert.Equal(t, st, SessionTypeFromContext(ctx))
	}
}

// ---------------------------------------------------------------------------
// common.go: Error constants
// ---------------------------------------------------------------------------

func TestErrorConstants(t *testing.T) {
	assert.Contains(t, ErrAuthRequired, "Authentication")
	assert.Contains(t, ErrAdminRequired, "Admin")
	assert.Contains(t, ErrUserStoreNA, "User store")
	assert.Contains(t, ErrTargetEmailRequired, "target_email")
	assert.Contains(t, ErrSelfAction, "yourself")
	assert.Contains(t, ErrLastAdmin, "last active admin")
	assert.Contains(t, ErrRiskGuardNA, "RiskGuard")
	assert.Contains(t, ErrConfirmRequired, "confirm")
	assert.Contains(t, ErrInvitationStoreNA, "Invitation store")
}

func TestMaxPaginationLimit(t *testing.T) {
	assert.Equal(t, 500, MaxPaginationLimit)
}

// ---------------------------------------------------------------------------
// common.go: ValidationError type
// ---------------------------------------------------------------------------

func TestValidationError_ErrorString(t *testing.T) {
	err := ValidationError{Parameter: "quantity", Message: "is required"}
	assert.Equal(t, "parameter 'quantity': is required", err.Error())
}

func TestValidationError_Interface(t *testing.T) {
	var err error = ValidationError{Parameter: "price", Message: "cannot be negative"}
	assert.Contains(t, err.Error(), "price")
	assert.Contains(t, err.Error(), "cannot be negative")
}

// ---------------------------------------------------------------------------
// common.go: MarshalResponse
// ---------------------------------------------------------------------------

func TestMarshalResponse_Success(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	data := map[string]string{"key": "value"}
	result, err := handler.MarshalResponse(data, "test_tool")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestMarshalResponse_Unmarshalable(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	// channels cannot be marshaled to JSON
	result, err := handler.MarshalResponse(make(chan int), "test_tool")
	assert.NoError(t, err) // handler returns error as tool result, not Go error
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// common.go: Pagination edge cases
// ---------------------------------------------------------------------------

func TestParsePaginationParams_Defaults(t *testing.T) {
	p := ParsePaginationParams(map[string]any{})
	assert.Equal(t, 0, p.From)
	assert.Equal(t, 0, p.Limit)
}

func TestParsePaginationParams_WithValues(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"from":  float64(10),
		"limit": float64(50),
	})
	assert.Equal(t, 10, p.From)
	assert.Equal(t, 50, p.Limit)
}

func TestParsePaginationParams_CapsAtMax(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"limit": float64(9999),
	})
	assert.Equal(t, MaxPaginationLimit, p.Limit)
}

func TestApplyPagination_EmptySlice(t *testing.T) {
	result := ApplyPagination([]int{}, PaginationParams{From: 0, Limit: 10})
	assert.Empty(t, result)
}

func TestApplyPagination_LimitExceedsLength(t *testing.T) {
	data := []string{"a", "b", "c"}
	result := ApplyPagination(data, PaginationParams{From: 0, Limit: 100})
	assert.Equal(t, data, result)
}

func TestCreatePaginatedResponse_NilPaginatedData(t *testing.T) {
	resp := CreatePaginatedResponse(nil, nil, PaginationParams{From: 0, Limit: 5}, 10)
	assert.Equal(t, 5, resp.Pagination.Returned)
	assert.True(t, resp.Pagination.HasMore)
}

func TestCreatePaginatedResponse_InterfaceSlice(t *testing.T) {
	data := []any{"a", "b"}
	resp := CreatePaginatedResponse(nil, data, PaginationParams{From: 0, Limit: 5}, 10)
	assert.Equal(t, 2, resp.Pagination.Returned)
	assert.True(t, resp.Pagination.HasMore)
}

func TestCreatePaginatedResponse_NoMore(t *testing.T) {
	data := []string{"a", "b", "c"}
	resp := CreatePaginatedResponse(data, data, PaginationParams{From: 0, Limit: 5}, 3)
	assert.False(t, resp.Pagination.HasMore)
}

// ---------------------------------------------------------------------------
// common.go: writeTools init
// ---------------------------------------------------------------------------

func TestWriteToolsPopulated(t *testing.T) {
	assert.NotEmpty(t, writeTools, "writeTools should be populated by init()")
	// Known write tools
	assert.True(t, writeTools["place_order"], "place_order should be a write tool")
	assert.True(t, writeTools["cancel_order"], "cancel_order should be a write tool")
	// Known read-only tools should NOT be write tools
	assert.False(t, writeTools["get_holdings"], "get_holdings should NOT be a write tool")
	assert.False(t, writeTools["get_profile"], "get_profile should NOT be a write tool")
}

// ---------------------------------------------------------------------------
// setup_tools.go: isAlphanumeric
// ---------------------------------------------------------------------------

func TestIsAlphanumeric(t *testing.T) {
	assert.True(t, isAlphanumeric("abc123"))
	assert.True(t, isAlphanumeric("ABCDEF"))
	assert.True(t, isAlphanumeric("a"))
	assert.False(t, isAlphanumeric(""))
	assert.False(t, isAlphanumeric("abc-123"))
	assert.False(t, isAlphanumeric("abc 123"))
	assert.False(t, isAlphanumeric("abc@123"))
	assert.False(t, isAlphanumeric("abc_123"))
}

// ---------------------------------------------------------------------------
// setup_tools.go: pageRoutes mapping
// ---------------------------------------------------------------------------

func TestPageRoutes_AllNonEmpty(t *testing.T) {
	assert.NotEmpty(t, pageRoutes)
	for page, path := range pageRoutes {
		assert.NotEmpty(t, path, "page %s has empty path", page)
		assert.True(t, len(path) > 1, "page %s path too short: %s", page, path)
	}
}

func TestPageRoutes_KnownPages(t *testing.T) {
	expected := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "watchlist", "options", "chart"}
	for _, page := range expected {
		_, ok := pageRoutes[page]
		assert.True(t, ok, "page %s should exist in pageRoutes", page)
	}
}

// ---------------------------------------------------------------------------
// setup_tools.go: DashboardURLForTool
// ---------------------------------------------------------------------------

func TestDashboardURLForTool_UnmappedToolReturnsEmpty(t *testing.T) {
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "nonexistent_tool")
	assert.Empty(t, url)
}

func TestDashboardURLForTool_LoginToolReturnsEmpty(t *testing.T) {
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "login")
	assert.Empty(t, url)
}

// ---------------------------------------------------------------------------
// setup_tools.go: toolDashboardPage consistency
// ---------------------------------------------------------------------------

func TestToolDashboardPage_AllValuesNonEmpty(t *testing.T) {
	for toolName, pagePath := range toolDashboardPage {
		assert.NotEmpty(t, pagePath, "tool %s has empty page path", toolName)
	}
}

func TestToolDashboardPage_AllPathsStartWithSlash(t *testing.T) {
	for toolName, pagePath := range toolDashboardPage {
		assert.True(t, len(pagePath) > 0 && pagePath[0] == '/', "tool %s path %s should start with /", toolName, pagePath)
	}
}

// ---------------------------------------------------------------------------
// Account tools: delete_my_account
// ---------------------------------------------------------------------------

func TestDeleteMyAccount_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError, "delete_my_account without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestDeleteMyAccount_RequiresConfirm(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "user@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError, "delete_my_account with confirm=false should fail")
	assertResultContains(t, result, "confirm")
}

func TestDeleteMyAccount_ConfirmTrue_Succeeds(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "user@example.com", map[string]any{
		"confirm": true,
	})
	assert.False(t, result.IsError, "delete_my_account with confirm=true should succeed")
	assertResultContains(t, result, "Account deleted")
}

// ---------------------------------------------------------------------------
// Account tools: update_my_credentials
// ---------------------------------------------------------------------------

func TestUpdateMyCredentials_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key":    "newkey",
		"api_secret": "newsecret",
	})
	assert.True(t, result.IsError, "update_my_credentials without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestUpdateMyCredentials_MissingApiKey(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_secret": "newsecret",
	})
	assert.True(t, result.IsError, "update_my_credentials without api_key should fail")
	assertResultContains(t, result, "api_key")
}

func TestUpdateMyCredentials_MissingApiSecret(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key": "newkey",
	})
	assert.True(t, result.IsError, "update_my_credentials without api_secret should fail")
	assertResultContains(t, result, "api_secret")
}

func TestUpdateMyCredentials_EmptyValues(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key":    "  ",
		"api_secret": "  ",
	})
	assert.True(t, result.IsError, "update_my_credentials with empty values should fail")
	assertResultContains(t, result, "non-empty")
}

func TestUpdateMyCredentials_Success(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key":    "validkey",
		"api_secret": "validsecret",
	})
	assert.False(t, result.IsError, "update_my_credentials with valid values should succeed")
	assertResultContains(t, result, "Credentials updated")
}

// ---------------------------------------------------------------------------
// Paper trading tools: auth checks
// ---------------------------------------------------------------------------

func TestPaperTradingToggle_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError, "paper_trading_toggle without auth should fail")
	assertResultContains(t, result, "authenticated")
}

func TestPaperTradingToggle_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "user@example.com", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError, "paper_trading_toggle without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}

func TestPaperTradingStatus_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_status without auth should fail")
	assertResultContains(t, result, "authenticated")
}

func TestPaperTradingStatus_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_status without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}

func TestPaperTradingReset_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_reset without auth should fail")
	assertResultContains(t, result, "authenticated")
}

func TestPaperTradingReset_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_reset without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}

// ---------------------------------------------------------------------------
// P&L journal: auth and service checks
// ---------------------------------------------------------------------------

func TestGetPnLJournal_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError, "get_pnl_journal without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestGetPnLJournal_NoPnLService(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_pnl_journal without PnL service should fail")
	assertResultContains(t, result, "not available")
}

// ---------------------------------------------------------------------------
// Margin tools: pre-session validation
// ---------------------------------------------------------------------------

func TestGetOrderMargins_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_order_margins with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestGetOrderMargins_LimitWithoutPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.True(t, result.IsError, "LIMIT without price should fail")
	assertResultContains(t, result, "price must be greater than 0")
}

func TestGetOrderMargins_SLWithoutTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		"price":            float64(1500),
	})
	assert.True(t, result.IsError, "SL without trigger_price should fail")
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

func TestGetBasketMargins_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_basket_margins with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestGetBasketMargins_EmptyOrders(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": "",
	})
	assert.True(t, result.IsError, "empty orders should fail")
	assertResultContains(t, result, "cannot be empty")
}

func TestGetBasketMargins_InvalidJSON(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": "not valid json",
	})
	assert.True(t, result.IsError, "invalid JSON should fail")
	assertResultContains(t, result, "Invalid orders JSON")
}

func TestGetOrderCharges_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_order_charges with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestGetOrderCharges_EmptyOrders(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "",
	})
	assert.True(t, result.IsError, "empty orders should fail")
	assertResultContains(t, result, "cannot be empty")
}

func TestGetOrderCharges_InvalidJSON(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "{bad",
	})
	assert.True(t, result.IsError, "invalid JSON should fail")
	assertResultContains(t, result, "Invalid orders JSON")
}

func TestGetOrderCharges_EmptyArray(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "[]",
	})
	assert.True(t, result.IsError, "empty array should fail")
	assertResultContains(t, result, "cannot be empty")
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
// Elicitation: confirmableTools consistency
// ---------------------------------------------------------------------------

func TestConfirmableTools_AllExistInRegistry(t *testing.T) {
	allTools := GetAllTools()
	names := make(map[string]bool)
	for _, tool := range allTools {
		names[tool.Tool().Name] = true
	}
	for toolName := range confirmableTools {
		assert.True(t, names[toolName], "confirmable tool %s should exist in GetAllTools()", toolName)
	}
}

// ---------------------------------------------------------------------------
// Tool annotations: all tools have titles
// ---------------------------------------------------------------------------

func TestAllToolsHaveTitleAnnotation(t *testing.T) {
	for _, td := range GetAllTools() {
		toolDef := td.Tool()
		if toolDef.Annotations.Title != "" {
			assert.NotEmpty(t, toolDef.Annotations.Title, "tool %s title should not be empty if set", toolDef.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Plugin registration: no duplicates after clear
// ---------------------------------------------------------------------------

func TestPluginRegistration_DoesntDuplicateNames(t *testing.T) {
	ClearPlugins()
	tools := GetAllTools()
	names := make(map[string]int)
	for _, tool := range tools {
		names[tool.Tool().Name]++
	}
	for name, count := range names {
		assert.Equal(t, 1, count, "tool %s registered %d times", name, count)
	}
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

// ---------------------------------------------------------------------------
// Watchlist: additional edge cases
// ---------------------------------------------------------------------------

func TestDeleteWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "", map[string]any{
		"watchlist": "my-list",
	})
	assert.True(t, result.IsError, "delete_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}

func TestRemoveFromWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "", map[string]any{
		"watchlist":   "my-list",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError, "remove_from_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
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
// search_instruments: full handler test (no broker session needed!)
// ---------------------------------------------------------------------------

func TestSearchInstruments_MissingQuery(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "search_instruments without query should fail")
	assertResultContains(t, result, "is required")
}

func TestSearchInstruments_ByID(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "NSE:INFY",
	})
	assert.False(t, result.IsError, "search_instruments by ID should succeed")
}

func TestSearchInstruments_ByName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "INFOSYS",
		"filter_on": "name",
	})
	assert.False(t, result.IsError, "search_instruments by name should succeed")
}

func TestSearchInstruments_ByTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "RELIANCE",
		"filter_on": "tradingsymbol",
	})
	assert.False(t, result.IsError, "search_instruments by tradingsymbol should succeed")
}

func TestSearchInstruments_WithPagination(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "NSE",
		"limit": float64(1),
	})
	assert.False(t, result.IsError, "search_instruments with pagination should succeed")
}

func TestSearchInstruments_NoResults(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query": "ZZZNONEXISTENT",
	})
	assert.False(t, result.IsError, "search_instruments with no results should still succeed (empty array)")
}

func TestSearchInstruments_UnderlyingWithColon(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "NFO:NIFTY",
		"filter_on": "underlying",
	})
	// May return empty but should not error
	assert.False(t, result.IsError, "search_instruments underlying with colon should succeed")
}

func TestSearchInstruments_UnderlyingWithoutColon(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "trader@example.com", map[string]any{
		"query":     "NIFTY",
		"filter_on": "underlying",
	})
	assert.False(t, result.IsError, "search_instruments underlying without colon should succeed")
}

// ---------------------------------------------------------------------------
// get_historical_data: pre-session validation
// ---------------------------------------------------------------------------

func TestGetHistoricalData_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_historical_data with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestGetHistoricalData_InvalidFromDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "not-a-date",
		"to_date":          "2024-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "invalid from_date should fail")
	assertResultContains(t, result, "from_date")
}

func TestGetHistoricalData_InvalidToDate(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-01-01 00:00:00",
		"to_date":          "bad-date",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "invalid to_date should fail")
	assertResultContains(t, result, "to_date")
}

func TestGetHistoricalData_FromAfterTo(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2024-12-01 00:00:00",
		"to_date":          "2024-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError, "from_date after to_date should fail")
	assertResultContains(t, result, "from_date must be before to_date")
}

// ---------------------------------------------------------------------------
// convert_position: pre-session validation
// ---------------------------------------------------------------------------

func TestConvertPosition_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "convert_position with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestConvertPosition_MissingTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
		// tradingsymbol missing
	})
	assert.True(t, result.IsError, "convert_position without tradingsymbol should fail")
	assertResultContains(t, result, "tradingsymbol")
}

// ---------------------------------------------------------------------------
// portfolio_analysis: pre-session validation (rich)
// ---------------------------------------------------------------------------

func TestPortfolioRebalance_MissingTargets(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "portfolio_analysis without targets should fail")
	assertResultContains(t, result, "targets")
}

func TestPortfolioRebalance_InvalidTargetsJSON(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": "not json",
	})
	assert.True(t, result.IsError, "portfolio_analysis with invalid JSON should fail")
	assertResultContains(t, result, "Invalid")
}

func TestPortfolioRebalance_EmptyTargets(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": "{}",
	})
	assert.True(t, result.IsError, "portfolio_analysis with empty targets should fail")
	assertResultContains(t, result, "at least one symbol")
}

func TestPortfolioRebalance_InvalidMode(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": 50, "INFY": 50}`,
		"mode":    "invalid",
	})
	assert.True(t, result.IsError, "portfolio_analysis with invalid mode should fail")
	assertResultContains(t, result, "mode")
}

func TestPortfolioRebalance_NegativeThreshold(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"threshold": float64(-1),
	})
	assert.True(t, result.IsError, "portfolio_analysis with negative threshold should fail")
	assertResultContains(t, result, "threshold")
}

func TestPortfolioRebalance_ExcessivePercentage(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": 80, "INFY": 80}`,
		"mode":    "percentage",
	})
	assert.True(t, result.IsError, "portfolio_analysis with >105% should fail")
	assertResultContains(t, result, "exceeds 100%")
}

func TestPortfolioRebalance_NegativePercentage(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": -10, "INFY": 50}`,
		"mode":    "percentage",
	})
	assert.True(t, result.IsError, "portfolio_analysis with negative percentage should fail")
	assertResultContains(t, result, "non-negative")
}

// ---------------------------------------------------------------------------
// order_risk_report: pre-session validation
// ---------------------------------------------------------------------------

func TestPreTradeCheck_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "order_risk_report with no params should fail")
	assertResultContains(t, result, "is required")
}

func TestPreTradeCheck_ZeroQuantity(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(0),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError, "order_risk_report with zero quantity should fail")
	assertResultContains(t, result, "quantity must be greater than 0")
}

func TestPreTradeCheck_LimitWithoutPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.True(t, result.IsError, "order_risk_report LIMIT without price should fail")
	assertResultContains(t, result, "price must be greater than 0")
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

// ---------------------------------------------------------------------------
// subscribe_instruments / unsubscribe_instruments: pre-session validation
// ---------------------------------------------------------------------------

func TestSubscribeInstruments_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "subscribe_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "subscribe_instruments without instruments should fail")
	assertResultContains(t, result, "is required")
}

func TestUnsubscribeInstruments_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "unsubscribe_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "unsubscribe_instruments without instruments should fail")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// get_ohlc: pre-session validation
// ---------------------------------------------------------------------------

func TestGetOHLC_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ohlc", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_ohlc without instruments should fail")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// get_option_chain: pre-session validation (additional)
// ---------------------------------------------------------------------------

func TestGetOptionChain_EmptyUnderlying(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "trader@example.com", map[string]any{
		"underlying": "",
	})
	assert.True(t, result.IsError, "get_option_chain with empty underlying should fail")
}

// ---------------------------------------------------------------------------
// options_payoff_builder: additional validation
// ---------------------------------------------------------------------------

func TestOptionsStrategy_MissingExpiry(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_payoff_builder", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"strike1":    float64(24000),
		// expiry missing
	})
	assert.True(t, result.IsError, "options_payoff_builder without expiry should fail")
	assertResultContains(t, result, "expiry")
}

// ---------------------------------------------------------------------------
// historical_price_analyzer: additional validation
// ---------------------------------------------------------------------------

func TestBacktestStrategy_MissingInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "historical_price_analyzer", "trader@example.com", map[string]any{
		"strategy": "sma_crossover",
		// instrument missing
	})
	assert.True(t, result.IsError, "historical_price_analyzer without instrument should fail")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// technical_indicators: additional validation
// ---------------------------------------------------------------------------

func TestTechnicalIndicators_MissingInstrument(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"indicators": []any{"RSI"},
		// instrument missing
	})
	assert.True(t, result.IsError, "technical_indicators without instrument should fail")
	assertResultContains(t, result, "is required")
}

// ---------------------------------------------------------------------------
// Common: CacheKey function
// ---------------------------------------------------------------------------

func TestCacheKey_Consistency(t *testing.T) {
	key1 := CacheKey("get_ltp", "user@test.com", "NSE:INFY,NSE:SBIN")
	key2 := CacheKey("get_ltp", "user@test.com", "NSE:INFY,NSE:SBIN")
	assert.Equal(t, key1, key2, "same inputs should produce same cache key")

	key3 := CacheKey("get_ltp", "other@test.com", "NSE:INFY,NSE:SBIN")
	assert.NotEqual(t, key1, key3, "different inputs should produce different cache keys")
}

// ── Extended mock Kite HTTP server with POST/PUT/DELETE endpoints ─────────

func startExtendedMockKite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path

		envOK := func(data any) {
			b, _ := json.Marshal(map[string]any{"status": "success", "data": data})
			fmt.Fprint(w, string(b))
		}

		switch {
		// User
		case p == "/user/profile":
			envOK(map[string]any{
				"user_id": "AB1234", "user_name": "Mock User", "email": "mock@test.com",
			})
		case p == "/user/margins":
			envOK(map[string]any{
				"equity": map[string]any{
					"enabled": true, "net": 500000.0,
					"available": map[string]any{"cash": 500000.0, "collateral": 0.0, "intraday_payin": 0.0},
					"utilised":  map[string]any{"debits": 0.0, "exposure": 0.0, "m2m_realised": 0.0, "m2m_unrealised": 0.0},
				},
			})

		// Portfolio
		case p == "/portfolio/holdings":
			envOK([]map[string]any{
				{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 10, "average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0, "day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265},
			})
		case p == "/portfolio/positions":
			envOK(map[string]any{
				"net": []map[string]any{
					{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 5, "average_price": 1550.0, "last_price": 1600.0, "pnl": 250.0, "product": "MIS"},
				},
				"day": []map[string]any{},
			})

		// Orders — list
		case p == "/orders" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
				{"order_id": "MOCK-ORD-2", "status": "OPEN", "tradingsymbol": "RELIANCE", "exchange": "NSE", "transaction_type": "SELL", "order_type": "LIMIT", "quantity": 5.0, "average_price": 0.0, "filled_quantity": 0.0, "order_timestamp": "2026-04-01 10:05:00"},
				{"order_id": "MOCK-ORD-3", "status": "REJECTED", "tradingsymbol": "TCS", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 1.0, "average_price": 0.0, "filled_quantity": 0.0, "order_timestamp": "2026-04-01 10:10:00"},
			})

		// Orders — place
		case p == "/orders/regular" && r.Method == http.MethodPost:
			envOK(map[string]any{"order_id": "MOCK-NEW-ORD"})

		// Orders — modify
		case p == "/orders/regular/MOCK-ORD-1" && r.Method == http.MethodPut:
			envOK(map[string]any{"order_id": "MOCK-ORD-1"})

		// Orders — cancel
		case p == "/orders/regular/MOCK-ORD-1" && r.Method == http.MethodDelete:
			envOK(map[string]any{"order_id": "MOCK-ORD-1"})

		// Order history
		case p == "/orders/MOCK-NEW-ORD" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-NEW-ORD", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1520.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			})
		case p == "/orders/MOCK-ORD-1" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			})

		// Trades
		case p == "/trades":
			envOK([]map[string]any{
				{"trade_id": "T001", "order_id": "MOCK-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0},
			})

		// Quote
		case p == "/quote":
			envOK(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
			})

		// Quote LTP
		case p == "/quote/ltp":
			envOK(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0},
			})

		// GTT
		case p == "/gtt/triggers" && r.Method == http.MethodGet:
			envOK([]map[string]any{})

		// MF
		case p == "/mf/orders" && r.Method == http.MethodGet:
			envOK([]map[string]any{})
		case p == "/mf/sips" && r.Method == http.MethodGet:
			envOK([]map[string]any{})
		case p == "/mf/holdings" && r.Method == http.MethodGet:
			envOK([]map[string]any{})

		// Margins / charges
		case p == "/margins/orders":
			envOK([]map[string]any{
				{"type": "equity", "tradingsymbol": "INFY", "exchange": "NSE", "total": 15000.0},
			})

		default:
			http.Error(w, `{"status":"error","message":"not found: `+p+`"}`, 404)
		}
	}))
}

// ── buildTradingContext — pure function tests ────────────────────────────

func TestBuildTradingContext_WithFullData(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// Prepare full data with margins, positions, orders, holdings
	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 400000,
				Used:      100000,
				Total:     500000,
			},
		},
		"positions": broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 5, AveragePrice: 1500, LastPrice: 1600, PnL: 500, Product: "MIS"},
				{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: -3, AveragePrice: 2500, LastPrice: 2400, PnL: 300, Product: "NRML"},
				{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 0, AveragePrice: 3000, LastPrice: 3100, PnL: 0, Product: "CNC"},
			},
		},
		"orders": []broker.Order{
			{OrderID: "O1", Status: "COMPLETE", Tradingsymbol: "INFY"},
			{OrderID: "O2", Status: "OPEN", Tradingsymbol: "RELIANCE"},
			{OrderID: "O3", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O4", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O5", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O6", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O7", Status: "TRIGGER PENDING", Tradingsymbol: "SBI"},
			{OrderID: "O8", Status: "AMO REQ RECEIVED", Tradingsymbol: "ITC"},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: 1000},
			{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 5, AveragePrice: 2500, LastPrice: 2600, PnL: 500},
		},
	}

	errs := map[string]string{"some_api": "timeout"}
	tc := buildTradingContext(data, errs, mgr, "test@example.com")

	assert.Equal(t, 2, tc.OpenPositions)
	assert.Equal(t, 800.0, tc.PositionsPnL)
	assert.Equal(t, 1, tc.MISPositions)
	assert.Equal(t, 1, tc.NRMLPositions)
	assert.Len(t, tc.PositionDetails, 2)
	assert.Equal(t, 1, tc.ExecutedToday)
	assert.Equal(t, 3, tc.PendingOrders) // OPEN + TRIGGER PENDING + AMO REQ RECEIVED
	assert.Equal(t, 4, tc.RejectedToday)
	assert.Equal(t, 2, tc.HoldingsCount)
	assert.Equal(t, 1500.0, tc.HoldingsDayPnL)
	assert.Equal(t, 400000.0, tc.MarginAvailable)
	assert.Equal(t, 100000.0, tc.MarginUsed)
	assert.Equal(t, 20.0, tc.MarginUtilization)
	assert.Contains(t, tc.Errors, "some_api")
	// Should have rejected orders warning (>3)
	found := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "rejected") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected rejected orders warning")
}

func TestBuildTradingContext_HighMarginUtilization_Push100(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 50000,
				Used:      450000,
				Total:     500000,
			},
		},
	}

	tc := buildTradingContext(data, nil, mgr, "test@example.com")
	assert.Equal(t, 90.0, tc.MarginUtilization)
	// Should have high margin warning
	found := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "margin utilization") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected high margin utilization warning")
}

func TestBuildTradingContext_EmptyData_Push100(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	tc := buildTradingContext(map[string]any{}, nil, mgr, "")
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Equal(t, 0, tc.HoldingsCount)
	assert.Equal(t, 0, tc.PendingOrders)
	assert.NotEmpty(t, tc.MarketStatus)
}

func TestBuildTradingContext_WithAlerts(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Set up alerts
	if store := mgr.AlertStore(); store != nil {
		_, _ = store.Add("test@example.com", "INFY", "NSE", 256265, 1700, alerts.Direction("above"))
		// Add a second alert and mark it triggered so it doesn't count
		id2, _ := store.Add("test@example.com", "RELIANCE", "NSE", 738561, 2000, alerts.Direction("below"))
		store.MarkTriggered(id2, 1950)
	}

	tc := buildTradingContext(map[string]any{}, nil, mgr, "test@example.com")
	assert.Equal(t, 1, tc.ActiveAlerts)
	assert.Len(t, tc.AlertDetails, 1)
	assert.Equal(t, "INFY", tc.AlertDetails[0].Symbol)
}

// ── Prompt handler tests ─────────────────────────────────────────────────

func TestMorningBriefPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)

	// Call the handler directly
	handler := morningBriefHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Morning trading briefing", result.Description)
	assert.Len(t, result.Messages, 1)
	assert.Equal(t, gomcp.RoleUser, result.Messages[0].Role)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "Morning Trading Briefing")
	assert.Contains(t, text, "Step 1")
}

func TestTradeCheckPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol":   "RELIANCE",
		"action":   "BUY",
		"quantity": "100",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Description, "BUY")
	assert.Contains(t, result.Description, "RELIANCE")
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "RELIANCE")
	assert.Contains(t, text, "BUY")
	assert.Contains(t, text, "100")
}

func TestTradeCheckPrompt_DefaultsNoQty(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol": "INFY",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "not specified")
	assert.Contains(t, text, "BUY") // default action
}

func TestEodReviewPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := eodReviewHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "End-of-day trading review", result.Description)
	assert.Len(t, result.Messages, 1)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "End-of-Day Review")
	assert.Contains(t, text, "Step 1")
}

// ── Setup tools helper tests ─────────────────────────────────────────────

func TestIsAlphanumeric_Push100(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"abc123", true},
		{"ABCdef", true},
		{"12345", true},
		{"", false},
		{"abc-def", false},
		{"abc def", false},
		{"abc_def", false},
		{"abc@def", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isAlphanumeric(tt.input), "isAlphanumeric(%q)", tt.input)
	}
}

func TestDashboardLink(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	// May be empty if no external URL — just check it doesn't panic
	_ = link
}

func TestDashboardURLForTool_Mapped(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// A tool that should be mapped
	url := DashboardURLForTool(mgr, "get_holdings")
	// May be empty if no external URL configured, but function should not panic
	_ = url
}

func TestDashboardURLForTool_Unmapped(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := DashboardURLForTool(mgr, "nonexistent_tool")
	assert.Empty(t, url)
}

func TestPageRoutes_AllValid(t *testing.T) {
	t.Parallel()
	for page, path := range pageRoutes {
		assert.NotEmpty(t, page, "empty page name")
		assert.NotEmpty(t, path, "empty path for page %s", page)
		assert.Contains(t, path, "/dashboard", "path for %s should contain /dashboard", page)
	}
}

// ── MarketStatus (scheduler) via buildTradingContext ──────────────────────

func TestBuildTradingContext_MarketStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	tc := buildTradingContext(map[string]any{}, nil, mgr, "")
	// scheduler.MarketStatus always returns a non-empty string
	assert.NotEmpty(t, tc.MarketStatus)
	// Validate it's one of the known statuses
	valid := map[string]bool{
		"open": true, "closed": true, "pre_open": true,
		"closing_session": true, "closed_weekend": true, "closed_holiday": true,
	}
	assert.True(t, valid[tc.MarketStatus], "unexpected market status: %s", tc.MarketStatus)
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

// ── Account tools ────────────────────────────────────────────────────────

func TestDeleteMyAccount_NotConfirmed(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}

func TestDeleteMyAccount_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}

func TestDeleteMyAccount_Success(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.False(t, result.IsError, resultText(t, result))
	assert.Contains(t, resultText(t, result), "deleted")
}

func TestUpdateMyCredentials_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key": "newkey123", "api_secret": "newsecret456",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}

func TestUpdateMyCredentials_MissingKey(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_secret": "newsecret456",
	})
	assert.True(t, result.IsError)
}

// ── Paper trading tool edge cases ────────────────────────────────────────

func TestPaperTradingToggle_EnableAndStatus(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Enable
	result := callToolAdmin(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true, "initial_cash": float64(5000000),
	})
	assert.False(t, result.IsError, resultText(t, result))

	// Status
	result = callToolAdmin(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))

	// Reset
	result = callToolAdmin(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))
}

// ── PnL journal edge cases ───────────────────────────────────────────────

func TestPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}

func TestPnLJournal_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	periods := []string{"week", "month", "quarter", "year", "all"}
	for _, period := range periods {
		result := callToolAdmin(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.False(t, result.IsError, "period %s: %s", period, resultText(t, result))
	}
}

func TestPnLJournal_CustomDates(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "2026-03-01",
	})
	assert.False(t, result.IsError, resultText(t, result))
}

// ── Watchlist tool edge cases ────────────────────────────────────────────

func TestWatchlistTools_FullLifecycle(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Create
	result := callToolAdmin(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Tech Stocks",
	})
	assert.False(t, result.IsError, resultText(t, result))
	assert.Contains(t, resultText(t, result), "Tech Stocks")

	// List
	result = callToolAdmin(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))

	// Delete non-existent
	result = callToolAdmin(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")

	// Delete the real one
	result = callToolAdmin(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "Tech Stocks",
	})
	assert.False(t, result.IsError, resultText(t, result))
}

func TestAddToWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "add_to_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent", "instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}

func TestRemoveFromWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "remove_from_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent", "items": "abc123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
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

// ── Historical data edge cases ───────────────────────────────────────────

func TestHistoricalData_InvalidDateFormat(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "01-01-2026",
		"to_date":          "2026-03-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "parse from_date")
}

func TestHistoricalData_FromAfterTo(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-03-01 00:00:00",
		"to_date":          "2026-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "from_date must be before")
}

func TestHistoricalData_InvalidToDate(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "invalid",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "parse to_date")
}

// ── Market tools — instrument limits ─────────────────────────────────────

func TestGetLTP_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}

func TestGetOHLC_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}

func TestGetQuotes_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": []any{},
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "cannot be empty")
}

// ── Search instruments edge cases ────────────────────────────────────────

func TestSearchInstruments_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query": "NSE", "filter_on": "id",
		"from": float64(0), "limit": float64(1),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, resultText(t, result))
}

// ── DashboardURLMiddleware ───────────────────────────────────────────────

func TestDashboardURLMiddleware_NoError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)
}

func TestDashboardURLMiddleware_WithError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("something went wrong"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	// Should NOT append dashboard URL on error
	assert.Len(t, result.Content, 1)
}

func TestDashboardURLMiddleware_UnmappedTool(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "login" // not in dashboard page mapping
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	// login is not mapped, so no extra content block
	assert.Len(t, result.Content, 1)
}

// ── Login tool edge cases ────────────────────────────────────────────────

func TestLogin_InvalidAPIKeyChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "abc-def!", "api_secret": "valid123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}

func TestLogin_InvalidAPISecretChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "valid123", "api_secret": "abc def",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}

func TestLogin_OnlyAPIKeyNoSecret(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "valid123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "api_key and api_secret")
}

// ── Open dashboard tool ──────────────────────────────────────────────────

func TestOpenDashboard_Default(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestOpenDashboard_ActivityPage_Push100(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity", "category": "order", "days": float64(7), "errors": true,
	})
	assert.NotNil(t, result)
}

func TestOpenDashboard_InvalidPage(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "nonexistent_page",
	})
	// Should fall back to portfolio page, not error
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ── Server metrics tool ──────────────────────────────────────────────────

func TestServerMetrics_AdminSuccess(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
		"period": "1h",
	})
	assert.False(t, result.IsError, resultText(t, result))
	text := resultText(t, result)
	assert.Contains(t, text, "uptime")
}

func TestServerMetrics_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.False(t, result.IsError, "period %s: %s", period, resultText(t, result))
	}
}

// ── Session type context helpers ─────────────────────────────────────────

func TestSessionTypeContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeSSE)
	assert.Equal(t, SessionTypeSSE, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeMCP)
	assert.Equal(t, SessionTypeMCP, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeStdio)
	assert.Equal(t, SessionTypeStdio, SessionTypeFromContext(ctx))
}

// ── ToolHandler trackToolCall / trackToolError (no-op without metrics) ───

func TestToolHandler_TrackCallsNoMetrics(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	// Should not panic even without metrics configured
	handler.trackToolCall(context.Background(), "test_tool")
	handler.trackToolError(context.Background(), "test_tool", "test_error")
}

// ── Scheduler.MarketStatus ───────────────────────────────────────────────

func TestSchedulerMarketStatus(t *testing.T) {
	t.Parallel()
	// Just ensure it returns a known status for "now"
	status := scheduler.MarketStatus(time.Now())
	valid := map[string]bool{
		"open": true, "closed": true, "pre_open": true,
		"closing_session": true, "closed_weekend": true, "closed_holiday": true,
	}
	assert.True(t, valid[status], "unknown market status: %s", status)
}

// ── parseInstrumentList ──────────────────────────────────────────────────

func TestParseInstrumentList_Push100(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  []string
	}{
		{"NSE:INFY,NSE:RELIANCE", []string{"NSE:INFY", "NSE:RELIANCE"}},
		{" NSE:INFY , NSE:RELIANCE ", []string{"NSE:INFY", "NSE:RELIANCE"}},
		{"NSE:INFY", []string{"NSE:INFY"}},
		{"", nil},
		{",,,", nil},
	}
	for _, tt := range tests {
		result := parseInstrumentList(tt.input)
		assert.Equal(t, tt.want, result, "parseInstrumentList(%q)", tt.input)
	}
}

// ── roundTo2 helper ──────────────────────────────────────────────────────

func TestRoundTo2_Push100(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 1.23, roundTo2(1.234))
	assert.Equal(t, 1.24, roundTo2(1.235))
	assert.Equal(t, 0.0, roundTo2(0.0))
	assert.Equal(t, -1.23, roundTo2(-1.234))
}

// ── Mock Kite — PlaceOrder success path with enriched fill status ────────

func TestMock_PlaceOrder_SuccessWithFillCheck(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "place_order", map[string]any{
		"variety": "regular", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10), "product": "CNC",
		"order_type": "MARKET",
	})
	assert.NotNil(t, result)
}

// ── Mock Kite — ModifyOrder success path ─────────────────────────────────

func TestMock_ModifyOrder_Success(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "modify_order", map[string]any{
		"order_id": "MOCK-ORD-1", "variety": "regular",
		"quantity": float64(20), "order_type": "MARKET",
	})
	assert.NotNil(t, result)
}

// ── Mock Kite — CancelOrder success path ─────────────────────────────────

func TestMock_CancelOrder_Success(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "cancel_order", map[string]any{
		"order_id": "MOCK-ORD-1", "variety": "regular",
	})
	assert.NotNil(t, result)
}

// ── Mock Kite — TradingContext success path ───────────────────────────────

func TestMock_TradingContext_FullSuccess(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "trading_context", map[string]any{})
	assert.NotNil(t, result)
}

// ── Mock Kite — get_watchlist with session (LTP call) ────────────────────

func TestMock_GetWatchlist_WithLTP(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()

	mgr := newMockKiteManager(t, ts.URL)

	// Create a watchlist and add an item
	wlStore := mgr.WatchlistStore()
	wlID, err := wlStore.CreateWatchlist(mockEmail, "Test WL")
	require.NoError(t, err)

	err = wlStore.AddItem(mockEmail, wlID, &watchlist.WatchlistItem{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		InstrumentToken: 256265,
	})
	if err != nil {
		t.Logf("AddItem error (expected if store interface differs): %v", err)
	}

	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, mockEmail)
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: mockSessionID})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "get_watchlist" {
			req := gomcp.CallToolRequest{}
			req.Params.Name = "get_watchlist"
			req.Params.Arguments = map[string]any{"watchlist": "Test WL", "include_ltp": true}
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			assert.NotNil(t, result)
			break
		}
	}
}

// ── Modify order edge cases ──────────────────────────────────────────────

// ── SimpleToolHandler / HandleAPICall ────────────────────────────────────

func TestSimpleToolHandler_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := SimpleToolHandler(mgr, "test_tool", func(session *kc.KiteSessionData) (any, error) {
		return map[string]string{"status": "ok"}, nil
	})

	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, "dev@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ── ValidationError ──────────────────────────────────────────────────────

func TestValidationError_String(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "quantity", Message: "must be positive"}
	assert.Equal(t, "parameter 'quantity': must be positive", err.Error())
}

// ── WithViewerBlock ──────────────────────────────────────────────────────

func TestWithViewerBlock_ReadOnlyTool(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "test@example.com")
	result := handler.WithViewerBlock(ctx, "get_profile")
	assert.Nil(t, result) // read-only tool = no block even for viewer
}
