package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
