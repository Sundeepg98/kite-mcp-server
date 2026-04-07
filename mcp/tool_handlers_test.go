package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newTestManager creates a minimal Manager that never makes HTTP calls.
// It uses instruments.Config.TestData to skip instrument downloading.
func newTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Provide minimal test data so instruments.New skips HTTP loading.
	testData := map[uint32]*instruments.Instrument{
		256265: {
			InstrumentToken: 256265,
			Tradingsymbol:   "INFY",
			Name:            "INFOSYS",
			Exchange:        "NSE",
			Segment:         "NSE",
			InstrumentType:  "EQ",
		},
		408065: {
			InstrumentToken: 408065,
			Tradingsymbol:   "RELIANCE",
			Name:            "RELIANCE INDUSTRIES",
			Exchange:        "NSE",
			Segment:         "NSE",
			InstrumentType:  "EQ",
		},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
	})
	require.NoError(t, err)

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

// callToolWithManager invokes a tool handler with the given manager and context params.
// Only pre-session validation paths are exercised (bare context, no MCP session).
func callToolWithManager(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------

func TestAllToolsRegistered(t *testing.T) {
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
		"portfolio_summary", "pre_trade_check",
		"backtest_strategy", "technical_indicators",
		"options_greeks", "options_strategy",
		"sector_exposure", "tax_harvest_analysis",
		"sebi_compliance_status",
	}
	for _, name := range required {
		assert.True(t, names[name], "required tool %s should be registered", name)
	}
}

func TestAllToolsHaveUniqueNames(t *testing.T) {
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
	insts := make([]interface{}, 501)
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
	args := map[string]interface{}{
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
	args := map[string]interface{}{
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
	args := map[string]interface{}{
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
	args := map[string]interface{}{
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
		reduced := make(map[string]interface{})
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
	args := map[string]interface{}{
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
// Helper
// ---------------------------------------------------------------------------

func assertResultContains(t *testing.T, result *gomcp.CallToolResult, substr string) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatalf("result has no content to check for %q", substr)
	}
	text := result.Content[0].(gomcp.TextContent).Text
	assert.Contains(t, text, substr)
}
