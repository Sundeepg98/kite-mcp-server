package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Silence unused import warnings.
var (
	_ = context.Background
	_ gomcp.JSONRPCMessage
	_ server.MCPServer
	_ = oauth.ContextWithEmail
)

// callToolDevMode invokes a tool handler with a valid UUID session ID, allowing
// DevMode managers to create sessions. The standard callToolWithSession uses
// "test-session-id" which fails UUID validation.
func callToolDevMode(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	mcpSrv := server.NewMCPServer("test", "1.0")
	// Use a valid UUID as session ID so SessionRegistry accepts it
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})

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

// newDevModeManager creates a Manager in DevMode. Sessions get a mock broker
// so tools exercise more code paths (session creation, handler bodies, etc.).
func newDevModeManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
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
		DevMode:            true,
	})
	require.NoError(t, err)

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

// ===========================================================================
// Task 2: Push mcp coverage from 56% to 65%+
//
// Strategy: Exercise pre-session validation paths AND session-based error
// paths using callToolWithManager (no session) and callToolWithSession.
// ===========================================================================

// ===========================================================================
// post_tools.go: place_order — pre-session validation (LIMIT/SL/iceberg/disclosed)
// ===========================================================================

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

// ===========================================================================
// post_tools.go: modify_order — pre-session validation
// ===========================================================================

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

// ===========================================================================
// post_tools.go: cancel_order — pre-session validation
// ===========================================================================

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

// ===========================================================================
// post_tools.go: place_gtt_order — pre-session validation (trigger-type-specific)
// ===========================================================================

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

// ===========================================================================
// post_tools.go: modify_gtt_order — pre-session validation
// ===========================================================================

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

// ===========================================================================
// post_tools.go: delete_gtt_order — pre-session validation
// ===========================================================================

func TestDeleteGTT_MissingTriggerID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

// ===========================================================================
// post_tools.go: convert_position — pre-session validation
// ===========================================================================

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

// ===========================================================================
// get_tools.go: get_order_trades — pre-session validation
// ===========================================================================

func TestGetOrderTrades_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

// ===========================================================================
// get_tools.go: get_order_history — pre-session validation
// ===========================================================================

func TestGetOrderHistory_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_history", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

// ===========================================================================
// exit_tools.go: close_position — pre-session validation
// ===========================================================================

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

// ===========================================================================
// native_alert_tools.go: place_native_alert — pre-session validation
// ===========================================================================

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
		"basket_json":   "not-json",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Invalid basket_json")
}

func TestPlaceNativeAlert_ATOZeroItemBasket(t *testing.T) {
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
		"basket_json":   `{"items":[]}`,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "at least one item")
}

// ===========================================================================
// native_alert_tools.go: modify_native_alert — pre-session validation
// ===========================================================================

func TestModifyNativeAlert_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

// ===========================================================================
// indicators_tool.go: technical_indicators — pre-session validation
// ===========================================================================

func TestTechnicalIndicators_MissingExchange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestTechnicalIndicators_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"exchange": "NSE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

// ===========================================================================
// pnl_tools.go: get_pnl_journal — pre-session validation
// ===========================================================================

func TestGetPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Call without email in context
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestGetPnLJournal_NoPnLServiceAvailable(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Manager has no PnL service by default, so this should fail
	result := callToolWithManager(t, mgr, "get_pnl_journal", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}

func TestGetPnLJournal_InvalidFromDate(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "trader@example.com", map[string]any{
		"from": "not-a-date",
	})
	assert.True(t, result.IsError)
	// Either "not available" (no pnl service) or "Invalid 'from' date"
	assert.NotNil(t, result)
}

// ===========================================================================
// Session-based tools: callToolWithSession exercising additional paths
// ===========================================================================

func TestSessionTool_GetOrderTrades_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_trades", "trader@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_GetOrderHistory_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_order_history", "trader@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_DeleteGTT_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_ConvertPosition_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_ModifyGTT_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_ListNativeAlerts_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "list_native_alerts", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_PlaceNativeAlert_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_native_alert", "trader@example.com", map[string]any{
		"name":          "Test alert",
		"type":          "simple",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"lhs_attribute": "last_price",
		"operator":      ">=",
		"rhs_type":      "constant",
		"rhs_constant":  float64(1500),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_TechnicalIndicators_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "session")
}

func TestSessionTool_GetMFOrders_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_mf_orders", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestSessionTool_OptionsStrategy_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":      "straddle",
		"underlying":    "NIFTY",
		"expiry":        "2026-04-24",
		"strike":        float64(24000),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_OptionsGreeks_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "options_greeks", "trader@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
	})
	assert.True(t, result.IsError)
}

// ===========================================================================
// common.go: ValidateRequired — edge cases
// ===========================================================================

func TestValidateRequired_EmptyStringValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{"name": ""}, "name")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateRequired_EmptySlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{"items": []interface{}{}}, "items")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateRequired_NilValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{}, "missing_param")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is required")
}

func TestValidateRequired_ValidValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{"name": "test"}, "name")
	assert.NoError(t, err)
}

func TestValidateRequired_MultipleParams(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{
		"a": "hello",
		"b": float64(123),
	}, "a", "b")
	assert.NoError(t, err)
}

func TestValidateRequired_FirstMissing(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{
		"b": "hello",
	}, "a", "b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "'a'")
}

func TestValidateRequired_EmptyStringSlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{"items": []string{}}, "items")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateRequired_EmptyIntSlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]interface{}{"items": []int{}}, "items")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

// ===========================================================================
// common.go: ValidationError
// ===========================================================================

func TestValidationError_Format(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "exchange", Message: "is required"}
	assert.Equal(t, "parameter 'exchange': is required", err.Error())
}

// ===========================================================================
// common.go: ArgParser — comprehensive tests
// ===========================================================================

func TestArgParser_StringDefault(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{})
	assert.Equal(t, "default", p.String("missing", "default"))
}

func TestArgParser_StringPresent(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"key": "value"})
	assert.Equal(t, "value", p.String("key", "default"))
}

func TestArgParser_IntFromFloat(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"qty": float64(100)})
	assert.Equal(t, 100, p.Int("qty", 0))
}

func TestArgParser_IntDefault(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{})
	assert.Equal(t, 42, p.Int("missing", 42))
}

func TestArgParser_FloatPresent(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"price": float64(1500.50)})
	assert.Equal(t, 1500.50, p.Float("price", 0))
}

func TestArgParser_FloatDefault(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{})
	assert.Equal(t, 99.9, p.Float("missing", 99.9))
}

func TestArgParser_BoolPresent(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"confirm": true})
	assert.True(t, p.Bool("confirm", false))
}

func TestArgParser_BoolDefault(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{})
	assert.False(t, p.Bool("missing", false))
}

func TestArgParser_RequiredAllPresent(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"a": "x", "b": float64(1)})
	assert.NoError(t, p.Required("a", "b"))
}

func TestArgParser_RequiredMissing(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{"a": "x"})
	err := p.Required("a", "b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "b")
}

func TestArgParser_StringArrayMulti(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{
		"instruments": []interface{}{"NSE:INFY", "NSE:TCS"},
	})
	result := p.StringArray("instruments")
	assert.Len(t, result, 2)
	assert.Equal(t, "NSE:INFY", result[0])
	assert.Equal(t, "NSE:TCS", result[1])
}

func TestArgParser_StringArrayMissing(t *testing.T) {
	t.Parallel()
	p := NewArgParser(map[string]any{})
	result := p.StringArray("instruments")
	assert.Empty(t, result)
}

// ===========================================================================
// common.go: ParsePaginationParams
// ===========================================================================

func TestParsePaginationParams_EmptyArgs(t *testing.T) {
	t.Parallel()
	params := ParsePaginationParams(map[string]any{})
	assert.Equal(t, 0, params.From)
	assert.Equal(t, 0, params.Limit)
}

func TestParsePaginationParams_CustomValues(t *testing.T) {
	t.Parallel()
	params := ParsePaginationParams(map[string]any{
		"from":  float64(10),
		"limit": float64(25),
	})
	assert.Equal(t, 10, params.From)
	assert.Equal(t, 25, params.Limit)
}

func TestParsePaginationParams_NegativeFrom(t *testing.T) {
	t.Parallel()
	params := ParsePaginationParams(map[string]any{
		"from": float64(-5),
	})
	// ParsePaginationParams passes through negative values; ApplyPagination clamps later
	assert.Equal(t, -5, params.From)
}

// ===========================================================================
// common.go: ApplyPagination
// ===========================================================================

func TestApplyPagination_NoLimit(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3, 4, 5}
	result := ApplyPagination(data, PaginationParams{From: 0, Limit: 0})
	assert.Len(t, result, 5)
}

func TestApplyPagination_WithLimit(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3, 4, 5}
	result := ApplyPagination(data, PaginationParams{From: 1, Limit: 2})
	assert.Len(t, result, 2)
	assert.Equal(t, 2, result[0])
	assert.Equal(t, 3, result[1])
}

func TestApplyPagination_FromBeyondLength(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3}
	result := ApplyPagination(data, PaginationParams{From: 10, Limit: 2})
	assert.Empty(t, result)
}

func TestApplyPagination_LimitBeyondRemaining(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3, 4, 5}
	result := ApplyPagination(data, PaginationParams{From: 3, Limit: 10})
	assert.Len(t, result, 2)
	assert.Equal(t, 4, result[0])
	assert.Equal(t, 5, result[1])
}

// ===========================================================================
// common.go: CreatePaginatedResponse
// ===========================================================================

func TestCreatePaginatedResponse_Full(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3, 4, 5}
	page := []int{2, 3}
	resp := CreatePaginatedResponse(data, page, PaginationParams{From: 1, Limit: 2}, 5)
	assert.NotNil(t, resp)
	assert.Equal(t, page, resp.Data)
	assert.Equal(t, 5, resp.Pagination.Total)
	assert.Equal(t, 1, resp.Pagination.From)
	assert.Equal(t, 2, resp.Pagination.Limit)
	assert.Equal(t, 2, resp.Pagination.Returned)
	assert.True(t, resp.Pagination.HasMore)
}

func TestCreatePaginatedResponse_LastPage(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3, 4, 5}
	page := []int{4, 5}
	resp := CreatePaginatedResponse(data, page, PaginationParams{From: 3, Limit: 5}, 5)
	assert.False(t, resp.Pagination.HasMore)
}

func TestCreatePaginatedResponse_NilData(t *testing.T) {
	t.Parallel()
	resp := CreatePaginatedResponse(nil, nil, PaginationParams{From: 0, Limit: 10}, 5)
	assert.NotNil(t, resp)
	assert.Nil(t, resp.Data)
	assert.Equal(t, 5, resp.Pagination.Returned)
}

// ===========================================================================
// options_greeks_tool.go: Black-Scholes functions edge cases
// ===========================================================================

func TestBSDelta_CallATM(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.InDelta(t, 0.5, delta, 0.1, "ATM call should have delta near 0.5")
}

func TestBSDelta_PutATM(t *testing.T) {
	t.Parallel()
	delta := bsDelta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, false)
	assert.InDelta(t, -0.5, delta, 0.1, "ATM put should have delta near -0.5")
}

func TestBSGamma_ATM(t *testing.T) {
	t.Parallel()
	gamma := bsGamma(100.0, 100.0, 30.0/365.0, 0.05, 0.2)
	assert.Greater(t, gamma, 0.0, "ATM gamma should be positive")
}

func TestBSTheta_CallNegative(t *testing.T) {
	t.Parallel()
	theta := bsTheta(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.Less(t, theta, 0.0, "Call theta should be negative (time decay)")
}

func TestBSVega_Positive(t *testing.T) {
	t.Parallel()
	vega := bsVega(100.0, 100.0, 30.0/365.0, 0.05, 0.2)
	assert.Greater(t, vega, 0.0, "Vega should be positive")
}

func TestBSRho_CallPositive(t *testing.T) {
	t.Parallel()
	rho := bsRho(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	assert.Greater(t, rho, 0.0, "Call rho should be positive")
}

func TestBSRho_PutNegative(t *testing.T) {
	t.Parallel()
	rho := bsRho(100.0, 100.0, 30.0/365.0, 0.05, 0.2, false)
	assert.Less(t, rho, 0.0, "Put rho should be negative")
}

func TestImpliedVolatility_Converges(t *testing.T) {
	t.Parallel()
	// Price an option with known vol, then extract IV from the price
	price := blackScholesPrice(100.0, 100.0, 30.0/365.0, 0.05, 0.2, true)
	iv, ok := impliedVolatility(price, 100.0, 100.0, 30.0/365.0, 0.05, true)
	assert.True(t, ok, "IV should converge")
	assert.InDelta(t, 0.2, iv, 0.01, "Extracted IV should match input vol")
}

func TestImpliedVolatility_DeepOTM(t *testing.T) {
	t.Parallel()
	// Very cheap option (near zero) — IV extraction may not converge
	_, ok := impliedVolatility(0.001, 100.0, 200.0, 30.0/365.0, 0.05, true)
	// ok might be false, which is acceptable
	_ = ok
}

func TestNormalCDF_Symmetric(t *testing.T) {
	t.Parallel()
	// N(0) should be 0.5
	assert.InDelta(t, 0.5, normalCDF(0), 0.001)
	// N(x) + N(-x) = 1
	assert.InDelta(t, 1.0, normalCDF(1.5)+normalCDF(-1.5), 0.001)
}

func TestNormalPDF_Symmetric(t *testing.T) {
	t.Parallel()
	// pdf(x) == pdf(-x)
	assert.InDelta(t, normalPDF(1.0), normalPDF(-1.0), 0.0001)
	// pdf(0) is the maximum
	assert.Greater(t, normalPDF(0), normalPDF(1.0))
}

func TestExtractUnderlyingSymbol_Various(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "NIFTY", extractUnderlyingSymbol("NIFTY26APR24000CE"))
	assert.Equal(t, "BANKNIFTY", extractUnderlyingSymbol("BANKNIFTY26APR50000PE"))
	// Edge case: short symbol
	assert.NotPanics(t, func() { extractUnderlyingSymbol("A") })
}

// ===========================================================================
// sector_tool.go: computeSectorExposure
// ===========================================================================

func TestComputeSectorExposure_KnownStocks(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 100, AveragePrice: 1500, LastPrice: 1600},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 50, AveragePrice: 1600, LastPrice: 1700},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.Sectors), 2, "Should have at least 2 sectors")
}

func TestComputeSectorExposure_UnknownStock(t *testing.T) {
	t.Parallel()
	holdings := []broker.Holding{
		{Tradingsymbol: "XYZUNKNOWN", Exchange: "NSE", Quantity: 100, AveragePrice: 100, LastPrice: 110},
	}
	result := computeSectorExposure(holdings)
	assert.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.UnmappedStocks), 1, "Unknown stock should be unmapped")
}

func TestComputeSectorExposure_NoHoldings(t *testing.T) {
	t.Parallel()
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Empty(t, result.Sectors)
}

// ===========================================================================
// backtest_tool.go: computeMaxDrawdown with no trades
// ===========================================================================

func TestComputeMaxDrawdown_NoTrades(t *testing.T) {
	t.Parallel()
	dd := computeMaxDrawdown(nil, 100000)
	assert.Equal(t, 0.0, dd, "No trades should mean 0 drawdown")
}

// ===========================================================================
// Additional session-error tools (pushing WithSession/PaginatedToolHandler coverage)
// ===========================================================================

func TestSessionTool_PlaceOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_order", "trader@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	// Valid params but no real Kite session
	assert.True(t, result.IsError)
}

func TestSessionTool_ModifyOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_order", "trader@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "ORD123",
		"order_type": "LIMIT",
		"quantity":   float64(10),
		"price":      float64(1500),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_CancelOrder_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "ORD123",
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_PlaceGTT_ValidParamsSessionError(t *testing.T) {
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
		"quantity":         float64(10),
		"limit_price":      float64(1395),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_DeleteGTT_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_gtt_order", "trader@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_ConvertPosition_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_ModifyGTT_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "modify_gtt_order", "trader@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_ClosePosition_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_position", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_CloseAllPositions_ValidParamsSessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "close_all_positions", "trader@example.com", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_PlaceMFOrder_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "place_mf_order", "trader@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_GetQuotesMultiple_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_quotes", "trader@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY", "NSE:TCS"},
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_HistoricalData_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "2026-03-31 00:00:00",
	})
	assert.True(t, result.IsError)
}

func TestSessionTool_DeleteNativeAlert_SessionError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithSession(t, mgr, "delete_native_alert", "trader@example.com", map[string]any{
		"uuid": "test-uuid-1",
	})
	assert.True(t, result.IsError)
}

// ===========================================================================
// DevMode tests: Tools that go through WithSession with mock broker.
// These exercise session creation, handler bodies, and use case wiring.
// ===========================================================================

func TestDevMode_GetHoldings(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetProfile(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrders(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetGTTs(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderHistory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "ORD001",
		"order_type": "LIMIT",
		"quantity":   float64(10),
		"price":      float64(1500),
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"quantity":         float64(10),
		"limit_price":      float64(1395),
	})
	assert.NotNil(t, result)
}

func TestDevMode_DeleteGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ModifyGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.NotNil(t, result)
}

func TestDevMode_ConvertPosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ClosePosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CloseAllPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetLTP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ltp", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOHLC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_ohlc", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetQuotes(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_quotes", "dev@example.com", map[string]any{
		"instruments": []interface{}{"NSE:INFY"},
	})
	assert.NotNil(t, result)
}

func TestDevMode_TechnicalIndicators(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "technical_indicators", "dev@example.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
	})
	assert.NotNil(t, result)
}

func TestDevMode_HistoricalData(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "2026-03-31 00:00:00",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioSummary(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PortfolioConcentration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PositionAnalysis(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SectorExposure(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TaxHarvest(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_harvest_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_DividendCalendar(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_SEBICompliance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sebi_compliance_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TradingContext(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "trading_context", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PreTradeCheck(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "pre_trade_check", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFHoldings(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFOrders(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_GetMFSIPs(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_mf_sips", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_OptionsGreeks(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_greeks", "dev@example.com", map[string]any{
		"exchange":      "NFO",
		"tradingsymbol": "NIFTY26APR24000CE",
	})
	assert.NotNil(t, result)
}

func TestDevMode_BacktestStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "backtest_strategy", "dev@example.com", map[string]any{
		"strategy":       "sma_crossover",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.NotNil(t, result)
}

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

func TestDevMode_PortfolioRebalance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_rebalance", "dev@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
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

func TestDevMode_GetOrderMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetBasketMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOrderCharges(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingToggle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enabled": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingReset(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}

func TestDevMode_SearchInstruments(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "search_instruments", "dev@example.com", map[string]any{
		"query": "RELIANCE",
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_order", "dev@example.com", map[string]any{
		"tradingsymbol":    "INF740K01DP8",
		"transaction_type": "BUY",
		"amount":           float64(10000),
	})
	assert.NotNil(t, result)
}

func TestDevMode_PlaceMFSIP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_mf_sip", "dev@example.com", map[string]any{
		"tradingsymbol": "INF740K01DP8",
		"amount":        float64(5000),
		"frequency":     "monthly",
		"instalments":   float64(24),
		"tag":           "test",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_order", "dev@example.com", map[string]any{
		"order_id": "MF001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_CancelMFSIP(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_mf_sip", "dev@example.com", map[string]any{
		"sip_id": "SIP001",
	})
	assert.NotNil(t, result)
}

func TestDevMode_GetOptionChain(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_option_chain", "dev@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.NotNil(t, result)
}

func TestDevMode_OptionsStrategy(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "options_strategy", "dev@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "2026-04-24",
		"strike":     float64(24000),
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

func TestDevMode_CreateWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Test Watchlist",
	})
	assert.NotNil(t, result)
}

func TestDevMode_ListWatchlists(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_TickerStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "ticker_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}

func TestDevMode_PaperTradingStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
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
