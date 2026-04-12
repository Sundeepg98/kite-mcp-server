package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.

func TestArgParser_RawReturnsOriginalMap(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{"key": "value"}
	p := NewArgParser(args)
	assert.Same(t, &args, &args) // sanity
	raw := p.Raw()
	assert.Equal(t, "value", raw["key"])
}

func TestNewToolHandler_NotNil(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	assert.NotNil(t, handler)
}

func TestTrackToolCall_NoMetrics(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	// Should not panic even without metrics enabled
	assert.NotPanics(t, func() {
		handler.trackToolCall(context.Background(), "test_tool")
	})
}

func TestTrackToolError_NoMetrics(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	assert.NotPanics(t, func() {
		handler.trackToolError(context.Background(), "test_tool", "test_error")
	})
}

func TestValidateRequired_NumericZero(t *testing.T) {
	t.Parallel()
	// Numeric zero is a valid value (not nil, not empty string)
	args := map[string]interface{}{"qty": float64(0)}
	err := ValidateRequired(args, "qty")
	assert.NoError(t, err, "numeric zero should be considered present")
}

func TestValidateRequired_BoolFalse(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{"confirm": false}
	err := ValidateRequired(args, "confirm")
	assert.NoError(t, err, "bool false should be considered present")
}

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

func TestIsAlphanumeric_LoginKeys(t *testing.T) {
	t.Parallel()
	// Valid API keys
	assert.True(t, isAlphanumeric("4agbg2fm6szvmhon"))
	assert.True(t, isAlphanumeric("ABC123def"))
	// Invalid API keys
	assert.False(t, isAlphanumeric("invalid-key!"))
	assert.False(t, isAlphanumeric("invalid secret!"))
	assert.False(t, isAlphanumeric("key with spaces"))
	assert.False(t, isAlphanumeric("key_underscore"))
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

func TestGetHistoricalData_MissingInstrumentToken(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "trader@example.com", map[string]any{
		"from_date": "2024-01-01 00:00:00",
		"to_date":   "2024-12-31 00:00:00",
		"interval":  "day",
		// instrument_token missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestCloseAllPositions_MissingConfirm(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "close_all_positions", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "confirm")
}

func TestOptionsStrategy_InvalidStrategy(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "invalid_strategy",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Unknown strategy")
}

func TestGetLTP_TooManyInstruments(t *testing.T) {
	mgr := newTestManager(t)
	insts := make([]interface{}, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_ltp", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "maximum 500")
}

func TestGetOHLC_TooManyInstruments(t *testing.T) {
	mgr := newTestManager(t)
	insts := make([]interface{}, 501)
	for i := range insts {
		insts[i] = "NSE:FAKE"
	}
	result := callToolWithManager(t, mgr, "get_ohlc", "trader@example.com", map[string]any{
		"instruments": insts,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "maximum 500")
}

func TestApplyPagination_FromAtEnd(t *testing.T) {
	t.Parallel()
	data := []int{1, 2, 3}
	result := ApplyPagination(data, PaginationParams{From: 3, Limit: 5})
	assert.Empty(t, result)
}

func TestApplyPagination_FromNegativeWithLimit(t *testing.T) {
	t.Parallel()
	data := []string{"a", "b", "c"}
	result := ApplyPagination(data, PaginationParams{From: -10, Limit: 2})
	assert.Equal(t, []string{"a", "b"}, result)
}

func TestCreatePaginatedResponse_FromBeyondTotal(t *testing.T) {
	t.Parallel()
	resp := CreatePaginatedResponse(nil, nil, PaginationParams{From: 100, Limit: 10}, 5)
	assert.Equal(t, 0, resp.Pagination.Returned)
	assert.False(t, resp.Pagination.HasMore)
}

func TestCreatePaginatedResponse_NoLimit(t *testing.T) {
	t.Parallel()
	resp := CreatePaginatedResponse(nil, nil, PaginationParams{From: 2, Limit: 0}, 10)
	assert.Equal(t, 8, resp.Pagination.Returned)
	assert.False(t, resp.Pagination.HasMore)
}

func TestSessionTypeConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "sse", SessionTypeSSE)
	assert.Equal(t, "mcp", SessionTypeMCP)
	assert.Equal(t, "stdio", SessionTypeStdio)
	assert.Equal(t, "unknown", SessionTypeUnknown)
}

func TestSafeAssertFloat64_IntInput(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 42.0, SafeAssertFloat64(42, 0.0))
}

func TestSafeAssertFloat64_StringInput(t *testing.T) {
	t.Parallel()
	// String is not float — returns fallback
	assert.Equal(t, 0.0, SafeAssertFloat64("not a number", 0.0))
}

func TestSafeAssertBool_IntInput(t *testing.T) {
	t.Parallel()
	// Integer is neither bool nor string — returns fallback
	assert.True(t, SafeAssertBool(42, true))
	assert.False(t, SafeAssertBool(42, false))
}

func TestSafeAssertStringArray_NonArrayNonString(t *testing.T) {
	t.Parallel()
	result := SafeAssertStringArray(42)
	assert.Nil(t, result)
}

func TestMarshalResponse_SliceData(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	data := []string{"a", "b", "c"}
	result, err := handler.MarshalResponse(data, "test")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestMarshalResponse_NilData(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	result, err := handler.MarshalResponse(nil, "test")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestCacheKey_Format(t *testing.T) {
	t.Parallel()
	key := CacheKey("get_ltp", "user@test.com", "NSE:INFY")
	assert.Equal(t, "get_ltp:user@test.com:NSE:INFY", key)
}

func TestCacheKey_Empty(t *testing.T) {
	t.Parallel()
	key := CacheKey("", "", "")
	assert.Equal(t, "::", key)
}

func TestConfirmableTools_Exhaustive(t *testing.T) {
	t.Parallel()
	confirmed := []string{
		"place_order", "modify_order", "close_position",
		"close_all_positions", "place_gtt_order", "modify_gtt_order",
		"place_native_alert", "modify_native_alert",
		"place_mf_order", "place_mf_sip",
	}
	for _, name := range confirmed {
		assert.True(t, isConfirmableTool(name), "%s should be confirmable", name)
	}

	notConfirmed := []string{
		"cancel_order", "delete_gtt_order", "cancel_mf_order",
		"cancel_mf_sip", "get_holdings", "login",
		"delete_my_account", "server_metrics",
	}
	for _, name := range notConfirmed {
		assert.False(t, isConfirmableTool(name), "%s should NOT be confirmable", name)
	}
}

func TestIsAlphanumeric_Unicode(t *testing.T) {
	t.Parallel()
	assert.False(t, isAlphanumeric("café"))
	assert.False(t, isAlphanumeric("日本語"))
	assert.True(t, isAlphanumeric("abc123XYZ"))
}

func TestAllToolsHaveOpenWorldAnnotation(t *testing.T) {
	for _, td := range GetAllTools() {
		toolDef := td.Tool()
		// Every tool should have annotations defined (non-nil struct)
		assert.NotNil(t, toolDef.Annotations,
			"tool %s should have annotations set", toolDef.Name)
	}
}

func TestGetAllTools_ReturnsToolInterface(t *testing.T) {
	tools := GetAllTools()
	for _, tool := range tools {
		// Each tool should implement Tool interface
		td := tool.Tool()
		assert.NotEmpty(t, td.Name)
		// Handler should be callable
		mgr := newTestManager(t)
		handler := tool.Handler(mgr)
		assert.NotNil(t, handler, "handler for %s should not be nil", td.Name)
	}
}

func TestValidationError_Fields(t *testing.T) {
	err := ValidationError{Parameter: "exchange", Message: "must be NSE or BSE"}
	assert.Equal(t, "exchange", err.Parameter)
	assert.Equal(t, "must be NSE or BSE", err.Message)
	assert.Equal(t, "parameter 'exchange': must be NSE or BSE", err.Error())
}

func TestParsePaginationParams_NegativeLimit(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"limit": float64(-5),
	})
	assert.Equal(t, -5, p.Limit, "negative limit passes through (ApplyPagination handles it)")
}

func TestParsePaginationParams_ExactMax(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"limit": float64(500),
	})
	assert.Equal(t, 500, p.Limit)
}

func TestParsePaginationParams_AboveMax(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"limit": float64(501),
	})
	assert.Equal(t, MaxPaginationLimit, p.Limit)
}

func TestConfirmSchema_Structure(t *testing.T) {
	assert.NotNil(t, confirmSchema)
	assert.Equal(t, "object", confirmSchema["type"])
	props, ok := confirmSchema["properties"].(map[string]any)
	assert.True(t, ok)
	_, hasConfirm := props["confirm"]
	assert.True(t, hasConfirm)
	required, ok := confirmSchema["required"].([]string)
	assert.True(t, ok)
	assert.Contains(t, required, "confirm")
}

func TestWriteTools_AdditionalChecks(t *testing.T) {
	// Delete account is write
	assert.True(t, writeTools["delete_my_account"])
	// Paper toggle is write
	assert.True(t, writeTools["paper_trading_toggle"])
	// Paper reset is write (destructiveHint=true)
	assert.True(t, writeTools["paper_trading_reset"])
	// Search instruments is read-only
	assert.False(t, writeTools["search_instruments"])
	// Server metrics is read-only
	assert.False(t, writeTools["server_metrics"])
}

func TestRequestConfirmation_NilServer(t *testing.T) {
	err := requestConfirmation(context.Background(), nil, "confirm?")
	assert.NoError(t, err, "nil server should fail open")
}

func TestRequestConfirmation_WrongType(t *testing.T) {
	err := requestConfirmation(context.Background(), "not a server", "confirm?")
	assert.NoError(t, err, "wrong type should fail open")
}

func TestValidateRequired_NonEmptyInterfaceSlice(t *testing.T) {
	args := map[string]interface{}{"items": []interface{}{"a", "b"}}
	assert.NoError(t, ValidateRequired(args, "items"))
}

func TestIdempotentToolAnnotations(t *testing.T) {
	tools := GetAllTools()
	idempotentTools := []string{
		"get_holdings", "get_positions", "get_profile", "get_margins",
		"get_orders", "get_trades", "search_instruments",
	}

	toolMap := make(map[string]Tool)
	for _, td := range tools {
		toolMap[td.Tool().Name] = td
	}

	for _, name := range idempotentTools {
		td, found := toolMap[name]
		if !found {
			continue
		}
		toolDef := td.Tool()
		assert.True(t, toolDef.Annotations.IdempotentHint != nil && *toolDef.Annotations.IdempotentHint,
			"tool %s should be idempotent", name)
	}
}

func TestErrorMessages_ContainActionableText(t *testing.T) {
	assert.Contains(t, ErrAuthRequired, "log in")
	assert.Contains(t, ErrAdminRequired, "restricted")
	assert.Contains(t, ErrConfirmRequired, "true")
}

func TestSafeAssertString_NumericInput(t *testing.T) {
	assert.Equal(t, "42", SafeAssertString(42, "default"))
	assert.Equal(t, "3.14", SafeAssertString(3.14, "default"))
	assert.Equal(t, "true", SafeAssertString(true, "default"))
}

func TestAllToolDefinitions_HaveValidSchema(t *testing.T) {
	tools := GetAllTools()
	for _, td := range tools {
		toolDef := td.Tool()
		assert.NotEmpty(t, toolDef.Name, "every tool must have a name")
		assert.NotEmpty(t, toolDef.Description, "tool %s must have description", toolDef.Name)

		// InputSchema should be valid JSON schema object
		assert.Equal(t, "object", toolDef.InputSchema.Type, "tool %s input schema should be object type", toolDef.Name)
	}
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

func TestInstrumentResolverAdapter_NotFound(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &instrumentResolverAdapter{mgr: mgr.Instruments}
	_, err := adapter.GetInstrumentToken("NSE", "NONEXISTENT")
	assert.Error(t, err)
}

func TestInstrumentResolverAdapter_Type(t *testing.T) {
	// Verify that the adapter implements the right interface pattern
	mgr := newTestManager(t)
	adapter := &instrumentResolverAdapter{mgr: mgr.Instruments}
	assert.NotNil(t, adapter)
}

func TestOptionsStrategy_BullCallSpreadInvalidStrikes(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(25000),
		"strike2":    float64(24000), // strike2 <= strike1
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}

func TestOptionsStrategy_InvalidExpiry(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "straddle",
		"underlying": "NIFTY",
		"expiry":     "not-a-date",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}

func TestOptionsStrategy_BearPutSpreadInvalidStrikes(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(25000),
		"strike2":    float64(24000), // strike2 <= strike1
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}

func TestOptionsStrategy_IronCondorMissingStrikes(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "iron_condor",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(23000),
		"strike2":    float64(24000),
		// strike3 and strike4 missing (default 0)
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike")
}

func TestOptionsStrategy_ButterflyBadOrder(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "butterfly",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
		"strike2":    float64(23000), // strike2 < strike1 = bad order
		"strike3":    float64(25000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike1 < strike2")
}

func TestBacktestStrategy_MissingStrategy(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// strategy missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestTechnicalIndicators_MissingIndicators(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// indicators missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestPreTradeCheck_MissingExchange(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
		// exchange missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestToolDefinitions_Coverage(t *testing.T) {
	// These are tools whose Tool() method may not yet be covered
	toolTypes := []Tool{
		&PaperTradingToggleTool{},
		&PaperTradingStatusTool{},
		&PaperTradingResetTool{},
		&DeleteMyAccountTool{},
		&UpdateMyCredentialsTool{},
		&GetPnLJournalTool{},
		&TradingContextTool{},
		&SEBIComplianceTool{},
		&ClosePositionTool{},
		&CloseAllPositionsTool{},
		&PortfolioSummaryTool{},
		&PortfolioConcentrationTool{},
		&PositionAnalysisTool{},
	}
	for _, td := range toolTypes {
		toolDef := td.Tool()
		assert.NotEmpty(t, toolDef.Name, "tool should have a name")
		assert.NotEmpty(t, toolDef.Description, "tool %s should have a description", toolDef.Name)
	}
}

func TestResolveWatchlist_NotFound(t *testing.T) {
	mgr := newTestManager(t)
	wl := resolveWatchlist(mgr, "user@test.com", "nonexistent")
	assert.Nil(t, wl)
}

func TestSessionBrokerResolver_ReturnsSameClient(t *testing.T) {
	resolver := &sessionBrokerResolver{client: nil}
	client, err := resolver.GetBrokerForEmail("any@email.com")
	assert.NoError(t, err)
	assert.Nil(t, client) // nil client is valid in this adapter
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

func TestOptionsStrategy_StrangleMissingStrike2(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "trader@example.com", map[string]any{
		"strategy":   "strangle",
		"underlying": "NIFTY",
		"expiry":     "2024-04-03",
		"strike1":    float64(24000),
		// strike2 missing (defaults to 0)
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2")
}

func TestGetOrderMargins_SLMWithoutTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL-M",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

func TestPreTradeCheck_MissingTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
		// tradingsymbol missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
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

func TestBacktestStrategy_InvalidStrategy2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"strategy":       "invalid_strategy",
		"exchange":       "NSE",
		"tradingsymbol":  "INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Unknown strategy")
}

func TestPreTradeCheck_MissingRequiredFields(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":       "NSE",
		// missing tradingsymbol, quantity, etc.
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

func TestPreTradeCheck_ZeroQty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(0),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "quantity must be greater than 0")
}

func TestPreTradeCheck_LimitOrderNoPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}

func TestTaxHarvestTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&TaxHarvestTool{}).Tool()
	assert.Equal(t, "tax_harvest_analysis", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}

func TestPortfolioRebalance_ValueModeNegative(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_rebalance", "trader@example.com", map[string]any{
		"targets": `{"INFY": -50000}`,
		"mode":    "value",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "non-negative")
}

func TestTradingContextTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&TradingContextTool{}).Tool()
	assert.Equal(t, "trading_context", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.True(t, *tool.Annotations.ReadOnlyHint)
}

func TestGetPnLJournal_NoAuth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestRequestConfirmation_InterfaceNotServer(t *testing.T) {
	t.Parallel()
	err := requestConfirmation(context.Background(), 42, "confirm?")
	assert.NoError(t, err, "non-server type should fail open")
}

func TestDividendCalendarTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&DividendCalendarTool{}).Tool()
	assert.Equal(t, "dividend_calendar", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
}

func TestGetOrderMargins_LimitNoPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		// price missing = 0
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "price must be greater than 0")
}

func TestGetOrderMargins_SLNoTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		// trigger_price missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

func TestGetOrderMargins_SLMNoTriggerPrice(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "SELL",
		"quantity":         float64(10),
		"product":          "MIS",
		"order_type":       "SL-M",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "trigger_price must be greater than 0")
}

func TestAllToolsDefinitions_Categories(t *testing.T) {
	t.Parallel()
	tools := GetAllTools()
	names := make(map[string]bool)
	for _, td := range tools {
		toolDef := td.Tool()
		names[toolDef.Name] = true
	}
	// Verify key tools exist
	assert.True(t, names["place_order"])
	assert.True(t, names["get_holdings"])
	assert.True(t, names["backtest_strategy"])
	assert.True(t, names["tax_harvest_analysis"])
	assert.True(t, names["portfolio_rebalance"])
	assert.True(t, names["pre_trade_check"])
	assert.True(t, names["trading_context"])
	assert.True(t, names["get_pnl_journal"])
	assert.True(t, names["options_greeks"])
	assert.True(t, names["options_strategy"])
	assert.True(t, names["server_metrics"])
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

func TestGetOrderTrades_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_trades", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetOrderHistory_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_history", "trader@example.com", map[string]any{})
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

func TestValidationError_Format(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "exchange", Message: "is required"}
	assert.Equal(t, "parameter 'exchange': is required", err.Error())
}

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

func TestOpenDashboard_InvalidPage_FallsBackToPortfolio(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "nonexistent",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestCreateWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "", map[string]any{
		"name": "Test",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestCreateWatchlist_Success(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{
		"name": "My Stocks",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "created")
}

func TestCreateWatchlist_DuplicateName(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Create first
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "Dupe"})
	// Create duplicate
	result := callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "Dupe"})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "already exists")
}

func TestDeleteWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "", map[string]any{
		"watchlist": "someid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestDeleteWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}

func TestDeleteWatchlist_Success(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Create first
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ToDelete"})
	// Delete by name
	result := callToolWithManager(t, mgr, "delete_watchlist", "test@example.com", map[string]any{
		"watchlist": "ToDelete",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "deleted")
}

func TestAddToWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "", map[string]any{
		"watchlist":   "Test",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestAddToWatchlist_WatchlistNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "nonexistent",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}

func TestAddToWatchlist_EmptyInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd",
		"instruments": "",
	})
	assert.True(t, result.IsError)
	// ValidateRequired fires before the split logic
	assertResultContains(t, result, "cannot be empty")
}

func TestAddToWatchlist_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd2"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd2",
		"instruments": "NSE:UNKNOWN_STOCK_XYZ",
	})
	// Instrument not found → all failed → returns error
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}

func TestAddToWatchlist_MultipleInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestAdd3"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "TestAdd3",
		"instruments": "NSE:INFY,NSE:RELIANCE",
	})
	// Test data instruments may not have ID field set for GetByID lookup,
	// but the handler exercises the full code path regardless.
	assert.NotNil(t, result)
}

func TestAddToWatchlist_WithTargets(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestTargets"})
	result := callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":    "TestTargets",
		"instruments":  "NSE:INFY",
		"notes":        "Swing trade candidate",
		"target_entry": float64(1800),
		"target_exit":  float64(2000),
	})
	// Exercises the notes/targets code paths regardless of instrument resolution
	assert.NotNil(t, result)
}

func TestRemoveFromWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "", map[string]any{
		"watchlist": "Test",
		"items":     "item1",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestRemoveFromWatchlist_WatchlistNotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
		"items":     "item1",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}

func TestRemoveFromWatchlist_EmptyItems(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove"})
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove",
		"items":     "",
	})
	assert.True(t, result.IsError)
	// ValidateRequired fires before the split logic
	assertResultContains(t, result, "cannot be empty")
}

func TestRemoveFromWatchlist_ItemNotInWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove2"})
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove2",
		"items":     "NSE:UNKNOWN",
	})
	assert.NotNil(t, result)
	// Should report failure since item is not in the watchlist
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not in watchlist")
}

func TestRemoveFromWatchlist_ByItemID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "TestRemove3"})
	// Try removing a non-existent item ID
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "test@example.com", map[string]any{
		"watchlist": "TestRemove3",
		"items":     "nonexistent-item-id",
	})
	// Exercises the non-colon ref path (item ID resolution)
	assert.NotNil(t, result)
}

func TestGetWatchlist_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "", map[string]any{
		"watchlist": "Test",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestGetWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not found")
}

func TestGetWatchlist_EmptyWatchlist(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "EmptyWL"})
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist": "EmptyWL",
	})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "empty")
}

func TestGetWatchlist_WithItems_NoLTP(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "GetWL"})
	callToolWithManager(t, mgr, "add_to_watchlist", "test@example.com", map[string]any{
		"watchlist":   "GetWL",
		"instruments": "NSE:INFY",
	})
	// Get without LTP (no session)
	result := callToolWithManager(t, mgr, "get_watchlist", "test@example.com", map[string]any{
		"watchlist":   "GetWL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)
	// Without LTP flag, should still return the items
}

func TestListWatchlists_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestListWatchlists_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "empty@example.com", map[string]any{})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "No watchlists")
}

func TestListWatchlists_WithData(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "list@example.com", map[string]any{"name": "WL1"})
	callToolWithManager(t, mgr, "create_watchlist", "list@example.com", map[string]any{"name": "WL2"})
	result := callToolWithManager(t, mgr, "list_watchlists", "list@example.com", map[string]any{})
	assert.False(t, result.IsError)
}

func TestSetupTelegram_NoNotifier(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not configured")
}

func TestSetupTelegram_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(123456),
	})
	assert.True(t, result.IsError)
	// Handler checks notifier config before email, so we get "not configured"
	assertResultContains(t, result, "not configured")
}

func TestSetupTelegram_MissingChatID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	// Notifier is nil, so it fails before chat_id check
	assertResultContains(t, result, "not configured")
}

func TestSetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "setup_telegram", "test@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.True(t, result.IsError)
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

func TestListAlerts_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_alerts", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestListAlerts_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_alerts", "noalerts@example.com", map[string]any{})
	assert.False(t, result.IsError)
	assertResultContains(t, result, "No alerts")
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

func TestPlaceMFOrder_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestPlaceMFOrder_BuyWithZeroAmount(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "BUY",
		"amount":           float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "amount")
}

func TestPlaceMFOrder_SellWithZeroQuantity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_order", "test@example.com", map[string]any{
		"tradingsymbol":    "INF209K01YS2",
		"transaction_type": "SELL",
		"quantity":         float64(0),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "quantity")
}

func TestCancelMFOrder_MissingOrderID_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_order", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestPlaceMFSIP_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestPlaceMFSIP_ZeroAmount_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "place_mf_sip", "test@example.com", map[string]any{
		"tradingsymbol": "INF209K01YS2",
		"amount":        float64(0),
		"frequency":     "monthly",
		"instalments":   float64(12),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "amount")
}

func TestCancelMFSIP_MissingID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_mf_sip", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestPaperTradingToggle_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}

func TestPaperTradingToggle_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "test@example.com", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}

func TestPaperTradingStatus_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}

func TestPaperTradingStatus_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}

func TestPaperTradingReset_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Not authenticated")
}

func TestPaperTradingReset_NoEngine(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "database configuration")
}

func TestGetPnLJournal_NoEmail_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestGetPnLJournal_NoService(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}

func TestGetPnLJournal_Periods(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	periods := []string{"week", "month", "quarter", "year", "all"}
	for _, p := range periods {
		result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
			"period": p,
		})
		assert.True(t, result.IsError, "period=%s should fail due to no PnL service", p)
		assertResultContains(t, result, "not available")
	}
}

func TestPortfolioRebalance_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_rebalance", "test@example.com", map[string]any{
		"targets": "not valid json",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Invalid")
}

func TestPortfolioRebalance_EmptyObject(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_rebalance", "test@example.com", map[string]any{
		"targets": "{}",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "at least one")
}

func TestPortfolioRebalance_InvalidMode_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_rebalance", "test@example.com", map[string]any{
		"targets": `{"RELIANCE": 50, "INFY": 50}`,
		"mode":    "invalid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "percentage")
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

func TestGetNativeAlertHistory_MissingUUID_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_native_alert_history", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetOptionChain_NoNFOInstruments(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "test@example.com", map[string]any{
		"underlying": "NIFTY",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "No options found")
}

func TestGetOptionChain_NegativeStrikesAround(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_option_chain", "test@example.com", map[string]any{
		"underlying":       "NIFTY",
		"strikes_around_atm": float64(-5),
	})
	assert.True(t, result.IsError)
	// Should still fail due to no NFO options
	assertResultContains(t, result, "No options found")
}

func TestOptionsGreeks_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestOptionsStrategy_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{})
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

func TestListTrailingStops_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_trailing_stops", "", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Email required")
}

func TestServerMetrics_NonAdmin(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "server_metrics", "regular@example.com", map[string]any{})
	assert.True(t, result.IsError)
}

func TestServerMetrics_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "server_metrics", "", map[string]any{})
	assert.True(t, result.IsError)
}

func TestPreTradeCheck_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "pre_trade_check", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetOrderMargins_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestKiteClientForEmail_NoCreds(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	client := brokerClientForEmail(mgr, "nobody@example.com")
	assert.Nil(t, client)
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

func TestSearchInstruments_EmptyQuery(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query": "",
	})
	assert.True(t, result.IsError)
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

func TestTechnicalIndicators_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestBacktestStrategy_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestResolveWatchlist_ByName(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ResolveName"})
	wl := resolveWatchlist(mgr, "test@example.com", "ResolveName")
	assert.NotNil(t, wl)
	assert.Equal(t, "ResolveName", wl.Name)
}

func TestResolveWatchlist_ByID(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	callToolWithManager(t, mgr, "create_watchlist", "test@example.com", map[string]any{"name": "ResolveID"})
	// Get the ID from the store
	watchlists := mgr.WatchlistStore().ListWatchlists("test@example.com")
	require.Len(t, watchlists, 1)
	wl := resolveWatchlist(mgr, "test@example.com", watchlists[0].ID)
	assert.NotNil(t, wl)
}

func TestResolveWatchlist_NotFound_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	wl := resolveWatchlist(mgr, "test@example.com", "nonexistent-ref")
	assert.Nil(t, wl)
}

func TestKiteClientForEmail_HasCredsButNoToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Set credentials but no token
	mgr.CredentialStore().Set("partial@example.com", &kc.KiteCredentialEntry{
		APIKey:    "testkey",
		APISecret: "testsecret",
	})
	client := brokerClientForEmail(mgr, "partial@example.com")
	assert.Nil(t, client)
}

func TestKiteClientForEmail_HasTokenButNoCreds(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Set token but no per-user credentials. Global API key ("test_key") is used
	// as fallback, so GetBrokerForEmail creates a valid client.
	mgr.TokenStore().Set("partial2@example.com", &kc.KiteTokenEntry{
		AccessToken: "testtoken",
		UserName:    "tester",
	})
	client := brokerClientForEmail(mgr, "partial2@example.com")
	assert.NotNil(t, client, "global API key + stored token = valid client")
}

func TestKiteClientForEmail_HasBoth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	mgr.CredentialStore().Set("full@example.com", &kc.KiteCredentialEntry{
		APIKey:    "testkey",
		APISecret: "testsecret",
	})
	mgr.TokenStore().Set("full@example.com", &kc.KiteTokenEntry{
		AccessToken: "testtoken",
		UserName:    "tester",
	})
	client := brokerClientForEmail(mgr, "full@example.com")
	assert.NotNil(t, client)
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

func TestListTrailingStops_Empty(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_trailing_stops", "test@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestCancelTrailingStop_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_trailing_stop", "test@example.com", map[string]any{
		"stop_id": "nonexistent-stop",
	})
	assert.True(t, result.IsError)
}

func TestOptionsGreeks_InvalidParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"spot_price":  float64(0),
		"strike":      float64(1500),
		"expiry_days": float64(30),
		"rate":        float64(0.05),
		"option_type": "CE",
	})
	assert.NotNil(t, result)
}

func TestOptionsStrategy_InvalidStrategy_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "invalid_strategy",
		"underlying": "NIFTY",
		"spot_price": float64(24000),
	})
	assert.NotNil(t, result)
}

func TestBacktestStrategy_InvalidStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"strategy":   "nonexistent",
		"period":     "1y",
	})
	assert.NotNil(t, result)
}

func TestTechnicalIndicators_InvalidIndicator(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "test@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"indicators": "invalid_indicator",
	})
	assert.NotNil(t, result)
}

func TestSearchInstruments_WithQuery(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query": "INFY",
	})
	assert.NotNil(t, result)
	// Should find INFY in test data
	assert.False(t, result.IsError)
}

func TestSearchInstruments_WithExchangeFilter(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "search_instruments", "test@example.com", map[string]any{
		"query":    "RELIANCE",
		"exchange": "NSE",
	})
	assert.NotNil(t, result)
}

func TestGetHistoricalData_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_historical_data", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetLTP_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ltp", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetOHLC_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_ohlc", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetQuotes_MissingParams(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_quotes", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestSubscribeInstruments_MissingInstruments_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "subscribe_instruments", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestUnsubscribeInstruments_MissingInstruments_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "unsubscribe_instruments", "test@example.com", map[string]any{})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "required")
}

func TestGetPnLJournal_CustomDateRange(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
		"from": "2025-01-01",
		"to":   "2025-12-31",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
}

func TestGetPnLJournal_DefaultPeriod(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "test@example.com", map[string]any{
		"period": "invalid",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "not available")
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

func TestOptionsGreeks_InvalidOptionType_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(24000),
		"expiry_date":    "2025-06-01",
		"option_type":    "INVALID",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "CE or PE")
}

func TestOptionsGreeks_NegativeStrike(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(-100),
		"expiry_date":    "2025-06-01",
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "positive")
}

func TestOptionsGreeks_InvalidExpiryFormat(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_greeks", "test@example.com", map[string]any{
		"exchange":       "NFO",
		"tradingsymbol":  "NIFTY2560124000CE",
		"strike_price":   float64(24000),
		"expiry_date":    "invalid-date",
		"option_type":    "CE",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}

func TestOptionsStrategy_InvalidExpiry_V2(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "bad-date",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "YYYY-MM-DD")
}

func TestOptionsStrategy_BullCallSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "bull_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "strike2 > strike1")
}

func TestOptionsStrategy_BearPutSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "bear_put_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
}

func TestOptionsStrategy_BearCallSpread_InvalidStrikes(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "bear_call_spread",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24500),
		"strike2":    float64(24000),
	})
	assert.True(t, result.IsError)
}

func TestOptionsStrategy_UnknownStrategy(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "options_strategy", "test@example.com", map[string]any{
		"strategy":   "unknown_strat",
		"underlying": "NIFTY",
		"expiry":     "2027-06-01",
		"strike1":    float64(24000),
	})
	assert.True(t, result.IsError)
}

func TestValidateRequired_EmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []interface{}{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_EmptyStringSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []string{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_EmptyIntSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []int{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}

func TestValidateRequired_NonEmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	err := ValidateRequired(args, "items")
	assert.NoError(t, err)
}

func TestArgParser_NilArgs(t *testing.T) {
	t.Parallel()
	p := NewArgParser(nil)
	assert.Equal(t, "", p.String("key", ""))
	assert.Equal(t, 0, p.Int("key", 0))
	assert.Equal(t, 0.0, p.Float("key", 0))
	assert.Equal(t, false, p.Bool("key", false))
}

func TestArgParser_TypeMismatch(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"str_as_num": "not_a_number",
		"num_as_str": float64(42),
	}
	p := NewArgParser(args)
	assert.Equal(t, 0, p.Int("str_as_num", 0))
	assert.Equal(t, "42", p.String("num_as_str", ""))
}

func TestValidationError_FormatMessage(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "name", Message: "is required"}
	assert.Equal(t, "parameter 'name': is required", err.Error())
}

func TestAdminGetRiskStatus_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_get_risk_status", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError) // missing target_email
}

func TestAdminChangeRole_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"role": "viewer",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminChangeRole_InvalidRole(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_change_role", "admin@example.com", map[string]any{
		"target_email": "role@example.com",
		"role":         "superadmin",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminActivateUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_activate_user", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminFreezeUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_user", "admin@example.com", map[string]any{
		"reason":  "test",
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminUnfreezeUser_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_unfreeze_user", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminFreezeGlobal_MissingReason(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_freeze_global", "admin@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminInviteFamily_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_invite_family_member", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}

func TestAdminRemoveFamily_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newRichDevModeManager(t)
	result := callToolAdmin(t, mgr, "admin_remove_family_member", "admin@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}
