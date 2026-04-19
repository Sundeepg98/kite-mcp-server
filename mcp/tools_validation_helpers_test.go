package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Input validation tests: missing params, invalid values, arg parsing, pagination, type assertions.

func TestArgParser_RawReturnsOriginalMap(t *testing.T) {
	t.Parallel()
	args := map[string]any{"key": "value"}
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
	args := map[string]any{"qty": float64(0)}
	err := ValidateRequired(args, "qty")
	assert.NoError(t, err, "numeric zero should be considered present")
}


func TestValidateRequired_BoolFalse(t *testing.T) {
	t.Parallel()
	args := map[string]any{"confirm": false}
	err := ValidateRequired(args, "confirm")
	assert.NoError(t, err, "bool false should be considered present")
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
	args := map[string]any{"items": []any{"a", "b"}}
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


func TestRequestConfirmation_InterfaceNotServer(t *testing.T) {
	t.Parallel()
	err := requestConfirmation(context.Background(), 42, "confirm?")
	assert.NoError(t, err, "non-server type should fail open")
}


func TestValidateRequired_EmptyStringValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{"name": ""}, "name")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}


func TestValidateRequired_EmptySlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{"items": []any{}}, "items")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}


func TestValidateRequired_NilValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{}, "missing_param")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is required")
}


func TestValidateRequired_ValidValue(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{"name": "test"}, "name")
	assert.NoError(t, err)
}


func TestValidateRequired_MultipleParams(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{
		"a": "hello",
		"b": float64(123),
	}, "a", "b")
	assert.NoError(t, err)
}


func TestValidateRequired_FirstMissing(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{
		"b": "hello",
	}, "a", "b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "'a'")
}


func TestValidateRequired_EmptyStringSlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{"items": []string{}}, "items")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}


func TestValidateRequired_EmptyIntSlice(t *testing.T) {
	t.Parallel()
	err := ValidateRequired(map[string]any{"items": []int{}}, "items")
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
		"instruments": []any{"NSE:INFY", "NSE:TCS"},
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


func TestValidateRequired_EmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"items": []any{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}


func TestValidateRequired_EmptyStringSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"items": []string{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}


func TestValidateRequired_EmptyIntSlice_P7(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"items": []int{},
	}
	err := ValidateRequired(args, "items")
	assert.Error(t, err)
}


func TestValidateRequired_NonEmptyArray_P7(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"items": []any{"a", "b"},
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
	args := map[string]any{
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
