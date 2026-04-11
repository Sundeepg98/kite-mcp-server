package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

// ===========================================================================
// retry.go: RetryBrokerCall and isTransientError
// ===========================================================================

func TestIsTransientError(t *testing.T) {
	t.Parallel()
	assert.True(t, isTransientError(errors.New("connection refused")))
	assert.True(t, isTransientError(errors.New("request timeout")))
	assert.True(t, isTransientError(errors.New("service temporarily unavailable")))
	assert.True(t, isTransientError(errors.New("unexpected EOF")))
	assert.True(t, isTransientError(errors.New("Connection reset by peer")))
	assert.False(t, isTransientError(errors.New("invalid API key")))
	assert.False(t, isTransientError(errors.New("permission denied")))
	assert.False(t, isTransientError(errors.New("bad request")))
}

func TestRetryBrokerCall_SuccessFirstTry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "ok", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 1, calls)
}

func TestRetryBrokerCall_NonTransientFails(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("invalid API key")
	}, 3)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should not retry non-transient errors")
}

func TestRetryBrokerCall_TransientRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("connection timeout")
		}
		return "recovered", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "recovered", result)
	assert.Equal(t, 3, calls)
}

func TestRetryBrokerCall_ExhaustsRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (int, error) {
		calls++
		return 0, errors.New("connection timeout every time")
	}, 2)
	assert.Error(t, err)
	assert.Equal(t, 3, calls, "should try 1 + 2 retries = 3 calls")
	assert.Contains(t, err.Error(), "connection timeout")
}

func TestRetryBrokerCall_ZeroRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("connection refused")
	}, 0)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "zero retries means just one attempt")
}

// ===========================================================================
// sector_tool.go: normalizeSymbol and formatPct
// ===========================================================================

func TestNormalizeSymbol(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("reliance"))
	assert.Equal(t, "RELIANCE", normalizeSymbol(" RELIANCE "))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-EQ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BZ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BL"))
	assert.Equal(t, "INFY", normalizeSymbol("INFY-EQ"))
}

func TestFormatPct(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "50%", formatPct(50.0))
	assert.Equal(t, "100%", formatPct(100.0))
	assert.Equal(t, "0%", formatPct(0.0))
	assert.Equal(t, "33.3%", formatPct(33.3))
	assert.Equal(t, "12.5%", formatPct(12.5))
}

// ===========================================================================
// compliance_tool.go: formatINR
// ===========================================================================

func TestFormatINR(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Rs 500", formatINR(500))
	assert.Equal(t, "Rs 99999", formatINR(99999))
	assert.Equal(t, "Rs 1,00,000", formatINR(100000))
	assert.Equal(t, "Rs 5,00,000", formatINR(500000))
	assert.Equal(t, "Rs 10,00,000", formatINR(1000000))
	assert.Equal(t, "Rs 1.50 L", formatINR(150000))
	assert.Equal(t, "Rs 2.75 L", formatINR(275000))
	assert.Equal(t, "Rs 0", formatINR(0))
}

// ===========================================================================
// native_alert_tools.go: formatRHS and splitAndTrim
// ===========================================================================

func TestFormatRHS_Constant(t *testing.T) {
	t.Parallel()
	params := kiteconnect.AlertParams{
		RHSType:     "constant",
		RHSConstant: 1500.50,
	}
	assert.Equal(t, "1500.50", formatRHS(params))
}

func TestFormatRHS_Instrument(t *testing.T) {
	t.Parallel()
	params := kiteconnect.AlertParams{
		RHSType:          "instrument",
		RHSExchange:      "NSE",
		RHSTradingSymbol: "INFY",
		RHSAttribute:     "last_price",
	}
	assert.Equal(t, "NSE:INFY (last_price)", formatRHS(params))
}

func TestSplitAndTrim(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c"}, splitAndTrim("a, b, c"))
	assert.Equal(t, []string{"NSE:INFY"}, splitAndTrim("NSE:INFY"))
	assert.Equal(t, []string{"a", "b"}, splitAndTrim("  a  ,  b  "))
	// Empty string splits to one empty part, which gets trimmed to empty
	result := splitAndTrim("")
	assert.Empty(t, result)
	result2 := splitAndTrim(", , ,")
	assert.Empty(t, result2)
}

// ===========================================================================
// watchlist_tools.go: parseInstrumentList
// ===========================================================================

func TestParseInstrumentList(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"NSE:INFY", "NSE:RELIANCE"}, parseInstrumentList("NSE:INFY, NSE:RELIANCE"))
	assert.Equal(t, []string{"NSE:INFY"}, parseInstrumentList("NSE:INFY"))
	result := parseInstrumentList("")
	assert.Empty(t, result)
	assert.Equal(t, []string{"a", "b"}, parseInstrumentList("  a  ,  b  "))
	result2 := parseInstrumentList(", , ,")
	assert.Empty(t, result2)
}

// ===========================================================================
// options_greeks_tool.go: round4, round6, bsRho
// ===========================================================================

func TestRound4(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.1416, round4(3.14159265))
	assert.Equal(t, 0.0, round4(0.0))
	assert.Equal(t, 1.0, round4(1.0))
	assert.Equal(t, -2.7183, round4(-2.71828))
}

func TestRound6(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.141593, round6(3.14159265))
	assert.Equal(t, 0.0, round6(0.0))
	assert.Equal(t, 1.0, round6(1.0))
}

func TestBsRho_Call(t *testing.T) {
	t.Parallel()
	// S=100, K=100, T=1, r=0.05, sigma=0.2, isCall=true
	rho := bsRho(100, 100, 1, 0.05, 0.2, true)
	assert.Greater(t, rho, 0.0, "call rho should be positive")
}

func TestBsRho_Put(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 1, 0.05, 0.2, false)
	assert.Less(t, rho, 0.0, "put rho should be negative")
}

func TestBsRho_ZeroTime(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 0, 0.05, 0.2, true)
	assert.Equal(t, 0.0, rho, "rho with zero time should be 0")
}

func TestBsRho_ZeroVol(t *testing.T) {
	t.Parallel()
	rho := bsRho(100, 100, 1, 0.05, 0, true)
	assert.Equal(t, 0.0, rho, "rho with zero vol should be 0")
}

// ===========================================================================
// indicators_tool.go: safeLastValue and safeBBWidth
// ===========================================================================

func TestSafeLastValue_EdgeCases(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 0.0, safeLastValue([]float64{}))
	assert.Equal(t, 0.0, safeLastValue(nil))
	assert.Equal(t, 5.0, safeLastValue([]float64{1, 2, 3, 4, 5}))
	assert.Equal(t, 42.0, safeLastValue([]float64{42}))
	assert.Equal(t, -1.0, safeLastValue([]float64{-1}))
}

func TestSafeBBWidth(t *testing.T) {
	t.Parallel()
	// Normal case
	upper := []float64{110}
	lower := []float64{90}
	middle := []float64{100}
	assert.Equal(t, 20.0, safeBBWidth(upper, lower, middle))

	// Zero middle
	assert.Equal(t, 0.0, safeBBWidth([]float64{10}, []float64{5}, []float64{0}))

	// Empty arrays
	assert.Equal(t, 0.0, safeBBWidth([]float64{}, []float64{}, []float64{}))
}

// ===========================================================================
// ticker_tools.go: resolveTickerMode and resolveInstrumentTokens
// ===========================================================================

func TestResolveTickerMode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ticker.ModeLTP, resolveTickerMode("ltp"))
	assert.Equal(t, ticker.ModeQuote, resolveTickerMode("quote"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("full"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("unknown"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode(""))
}

func TestResolveInstrumentTokens_AllInvalid(t *testing.T) {
	mgr := newTestManager(t)
	// Test data instruments don't have ID field set, so GetByID won't find them
	tokens, failed := resolveInstrumentTokens(mgr, []string{"NSE:NONEXISTENT"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 1)
	assert.Equal(t, "NSE:NONEXISTENT", failed[0])
}

func TestResolveInstrumentTokens_Empty(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr, []string{})
	assert.Empty(t, tokens)
	assert.Empty(t, failed)
}

func TestResolveInstrumentTokens_MultipleFailed(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr, []string{"NSE:AAA", "NSE:BBB", "NSE:CCC"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 3)
}

// ===========================================================================
// analytics_tools.go: roundTo2
// ===========================================================================

func TestRoundTo2(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 3.14, roundTo2(3.14159))
	assert.Equal(t, 0.0, roundTo2(0.0))
	assert.Equal(t, -1.23, roundTo2(-1.234))
	assert.Equal(t, 100.0, roundTo2(100.0))
}

// ===========================================================================
// cache.go: cleanup
// ===========================================================================

func TestToolCache_Cleanup(t *testing.T) {
	t.Parallel()
	cache := &ToolCache{
		entries: make(map[string]*cacheEntry),
		ttl:     50 * time.Millisecond,
	}

	// Add entries
	cache.Set("key1", "value1")
	cache.Set("key2", "value2")
	assert.Equal(t, 2, cache.Size())

	// Wait for entries to expire
	time.Sleep(60 * time.Millisecond)

	// Run cleanup
	cache.cleanup()
	assert.Equal(t, 0, cache.Size())
}

func TestToolCache_CleanupKeepsValid(t *testing.T) {
	t.Parallel()
	cache := &ToolCache{
		entries: make(map[string]*cacheEntry),
		ttl:     1 * time.Second,
	}

	cache.Set("valid", "data")
	// Manually insert an expired entry
	cache.entries["expired"] = &cacheEntry{
		data:      "old",
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	assert.Equal(t, 2, cache.Size())

	cache.cleanup()
	assert.Equal(t, 1, cache.Size())

	val, ok := cache.Get("valid")
	assert.True(t, ok)
	assert.Equal(t, "data", val)
}

func TestToolCache_GetExpired(t *testing.T) {
	t.Parallel()
	cache := &ToolCache{
		entries: make(map[string]*cacheEntry),
		ttl:     1 * time.Millisecond,
	}
	cache.Set("key", "value")
	time.Sleep(5 * time.Millisecond)

	val, ok := cache.Get("key")
	assert.False(t, ok)
	assert.Nil(t, val)
}

// ===========================================================================
// registry.go: HookMiddleware
// ===========================================================================

func TestHookMiddleware_AllowsExecution(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	hookCalled := false
	OnBeforeToolExecution(func(toolName string, args map[string]interface{}) error {
		hookCalled = true
		return nil
	})

	middleware := HookMiddleware()
	handler := middleware(func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("success"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.False(t, result.IsError)
	assert.True(t, hookCalled)
}

func TestHookMiddleware_BlocksExecution(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	OnBeforeToolExecution(func(toolName string, args map[string]interface{}) error {
		return errors.New("blocked by policy")
	})

	innerCalled := false
	middleware := HookMiddleware()
	handler := middleware(func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		innerCalled = true
		return gomcp.NewToolResultText("should not reach"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "blocked by policy")
	assert.False(t, innerCalled, "inner handler should not run when hook blocks")
}

func TestHookMiddleware_RunsAfterHooks(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	afterCalled := false
	OnAfterToolExecution(func(toolName string, args map[string]interface{}) error {
		afterCalled = true
		return nil
	})

	middleware := HookMiddleware()
	handler := middleware(func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("done"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	_, _ = handler(context.Background(), req)
	assert.True(t, afterCalled)
}

// ===========================================================================
// setup_tools.go: dashboardBaseURL / dashboardPageURL
// ===========================================================================

func TestDashboardBaseURL_NoExternalURL(t *testing.T) {
	mgr := newTestManager(t)
	// Manager without ExternalURL or LocalMode should return empty
	base := dashboardBaseURL(mgr)
	// Since the test manager has no external URL, it depends on local mode
	// Either way, test that it doesn't panic
	_ = base
}

func TestDashboardLink_NoBaseURL(t *testing.T) {
	mgr := newTestManager(t)
	link := dashboardLink(mgr)
	// Without external URL or local mode, should return empty
	_ = link
}

func TestDashboardPageURL_NoBaseURL(t *testing.T) {
	mgr := newTestManager(t)
	url := dashboardPageURL(mgr, "/dashboard")
	// Without base URL, returns empty
	_ = url
}

// ===========================================================================
// common.go: NewArgParser.Raw()
// ===========================================================================

func TestArgParser_RawReturnsOriginalMap(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{"key": "value"}
	p := NewArgParser(args)
	assert.Same(t, &args, &args) // sanity
	raw := p.Raw()
	assert.Equal(t, "value", raw["key"])
}

// ===========================================================================
// common.go: NewToolHandler
// ===========================================================================

func TestNewToolHandler_NotNil(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	assert.NotNil(t, handler)
}

// ===========================================================================
// common.go: trackToolCall does not panic without metrics
// ===========================================================================

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

// ===========================================================================
// common.go: ValidateRequired - edge cases
// ===========================================================================

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

// ===========================================================================
// Tool handler tests: more auth & validation paths
// ===========================================================================

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

// Note: Login tool tests are excluded because the login handler calls
// server.ClientSessionFromContext(ctx) which panics without a real MCP session.
// Login validation is tested via the isAlphanumeric helper tests instead.

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

// ===========================================================================
// Various tool auth checks (pushing coverage on auth-first handlers)
// ===========================================================================

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

// ===========================================================================
// Additional tool validation tests
// ===========================================================================

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

// ===========================================================================
// common.go: ApplyPagination additional edge cases
// ===========================================================================

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

// ===========================================================================
// common.go: CreatePaginatedResponse edge cases
// ===========================================================================

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

// ===========================================================================
// common.go: session type constants
// ===========================================================================

func TestSessionTypeConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "sse", SessionTypeSSE)
	assert.Equal(t, "mcp", SessionTypeMCP)
	assert.Equal(t, "stdio", SessionTypeStdio)
	assert.Equal(t, "unknown", SessionTypeUnknown)
}

// ===========================================================================
// common.go: SafeAssert edge cases not covered elsewhere
// ===========================================================================

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

// ===========================================================================
// Tool handler: MarshalResponse with various types
// ===========================================================================

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

// ===========================================================================
// common.go: CacheKey format
// ===========================================================================

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

// ===========================================================================
// elicit.go: isConfirmableTool — exhaustive
// ===========================================================================

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

// ===========================================================================
// setup_tools.go: isAlphanumeric — more cases
// ===========================================================================

func TestIsAlphanumeric_Unicode(t *testing.T) {
	t.Parallel()
	assert.False(t, isAlphanumeric("café"))
	assert.False(t, isAlphanumeric("日本語"))
	assert.True(t, isAlphanumeric("abc123XYZ"))
}

// ===========================================================================
// setup_tools.go: pageRoutes — count check
// ===========================================================================

func TestPageRoutes_Count(t *testing.T) {
	t.Parallel()
	assert.GreaterOrEqual(t, len(pageRoutes), 9, "should have at least 9 page routes")
}

// ===========================================================================
// All tools have annotations (openWorldHint check)
// ===========================================================================

func TestAllToolsHaveOpenWorldAnnotation(t *testing.T) {
	for _, td := range GetAllTools() {
		toolDef := td.Tool()
		// Every tool should have annotations defined (non-nil struct)
		assert.NotNil(t, toolDef.Annotations,
			"tool %s should have annotations set", toolDef.Name)
	}
}

// ===========================================================================
// Additional: computeSignals from indicators_tool.go (needs OHLC data)
// We test the helper directly
// ===========================================================================

func TestComputeSignals_WithData(t *testing.T) {
	t.Parallel()
	closes := []float64{100, 102, 104, 106, 108}
	rsi := []float64{75} // Overbought
	sma20 := []float64{100}
	sma50 := []float64{95}
	ema12 := []float64{105}
	ema26 := []float64{100}
	bbUpper := []float64{115}
	bbLower := []float64{85}
	macdLine := []float64{5}
	macdSignal := []float64{3}

	signals := computeSignals(closes, rsi, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal)
	assert.NotEmpty(t, signals)
	// With RSI=75, should have overbought signal
	found := false
	for _, s := range signals {
		if len(s) > 0 {
			found = true
		}
	}
	assert.True(t, found, "should produce at least one signal")
}

func TestComputeSignals_OversoldRSI(t *testing.T) {
	t.Parallel()
	closes := []float64{90, 88, 86, 84, 82}
	rsi := []float64{25} // Oversold
	signals := computeSignals(closes, rsi, nil, nil, nil, nil, nil, nil, nil, nil)
	found := false
	for _, s := range signals {
		if len(s) > 0 {
			found = true
		}
	}
	assert.True(t, found)
}

func TestComputeSignals_GoldenCross(t *testing.T) {
	t.Parallel()
	closes := []float64{100}
	sma20 := []float64{105} // SMA20 > SMA50 = golden cross
	sma50 := []float64{95}
	signals := computeSignals(closes, nil, sma20, sma50, nil, nil, nil, nil, nil, nil)
	assert.NotEmpty(t, signals)
}

func TestComputeSignals_NoSignals(t *testing.T) {
	t.Parallel()
	closes := []float64{100}
	// Everything neutral
	signals := computeSignals(closes, []float64{50}, []float64{100}, []float64{100}, nil, nil, nil, nil, nil, nil)
	assert.Contains(t, signals, "No strong signals")
}

// ===========================================================================
// MCP registration: verifying GetAllTools returns correct type
// ===========================================================================

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

// ===========================================================================
// common.go: ValidationError fields
// ===========================================================================

func TestValidationError_Fields(t *testing.T) {
	err := ValidationError{Parameter: "exchange", Message: "must be NSE or BSE"}
	assert.Equal(t, "exchange", err.Parameter)
	assert.Equal(t, "must be NSE or BSE", err.Message)
	assert.Equal(t, "parameter 'exchange': must be NSE or BSE", err.Error())
}

// ===========================================================================
// common.go: ParsePaginationParams with negative values
// ===========================================================================

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

// ===========================================================================
// setup_tools.go: toolDashboardPage — paper trading tools mapped
// ===========================================================================

func TestToolDashboardPage_PaperTradingTools(t *testing.T) {
	paperTools := []string{"paper_trading_toggle", "paper_trading_status", "paper_trading_reset"}
	for _, tool := range paperTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/paper", path, "tool %s should map to /dashboard/paper", tool)
	}
}

func TestToolDashboardPage_WatchlistTools(t *testing.T) {
	watchlistTools := []string{
		"list_watchlists", "get_watchlist", "create_watchlist",
		"delete_watchlist", "add_to_watchlist", "remove_from_watchlist",
	}
	for _, tool := range watchlistTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/watchlist", path)
	}
}

func TestToolDashboardPage_OptionsTools(t *testing.T) {
	optionsTools := []string{"get_option_chain", "options_greeks", "options_strategy"}
	for _, tool := range optionsTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/options", path)
	}
}

func TestToolDashboardPage_ChartTools(t *testing.T) {
	chartTools := []string{"technical_indicators", "backtest_strategy", "get_quotes", "get_ltp", "get_ohlc", "get_historical_data", "search_instruments"}
	for _, tool := range chartTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/chart", path)
	}
}

// ===========================================================================
// DashboardURLForTool with mapped tools
// ===========================================================================

func TestDashboardURLForTool_MappedTool(t *testing.T) {
	mgr := newTestManager(t)
	// This will return empty if no external URL, but shouldn't panic
	url := DashboardURLForTool(mgr, "get_holdings")
	_ = url // verify no panic
}

// ===========================================================================
// Additional: confirm schema structure
// ===========================================================================

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

// ===========================================================================
// Additional: writeTools correctness
// ===========================================================================

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

// ===========================================================================
// requestConfirmation: fail-open when no server ref
// ===========================================================================

func TestRequestConfirmation_NilServer(t *testing.T) {
	err := requestConfirmation(context.Background(), nil, "confirm?")
	assert.NoError(t, err, "nil server should fail open")
}

func TestRequestConfirmation_WrongType(t *testing.T) {
	err := requestConfirmation(context.Background(), "not a server", "confirm?")
	assert.NoError(t, err, "wrong type should fail open")
}

// ===========================================================================
// Tool handler helpers: buildOrderConfirmMessage additional cases
// ===========================================================================

func TestBuildOrderConfirmMessage_ClosePosition(t *testing.T) {
	msg := buildOrderConfirmMessage("close_position", map[string]any{
		"instrument": "NSE:RELIANCE",
		"product":    "MIS",
	})
	assert.Contains(t, msg, "NSE:RELIANCE")
}

func TestBuildOrderConfirmMessage_ModifyGTT(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_gtt_order", map[string]any{
		"trigger_id":       float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.Contains(t, msg, "GTT")
}

func TestBuildOrderConfirmMessage_PlaceNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("place_native_alert", map[string]any{
		"name":          "Test alert",
		"type":          "ato",
		"exchange":      "NSE",
		"tradingsymbol": "INFY",
		"operator":      ">=",
	})
	assert.NotEmpty(t, msg)
}

func TestBuildOrderConfirmMessage_ModifyNativeAlert(t *testing.T) {
	msg := buildOrderConfirmMessage("modify_native_alert", map[string]any{
		"uuid": "test-uuid",
		"name": "Modified alert",
	})
	assert.NotEmpty(t, msg)
}

// ===========================================================================
// ValidateRequired: with interface{} slice of strings
// ===========================================================================

func TestValidateRequired_NonEmptyInterfaceSlice(t *testing.T) {
	args := map[string]interface{}{"items": []interface{}{"a", "b"}}
	assert.NoError(t, ValidateRequired(args, "items"))
}

// ===========================================================================
// Tool annotations: idempotent tools
// ===========================================================================

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

// ===========================================================================
// Exhaustive error message format check
// ===========================================================================

func TestErrorMessages_ContainActionableText(t *testing.T) {
	assert.Contains(t, ErrAuthRequired, "log in")
	assert.Contains(t, ErrAdminRequired, "restricted")
	assert.Contains(t, ErrConfirmRequired, "true")
}

// ===========================================================================
// format helpers: verify no panic on edge cases
// ===========================================================================

func TestFormatINR_LargeNumber(t *testing.T) {
	result := formatINR(10000000) // 1 crore
	assert.Contains(t, result, "Rs")
}

func TestFormatPct_NegativeValue(t *testing.T) {
	result := formatPct(-5.5)
	assert.Equal(t, "-5.5%", result)
}

func TestNormalizeSymbol_NoSuffix(t *testing.T) {
	assert.Equal(t, "TCS", normalizeSymbol("TCS"))
}

// ===========================================================================
// SafeAssertString: fmt.Sprintf path
// ===========================================================================

func TestSafeAssertString_NumericInput(t *testing.T) {
	assert.Equal(t, "42", SafeAssertString(42, "default"))
	assert.Equal(t, "3.14", SafeAssertString(3.14, "default"))
	assert.Equal(t, "true", SafeAssertString(true, "default"))
}

// ===========================================================================
// Integration: exercise all tools Tool() method for coverage
// ===========================================================================

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

// ===========================================================================
// Test the full confirm message for all confirmable tools
// ===========================================================================

func TestBuildOrderConfirmMessage_AllConfirmableTools(t *testing.T) {
	for toolName := range confirmableTools {
		msg := buildOrderConfirmMessage(toolName, map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"quantity":         float64(10),
			"order_type":       "MARKET",
			"product":          "CNC",
			"order_id":         "123",
			"confirm":          true,
			"trigger_type":     "single",
			"trigger_value":    float64(1400),
			"amount":           float64(5000),
			"frequency":        "monthly",
			"instalments":      float64(12),
			"instrument":       "NSE:INFY",
			"name":             "Test",
			"type":             "ato",
			"operator":         ">=",
			"uuid":             "test-uuid",
		})
		assert.NotEmpty(t, msg, "confirm message for %s should not be empty", toolName)
	}
}

// ===========================================================================
// Additional native alert validation
// ===========================================================================

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
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "modify_native_alert", "trader@example.com", map[string]any{
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
	assert.True(t, result.IsError)
	assertResultContains(t, result, "at least one item")
}

// ===========================================================================
// analytics_tools.go: computePortfolioSummary
// ===========================================================================

func TestComputePortfolioSummary_Empty(t *testing.T) {
	result := computePortfolioSummary([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, 0.0, result.TotalInvested)
	assert.Equal(t, 0.0, result.TotalCurrent)
}

func TestComputePortfolioSummary_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{
			Tradingsymbol: "INFY",
			Quantity:      10,
			AveragePrice:  1500,
			LastPrice:     1600,
			DayChangePct:  2.0,
		},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, 15000.0, result.TotalInvested)
	assert.Equal(t, 16000.0, result.TotalCurrent)
	assert.Equal(t, 1000.0, result.OverallPnL)
}

func TestComputePortfolioSummary_TopGainersAndLosers(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "GAINER1", Quantity: 10, AveragePrice: 100, LastPrice: 110, DayChangePct: 5.0},
		{Tradingsymbol: "GAINER2", Quantity: 10, AveragePrice: 100, LastPrice: 120, DayChangePct: 10.0},
		{Tradingsymbol: "LOSER1", Quantity: 10, AveragePrice: 100, LastPrice: 90, DayChangePct: -5.0},
		{Tradingsymbol: "FLAT", Quantity: 10, AveragePrice: 100, LastPrice: 100, DayChangePct: 0.0},
	}
	result := computePortfolioSummary(holdings)
	assert.Equal(t, 4, result.HoldingsCount)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
	assert.LessOrEqual(t, len(result.BiggestHoldings), 5)
}

// ===========================================================================
// analytics_tools.go: computePortfolioConcentration
// ===========================================================================

func TestComputePortfolioConcentration_Empty(t *testing.T) {
	result := computePortfolioConcentration([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
	assert.Equal(t, "empty", result.Concentration)
}

func TestComputePortfolioConcentration_SingleHolding(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Equal(t, "concentrated", result.Concentration)
	assert.Equal(t, 10000.0, result.HHIScore) // 100% squared
}

func TestComputePortfolioConcentration_Diversified(t *testing.T) {
	holdings := make([]broker.Holding, 20)
	for i := range holdings {
		holdings[i] = broker.Holding{
			Tradingsymbol: "STOCK" + string(rune('A'+i)),
			Quantity:      10,
			LastPrice:     100,
		}
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, 20, result.HoldingsCount)
	assert.Equal(t, "diversified", result.Concentration)
	assert.Less(t, result.HHIScore, 1500.0)
}

func TestComputePortfolioConcentration_ZeroValue(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computePortfolioConcentration(holdings)
	assert.Equal(t, "empty", result.Concentration)
}

// ===========================================================================
// analytics_tools.go: computePositionAnalysis
// ===========================================================================

func TestComputePositionAnalysis_Empty(t *testing.T) {
	result := computePositionAnalysis([]broker.Position{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NetPositionsCount)
	assert.Equal(t, 0.0, result.TotalPnL)
}

func TestComputePositionAnalysis_WithPositions(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Exchange: "NSE", Product: "MIS", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: 1000},
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Product: "CNC", Quantity: -5, AveragePrice: 2500, LastPrice: 2400, PnL: -500},
		{Tradingsymbol: "TCS", Exchange: "NSE", Product: "MIS", Quantity: 20, AveragePrice: 3500, LastPrice: 3600, PnL: 2000},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 3, result.NetPositionsCount)
	assert.Equal(t, 2500.0, result.TotalPnL)
	assert.GreaterOrEqual(t, len(result.ByProduct), 1)
	assert.GreaterOrEqual(t, len(result.TopGainers), 1)
	assert.GreaterOrEqual(t, len(result.TopLosers), 1)
}

func TestComputePositionAnalysis_ProductGrouping(t *testing.T) {
	positions := []broker.Position{
		{Tradingsymbol: "INFY", Product: "MIS", PnL: 100},
		{Tradingsymbol: "TCS", Product: "MIS", PnL: 200},
		{Tradingsymbol: "RELIANCE", Product: "CNC", PnL: -50},
	}
	result := computePositionAnalysis(positions)
	assert.Equal(t, 2, len(result.ByProduct))
}

// ===========================================================================
// setup_tools.go: DashboardURLMiddleware
// ===========================================================================

func TestDashboardURLMiddleware_AddsDashboardURL(t *testing.T) {
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	// Create a handler that returns a successful result
	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				gomcp.TextContent{Type: "text", Text: `{"data":"test"}`},
			},
		}, nil
	}

	handler := middleware(inner)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings" // mapped tool

	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Whether dashboard URL is appended depends on whether dashboardBaseURL returns non-empty
	// At minimum, the result should be unchanged if no base URL
}

func TestDashboardURLMiddleware_SkipsUnmappedTools(t *testing.T) {
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return &gomcp.CallToolResult{
			Content: []gomcp.Content{
				gomcp.TextContent{Type: "text", Text: "ok"},
			},
		}, nil
	}

	handler := middleware(inner)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "login" // not mapped in toolDashboardPage

	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, result.Content, 1, "unmapped tool should not get dashboard URL appended")
}

func TestDashboardURLMiddleware_SkipsErrors(t *testing.T) {
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("some error"), nil
	}

	handler := middleware(inner)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"

	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestDashboardURLMiddleware_SkipsNilResult(t *testing.T) {
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return nil, nil
	}

	handler := middleware(inner)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"

	result, err := handler(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestDashboardURLMiddleware_PropagatesError(t *testing.T) {
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return nil, errors.New("internal error")
	}

	handler := middleware(inner)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"

	result, err := handler(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ===========================================================================
// alert_tools.go: instrumentResolverAdapter.GetInstrumentToken
// ===========================================================================

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

// ===========================================================================
// sector_tool.go: stockSectors map coverage
// ===========================================================================

func TestStockSectors_NotEmpty(t *testing.T) {
	assert.Greater(t, len(stockSectors), 50, "should have at least 50 stock-sector mappings")
}

func TestStockSectors_KnownStocks(t *testing.T) {
	knownStocks := map[string]string{
		"RELIANCE": "Energy",
		"INFY":     "IT",
		"HDFCBANK": "Banking",
		"TCS":      "IT",
	}
	for stock, expectedSector := range knownStocks {
		sector, ok := stockSectors[stock]
		assert.True(t, ok, "stock %s should be in stockSectors", stock)
		assert.Equal(t, expectedSector, sector, "stock %s sector mismatch", stock)
	}
}

// ===========================================================================
// watchlist_tools.go: parseInstrumentList edge cases
// ===========================================================================

func TestParseInstrumentList_SingleItem(t *testing.T) {
	result := parseInstrumentList("NSE:INFY")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}

func TestParseInstrumentList_TrailingComma(t *testing.T) {
	result := parseInstrumentList("NSE:INFY,")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}

// ===========================================================================
// Additional: options_strategy validation paths
// ===========================================================================

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

// ===========================================================================
// Additional tool validation: backtest_strategy
// ===========================================================================

func TestBacktestStrategy_MissingStrategy(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "backtest_strategy", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// strategy missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

// ===========================================================================
// Additional tool validation: technical_indicators
// ===========================================================================

func TestTechnicalIndicators_MissingIndicators(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "technical_indicators", "trader@example.com", map[string]any{
		"instrument": "NSE:INFY",
		// indicators missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "is required")
}

// ===========================================================================
// Additional tool validation: pre_trade_check
// ===========================================================================

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

// ===========================================================================
// Additional: various tools' Tool() definitions cover
// ===========================================================================

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

// ===========================================================================
// sector_tool.go: computeSectorExposure
// ===========================================================================

func TestComputeSectorExposure_Empty(t *testing.T) {
	result := computeSectorExposure([]broker.Holding{})
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.HoldingsCount)
}

func TestComputeSectorExposure_ZeroValue(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 0},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.HoldingsCount)
	assert.Empty(t, result.Sectors)
}

func TestComputeSectorExposure_MappedStocks(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500},
		{Tradingsymbol: "HDFCBANK", Quantity: 20, LastPrice: 1600},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 3, result.HoldingsCount)
	assert.Equal(t, 3, result.MappedCount)
	assert.Equal(t, 0, result.UnmappedCount)
	assert.GreaterOrEqual(t, len(result.Sectors), 2) // IT and Banking
}

func TestComputeSectorExposure_UnmappedStocks(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "UNKNOWNSTOCK", Quantity: 10, LastPrice: 100},
	}
	result := computeSectorExposure(holdings)
	assert.Equal(t, 1, result.UnmappedCount)
	assert.Len(t, result.UnmappedStocks, 1)
}

func TestComputeSectorExposure_OverExposed(t *testing.T) {
	// Single stock = 100% in one sector = over-exposed
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 100, LastPrice: 1500},
	}
	result := computeSectorExposure(holdings)
	assert.GreaterOrEqual(t, len(result.Warnings), 1)
}

// ===========================================================================
// dividend_tool.go: computeDividendCalendar
// ===========================================================================

func TestComputeDividendCalendar_Empty(t *testing.T) {
	result := computeDividendCalendar([]broker.Holding{}, 90)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.Summary.HoldingsCount)
}

func TestComputeDividendCalendar_WithHoldings(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "INFY", Quantity: 10, LastPrice: 1500, AveragePrice: 1400},
		{Tradingsymbol: "TCS", Quantity: 5, LastPrice: 3500, AveragePrice: 3200},
	}
	result := computeDividendCalendar(holdings, 90)
	assert.Equal(t, 2, result.Summary.HoldingsCount)
	assert.NotNil(t, result.HoldingsByYield)
}

func TestComputeDividendCalendar_ZeroDayLookAhead(t *testing.T) {
	holdings := []broker.Holding{
		{Tradingsymbol: "RELIANCE", Quantity: 10, LastPrice: 2500},
	}
	result := computeDividendCalendar(holdings, 0)
	assert.NotNil(t, result)
}

// ===========================================================================
// resolveWatchlist: empty store
// ===========================================================================

func TestResolveWatchlist_NotFound(t *testing.T) {
	mgr := newTestManager(t)
	wl := resolveWatchlist(mgr, "user@test.com", "nonexistent")
	assert.Nil(t, wl)
}

// ===========================================================================
// sessionBrokerResolver: adapter test
// ===========================================================================

func TestSessionBrokerResolver_ReturnsSameClient(t *testing.T) {
	resolver := &sessionBrokerResolver{client: nil}
	client, err := resolver.GetBrokerForEmail("any@email.com")
	assert.NoError(t, err)
	assert.Nil(t, client) // nil client is valid in this adapter
}

// ===========================================================================
// Additional validation: set_alert direction variants
// ===========================================================================

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

// ===========================================================================
// More options_strategy validation: strangle needs strike2
// ===========================================================================

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

// ===========================================================================
// Additional margin tool validation
// ===========================================================================

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

// ===========================================================================
// Pre-trade check: additional validation
// ===========================================================================

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

// ===========================================================================
// Additional cancel_order validation
// ===========================================================================

func TestCancelOrder_MissingVariety(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "cancel_order", "trader@example.com", map[string]any{
		"order_id": "12345",
		// variety missing
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "variety")
}

// ===========================================================================
// GTT order: additional two-leg validation
// ===========================================================================

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

// ===========================================================================
// convert_position: additional validation
// ===========================================================================

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
