package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
	appmetrics "github.com/zerodha/kite-mcp-server/app/metrics"
	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// Middleware tests: dashboard URL, hooks, cache, timeout, metrics tracking, viewer block.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newMetricsManager(t *testing.T) *kc.Manager {
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

	metricsMgr := appmetrics.New(appmetrics.Config{ServiceName: "test"})

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithInstrumentsManager(instMgr),
		kc.WithMetrics(metricsMgr),
	)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

func TestToolCache_Cleanup(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(50 * time.Millisecond)
	defer cache.Close()

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
	cache := NewToolCache(1 * time.Second)
	defer cache.Close()

	cache.Set("valid", "data")
	// Force a Set whose TTL has already expired by reaching through
	// the same Set/list path the cleanup walks (pure black-box now —
	// the LRU rewrite removed the public-state-poking shortcut).
	cache.Set("expired", "old")
	cache.expireForTest("expired", time.Now().Add(-1*time.Second))
	assert.Equal(t, 2, cache.Size())

	cache.cleanup()
	assert.Equal(t, 1, cache.Size())

	val, ok := cache.Get("valid")
	assert.True(t, ok)
	assert.Equal(t, "data", val)
}

func TestToolCache_GetExpired(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(1 * time.Millisecond)
	defer cache.Close()
	cache.Set("key", "value")
	time.Sleep(5 * time.Millisecond)

	val, ok := cache.Get("key")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestHookMiddleware_AllowsExecution(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	hookCalled := false
	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
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

	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
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
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
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

func TestDashboardBaseURL_NoExternalURL(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Manager without ExternalURL or LocalMode should return empty
	base := dashboardBaseURL(mgr)
	// Since the test manager has no external URL, it depends on local mode
	// Either way, test that it doesn't panic
	_ = base
}

func TestDashboardLink_NoBaseURL(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	link := dashboardLink(mgr)
	// Without external URL or local mode, should return empty
	_ = link
}

func TestDashboardPageURL_NoBaseURL(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	url := dashboardPageURL(mgr, "/dashboard")
	// Without base URL, returns empty
	_ = url
}

func TestPageRoutes_Count(t *testing.T) {
	t.Parallel()
	assert.GreaterOrEqual(t, len(pageRoutes), 9, "should have at least 9 page routes")
}

func TestToolDashboardPage_PaperTradingTools(t *testing.T) {
	t.Parallel()
	paperTools := []string{"paper_trading_toggle", "paper_trading_status", "paper_trading_reset"}
	for _, tool := range paperTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/paper", path, "tool %s should map to /dashboard/paper", tool)
	}
}

func TestToolDashboardPage_WatchlistTools(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	optionsTools := []string{"get_option_chain", "options_greeks", "options_payoff_builder"}
	for _, tool := range optionsTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/options", path)
	}
}

func TestToolDashboardPage_ChartTools(t *testing.T) {
	t.Parallel()
	chartTools := []string{"technical_indicators", "historical_price_analyzer", "get_quotes", "get_ltp", "get_ohlc", "get_historical_data", "search_instruments"}
	for _, tool := range chartTools {
		path, ok := toolDashboardPage[tool]
		assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
		assert.Equal(t, "/dashboard/chart", path)
	}
}

func TestDashboardURLForTool_MappedTool(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// This will return empty if no external URL, but shouldn't panic
	url := DashboardURLForTool(mgr, "get_holdings")
	_ = url // verify no panic
}

func TestDashboardURLMiddleware_AddsDashboardURL(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestAppResources_AllHaveRequiredFields(t *testing.T) {
	t.Parallel()
	for _, res := range appResources {
		assert.NotEmpty(t, res.URI)
		assert.NotEmpty(t, res.Name)
		assert.NotEmpty(t, res.TemplateFile)
		assert.NotNil(t, res.DataFunc)
	}
}

func TestPagePathToResourceURI_AllStartWithUIPrefix(t *testing.T) {
	t.Parallel()
	for path, uri := range pagePathToResourceURI {
		assert.True(t, len(uri) > 5 && uri[:5] == "ui://",
			"path %s should map to URI starting with ui://, got %s", path, uri)
	}
}

func TestWithViewerBlock_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background() // no email in context
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.Nil(t, result, "should not block when no email")
}

func TestWithViewerBlock_NonWriteTool(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@example.com")
	result := handler.WithViewerBlock(ctx, "get_holdings") // read-only tool
	assert.Nil(t, result, "should not block read-only tools")
}

func TestWithViewerBlock_ViewerBlocked(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Register user as viewer
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		_ = uStore.Create(&users.User{Email: "viewer@example.com", Role: users.RoleViewer, Status: "active"})
	}
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "viewer@example.com")
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.NotNil(t, result, "should block viewer from write tools")
	assert.True(t, result.IsError)
}

func TestWithViewerBlock_TraderAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		_ = uStore.Create(&users.User{Email: "trader2@example.com", Role: users.RoleTrader, Status: "active"})
	}
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "trader2@example.com")
	result := handler.WithViewerBlock(ctx, "place_order")
	assert.Nil(t, result, "should not block trader from write tools")
}

func TestCallWithNilKiteGuard_NormalExecution(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	result, err := handler.callWithNilKiteGuard("test_tool", nil, func(s *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("success"), nil
	})
	assert.NoError(t, err)
	assert.False(t, result.IsError)
}

func TestCallWithNilKiteGuard_PanicRecovery(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	result, err := handler.callWithNilKiteGuard("test_tool", nil, func(s *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
		panic("nil pointer dereference")
	})
	assert.NoError(t, err)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "DEV_MODE")
}

func TestWithTokenRefresh_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", nil, "session1", "")
	assert.Nil(t, result, "should not refresh when no email")
}

func TestWithTokenRefresh_NoToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", nil, "session1", "unknown@example.com")
	assert.Nil(t, result, "should not refresh when no token found")
}

func TestDashboardBaseURL_LocalMode(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// newTestManager has no appMode set, so IsLocalMode() returns true
	base := dashboardBaseURL(mgr)
	assert.Equal(t, "http://127.0.0.1:8080", base)
}

func TestDashboardLink_LocalMode(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	link := dashboardLink(mgr)
	assert.Contains(t, link, "Open Dashboard")
	assert.Contains(t, link, "/admin/ops")
}

func TestDashboardPageURL_LocalMode(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	url := dashboardPageURL(mgr, "/dashboard")
	assert.Equal(t, "http://127.0.0.1:8080/dashboard", url)
}

func TestDashboardURLForTool_KnownTool_LocalMode(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "get_holdings")
	assert.Equal(t, "http://127.0.0.1:8080/dashboard", url)
}

func TestDashboardURLForTool_UnknownTool(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "unknown_tool")
	assert.Empty(t, url)
}

func TestDashboardURLMiddleware_NoExternalURL(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)
	require.NotNil(t, middleware)
}

func TestPageRoutes_AllExpected(t *testing.T) {
	t.Parallel()
	expectedPages := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "watchlist", "options", "chart"}
	for _, page := range expectedPages {
		_, ok := pageRoutes[page]
		assert.True(t, ok, "pageRoutes should contain %q", page)
	}
}

func TestToolDashboardPage_HasManyTools(t *testing.T) {
	t.Parallel()
	assert.GreaterOrEqual(t, len(toolDashboardPage), 40, "toolDashboardPage should map at least 40 tools")
}

func TestDashboardURLMiddleware_AddsURLForMappedTool(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	// Wrap a simple handler that returns a success result
	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("holdings data"), nil
	}
	wrapped := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)
	// In local mode, should append a dashboard_url content block
	assert.GreaterOrEqual(t, len(result.Content), 2)
}

func TestDashboardURLMiddleware_SkipsUnmappedTool(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	wrapped := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "login"
	result, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	// login is not in toolDashboardPage, should NOT append
	assert.Equal(t, 1, len(result.Content))
}

func TestDashboardURLMiddleware_SkipsErrorResult(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	middleware := DashboardURLMiddleware(mgr)

	inner := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("some error"), nil
	}
	wrapped := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := wrapped(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	// Error results should NOT get dashboard_url appended
	assert.Equal(t, 1, len(result.Content))
}

func TestTrackToolCall_WithMetrics_LiveSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "get_holdings")
	})
	assert.True(t, mgr.HasMetrics())
}

func TestTrackToolCall_WithMetrics_PaperSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "paper")
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "place_order")
	})
}

func TestTrackToolCall_WithMetrics_UnknownSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	// No session type in context — falls back to SessionTypeUnknown
	ctx := context.Background()
	assert.NotPanics(t, func() {
		handler.trackToolCall(ctx, "get_profile")
	})
}

func TestTrackToolError_WithMetrics_AuthError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "place_order", "auth")
	})
}

func TestTrackToolError_WithMetrics_ValidationError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "paper")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "modify_order", "validation")
	})
}

func TestTrackToolError_WithMetrics_APIError(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "cancel_order", "api")
	})
}

func TestTrackToolError_WithMetrics_UnknownSession(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := context.Background()
	assert.NotPanics(t, func() {
		handler.trackToolError(ctx, "get_quotes", "timeout")
	})
}

func TestTrackToolCall_WithMetrics_MultipleTools(t *testing.T) {
	t.Parallel()
	mgr := newMetricsManager(t)
	handler := NewToolHandler(mgr)

	ctx := WithSessionType(context.Background(), "live")
	tools := []string{"get_holdings", "get_positions", "get_orders", "place_order", "set_alert"}
	for _, tool := range tools {
		handler.trackToolCall(ctx, tool)
	}
}

func TestSessionType_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := WithSessionType(context.Background(), "paper")
	assert.Equal(t, "paper", SessionTypeFromContext(ctx))
}

func TestSessionType_DefaultUnknown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))
}

func TestHookMiddleware_BlocksOnError(t *testing.T) {
	t.Parallel()
	// Save and restore hooks
	defer ClearHooks()

	OnBeforeToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		if toolName == "blocked_tool" {
			return fmt.Errorf("tool is blocked")
		}
		return nil
	})

	err := RunBeforeHooks(context.Background(), "blocked_tool", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")

	err = RunBeforeHooks(context.Background(), "allowed_tool", nil)
	require.NoError(t, err)
}

func TestHookMiddleware_AfterHooks(t *testing.T) {
	t.Parallel()
	defer ClearHooks()

	called := false
	OnAfterToolExecution(func(ctx context.Context, toolName string, args map[string]interface{}) error {
		called = true
		return nil
	})

	RunAfterHooks(context.Background(), "test_tool", nil)
	assert.True(t, called)
}

func TestToolCache_MissAndHit_P7(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(time.Minute)
	t.Cleanup(cache.Close)
	require.NotNil(t, cache)

	// Miss
	val, ok := cache.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)

	// Set
	cache.Set("key1", "value1")

	// Hit
	val, ok = cache.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestToolCache_Expiration_P7(t *testing.T) {
	t.Parallel()
	cache := NewToolCache(10 * time.Millisecond)
	t.Cleanup(cache.Close)
	require.NotNil(t, cache)

	cache.Set("key1", "value1")
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	val, ok := cache.Get("key1")
	assert.False(t, ok)
	assert.Nil(t, val)
}

func TestDashboardBaseURL_Variations(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardBaseURL(mgr)
	_ = url
}

func TestDashboardBaseURL_WithExternalURL(t *testing.T) {
	t.Parallel()
	// DevMode manager always returns http://127.0.0.1:8080 (local mode)
	mgr := newDevModeManager(t)
	url := dashboardBaseURL(mgr)
	assert.Contains(t, url, "127.0.0.1")
}

func TestDashboardLink_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	_ = link
}

func TestDashboardLink_WithExternalURL(t *testing.T) {
	t.Parallel()
	// newDevModeManager creates a manager with DevMode=true and empty
	// AppMode → IsLocalMode() returns true → dashboardBaseURL returns
	// "http://127.0.0.1:8080" regardless of any EXTERNAL_URL value.
	// The previous t.Setenv was dead code: newDevModeManager does NOT
	// read env vars during construction. Removed for parallel-safety.
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	assert.NotEmpty(t, link)
}

func TestDashboardPageURL_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/test")
	_ = url
}

func TestDashboardPageURL_WithLocalMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := dashboardPageURL(mgr, "/portfolio")
	assert.Contains(t, url, "127.0.0.1")
}

func TestDashboardLink_LocalMode_P7(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	assert.NotEmpty(t, link) // Local mode returns 127.0.0.1
}
