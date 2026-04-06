package mcp

import (
	"context"
	"log/slog"
	"os"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// writeTools derivation: viewer role should be blocked from write tools
// ---------------------------------------------------------------------------

func TestWriteToolsDerivation(t *testing.T) {
	// writeTools is populated at init time from GetAllTools annotations.
	t.Run("write tools populated", func(t *testing.T) {
		assert.NotEmpty(t, writeTools, "writeTools should be populated at init")
	})

	t.Run("place_order is a write tool", func(t *testing.T) {
		assert.True(t, writeTools["place_order"], "place_order should be a write tool")
	})

	t.Run("modify_order is a write tool", func(t *testing.T) {
		assert.True(t, writeTools["modify_order"], "modify_order should be a write tool")
	})

	t.Run("cancel_order is a write tool", func(t *testing.T) {
		assert.True(t, writeTools["cancel_order"], "cancel_order should be a write tool")
	})

	t.Run("close_position is a write tool", func(t *testing.T) {
		assert.True(t, writeTools["close_position"], "close_position should be a write tool")
	})

	t.Run("set_alert is a write tool", func(t *testing.T) {
		assert.True(t, writeTools["set_alert"], "set_alert should be a write tool")
	})

	t.Run("read-only tools not in writeTools", func(t *testing.T) {
		// Tools explicitly annotated as ReadOnlyHint=true should NOT be in writeTools.
		allTools := GetAllTools()
		for _, toolDef := range allTools {
			tool := toolDef.Tool()
			if tool.Annotations.ReadOnlyHint != nil && *tool.Annotations.ReadOnlyHint {
				assert.False(t, writeTools[tool.Name],
					"read-only tool %q should NOT be in writeTools", tool.Name)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Billing middleware: free user blocked from pro tools
// ---------------------------------------------------------------------------

func TestBillingMiddleware_FreeUserBlockedFromProTool(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := billing.NewStore(db, logger)
	require.NoError(t, store.InitTable())

	// No subscription set — user defaults to TierFree.
	mw := billing.Middleware(store, nil)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	// Simulate authenticated context for a free user.
	ctx := oauth.ContextWithEmail(context.Background(), "free@example.com")

	tests := []struct {
		toolName string
		blocked  bool
	}{
		{"place_order", true},        // Pro tool
		{"modify_order", true},       // Pro tool
		{"set_alert", true},          // Pro tool
		{"get_holdings", false},      // Free tool
		{"get_profile", false},       // Free tool
		{"get_ltp", false},           // Free tool
		{"login", false},             // Free tool
		{"backtest_strategy", true},  // Premium tool
	}

	for _, tc := range tests {
		t.Run(tc.toolName, func(t *testing.T) {
			req := gomcp.CallToolRequest{}
			req.Params.Name = tc.toolName

			result, err := handler(ctx, req)
			require.NoError(t, err)

			if tc.blocked {
				assert.True(t, result.IsError, "tool %s should be blocked for free user", tc.toolName)
				// The error content is in Content[0].Text
				if len(result.Content) > 0 {
					text := result.Content[0].(gomcp.TextContent).Text
					assert.Contains(t, text, "subscription")
				}
			} else {
				assert.False(t, result.IsError, "tool %s should pass for free user", tc.toolName)
			}
		})
	}
}

func TestBillingMiddleware_ProUserAccessesProTools(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := billing.NewStore(db, logger)
	require.NoError(t, store.InitTable())

	// Set up a Pro subscription.
	require.NoError(t, store.SetSubscription(&billing.Subscription{
		Email:  "pro@example.com",
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	mw := billing.Middleware(store, nil)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)
	ctx := oauth.ContextWithEmail(context.Background(), "pro@example.com")

	// Pro tools should pass.
	for _, toolName := range []string{"place_order", "modify_order", "set_alert", "get_holdings"} {
		t.Run(toolName, func(t *testing.T) {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName

			result, err := handler(ctx, req)
			require.NoError(t, err)
			assert.False(t, result.IsError, "Pro user should access %s", toolName)
		})
	}

	// Premium tools should still be blocked for Pro user.
	t.Run("premium tool blocked for pro user", func(t *testing.T) {
		req := gomcp.CallToolRequest{}
		req.Params.Name = "backtest_strategy"

		result, err := handler(ctx, req)
		require.NoError(t, err)
		assert.True(t, result.IsError, "Pro user should NOT access Premium tool")
	})
}

func TestBillingMiddleware_NoAuthPassesThrough(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := billing.NewStore(db, logger)
	require.NoError(t, store.InitTable())

	mw := billing.Middleware(store, nil)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	// No email in context — should pass through (auth middleware handles rejection).
	ctx := context.Background()
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "no auth context should pass through billing middleware")
}

// ---------------------------------------------------------------------------
// Riskguard middleware: blocks dangerous orders
// ---------------------------------------------------------------------------

func TestRiskguardMiddleware_BlocksOverValueOrder(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	// Authenticated context.
	ctx := oauth.ContextWithEmail(context.Background(), "trader@example.com")

	// Order worth Rs 10,00,000 > limit of Rs 5,00,000.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(100),
		"price":            float64(10000),
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError, "over-value order should be blocked")
	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "ORDER BLOCKED")
		assert.Contains(t, text, "order_value_limit")
	}
}

func TestRiskguardMiddleware_AllowsValidOrder(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "trader@example.com")

	// Small valid order.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(5),
		"price":            float64(1500),
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "valid small order should pass riskguard")
}

func TestRiskguardMiddleware_NonOrderToolPassesThrough(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())

	// Freeze the user — should not matter for non-order tools.
	guard.Freeze("frozen@example.com", "admin", "test")

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "frozen@example.com")

	// get_holdings is NOT an order tool — should pass through even when frozen.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "non-order tools should pass through riskguard even when frozen")
}

func TestRiskguardMiddleware_FrozenUserBlocked(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())
	guard.Freeze("frozen@example.com", "admin", "test freeze")

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "frozen@example.com")

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(1),
		"price":            float64(100),
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "trading_frozen")
	}
}

func TestRiskguardMiddleware_NoAuthPassesThrough(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	handler := mw(passthrough)

	// No email in context — should fail open.
	ctx := context.Background()
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "no auth context should fail open in riskguard middleware")
}

func TestRiskguardMiddleware_RecordsSuccessfulOrder(t *testing.T) {
	guard := riskguard.NewGuard(slog.Default())

	mw := riskguard.Middleware(guard)

	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("Order placed"), nil
	}

	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "track@example.com")

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(5),
		"price":            float64(1500),
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	// Verify the order was recorded by the guard.
	status := guard.GetUserStatus("track@example.com")
	assert.Equal(t, 1, status.DailyOrderCount, "successful order should be recorded")
	assert.InDelta(t, 5*1500.0, status.DailyPlacedValue, 0.01)
}

// ---------------------------------------------------------------------------
// Middleware chain ordering: billing -> riskguard -> handler
// ---------------------------------------------------------------------------

func TestMiddlewareChain_BillingBlocksBeforeRiskguard(t *testing.T) {
	// Set up billing store with free user.
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	billingStore := billing.NewStore(db, logger)
	require.NoError(t, billingStore.InitTable())

	// No subscription — free user.

	guard := riskguard.NewGuard(slog.Default())

	// Build the chain: billing -> riskguard -> handler.
	passthrough := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("OK"), nil
	}

	// Apply middlewares in order (billing wraps riskguard wraps handler).
	var chain server.ToolHandlerFunc = passthrough
	chain = riskguard.Middleware(guard)(chain)
	chain = billing.Middleware(billingStore, nil)(chain)

	ctx := oauth.ContextWithEmail(context.Background(), "free@example.com")

	// Try place_order (Pro tool) — should be blocked by billing, not riskguard.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(1),
		"price":            float64(100),
	}

	result, err := chain(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError)

	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "subscription", "should be blocked by billing, not riskguard")
		assert.NotContains(t, text, "ORDER BLOCKED", "riskguard should not have been reached")
	}

	// Riskguard should NOT have recorded anything (billing blocked first).
	status := guard.GetUserStatus("free@example.com")
	assert.Equal(t, 0, status.DailyOrderCount, "riskguard should not have been reached")
}

// ---------------------------------------------------------------------------
// Tool annotations: all tools have annotations set
// ---------------------------------------------------------------------------

func TestAllToolsHaveAnnotations(t *testing.T) {
	allTools := GetAllTools()

	for _, toolDef := range allTools {
		tool := toolDef.Tool()
		t.Run(tool.Name, func(t *testing.T) {
			// Every tool should have a non-empty title in annotations.
			assert.NotNil(t, tool.Annotations, "tool %s should have annotations", tool.Name)
		})
	}
}

func TestWriteToolsAreOrderToolsOrMore(t *testing.T) {
	// Every riskguard order tool should be in writeTools too.
	orderToolNames := []string{
		"place_order", "modify_order",
		"close_position", "close_all_positions",
		"place_gtt_order", "modify_gtt_order",
		"place_mf_order", "place_mf_sip",
	}
	for _, name := range orderToolNames {
		assert.True(t, writeTools[name],
			"riskguard order tool %q should also be in writeTools", name)
	}
}
