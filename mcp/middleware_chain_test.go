package mcp

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Full middleware chain integration test:
//   audit -> billing -> riskguard -> actual handler
//
// The actual app order (from app.go) is:
//   audit → riskguard → billing → paper-trading → dashboard-url
//
// Middleware applied via WithToolHandlerMiddleware wraps in order,
// so the outermost (first applied) runs first.
// ---------------------------------------------------------------------------

// setupChain constructs the full middleware chain for testing.
// Returns the chain, the audit store, and a cleanup function.
func setupChain(t *testing.T, handler server.ToolHandlerFunc) (server.ToolHandlerFunc, *audit.Store, *billing.Store, *riskguard.Guard, func()) {
	t.Helper()

	// Use a temp file DB because :memory: with concurrent access (audit worker goroutine)
	// can cause issues with SQLite's connection pool in Go.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Audit store
	auditStore := audit.New(db)
	auditStore.SetLogger(logger)
	require.NoError(t, auditStore.InitTable())
	auditStore.StartWorker()

	// Billing store
	billingStore := billing.NewStore(db, logger)
	require.NoError(t, billingStore.InitTable())

	// Riskguard
	guard := riskguard.NewGuard(logger)

	// Build the chain: audit -> billing -> riskguard -> handler
	// Applied in reverse so that audit is outermost (runs first).
	var chain server.ToolHandlerFunc = handler
	chain = riskguard.Middleware(guard)(chain)
	chain = billing.Middleware(billingStore)(chain)
	chain = audit.Middleware(auditStore)(chain)

	cleanup := func() {
		auditStore.Stop()
		db.Close()
	}

	return chain, auditStore, billingStore, guard, cleanup
}

// TestFullChain_FreeUserBlockedByBilling verifies that a free user calling
// a pro tool (place_order) is blocked by billing middleware, and that the
// audit trail records the blocked attempt.
func TestFullChain_FreeUserBlockedByBilling(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalled = true
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, auditStore, _, _, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "free-chain@example.com"
	ctx := oauth.ContextWithEmail(context.Background(), email)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(1),
		"price":            float64(100),
	}

	result, err := chain(ctx, req)
	require.NoError(t, err)

	// Billing should block the free user from pro tool
	assert.True(t, result.IsError, "free user should be blocked from place_order")
	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "subscription")
	}

	// Handler should NOT have been called
	assert.False(t, handlerCalled, "handler should not be reached when billing blocks")

	// Give the audit worker time to process (it's async via channel)
	time.Sleep(100 * time.Millisecond)

	// Audit should have recorded the call (even though it was blocked)
	records, total, err := auditStore.List(email, audit.ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "audit should have recorded 1 call")
	assert.Len(t, records, 1)
	assert.Equal(t, "place_order", records[0].ToolName)
	assert.True(t, records[0].IsError, "audit should record that it was an error")
}

// TestFullChain_ProUserValidOrder verifies that a pro user with a valid small
// order passes through all middleware and reaches the handler.
func TestFullChain_ProUserValidOrder(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalled = true
		return gomcp.NewToolResultText("Order placed: 123456"), nil
	}

	chain, auditStore, billingStore, guard, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "pro-chain@example.com"

	// Set up Pro subscription
	require.NoError(t, billingStore.SetSubscription(&billing.Subscription{
		Email:  email,
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	ctx := oauth.ContextWithEmail(context.Background(), email)

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

	result, err := chain(ctx, req)
	require.NoError(t, err)

	// Should pass through all middleware
	assert.False(t, result.IsError, "pro user with valid order should succeed")
	assert.True(t, handlerCalled, "handler should be reached")

	// Riskguard should have recorded the order
	status := guard.GetUserStatus(email)
	assert.Equal(t, 1, status.DailyOrderCount, "riskguard should record successful order")

	// Audit should record the call
	time.Sleep(100 * time.Millisecond)
	records, total, err := auditStore.List(email, audit.ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, records, 1)
	assert.Equal(t, "place_order", records[0].ToolName)
	assert.False(t, records[0].IsError)
}

// TestFullChain_ProUserExcessiveValueBlocked verifies that a pro user
// with an order exceeding the riskguard value limit is blocked.
func TestFullChain_ProUserExcessiveValueBlocked(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalled = true
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, auditStore, billingStore, _, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "pro-overvalue@example.com"

	// Set up Pro subscription
	require.NoError(t, billingStore.SetSubscription(&billing.Subscription{
		Email:  email,
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	ctx := oauth.ContextWithEmail(context.Background(), email)

	// Order worth Rs 10,00,000 > riskguard limit of Rs 5,00,000
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

	result, err := chain(ctx, req)
	require.NoError(t, err)

	// Riskguard should block
	assert.True(t, result.IsError, "over-value order should be blocked by riskguard")
	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "ORDER BLOCKED")
	}

	// Handler should NOT be reached
	assert.False(t, handlerCalled, "handler should not be reached when riskguard blocks")

	// Audit should still record the blocked call
	time.Sleep(100 * time.Millisecond)
	records, total, err := auditStore.List(email, audit.ListOptions{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.True(t, records[0].IsError)
}

// TestFullChain_ReadOnlyToolPassesForAnyUser verifies that read-only tools
// pass through all middleware regardless of subscription tier.
func TestFullChain_ReadOnlyToolPassesForAnyUser(t *testing.T) {
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText(`{"holdings": []}`), nil
	}

	chain, auditStore, _, _, cleanup := setupChain(t, handler)
	defer cleanup()

	users := []struct {
		email string
		desc  string
	}{
		{"free-read@example.com", "free user"},
		{"unknown@example.com", "unknown user"},
	}

	readOnlyTools := []string{"get_holdings", "get_positions", "get_margins", "get_profile", "get_orders"}

	for _, user := range users {
		for _, toolName := range readOnlyTools {
			t.Run(user.desc+"_"+toolName, func(t *testing.T) {
				ctx := oauth.ContextWithEmail(context.Background(), user.email)
				req := gomcp.CallToolRequest{}
				req.Params.Name = toolName

				result, err := chain(ctx, req)
				require.NoError(t, err)
				assert.False(t, result.IsError,
					"%s should pass through middleware for %s", toolName, user.desc)
			})
		}
	}

	// Wait for audit records
	time.Sleep(100 * time.Millisecond)

	// Verify audit records were created for all calls
	for _, user := range users {
		records, total, err := auditStore.List(user.email, audit.ListOptions{Limit: 50})
		require.NoError(t, err)
		assert.Equal(t, len(readOnlyTools), total,
			"audit should have %d records for %s", len(readOnlyTools), user.desc)
		assert.Len(t, records, len(readOnlyTools))
	}
}

// TestFullChain_AuditRecordsCreatedForEveryCall verifies that audit records
// are created regardless of the outcome (success, billing block, riskguard block).
func TestFullChain_AuditRecordsCreatedForEveryCall(t *testing.T) {
	callCount := 0
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		callCount++
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, auditStore, billingStore, _, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "audit-all@example.com"
	ctx := oauth.ContextWithEmail(context.Background(), email)

	// Set up Pro subscription BEFORE making calls to avoid concurrent DB writes
	// between billing and audit worker (audit writes async, billing writes sync).
	require.NoError(t, billingStore.SetSubscription(&billing.Subscription{
		Email:  email,
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	// Wait for any pending audit writes from setup
	time.Sleep(50 * time.Millisecond)

	// 1. Read-only tool (passes all middleware)
	req1 := gomcp.CallToolRequest{}
	req1.Params.Name = "get_holdings"
	result1, err := chain(ctx, req1)
	require.NoError(t, err)
	assert.False(t, result1.IsError)

	// Small pause between calls to avoid SQLite busy
	time.Sleep(50 * time.Millisecond)

	// 2. Valid order (passes billing + riskguard, reaches handler)
	req2 := gomcp.CallToolRequest{}
	req2.Params.Name = "place_order"
	req2.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"quantity": float64(1), "price": float64(1500),
	}
	result2, err := chain(ctx, req2)
	require.NoError(t, err)
	assert.False(t, result2.IsError)

	time.Sleep(50 * time.Millisecond)

	// 3. Over-value order (passes billing, blocked by riskguard)
	req3 := gomcp.CallToolRequest{}
	req3.Params.Name = "place_order"
	req3.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"quantity": float64(200), "price": float64(10000),
	}
	result3, err := chain(ctx, req3)
	require.NoError(t, err)
	assert.True(t, result3.IsError, "over-value order should be blocked")

	// Wait for all async audit writes to complete
	time.Sleep(300 * time.Millisecond)

	// All 3 calls should be audited
	records, total, err := auditStore.List(email, audit.ListOptions{Limit: 50})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "all 3 tool calls should have audit records")
	assert.Len(t, records, 3)

	// Count errors vs successes in audit
	var errCount, okCount int
	for _, r := range records {
		if r.IsError {
			errCount++
		} else {
			okCount++
		}
	}

	// Call 3 (riskguard block) = 1 error
	// Call 1 (read-only) + Call 2 (valid order) = 2 successes
	assert.Equal(t, 1, errCount, "1 call should be recorded as error")
	assert.Equal(t, 2, okCount, "2 calls should be recorded as successes")

	// Only calls 1 and 2 should have reached the handler
	assert.Equal(t, 2, callCount, "only 2 calls should reach the handler")
}

// TestFullChain_FrozenUserBlockedByRiskguard verifies that a frozen user is
// blocked by riskguard even though billing allows pro tools.
func TestFullChain_FrozenUserBlockedByRiskguard(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalled = true
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, _, billingStore, guard, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "frozen-pro@example.com"

	// Set up Pro subscription
	require.NoError(t, billingStore.SetSubscription(&billing.Subscription{
		Email:  email,
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	// Freeze the user
	guard.Freeze(email, "admin", "suspicious activity")

	ctx := oauth.ContextWithEmail(context.Background(), email)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"quantity": float64(1), "price": float64(100),
	}

	result, err := chain(ctx, req)
	require.NoError(t, err)

	assert.True(t, result.IsError, "frozen user should be blocked")
	if len(result.Content) > 0 {
		text := result.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "trading_frozen")
	}
	assert.False(t, handlerCalled, "handler should not be reached for frozen user")
}

// TestFullChain_NoAuthContextPassesThrough verifies that calls without email
// in context pass through all middleware (auth is handled elsewhere).
func TestFullChain_NoAuthContextPassesThrough(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalled = true
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, _, _, _, cleanup := setupChain(t, handler)
	defer cleanup()

	// No email in context
	ctx := context.Background()

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"quantity": float64(1), "price": float64(100),
	}

	result, err := chain(ctx, req)
	require.NoError(t, err)

	// All middleware should fail-open for unauthenticated context
	assert.False(t, result.IsError, "no-auth context should pass through")
	assert.True(t, handlerCalled, "handler should be reached with no auth")
}

// TestFullChain_DuplicateOrderDetection verifies riskguard's duplicate
// order detection within the dedup window.
func TestFullChain_DuplicateOrderDetection(t *testing.T) {
	callCount := 0
	handler := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		callCount++
		return gomcp.NewToolResultText("OK"), nil
	}

	chain, _, billingStore, _, cleanup := setupChain(t, handler)
	defer cleanup()

	email := "dupe-chain@example.com"

	// Set up Pro subscription
	require.NoError(t, billingStore.SetSubscription(&billing.Subscription{
		Email:  email,
		Tier:   billing.TierPro,
		Status: billing.StatusActive,
	}))

	ctx := oauth.ContextWithEmail(context.Background(), email)

	makeReq := func() gomcp.CallToolRequest {
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
		return req
	}

	// First order should succeed
	result1, err := chain(ctx, makeReq())
	require.NoError(t, err)
	assert.False(t, result1.IsError, "first order should succeed")

	// Second identical order within dedup window should be blocked
	result2, err := chain(ctx, makeReq())
	require.NoError(t, err)
	assert.True(t, result2.IsError, "duplicate order should be blocked")
	if len(result2.Content) > 0 {
		text := result2.Content[0].(gomcp.TextContent).Text
		assert.Contains(t, text, "ORDER BLOCKED")
		assert.Contains(t, text, "duplicate_order")
	}

	// Only the first order should have reached the handler
	assert.Equal(t, 1, callCount, "only first order should reach handler")
}
