package riskguard

import (
	"context"
	"sync"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// TestDedup_SeenOrAdd_FirstCallAllowed verifies that the first submission of
// a (email, clientOrderID) pair is accepted (SeenOrAdd returns false meaning
// "not yet seen — now recorded").
func TestDedup_SeenOrAdd_FirstCallAllowed(t *testing.T) {
	t.Parallel()
	d := NewDedup(15 * time.Minute)
	assert.False(t, d.SeenOrAdd("user@test.com", "abc-123"),
		"first call should not be a duplicate")
}

// TestDedup_SeenOrAdd_SecondCallBlocked verifies that a second submission of
// the same (email, clientOrderID) within TTL is flagged as duplicate.
func TestDedup_SeenOrAdd_SecondCallBlocked(t *testing.T) {
	t.Parallel()
	d := NewDedup(15 * time.Minute)
	assert.False(t, d.SeenOrAdd("user@test.com", "abc-123"), "first call allowed")
	assert.True(t, d.SeenOrAdd("user@test.com", "abc-123"),
		"second call within TTL should be marked duplicate")
}

// TestDedup_SeenOrAdd_AfterTTL verifies that an entry expires after the TTL
// elapses and the same key can be used again.
func TestDedup_SeenOrAdd_AfterTTL(t *testing.T) {
	t.Parallel()
	d := NewDedup(100 * time.Millisecond)
	base := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	d.SetClock(func() time.Time { return base })
	assert.False(t, d.SeenOrAdd("user@test.com", "abc-123"), "first call allowed")

	// Advance beyond TTL.
	d.SetClock(func() time.Time { return base.Add(200 * time.Millisecond) })
	assert.False(t, d.SeenOrAdd("user@test.com", "abc-123"),
		"after TTL, same key should be accepted again")
}

// TestDedup_UserScoped verifies that different users with the same
// clientOrderID do NOT collide (hash is scoped per email).
func TestDedup_UserScoped(t *testing.T) {
	t.Parallel()
	d := NewDedup(15 * time.Minute)
	assert.False(t, d.SeenOrAdd("alice@test.com", "shared-key"), "alice first call")
	assert.False(t, d.SeenOrAdd("bob@test.com", "shared-key"),
		"bob with same key should not collide with alice")
	// Now Alice tries again — her own key is now a dup.
	assert.True(t, d.SeenOrAdd("alice@test.com", "shared-key"),
		"alice's second call is a duplicate")
}

// TestDedup_DifferentKeysAllowed verifies that different keys for the same
// user are all allowed independently.
func TestDedup_DifferentKeysAllowed(t *testing.T) {
	t.Parallel()
	d := NewDedup(15 * time.Minute)
	assert.False(t, d.SeenOrAdd("u@t.com", "key-1"))
	assert.False(t, d.SeenOrAdd("u@t.com", "key-2"))
	assert.False(t, d.SeenOrAdd("u@t.com", "key-3"))
	// But each individual key blocks on retry.
	assert.True(t, d.SeenOrAdd("u@t.com", "key-1"))
	assert.True(t, d.SeenOrAdd("u@t.com", "key-2"))
}

// TestDedup_Concurrent verifies that concurrent SeenOrAdd calls with the same
// key produce exactly one "first" (false) and the rest as duplicates (true).
// This is the critical race-condition test — mcp-remote retries after 504
// can fire concurrent requests.
func TestDedup_Concurrent(t *testing.T) {
	t.Parallel()
	d := NewDedup(15 * time.Minute)
	const N = 50
	results := make([]bool, N)
	var wg sync.WaitGroup
	for i := range N {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = d.SeenOrAdd("u@t.com", "race-key")
		}(i)
	}
	wg.Wait()

	// Exactly one caller must receive false (the winner), rest must be true.
	falseCount := 0
	for _, r := range results {
		if !r {
			falseCount++
		}
	}
	assert.Equal(t, 1, falseCount,
		"exactly one concurrent caller should win the first-write race")
}

// TestDedup_CleanupRemovesStaleEntries verifies that stale entries are purged
// so the map does not grow without bound.
func TestDedup_CleanupRemovesStaleEntries(t *testing.T) {
	t.Parallel()
	d := NewDedup(50 * time.Millisecond)
	base := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	d.SetClock(func() time.Time { return base })
	d.SeenOrAdd("u@t.com", "k1")
	d.SeenOrAdd("u@t.com", "k2")
	assert.Equal(t, 2, d.Size(), "two entries before cleanup")

	// Advance beyond TTL and trigger cleanup.
	d.SetClock(func() time.Time { return base.Add(200 * time.Millisecond) })
	d.Cleanup()
	assert.Equal(t, 0, d.Size(), "stale entries should be purged")
}

// =============================================================================
// Guard integration: checkDuplicate wiring
// =============================================================================

// TestGuard_CheckOrder_NoClientOrderID_BackwardCompat verifies that when
// ClientOrderID is empty, the idempotency dedup does not block the order
// (preserves existing behaviour).
func TestGuard_CheckOrder_NoClientOrderID_BackwardCompat(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	// Submit twice without ClientOrderID — should both pass the new dedup
	// check (time-based dedup still applies but that's different signature).
	req := OrderCheckRequest{
		Email: "u@t.com", ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 1, Price: 100, OrderType: "LIMIT",
		Confirmed: true,
	}
	r1 := g.CheckOrder(req)
	assert.True(t, r1.Allowed, "first order without client_order_id allowed")
	// Second with different tradingsymbol so time-based dedup doesn't fire.
	req.Tradingsymbol = "TCS"
	r2 := g.CheckOrder(req)
	assert.True(t, r2.Allowed, "second order (different symbol) allowed")
}

// TestGuard_CheckOrder_DuplicateClientOrderID_Blocked verifies that a retry
// with the same ClientOrderID is blocked with ReasonDuplicateOrder.
func TestGuard_CheckOrder_DuplicateClientOrderID_Blocked(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	req := OrderCheckRequest{
		Email: "u@t.com", ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 1, Price: 100, OrderType: "LIMIT",
		Confirmed:     true,
		ClientOrderID: "req-abc-123",
	}
	r1 := g.CheckOrder(req)
	assert.True(t, r1.Allowed, "first submission with client_order_id allowed")

	// Simulate retry — exact same ClientOrderID.
	r2 := g.CheckOrder(req)
	assert.False(t, r2.Allowed, "retry with same client_order_id must be blocked")
	assert.Equal(t, ReasonDuplicateOrder, r2.Reason, "TestGuard_CheckOrder_DuplicateClientOrderID_Blocked: want=%v got=%v", ReasonDuplicateOrder, r2.Reason)
}

// TestGuard_CheckOrder_ClientOrderID_DifferentUsers verifies that two users
// can independently use the same ClientOrderID.
func TestGuard_CheckOrder_ClientOrderID_DifferentUsers(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	base := OrderCheckRequest{
		ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 1, Price: 100, OrderType: "LIMIT",
		Confirmed:     true,
		ClientOrderID: "shared-id",
	}
	aliceReq := base
	aliceReq.Email = "alice@test.com"
	bobReq := base
	bobReq.Email = "bob@test.com"

	r1 := g.CheckOrder(aliceReq)
	assert.True(t, r1.Allowed, "alice's order allowed")
	r2 := g.CheckOrder(bobReq)
	assert.True(t, r2.Allowed,
		"bob's order with same client_order_id must be allowed (user-scoped)")
}

// =============================================================================
// Middleware wiring: client_order_id flows from tool args through to the guard
// =============================================================================

// TestMiddleware_ClientOrderID_Blocked_OnRetry exercises the full middleware
// path: place_order with the same client_order_id twice must be rejected the
// second time with a duplicate_order error. This simulates the mcp-remote
// "retry after 504" scenario Agent 54 flagged.
func TestMiddleware_ClientOrderID_Blocked_OnRetry(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	mw := Middleware(g)

	handlerCalls := 0
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalls++
		return gomcp.NewToolResultText("order placed"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(5),
		"price":            float64(1500),
		"order_type":       "LIMIT",
		"confirm":          true,
		"client_order_id":  "retry-key-xyz",
	}

	ctx := oauth.ContextWithEmail(context.Background(), "retry@test.com")

	// First submission — handler runs.
	r1, err := handler(ctx, req)
	require.NoError(t, err, "TestMiddleware_ClientOrderID_Blocked_OnRetry: err")
	assert.False(t, r1.IsError, "first submission should succeed")
	assert.Equal(t, 1, handlerCalls, "TestMiddleware_ClientOrderID_Blocked_OnRetry: want=%v got=%v", 1, handlerCalls)

	// Simulated retry — same client_order_id, handler MUST NOT run.
	r2, err := handler(ctx, req)
	require.NoError(t, err, "TestMiddleware_ClientOrderID_Blocked_OnRetry: err")
	assert.True(t, r2.IsError, "retry with same client_order_id must be blocked")
	assert.Equal(t, 1, handlerCalls, "handler should not be invoked on retry")
}

// TestMiddleware_ClientOrderID_ModifyOrder verifies the same wiring applies to
// modify_order (which is also listed in orderTools).
func TestMiddleware_ClientOrderID_ModifyOrder(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	mw := Middleware(g)

	handlerCalls := 0
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handlerCalls++
		return gomcp.NewToolResultText("order modified"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "modify_order"
	req.Params.Arguments = map[string]any{
		"order_id":        "ORD-42",
		"order_type":      "LIMIT",
		"quantity":        float64(10),
		"price":           float64(1000),
		"confirm":         true,
		"client_order_id": "mod-retry-1",
	}

	ctx := oauth.ContextWithEmail(context.Background(), "modifier@test.com")

	r1, err := handler(ctx, req)
	require.NoError(t, err, "TestMiddleware_ClientOrderID_ModifyOrder: err")
	assert.False(t, r1.IsError, "TestMiddleware_ClientOrderID_ModifyOrder: r1.IsError")

	r2, err := handler(ctx, req)
	require.NoError(t, err, "TestMiddleware_ClientOrderID_ModifyOrder: err")
	assert.True(t, r2.IsError, "TestMiddleware_ClientOrderID_ModifyOrder: r2.IsError")
	assert.Equal(t, 1, handlerCalls, "modify_order retry must be blocked before handler")
}
