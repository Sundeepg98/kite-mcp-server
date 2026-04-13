package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// TestGetOrderHistoryReconstituted_ReplaysFullLifecycle is the load-bearing
// test for Task #25 — it proves the new tool actually calls
// eventsourcing.LoadOrderFromEvents on a real persisted event stream and
// returns the reconstituted lifecycle. This is the first production consumer
// of aggregate reconstitution; the path existed only in package-level tests
// before.
//
// The test seeds a real SQLite-backed EventStore with a placed → modified →
// filled lifecycle via the public OrderAggregate API + ToStoredEvents, dispatches
// get_order_history_reconstituted through the tool handler, and asserts:
//  1. States count equals 3 (one snapshot per event)
//  2. Final status is FILLED
//  3. Each snapshot's Status matches the expected lifecycle progression
//  4. EventCount and final-state fields match the seeded values
func TestGetOrderHistoryReconstituted_ReplaysFullLifecycle(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	// Stand up a fresh event store in a temp DB and attach it to the manager.
	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "history_test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	// Build a full order lifecycle via the public aggregate API so the events
	// go through the same serialization the production code uses.
	agg := eventsourcing.NewOrderAggregate("order-history-test")
	require.NoError(t, agg.Place(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "SBIN",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           500.0,
	}, "replay@example.com"))

	require.NoError(t, agg.Modify(10, 505.0, "LIMIT"))
	require.NoError(t, agg.Fill(504.75, 10))

	storedEvents, err := eventsourcing.ToStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 3, "expected placed + modified + filled events")
	require.NoError(t, store.Append(storedEvents...))

	// Invoke the tool through the handler so the QueryBus registration path
	// gets exercised end-to-end.
	ctx := oauth.ContextWithEmail(context.Background(), "replay@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "e1f2a3b4-c5d6-7890-abcd-ef0123456789"})

	tool := &GetOrderHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_order_history_reconstituted"
	req.Params.Arguments = map[string]any{"order_id": "order-history-test"}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, "tool returned error result: %+v", result.Content)

	// The tool marshals OrderHistoryResult as JSON text. Unmarshal and assert.
	require.NotEmpty(t, result.Content)
	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])

	var res cqrs.OrderHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.True(t, res.Found, "order should be found in event store")
	assert.Equal(t, "order-history-test", res.OrderID)
	assert.Equal(t, 3, res.EventCount, "expected 3 events in the persisted lifecycle")
	assert.Equal(t, eventsourcing.OrderStatusFilled, res.FinalStatus)
	assert.Equal(t, "NSE", res.Exchange)
	assert.Equal(t, "SBIN", res.Tradingsymbol)
	assert.Equal(t, "BUY", res.TransactionType)
	assert.Equal(t, "replay@example.com", res.Email)
	assert.Equal(t, 10, res.FinalQuantity)
	assert.InDelta(t, 504.75, res.FinalFilledPrice, 0.001)
	assert.Equal(t, 1, res.ModifyCount)
	assert.Equal(t, 3, res.Version)

	// Each event should produce exactly one snapshot, and the snapshots must
	// walk the lifecycle in order (PLACED -> MODIFIED -> FILLED).
	require.Len(t, res.States, 3)
	assert.Equal(t, "OrderPlaced", res.States[0].EventType)
	assert.Equal(t, eventsourcing.OrderStatusPlaced, res.States[0].Status)
	assert.Equal(t, "OrderModified", res.States[1].EventType)
	assert.Equal(t, eventsourcing.OrderStatusModified, res.States[1].Status)
	assert.Equal(t, "OrderFilled", res.States[2].EventType)
	assert.Equal(t, eventsourcing.OrderStatusFilled, res.States[2].Status)
	assert.Equal(t, 10, res.States[2].FilledQuantity)
}

// TestGetOrderHistoryReconstituted_UnknownOrderReturnsNotFound asserts the
// tool returns Found=false (no error) when the requested order ID has no
// persisted events. This is the shape the MCP client expects — a query for
// an unknown order should produce a read model with Found=false, not a
// top-level error.
func TestGetOrderHistoryReconstituted_UnknownOrderReturnsNotFound(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "history_empty.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	ctx := oauth.ContextWithEmail(context.Background(), "replay@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "f0a1b2c3-d4e5-6789-abcd-ef0123456789"})

	tool := &GetOrderHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_order_history_reconstituted"
	req.Params.Arguments = map[string]any{"order_id": "does-not-exist"}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError)

	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	var res cqrs.OrderHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.False(t, res.Found)
	assert.Equal(t, "does-not-exist", res.OrderID)
	assert.Equal(t, 0, res.EventCount)
	assert.Empty(t, res.States)
}
