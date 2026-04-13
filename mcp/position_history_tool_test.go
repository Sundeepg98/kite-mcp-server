package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// TestGetPositionHistoryReconstituted_ReplaysFullLifecycle proves the new
// position-reconstitution endpoint joins open + close events via the
// natural-key aggregate ID and returns a coherent lifecycle. This is the
// first production caller of LoadPositionFromEvents and validates that
// the public-format deserializer (the "position.opened" / "position.closed"
// branches added in the same commit) correctly parses events that were
// written via MarshalPayload on the public domain structs — which is the
// format production's makeEventPersister uses.
//
// Without the dual-format deserializer fix, this test would fail with
// "unknown position event type: position.opened" because the event store
// persists the public format but the legacy deserializer only recognized
// the internal "PositionOpened" / "PositionClosed" event type strings.
func TestGetPositionHistoryReconstituted_ReplaysFullLifecycle(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "position_history_test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	// Seed events directly in the public format that production uses.
	// Aggregate ID is the natural key — open and close share it.
	email := "replay@example.com"
	instrument := domain.NewInstrumentKey("NSE", "RELIANCE")
	product := "MIS"
	aggID := domain.PositionAggregateID(email, instrument, product)

	openedAt := time.Now().UTC().Truncate(time.Microsecond)
	closedAt := openedAt.Add(30 * time.Minute)
	openQty, _ := domain.NewQuantity(10)
	closeQty, _ := domain.NewQuantity(10)

	openEvent := domain.PositionOpenedEvent{
		Email:           email,
		PositionID:      "ORD-OPEN-1",
		Instrument:      instrument,
		Product:         product,
		Qty:             openQty,
		AvgPrice:        domain.NewINR(2500.50),
		TransactionType: "BUY",
		Timestamp:       openedAt,
	}
	openPayload, err := eventsourcing.MarshalPayload(openEvent)
	require.NoError(t, err)

	closeEvent := domain.PositionClosedEvent{
		Email:           email,
		OrderID:         "ORD-CLOSE-1",
		Instrument:      instrument,
		Product:         product,
		Qty:             closeQty,
		TransactionType: "SELL",
		Timestamp:       closedAt,
	}
	closePayload, err := eventsourcing.MarshalPayload(closeEvent)
	require.NoError(t, err)

	require.NoError(t, store.Append(
		eventsourcing.StoredEvent{
			AggregateID:   aggID,
			AggregateType: "Position",
			EventType:     "position.opened",
			Payload:       openPayload,
			OccurredAt:    openedAt,
			Sequence:      1,
		},
		eventsourcing.StoredEvent{
			AggregateID:   aggID,
			AggregateType: "Position",
			EventType:     "position.closed",
			Payload:       closePayload,
			OccurredAt:    closedAt,
			Sequence:      2,
		},
	))

	ctx := oauth.ContextWithEmail(context.Background(), email)
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "c3d4e5f6-a7b8-9012-cdef-0123456789ab"})

	tool := &GetPositionHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_position_history_reconstituted"
	req.Params.Arguments = map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "RELIANCE",
		"product":       "MIS",
	}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, "tool returned error result: %+v", result.Content)

	require.NotEmpty(t, result.Content)
	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])

	var res cqrs.PositionHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.True(t, res.Found, "position history should be found")
	assert.Equal(t, aggID, res.AggregateID)
	assert.Equal(t, 2, res.EventCount)
	assert.Equal(t, eventsourcing.PositionStatusClosed, res.FinalStatus)
	assert.Equal(t, email, res.Email)
	assert.Equal(t, "NSE", res.Exchange)
	assert.Equal(t, "RELIANCE", res.Tradingsymbol)
	assert.Equal(t, "MIS", res.Product)
	assert.NotEmpty(t, res.OpenedAt)
	assert.NotEmpty(t, res.ClosedAt)

	require.Len(t, res.States, 2)
	assert.Equal(t, "position.opened", res.States[0].EventType)
	assert.Equal(t, eventsourcing.PositionStatusOpen, res.States[0].Status)
	assert.Equal(t, 10, res.States[0].Quantity)
	assert.InDelta(t, 2500.50, res.States[0].AvgPrice, 0.001)

	assert.Equal(t, "position.closed", res.States[1].EventType)
	assert.Equal(t, eventsourcing.PositionStatusClosed, res.States[1].Status)
}

// TestGetPositionHistoryReconstituted_UnknownPositionReturnsNotFound — query
// for a position that has never been opened should return Found=false
// without a top-level error.
func TestGetPositionHistoryReconstituted_UnknownPositionReturnsNotFound(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "position_history_empty.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	ctx := oauth.ContextWithEmail(context.Background(), "stranger@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "d4e5f6a7-b8c9-0123-def0-1234567890bc"})

	tool := &GetPositionHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_position_history_reconstituted"
	req.Params.Arguments = map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "DOESNOTEXIST",
		"product":       "CNC",
	}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError)

	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	var res cqrs.PositionHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.False(t, res.Found)
	assert.Equal(t, 0, res.EventCount)
	assert.Empty(t, res.States)
	assert.Contains(t, res.AggregateID, "DOESNOTEXIST")
}
