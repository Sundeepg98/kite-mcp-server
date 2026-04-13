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
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// TestGetAlertHistoryReconstituted_ReplaysFullLifecycle is the load-bearing
// test for Task #32 — it proves the new tool replays a persisted alert
// event stream via LoadAlertFromEvents and returns the reconstituted
// lifecycle. First production consumer of alert aggregate reconstitution.
//
// Seeds a real SQLite event store with create → trigger → delete via the
// public AlertAggregate API + ToAlertStoredEvents, then dispatches
// get_alert_history_reconstituted through the tool handler and asserts
// the timeline matches.
func TestGetAlertHistoryReconstituted_ReplaysFullLifecycle(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "alert_history_test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	// Build a full alert lifecycle via the public aggregate API.
	agg := eventsourcing.NewAlertAggregate("alert-history-test")
	require.NoError(t, agg.Create("replay@example.com", "RELIANCE", "NSE", 2500.0, "above"))
	require.NoError(t, agg.Trigger(2510.5))
	require.NoError(t, agg.Delete())

	storedEvents, err := eventsourcing.ToAlertStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 3, "expected created + triggered + deleted events")
	require.NoError(t, store.Append(storedEvents...))

	ctx := oauth.ContextWithEmail(context.Background(), "replay@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "a1b2c3d4-e5f6-7890-abcd-ef0123456789"})

	tool := &GetAlertHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_alert_history_reconstituted"
	req.Params.Arguments = map[string]any{"alert_id": "alert-history-test"}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, "tool returned error result: %+v", result.Content)

	require.NotEmpty(t, result.Content)
	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])

	var res cqrs.AlertHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.True(t, res.Found, "alert should be found in event store")
	assert.Equal(t, "alert-history-test", res.AlertID)
	assert.Equal(t, 3, res.EventCount)
	assert.Equal(t, eventsourcing.AlertStatusDeleted, res.FinalStatus)
	assert.Equal(t, "replay@example.com", res.Email)
	assert.Equal(t, "NSE", res.Exchange)
	assert.Equal(t, "RELIANCE", res.Tradingsymbol)
	assert.Equal(t, "above", res.Direction)
	assert.InDelta(t, 2500.0, res.TargetPrice, 0.001)
	assert.Equal(t, 3, res.Version)
	assert.NotEmpty(t, res.CreatedAt, "CreatedAt should be set from the Created event")
	assert.NotEmpty(t, res.TriggeredAt, "TriggeredAt should be set from the Triggered event")
	assert.NotEmpty(t, res.DeletedAt, "DeletedAt should be set from the Deleted event")

	// Each event should produce exactly one snapshot walking the lifecycle.
	require.Len(t, res.States, 3)
	assert.Equal(t, "AlertCreated", res.States[0].EventType)
	assert.Equal(t, eventsourcing.AlertStatusActive, res.States[0].Status)
	assert.Equal(t, "AlertTriggered", res.States[1].EventType)
	assert.Equal(t, eventsourcing.AlertStatusTriggered, res.States[1].Status)
	assert.Equal(t, "AlertDeleted", res.States[2].EventType)
	assert.Equal(t, eventsourcing.AlertStatusDeleted, res.States[2].Status)
}

// TestGetAlertHistoryReconstituted_UnknownAlertReturnsNotFound — query for an
// unknown alert ID should return Found=false with no top-level error.
func TestGetAlertHistoryReconstituted_UnknownAlertReturnsNotFound(t *testing.T) {
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode(), kcfixture.WithRiskGuard())

	dir := t.TempDir()
	db, err := alerts.OpenDB(filepath.Join(dir, "alert_history_empty.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())
	mgr.SetEventStore(store)

	ctx := oauth.ContextWithEmail(context.Background(), "replay@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "b2c3d4e5-f6a7-8901-bcde-f01234567890"})

	tool := &GetAlertHistoryReconstitutedTool{}
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_alert_history_reconstituted"
	req.Params.Arguments = map[string]any{"alert_id": "does-not-exist-alert"}
	result, err := tool.Handler(mgr)(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError)

	textContent, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	var res cqrs.AlertHistoryResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &res))

	assert.False(t, res.Found)
	assert.Equal(t, "does-not-exist-alert", res.AlertID)
	assert.Equal(t, 0, res.EventCount)
	assert.Empty(t, res.States)
}
