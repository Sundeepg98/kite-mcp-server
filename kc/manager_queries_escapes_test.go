package kc

import (
	"context"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// newRegisteredAuditStore returns an initialized audit.Store backed by an
// in-memory SQLite DB. The caller owns the cleanup via t.Cleanup.
func newRegisteredAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	store := audit.New(db)
	if err := store.InitTable(); err != nil {
		t.Fatalf("init audit table: %v", err)
	}
	store.StartWorker()
	t.Cleanup(func() {
		store.Stop()
		db.Close()
	})
	return store
}

// TestRegisterEscapeQueries_WidgetPortfolioDispatch confirms the QueryBus
// handler for GetPortfolioForWidgetQuery is wired and returns a typed
// WidgetPortfolioResult. Broker resolution fails (no session), but the
// handler must propagate the error structured so the upstream widget
// can render a degraded state — this verifies the dispatch path.
func TestRegisterEscapeQueries_WidgetPortfolioDispatch(t *testing.T) {
	t.Parallel()

	m := newTestManagerWithDB(t)

	// No session attached -> SessionSvc.GetBrokerForEmail returns an error.
	_, err := m.QueryBus().DispatchWithResult(context.Background(), cqrs.GetPortfolioForWidgetQuery{Email: "portfolio@test.com"})
	if err == nil {
		t.Fatal("expected broker-resolution error from unconfigured session, got nil")
	}
}

// TestRegisterEscapeQueries_WidgetActivityDispatch confirms the handler
// for GetActivityForWidgetQuery resolves the audit store from ctx
// (honoring the test-isolation contract), calls the use case, and
// returns *WidgetActivityResult.
func TestRegisterEscapeQueries_WidgetActivityDispatch(t *testing.T) {
	t.Parallel()

	m := newTestManagerWithDB(t)
	store := newRegisteredAuditStore(t)

	// Seed a tool call so the activity widget has something to return.
	store.Record(&audit.ToolCall{
		CallID:       "activity-dispatch-001",
		Email:        "activity@test.com",
		ToolName:     "get_holdings",
		ToolCategory: "query",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	ctx := cqrs.WithWidgetAuditStore(context.Background(), store)
	got, err := m.QueryBus().DispatchWithResult(ctx, cqrs.GetActivityForWidgetQuery{Email: "activity@test.com"})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	result, ok := got.(*usecases.WidgetActivityResult)
	if !ok {
		t.Fatalf("expected *WidgetActivityResult, got %T", got)
	}
	if result == nil {
		t.Fatal("result should not be nil when audit store is attached")
	}
}

// TestRegisterEscapeQueries_WidgetActivityDispatch_NoStore confirms the
// handler short-circuits to a nil result when neither ctx nor Manager
// carry an audit store, matching the legacy nil-store behavior.
func TestRegisterEscapeQueries_WidgetActivityDispatch_NoStore(t *testing.T) {
	t.Parallel()

	m := newTestManagerWithDB(t)

	got, err := m.QueryBus().DispatchWithResult(context.Background(), cqrs.GetActivityForWidgetQuery{Email: "nobody@test.com"})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result when no audit store, got %T", got)
	}
}

// TestRegisterEscapeQueries_WidgetOrdersDispatch confirms the handler for
// GetOrdersForWidgetQuery dispatches through to the use case and returns
// *WidgetOrdersResult.
func TestRegisterEscapeQueries_WidgetOrdersDispatch(t *testing.T) {
	t.Parallel()

	m := newTestManagerWithDB(t)
	store := newRegisteredAuditStore(t)

	ctx := cqrs.WithWidgetAuditStore(context.Background(), store)
	got, err := m.QueryBus().DispatchWithResult(ctx, cqrs.GetOrdersForWidgetQuery{Email: "orders@test.com"})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	result, ok := got.(*usecases.WidgetOrdersResult)
	if !ok {
		t.Fatalf("expected *WidgetOrdersResult, got %T", got)
	}
	if result == nil {
		t.Fatal("result should not be nil when audit store is attached")
	}
	if result.Orders == nil {
		t.Error("result.Orders should be initialized (empty slice ok)")
	}
}

// TestRegisterEscapeQueries_WidgetAlertsDispatch confirms the handler for
// GetAlertsForWidgetQuery dispatches through to the use case. The alert
// store is attached to the Manager via AlertDBPath, so no ctx injection
// is needed — this verifies the production-path resolution.
func TestRegisterEscapeQueries_WidgetAlertsDispatch(t *testing.T) {
	t.Parallel()

	m := newTestManagerWithDB(t)

	got, err := m.QueryBus().DispatchWithResult(context.Background(), cqrs.GetAlertsForWidgetQuery{Email: "alerts@test.com"})
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	result, ok := got.(*usecases.WidgetAlertsResult)
	if !ok {
		t.Fatalf("expected *WidgetAlertsResult, got %T", got)
	}
	if result == nil {
		t.Fatal("result should not be nil when alert store is attached")
	}
	// Fresh user has no alerts.
	if result.ActiveCount != 0 || result.TriggeredCount != 0 {
		t.Errorf("expected empty alert counts, got active=%d triggered=%d",
			result.ActiveCount, result.TriggeredCount)
	}
}
