package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// user_render.go: ordersToStatsData edge cases
// ---------------------------------------------------------------------------
func TestPush100_OrdersToStatsData_NoPnL(t *testing.T) {
	t.Parallel()
	s := ordersSummary{TotalOrders: 5, Completed: 3}
	result := ordersToStatsData(s)
	assert.Equal(t, "5", result.Cards[0].Value)
	assert.Equal(t, "3", result.Cards[1].Value)
	assert.Equal(t, "--", result.Cards[2].Value) // no PnL
	assert.Equal(t, "--", result.Cards[3].Value)  // no win rate
}


func TestPush100_OrdersToStatsData_WithWinRate(t *testing.T) {
	t.Parallel()
	pnl := 5000.0
	s := ordersSummary{
		TotalOrders:  10,
		Completed:    8,
		TotalPnL:     &pnl,
		WinningTrades: 6,
		LosingTrades:  2,
	}
	result := ordersToStatsData(s)
	assert.Contains(t, result.Cards[2].Value, "5,000") // PnL formatted
	assert.Equal(t, "green", result.Cards[2].Class)
	assert.Contains(t, result.Cards[3].Value, "75%")    // 6/(6+2) = 75%
	assert.Contains(t, result.Cards[3].Sub, "6W / 2L")
}


func TestPush100_OrdersToStatsData_NegativePnL(t *testing.T) {
	t.Parallel()
	pnl := -1500.0
	s := ordersSummary{
		TotalOrders:  3,
		Completed:    3,
		TotalPnL:     &pnl,
		WinningTrades: 0,
		LosingTrades:  3,
	}
	result := ordersToStatsData(s)
	assert.Equal(t, "red", result.Cards[2].Class)
	assert.Contains(t, result.Cards[3].Value, "0%") // 0/(0+3) = 0%
}


// ---------------------------------------------------------------------------
// user_render.go: activityToTimelineData with error entries
// ---------------------------------------------------------------------------
func TestPush100_ActivityToTimelineData_WithErrors(t *testing.T) {
	t.Parallel()
	entries := []audit.ToolCall{
		{
			StartedAt:    time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC),
			ToolName:     "place_order",
			ToolCategory: "order",
			InputSummary: "BUY RELIANCE",
			IsError:      true,
			ErrorMessage: "insufficient funds",
			DurationMs:   250,
		},
		{
			StartedAt:     time.Date(2026, 3, 15, 10, 31, 0, 0, time.UTC),
			ToolName:      "get_holdings",
			ToolCategory:  "query",
			OutputSummary: "5 holdings",
			DurationMs:    1500,
		},
	}
	result := activityToTimelineData(entries)
	assert.Len(t, result.Entries, 2)

	// Error entry
	assert.Equal(t, "fail", result.Entries[0].StatusClass)
	assert.Equal(t, "ERR", result.Entries[0].StatusLabel)
	assert.True(t, result.Entries[0].IsError)
	assert.Equal(t, "insufficient funds", result.Entries[0].ErrorMessage)
	assert.Equal(t, "ORDER", result.Entries[0].CatLabel)

	// Success entry
	assert.Equal(t, "success", result.Entries[1].StatusClass)
	assert.Equal(t, "OK", result.Entries[1].StatusLabel)
	assert.False(t, result.Entries[1].IsError)
	assert.Equal(t, "QUERY", result.Entries[1].CatLabel)
	assert.Equal(t, "1.5s", result.Entries[1].DurationFmt)
}


// ---------------------------------------------------------------------------
// user_render.go: alertsToStatsData edge cases
// ---------------------------------------------------------------------------
func TestPush100_AlertsToStatsData_NilNearest(t *testing.T) {
	t.Parallel()
	summary := alertsSummary{ActiveCount: 3, TriggeredCount: 1, AvgTimeToTrigger: "2h 30m"}
	result := alertsToStatsData(summary, nil)
	assert.Equal(t, "3", result.Cards[0].Value)
	assert.Equal(t, "1", result.Cards[1].Value)
	assert.Equal(t, "2h 30m", result.Cards[2].Value)
	assert.Equal(t, "--", result.Cards[3].Value) // no nearest
}


func TestPush100_AlertsToStatsData_WithNearest(t *testing.T) {
	t.Parallel()
	dist := 1.5
	nearest := &enrichedActiveAlert{
		Tradingsymbol: "RELIANCE",
		DistancePct:   &dist,
	}
	summary := alertsSummary{ActiveCount: 1, TriggeredCount: 0}
	result := alertsToStatsData(summary, nearest)
	assert.Equal(t, "RELIANCE", result.Cards[3].Value)
	assert.Contains(t, result.Cards[3].Sub, "1.5%")
}


func TestPush100_AlertsToStatsData_EmptyAvgTime(t *testing.T) {
	t.Parallel()
	summary := alertsSummary{ActiveCount: 0, TriggeredCount: 0}
	result := alertsToStatsData(summary, nil)
	assert.Equal(t, "--", result.Cards[2].Value) // empty AvgTimeToTrigger
}


// ---------------------------------------------------------------------------
// user_render.go: ordersToTableData with various statuses
// ---------------------------------------------------------------------------
func TestPush100_OrdersToTableData_SellSide(t *testing.T) {
	t.Parallel()
	fillPrice := 500.0
	currentPrice := 480.0
	pnl := 200.0
	pnlPct := 4.0
	entries := []orderEntry{
		{
			Symbol:       "INFY",
			Side:         "SELL",
			Quantity:     10,
			FillPrice:    &fillPrice,
			CurrentPrice: &currentPrice,
			PnL:          &pnl,
			PnLPct:       &pnlPct,
			Status:       "COMPLETE",
			PlacedAt:     "2026-03-15T10:00:00Z",
		},
	}
	result := ordersToTableData(entries)
	assert.Len(t, result.Orders, 1)
	assert.Equal(t, "side-sell", result.Orders[0].SideClass)
	assert.Equal(t, "status-complete", result.Orders[0].StatusBadge)
	assert.Equal(t, "pnl-pos", result.Orders[0].PnLClass)
}


func TestPush100_OrdersToTableData_AllNilOptionals(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{
			Symbol:   "TCS",
			Side:     "BUY",
			Quantity: 5,
			Status:   "OPEN",
			PlacedAt: "",
		},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "--", result.Orders[0].FillPriceFmt)
	assert.Equal(t, "--", result.Orders[0].CurrentPriceFmt)
	assert.Equal(t, "--", result.Orders[0].PnLFmt)
	assert.Equal(t, "--", result.Orders[0].PnLPctFmt)
	assert.Equal(t, "status-open", result.Orders[0].StatusBadge)
}


func TestPush100_OrdersToTableData_TriggerPending(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "TRIGGER PENDING"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-open", result.Orders[0].StatusBadge)
}


func TestPush100_OrdersToTableData_Rejected(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "REJECTED"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-rejected", result.Orders[0].StatusBadge)
}


func TestPush100_OrdersToTableData_Cancelled(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "CANCELLED"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-cancelled", result.Orders[0].StatusBadge)
}


func TestPush100_OrdersToTableData_UnknownStatus(t *testing.T) {
	t.Parallel()
	entries := []orderEntry{
		{Symbol: "HDFC", Side: "BUY", Status: "VALIDATION PENDING"},
	}
	result := ordersToTableData(entries)
	assert.Equal(t, "status-pending", result.Orders[0].StatusBadge)
}


// ---------------------------------------------------------------------------
// user_render.go: alertsToActiveData with distance
// ---------------------------------------------------------------------------
func TestPush100_AlertsToActiveData_WithDistance(t *testing.T) {
	t.Parallel()
	dist := 1.5
	active := []enrichedActiveAlert{
		{
			ID: "a1", Tradingsymbol: "RELIANCE", Exchange: "NSE",
			Direction: "above", TargetPrice: 2500, CurrentPrice: 2450,
			DistancePct: &dist, CreatedAt: "2026-03-15T10:00:00Z",
		},
	}
	result := alertsToActiveData(active)
	assert.Len(t, result.Alerts, 1)
	assert.Equal(t, "1.5%", result.Alerts[0].DistFmt)
	assert.Equal(t, "dist-green", result.Alerts[0].DistClass) // < 2%
	assert.Equal(t, "green", result.Alerts[0].DirBadge)
}


func TestPush100_AlertsToActiveData_HighDistance(t *testing.T) {
	t.Parallel()
	dist := 7.0
	active := []enrichedActiveAlert{
		{
			ID: "a2", Tradingsymbol: "TCS",
			Direction: "below", DistancePct: &dist,
			CreatedAt: "2026-03-15T10:00:00Z",
		},
	}
	result := alertsToActiveData(active)
	assert.Equal(t, "dist-red", result.Alerts[0].DistClass) // >= 5%
	assert.Equal(t, "red", result.Alerts[0].DirBadge)
}


// ---------------------------------------------------------------------------
// user_render.go: alertsToTriggeredData
// ---------------------------------------------------------------------------
func TestPush100_AlertsToTriggeredData_WithNotification(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			Tradingsymbol:     "INFY",
			Direction:         "rise_pct",
			TargetPrice:       1500,
			CreatedAt:         "2026-03-14T09:00:00Z",
			TriggeredAt:       "2026-03-15T10:00:00Z",
			TimeToTrigger:     "1d 1h 0m",
			NotificationSentAt: "2026-03-15T10:00:05Z",
			NotificationDelay:  "5s",
		},
	}
	result := alertsToTriggeredData(triggered)
	assert.Len(t, result.Alerts, 1)
	assert.Equal(t, "green", result.Alerts[0].DirBadge) // rise_pct -> green
	assert.Contains(t, result.Alerts[0].NotificationFmt, "15 Mar")
}


func TestPush100_AlertsToTriggeredData_EmptyNotification(t *testing.T) {
	t.Parallel()
	triggered := []enrichedTriggeredAlert{
		{
			Tradingsymbol:      "TCS",
			Direction:          "drop_pct",
			CreatedAt:          "2026-03-14T09:00:00Z",
			TriggeredAt:        "2026-03-15T10:00:00Z",
			NotificationSentAt: "",
		},
	}
	result := alertsToTriggeredData(triggered)
	assert.Equal(t, "", result.Alerts[0].NotificationFmt)
	assert.Equal(t, "red", result.Alerts[0].DirBadge) // drop_pct -> red
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: buildOrderSummary with mixed entries
// ---------------------------------------------------------------------------
func TestPush100_BuildOrderSummary_MixedEntries(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	win := 500.0
	loss := -200.0
	entries := []orderEntry{
		{Status: "COMPLETE", PnL: &win},
		{Status: "COMPLETE", PnL: &loss},
		{Status: "OPEN"},
		{Status: "REJECTED"},
	}
	summary := d.orders.buildOrderSummary(entries)
	assert.Equal(t, 4, summary.TotalOrders)
	assert.Equal(t, 2, summary.Completed)
	assert.Equal(t, 1, summary.WinningTrades)
	assert.Equal(t, 1, summary.LosingTrades)
	require.NotNil(t, summary.TotalPnL)
	assert.InDelta(t, 300.0, *summary.TotalPnL, 0.01)
}


func TestPush100_BuildOrderSummary_NoPnLEntries(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	entries := []orderEntry{
		{Status: "OPEN"},
		{Status: "OPEN"},
	}
	summary := d.orders.buildOrderSummary(entries)
	assert.Equal(t, 2, summary.TotalOrders)
	assert.Nil(t, summary.TotalPnL)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: buildOrderEntries with nil ToolCall
// ---------------------------------------------------------------------------
func TestPush100_BuildOrderEntries_NilToolCall(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	toolCalls := []*audit.ToolCall{
		nil,
		{OrderID: "order-1", StartedAt: time.Now(), InputParams: `{}`},
		nil,
	}
	entries := d.orders.buildOrderEntries(toolCalls, "test@example.com")
	assert.Len(t, entries, 1) // nils skipped
	assert.Equal(t, "order-1", entries[0].OrderID)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: parseOrderParamsJSON
// ---------------------------------------------------------------------------
func TestPush100_ParseOrderParamsJSON_AllFields(t *testing.T) {
	t.Parallel()
	raw := `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"BUY","order_type":"LIMIT","quantity":100,"price":2500.5}`
	var oe orderEntry
	parseOrderParamsJSON(raw, &oe)
	assert.Equal(t, "RELIANCE", oe.Symbol)
	assert.Equal(t, "NSE", oe.Exchange)
	assert.Equal(t, "BUY", oe.Side)
	assert.Equal(t, "LIMIT", oe.OrderType)
	assert.Equal(t, float64(100), oe.Quantity)
}


// ---------------------------------------------------------------------------
// handler.go: logStream keepalive (test cancelled context during stream)
// ---------------------------------------------------------------------------
func TestPush100_LogStream_CancelledDuringStream(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	lb := h.logBuffer

	// Add some log entries for backfill
	lb.Add(LogEntry{Time: time.Now(), Level: "INFO", Message: "test entry"})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	req := push100AdminReq(http.MethodGet, "/admin/ops/api/logs", "")
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ServeHTTP(rec, req)
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	assert.Contains(t, rec.Body.String(), "test entry")
}


// ---------------------------------------------------------------------------
// overview_sse.go: sendAllAdminEvents
// ---------------------------------------------------------------------------
func TestPush100_SendAllAdminEvents_WithData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed some data
	h.manager.CredentialStore().Set("user2@test.com", &kc.KiteCredentialEntry{
		APIKey: "key2", APISecret: "secret2", StoredAt: time.Now(),
	})
	h.manager.TokenStore().Set("user2@test.com", &kc.KiteTokenEntry{
		AccessToken: "tok2", StoredAt: time.Now(),
	})

	// Add an alert
	_, _ = h.manager.AlertStore().Add("user2@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	rec := httptest.NewRecorder()
	// httptest.ResponseRecorder implements http.Flusher directly
	h.sendAllAdminEvents(context.Background(), rec, rec, "admin@test.com")

	body := rec.Body.String()
	assert.Contains(t, body, "event:")
}


// ---------------------------------------------------------------------------
// logbuffer.go: TeeHandler.WithAttrs and WithGroup
// ---------------------------------------------------------------------------
func TestPush100_TeeHandler_WithAttrs(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	withAttrs := th.WithAttrs([]slog.Attr{slog.String("key", "val")})
	assert.NotNil(t, withAttrs)
	// Must still be a TeeHandler
	_, ok := withAttrs.(*TeeHandler)
	assert.True(t, ok)
}


func TestPush100_TeeHandler_WithGroup(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	withGroup := th.WithGroup("mygroup")
	assert.NotNil(t, withGroup)
	_, ok := withGroup.(*TeeHandler)
	assert.True(t, ok)
}


func TestPush100_TeeHandler_Handle(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	inner := slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	th := NewTeeHandler(inner, buf)

	logger := slog.New(th)
	logger.Info("test message", "key1", "val1", "key2", 42)

	entries := buf.Recent(10)
	require.Len(t, entries, 1)
	assert.Equal(t, "INFO", entries[0].Level)
	assert.Equal(t, "test message", entries[0].Message)
	assert.Contains(t, entries[0].Attrs, "key1=val1")
}


// ---------------------------------------------------------------------------
// logbuffer.go: LogBuffer fan-out to multiple listeners
// ---------------------------------------------------------------------------
func TestPush100_LogBuffer_MultipleListeners(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(10)
	ch1 := buf.AddListener("l1")
	ch2 := buf.AddListener("l2")

	entry := LogEntry{Time: time.Now(), Level: "INFO", Message: "broadcast"}
	buf.Add(entry)

	// Both listeners should receive
	select {
	case e := <-ch1:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("l1 did not receive entry")
	}
	select {
	case e := <-ch2:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("l2 did not receive entry")
	}

	buf.RemoveListener("l1")
	buf.RemoveListener("l2")
}


func TestPush100_LogBuffer_RingBufferWrapAround(t *testing.T) {
	t.Parallel()
	buf := NewLogBuffer(3)
	for i := 0; i < 5; i++ {
		buf.Add(LogEntry{Message: fmt.Sprintf("msg-%d", i)})
	}
	// Should only have the last 3
	entries := buf.Recent(10)
	assert.Len(t, entries, 3)
	assert.Equal(t, "msg-2", entries[0].Message)
	assert.Equal(t, "msg-3", entries[1].Message)
	assert.Equal(t, "msg-4", entries[2].Message)
}


// ===========================================================================
// dashboard.go: activityAPI — method not allowed, no email, no audit store,
// full success with filters
// ===========================================================================
func TestPush100_ActivityAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_ActivityAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_ActivityAPI_WithFilters(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Insert test audit entries
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "c1",
		Email:        "user@test.com",
		ToolName:     "get_holdings",
		ToolCategory: "portfolio",
		StartedAt:    time.Now().Add(-1 * time.Hour),
		CompletedAt:  time.Now().Add(-1 * time.Hour),
	})

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	until := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	req := push100DashReq(http.MethodGet,
		"/dashboard/api/activity?category=portfolio&errors=true&since="+since+"&until="+until+"&limit=5&offset=0",
		"user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}


func TestPush100_ActivityAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// dashboard.go: activityExport — CSV, JSON, no email/auditStore
// ===========================================================================
func TestPush100_ActivityExport_CSV(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "ex1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
		IsError:      true,
		ErrorMessage: "rate limited",
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Body.String(), "place_order")
}


func TestPush100_ActivityExport_JSON(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}


func TestPush100_ActivityExport_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/export", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestPush100_ActivityExport_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity/export", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_ActivityExport_WithTimeRange(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	req := push100DashReq(http.MethodGet,
		"/dashboard/api/activity/export?since="+since+"&until="+until+"&category=admin&errors=true",
		"user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard.go: activityStreamSSE — no email, no audit store
// ===========================================================================
func TestPush100_ActivityStreamSSE_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_ActivityStreamSSE_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/stream", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_ActivityStreamSSE_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestPush100_ActivityStreamSSE_CancelledContext(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "user@test.com")
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	assert.Contains(t, rec.Body.String(), ": connected")
}


// ===========================================================================
// dashboard.go: ordersAPI — method not allowed, no email, no audit store,
// with since param, with audit data
// ===========================================================================
func TestPush100_OrdersAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_OrdersAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_OrdersAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


func TestPush100_OrdersAPI_WithSinceParam(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	req := push100DashReq(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_OrdersAPI_WithAuditData(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "ord1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-100",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
}


// ===========================================================================
// dashboard.go: orderAttributionAPI — missing order_id, no audit store, success
// ===========================================================================
func TestPush100_OrderAttribution_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-1", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_OrderAttribution_MissingOrderID(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestPush100_OrderAttribution_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/order-attribution?order_id=ORD-1", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_OrderAttribution_Success(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Record an attribution
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "attr1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-99",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-99", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ORD-99")
}


// ===========================================================================
// dashboard.go: alertsEnrichedAPI — DELETE, GET
// ===========================================================================
func TestPush100_AlertsEnriched_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestPush100_AlertsEnriched_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_AlertsEnriched_DeleteNoAlertID(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodDelete, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


func TestPush100_AlertsEnriched_DeleteSuccess(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	alertID, _ := mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	req := push100DashReq(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id="+alertID, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}


func TestPush100_AlertsEnriched_GetWithAlerts(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 408065, 2500, alerts.DirectionAbove)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "RELIANCE")
}


// ===========================================================================
// dashboard.go: alerts API — method not allowed, no email, success
// ===========================================================================
func TestPush100_AlertsAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_AlertsAPI_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: status API
// ===========================================================================
func TestPush100_StatusAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodPost, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


// ===========================================================================
// handler.go: verifyChain — success, no audit store, method not allowed
// ===========================================================================
func TestPush100_VerifyChain_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_VerifyChain_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandler(t) // nil audit store
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Will get 403 because nil userStore means isAdmin returns false
	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestPush100_VerifyChain_Success(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/verify-chain", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: logStream — backfill, keepalive, cancel
// ===========================================================================
func TestPush100_LogStream_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/logs", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestPush100_LogStream_Backfill(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Add some log entries to the buffer
	h.logBuffer.Add(LogEntry{Time: time.Now(), Level: "INFO", Message: "test entry"})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}


// ===========================================================================
// handler.go: logAdminAction — nil audit store path
// ===========================================================================
func TestPush100_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandler(t) // nil audit store
	// Just call directly — should not panic
	h.logAdminAction("admin@test.com", "test_action", "target@test.com")
}


// ===========================================================================
// data.go: buildOverview — per-user view with tokens and credentials
// ===========================================================================
func TestPush100_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed user data
	h.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{APIKey: "k", APISecret: "s", StoredAt: time.Now()})
	h.manager.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{AccessToken: "t", StoredAt: time.Now()})
	_, _ = h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
	assert.Equal(t, 1, overview.TotalAlerts)
	assert.Equal(t, 1, overview.ActiveAlerts)
}


// ===========================================================================
// dashboard_templates.go: serveSafetyFragment
// ===========================================================================

// ===========================================================================
// dashboard.go: ordersAPI — with creds/tokens (Kite client created, API fails)
// ===========================================================================
func TestPush100_OrdersAPI_WithCredsButKiteFails(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Record an order in audit trail
	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "kiteord1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "trading",
		OrderID:      "ORD-200",
		InputParams:  `{"tradingsymbol":"TCS","exchange":"NSE","transaction_type":"BUY","order_type":"LIMIT","quantity":5}`,
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	// Set up creds+token so the handler creates a Kite client (which will fail since no real API)
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should still return 200 (order entries with error field set)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "TCS")
}


// ===========================================================================
// dashboard.go: alertsEnrichedAPI — with creds (Kite LTP fails gracefully)
// ===========================================================================
func TestPush100_AlertsEnriched_WithCredsAndAlerts(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "test_token", StoredAt: time.Now(),
	})

	// Add active and triggered alerts
	_, _ = mgr.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)
	alertID2, _ := mgr.AlertStore().Add("user@test.com", "TCS", "NSE", 0, 3500, alerts.DirectionAbove)
	_ = mgr.AlertStore().MarkTriggered(alertID2, 3550)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
	assert.Contains(t, rec.Body.String(), "TCS")
}


// ===========================================================================
// dashboard.go: alerts — with data
// ===========================================================================
func TestPush100_AlertsAPI_WithAlerts(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	req := push100DashReq(http.MethodGet, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "RELIANCE")
}


// ===========================================================================
// dashboard.go: status — success
// ===========================================================================
func TestPush100_StatusAPI_Success(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
