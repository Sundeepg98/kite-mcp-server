package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// dashboard.go: activityAPI various filter paths
// ===========================================================================
func TestMax_ActivityAPI_WithFilters(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity?since=%s&until=%s&category=orders&errors=true&limit=10&offset=0", since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestMax_ActivityAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// dashboard.go: activityExport CSV and JSON
// ===========================================================================
func TestMax_ActivityExport_CSV(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)

	d.auditStore.Record(&audit.ToolCall{
		CallID: "test-1", Email: "user@test.com", ToolName: "get_holdings",
		ToolCategory: "portfolio", InputSummary: "test", OutputSummary: "ok",
		StartedAt: time.Now(), CompletedAt: time.Now(),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
}


func TestMax_ActivityExport_JSON(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}


func TestMax_ActivityExport_WithErrorEntries(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)

	d.auditStore.Record(&audit.ToolCall{
		CallID: "err-1", Email: "user@test.com", ToolName: "place_order",
		ToolCategory: "orders", InputSummary: "test", OutputSummary: "failed",
		IsError: true, ErrorMessage: "insufficient funds",
		StartedAt: time.Now(), CompletedAt: time.Now(),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	until := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity/export?format=csv&since=%s&until=%s&category=orders&errors=true", since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "true")
}


// ===========================================================================
// dashboard.go: activityStreamSSE - cancel context path
// ===========================================================================
func TestMax_ActivityStreamSSE_CancelledContext(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}


// ===========================================================================
// dashboard.go: ordersAPI - with audit store
// ===========================================================================
func TestMax_OrdersAPI_WithAuditAndOrder(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)

	d.auditStore.Record(&audit.ToolCall{
		CallID: "ord-1", Email: "user@test.com", ToolName: "place_order",
		ToolCategory: "orders", InputSummary: "INFY BUY",
		OutputSummary: "order placed", OrderID: "ORD123",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		StartedAt:    time.Now(), CompletedAt: time.Now(),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard.go: orderAttributionAPI - with audit but no matching order
// ===========================================================================
func TestMax_OrderAttribution_NoMatch(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/order-attribution?order_id=NONEXISTENT", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard.go: ordersAPI with mock kite server (47.1% -> high)
// ===========================================================================
func TestFinal_OrdersAPI_WithMockKite(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	d.manager.CredentialStore().Set("kite@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	d.manager.TokenStore().Set("kite@test.com", &kc.KiteTokenEntry{
		AccessToken: "mock_token", StoredAt: time.Now(),
	})

	// Seed audit entries with order data
	d.auditStore.Record(&audit.ToolCall{
		CallID:       "call-kite-ord-1",
		Email:        "kite@test.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD-001",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		StartedAt:    time.Now().Add(-1 * time.Hour),
		CompletedAt:  time.Now().Add(-1 * time.Hour),
	})
	time.Sleep(50 * time.Millisecond)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders", "kite@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ordersResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.Summary.TotalOrders, 1)
}


func TestFinal_OrdersAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// dashboard.go: activityExport JSON format
// ===========================================================================
func TestFinal_ActivityExport_JSON_WithData(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.auditStore.Record(&audit.ToolCall{
		CallID:    "export-json-1",
		Email:     "user@test.com",
		ToolName:  "get_profile",
		StartedAt: time.Now(),
		IsError:   true,
	})
	time.Sleep(50 * time.Millisecond)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}


func TestFinal_ActivityExport_CSV_WithData(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.auditStore.Record(&audit.ToolCall{
		CallID:       "export-csv-1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		IsError:      true,
		ErrorMessage: "test error",
		StartedAt:    time.Now(),
	})
	time.Sleep(50 * time.Millisecond)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "Tool")
	assert.Contains(t, rec.Body.String(), "true") // isError
}


func TestFinal_ActivityExport_WithFilters(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.auditStore.Record(&audit.ToolCall{
		CallID:       "export-filt-1",
		Email:        "user@test.com",
		ToolName:     "get_profile",
		ToolCategory: "query",
		StartedAt:    time.Now(),
	})
	time.Sleep(50 * time.Millisecond)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	until := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity/export?format=csv&category=query&errors=true&since=%s&until=%s", since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_ActivityExport_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity/export", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


// ===========================================================================
// dashboard.go: activityStreamSSE with data
// ===========================================================================
func TestFinal_ActivityStreamSSE_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_OrderAttribution_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/order-attribution?order_id=ORD001", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_OrderAttribution_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD001", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_OrderAttribution_MissingOrderID(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR - nil template
// ===========================================================================
func TestFinal_ActivityPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.activityTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code) // fallback
}


// ===========================================================================
// dashboard.go: activityAPI with admin
// ===========================================================================
func TestFinal_ActivityAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_ActivityAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_ActivityAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
