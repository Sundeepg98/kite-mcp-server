package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.
func newHandlerWithAuditAndMetrics(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	require.NoError(t, auditStore.InitTable())

	uStore := mgr.UserStoreConcrete()
	if uStore != nil {
		uStore.EnsureAdmin("admin@test.com")
	}

	// Seed credentials + tokens
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "mock_token", StoredAt: time.Now(),
	})

	lb := NewLogBuffer(100)
	return New(mgr, nil, lb, logger, "test-v1", time.Now(), uStore, auditStore)
}

// newDashboardWithAuditAndPaper creates a DashboardHandler with audit store and paper engine.
func newDashboardWithAuditAndPaper(t *testing.T) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_api_key",
		APISecret:          "test_api_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	paperStore := papertrading.NewStore(mgr.AlertDB(), logger)
	require.NoError(t, paperStore.InitTables())
	mgr.SetPaperEngine(papertrading.NewEngine(paperStore, logger))

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	require.NoError(t, auditStore.InitTable())

	d := NewDashboardHandler(mgr, logger, auditStore)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d
}

// ===========================================================================
// handler.go: Non-admin user branches for sessions/tickers/alerts
// ===========================================================================

func TestMax_Sessions_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/sessions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_Tickers_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/tickers", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_Alerts_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: verifyChain admin-only + audit store available
// ===========================================================================

func TestMax_VerifyChain_WithAudit(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: suspendUser/activateUser self-action guard and UpdateStatus error
// ===========================================================================

func TestMax_SuspendUser_SelfGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMax_SuspendUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=nonexistent@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMax_ActivateUser_SelfGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMax_ActivateUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=nonexistent@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// handler.go: offboardUser - nil userStore and updateStatus error
// ===========================================================================

// Coverage note: The nil-userStore guard in offboardUser (handler.go:545) is unreachable
// because isAdmin() returns false when userStore is nil, causing a 403 before the guard.
// This is a defensive pattern; the guard exists but cannot be triggered via HTTP.

func TestMax_OffboardUser_UpdateStatusError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/offboard?email=nonexistent@test.com", `{"confirm": true}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// handler.go: changeRole - nil userStore, last-admin guard, UpdateRole error
// ===========================================================================

// Coverage note: The nil-userStore guard in changeRole (handler.go:581) is unreachable
// because isAdmin() returns false when userStore is nil, causing a 403 before the guard.
// Same defensive pattern as offboardUser/suspendUser/activateUser.

func TestMax_ChangeRole_LastAdminGuard(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=admin@test.com", `{"role": "viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestMax_ChangeRole_UpdateRoleError(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/users/role?email=nonexistent@test.com", `{"role": "viewer"}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// handler.go: logAdminAction with nil auditStore
// ===========================================================================

func TestMax_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.logAdminAction("admin@test.com", "test_action", "target")
	// No panic = pass
}

// ===========================================================================
// handler.go: metricsAPI various periods
// ===========================================================================

func TestMax_MetricsAPI_Periods(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	periods := []string{"1h", "7d", "30d", "24h"}
	for _, p := range periods {
		t.Run(p, func(t *testing.T) {
			req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics?period="+p, "admin@test.com")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

// ===========================================================================
// handler.go: metricsFragment admin with templates
// ===========================================================================

func TestMax_MetricsFragment_Success(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment?period=1h", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_MetricsFragment_NilAdminTmpl(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.adminTmpl = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// handler.go: registryHandler/registryItemHandler nil registryStore
// ===========================================================================

func TestMax_Registry_NilStore(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.registryStore = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/registry", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestMax_RegistryItem_NilStore(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.registryStore = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPut, "/admin/ops/api/registry/some-id", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ===========================================================================
// handler.go: overviewStream SSE - cancelled context triggers return
// ===========================================================================

func TestMax_OverviewStream_CancelledContext(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// handler.go: logStream SSE - cancelled-context path
// ===========================================================================

func TestMax_LogStream_CancelledContext(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// handler.go: credentials POST auto-register in registry
// ===========================================================================

func TestMax_Credentials_Post_AutoRegister(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/credentials", "user@test.com",
		strings.NewReader(`{"api_key":"new_key_12345678","api_secret":"new_secret_12345678"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: credentials GET with short secret (<= 7 chars)
// ===========================================================================

func TestMax_Credentials_Get_ShortSecret(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "shorty", StoredAt: time.Now(),
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "****")
}

// ===========================================================================
// handler.go: credentials DELETE as admin with email param
// ===========================================================================

func TestMax_Credentials_Delete_AdminWithEmail(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/admin/ops/api/credentials?email=user@test.com", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

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
// dashboard.go: paper trading success paths (engine returns data)
// ===========================================================================

func TestMax_PaperStatus_Success(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_PaperHoldings_Success(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_PaperPositions_Success(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_PaperOrders_Success(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_PaperReset_Success(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
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
// dashboard.go: pnlChartAPI with alertDB, period clamping
// ===========================================================================

func TestMax_PnlChart_PeriodClamping(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// period < 1 -> default to 90
	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=0", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	var resp pnlChartResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, 90, resp.Period)

	// period > 365 -> cap at 365
	req = reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=999", "user@test.com")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, 365, resp.Period)
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
// dashboard.go: sectorExposureAPI/taxAnalysisAPI - no credentials
// ===========================================================================

func TestMax_SectorExposure_NoCreds(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMax_TaxAnalysis_NoCreds(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: selfDeleteAccount - no confirm
// ===========================================================================

func TestMax_SelfDeleteAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com",
		strReaderPtr(`{"confirm": false}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// strReaderPtr returns a *strings.Reader for use with requestWithEmail.
func strReaderPtr(s string) *strings.Reader {
	return strings.NewReader(s)
}

// ===========================================================================
// dashboard.go: RegisterRoutes - billing page without billingStore
// ===========================================================================

func TestMax_BillingPage_NoBillingStore(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Free Plan")
}

// ===========================================================================
// dashboard.go: static files
// ===========================================================================

func TestMax_StaticCSS(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}

func TestMax_StaticHTMX(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
}

// ===========================================================================
// data.go: buildOverview with alerts, riskguard
// ===========================================================================

func TestMax_BuildOverview_WithAlerts(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)
	_, err = h.manager.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 408065, 2500, alerts.DirectionBelow)
	require.NoError(t, err)

	overview := h.buildOverview()
	assert.Equal(t, 2, overview.TotalAlerts)
	assert.Equal(t, 2, overview.ActiveAlerts) // both untriggered
	assert.NotZero(t, overview.HeapAllocMB)
	assert.NotZero(t, overview.Goroutines)
}

// ===========================================================================
// data.go: buildOverviewForUser
// ===========================================================================

func TestMax_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, 1, overview.TotalAlerts)
	assert.Equal(t, 1, overview.ActiveAlerts)
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
}

// ===========================================================================
// data.go: buildSessionsForUser / buildTickersForUser / buildAlertsForUser
// ===========================================================================

func TestMax_BuildSessionsForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	sessions := h.buildSessionsForUser("nobody@test.com")
	assert.Empty(t, sessions)
}

func TestMax_BuildTickersForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	tickers := h.buildTickersForUser("nobody@test.com")
	assert.Empty(t, tickers.Tickers)
}

func TestMax_BuildAlertsForUser_WithTelegram(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)
	h.manager.TelegramStore().SetTelegramChatID("user@test.com", 12345)

	data := h.buildAlertsForUser("user@test.com")
	assert.Len(t, data.Alerts["user@test.com"], 1)
	assert.Equal(t, int64(12345), data.Telegram["user@test.com"])
}

// ===========================================================================
// overview_sse.go: sendAllAdminEvents
// ===========================================================================

func TestMax_SendAllAdminEvents(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	rec := httptest.NewRecorder()
	h.sendAllAdminEvents(rec, rec, "admin@test.com")
	body := rec.Body.String()
	assert.Contains(t, body, "event: overview-stats")
	assert.Contains(t, body, "event: overview-tools")
	assert.Contains(t, body, "event: overview-uptime")
	assert.Contains(t, body, "event: admin-sessions")
	assert.Contains(t, body, "event: admin-tickers")
	assert.Contains(t, body, "event: admin-alerts")
	assert.Contains(t, body, "event: admin-users")
}

// ===========================================================================
// dashboard.go: serveBillingPage - no email redirect
// ===========================================================================

func TestMax_ServeBillingPage_NoEmail(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	d.SetBillingStore(&mockBillingStore{subs: map[string]*billing.Subscription{}})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
}

// ===========================================================================
// dashboard.go: marketIndices, portfolio, alerts, status with no creds
// ===========================================================================

func TestMax_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusUnauthorized || rec.Code == http.StatusBadGateway)
}

func TestMax_Portfolio_NoCreds(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusUnauthorized || rec.Code == http.StatusBadGateway)
}

func TestMax_DashboardAlerts_WithEmail(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_Status_WithEmail(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: servePage with opsTmpl nil
// ===========================================================================

func TestMax_ServePage_NilOpsTmpl(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	h.opsTmpl = nil
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// handler.go: sessions/tickers/alerts admin branches
// ===========================================================================

func TestMax_Sessions_Admin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/sessions", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_Tickers_Admin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/tickers", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_Alerts_Admin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/alerts", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: metricsAPI with ALERT_DB_PATH env (db size branch)
// ===========================================================================

func TestMax_MetricsAPI_WithDBPath(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Set ALERT_DB_PATH to exercise the db size calculation branch.
	tmpFile := t.TempDir() + "/test.db"
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))
	t.Setenv("ALERT_DB_PATH", tmpFile)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics?period=1h", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: listUsers with userStore (admin)
// ===========================================================================

func TestMax_ListUsers_Admin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/users", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: logStream with backfill entries
// ===========================================================================

func TestMax_LogStream_WithBackfill(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)

	// Add some log entries before starting the stream
	h.logBuffer.Add(LogEntry{
		Level:   "info",
		Message: "test entry",
		Time:    time.Now(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to exit the loop

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Contains(t, rec.Body.String(), "test entry")
}

// ===========================================================================
// dashboard_templates.go: servePortfolioPage success path
// ===========================================================================

func TestMax_ServePortfolioPage(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR success path
// ===========================================================================

func TestMax_ServeActivityPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveOrdersPageSSR success path
// ===========================================================================

func TestMax_ServeOrdersPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR success path
// ===========================================================================

func TestMax_ServeAlertsPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePaperPageSSR success path
// ===========================================================================

func TestMax_ServePaperPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveSafetyPageSSR success path
// ===========================================================================

func TestMax_ServeSafetyPageSSR(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: fragment endpoints
// ===========================================================================

func TestMax_PortfolioFragment(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_SafetyFragment(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMax_PaperFragment(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard.go: safetyStatus endpoint
// ===========================================================================

func TestMax_SafetyStatus(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard.go: selfManageCredentials
// ===========================================================================

func TestMax_SelfManageCredentials_GET(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// overview_sse.go: writeSSEEvent with multiline data
// ===========================================================================

func TestMax_WriteSSEEvent_Multiline(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeSSEEvent(rec, "test-event", "line1\nline2\nline3")
	body := rec.Body.String()
	assert.Contains(t, body, "event: test-event\n")
	assert.Contains(t, body, "data: line1\n")
	assert.Contains(t, body, "data: line2\n")
	assert.Contains(t, body, "data: line3\n")
}
