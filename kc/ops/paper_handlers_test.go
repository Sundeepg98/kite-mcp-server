package ops

// coverage_100_test.go: push ops coverage toward 100%.
// Targets every function below 95% with specific branch/path tests.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// Paper trading: unauthenticated paths for Holdings, Positions, Orders, Reset
// ===========================================================================

func TestCov100_PaperHoldings_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/holdings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_PaperPositions_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/positions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_PaperOrders_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_PaperReset_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/paper/reset", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Wrong method for paper holdings/positions/orders
func TestCov100_PaperHoldings_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_PaperPositions_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_PaperOrders_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: non-admin user paths for overview/sessions/tickers/alerts
// ===========================================================================

func TestCov100_Overview_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/overview", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov100_Sessions_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/sessions", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov100_Tickers_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/tickers", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov100_Alerts_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: sessions/tickers/alerts wrong method
// ===========================================================================

func TestCov100_Sessions_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/sessions", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_Tickers_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/tickers", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_Alerts_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/alerts", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: verifyChain error paths
// ===========================================================================

func TestCov100_VerifyChain_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_VerifyChain_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCov100_VerifyChain_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // no audit store
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// newTestHandler uses mgr.UserStoreConcrete() for userStore.
	// We need to ensure the handler considers the email as admin.
	// Use the admin email that the handler recognizes.
	mgr := h.manager
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		uStore.EnsureAdmin("admin@test.com")
	}

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCov100_VerifyChain_AdminSuccess(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/verify-chain", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// handler.go: listUsers error paths
// ===========================================================================

func TestCov100_ListUsers_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_ListUsers_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/users", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ===========================================================================
// handler.go: suspendUser / activateUser self-action block
// ===========================================================================

func TestCov100_SuspendUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/suspend?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "yourself")
}

func TestCov100_ActivateUser_SelfAction(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/users/activate?email=admin@test.com", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "yourself")
}

// ===========================================================================
// handler.go: metricsAPI additional periods
// ===========================================================================

func TestCov100_MetricsAPI_Periods(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	periods := []string{"1h", "7d", "30d", ""}
	for _, p := range periods {
		t.Run("period="+p, func(t *testing.T) {
			url := "/admin/ops/api/metrics"
			if p != "" {
				url += "?period=" + p
			}
			req := requestWithEmail(http.MethodGet, url, "admin@test.com", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestCov100_MetricsAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/metrics", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_MetricsAPI_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCov100_MetricsAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // no audit store
	mgr := h.manager
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		uStore.EnsureAdmin("admin@test.com")
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ===========================================================================
// handler.go: metricsFragment
// ===========================================================================

func TestCov100_MetricsFragment_AllPeriods(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	periods := []string{"1h", "7d", "30d", ""}
	for _, p := range periods {
		t.Run("period="+p, func(t *testing.T) {
			url := "/admin/ops/api/metrics-fragment"
			if p != "" {
				url += "?period=" + p
			}
			req := requestWithEmail(http.MethodGet, url, "admin@test.com", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
		})
	}
}

func TestCov100_MetricsFragment_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/metrics-fragment", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_MetricsFragment_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCov100_MetricsFragment_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mgr := h.manager
	if uStore := mgr.UserStoreConcrete(); uStore != nil {
		uStore.EnsureAdmin("admin@test.com")
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ===========================================================================
// handler.go: logAdminAction with nil auditStore
// ===========================================================================

func TestCov100_LogAdminAction_NilAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // nil auditStore
	// Should not panic
	h.logAdminAction("admin@test.com", "test_action", "target")
}

// ===========================================================================
// handler.go: logStream non-admin and wrong method
// ===========================================================================

func TestCov100_LogStream_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/logs", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_LogStream_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/logs", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ===========================================================================
// handler.go: overviewStream SSE with context cancel
// ===========================================================================

func TestCov100_OverviewStream_WithCancel(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Use a cancellable context so the SSE loop exits quickly.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	rec := httptest.NewRecorder()

	// Run in a goroutine since SSE blocks.
	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()

	// Cancel after a short delay to let the initial event fire.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SSE stream did not close after context cancel")
	}

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
	assert.Contains(t, rec.Body.String(), "event:")
}

// ===========================================================================
// dashboard.go: activityAPI with since/until/category/errors params
// ===========================================================================

func TestCov100_ActivityAPI_WithAllParams(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity?since=%s&until=%s&category=order&errors=true&limit=10&offset=0",
		since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

func TestCov100_ActivityAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_ActivityAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_ActivityAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ===========================================================================
// dashboard.go: activityExport with JSON format and time params
// ===========================================================================

func TestCov100_ActivityExport_JSONFormat(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity/export?format=json&since=%s&until=%s&category=order&errors=true",
		since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "activity.json")
}

func TestCov100_ActivityExport_CSVFormat(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/export", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
}

func TestCov100_ActivityExport_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity/export", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_ActivityExport_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/export", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// dashboard.go: activityStreamSSE
// ===========================================================================

func TestCov100_ActivityStream_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_ActivityStream_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_ActivityStream_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// dashboard.go: marketIndices error paths
// ===========================================================================

func TestCov100_MarketIndices_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_MarketIndices_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/market-indices", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_MarketIndices_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no credentials seeded
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_MarketIndices_NoToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	// Set credentials but delete token
	d.manager.TokenStore().Delete("user@test.com")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: portfolio error paths
// ===========================================================================

func TestCov100_Portfolio_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_Portfolio_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/portfolio", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_Portfolio_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_Portfolio_NoToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.manager.TokenStore().Delete("user@test.com")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: ordersAPI branch coverage
// ===========================================================================

func TestCov100_OrdersAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_OrdersAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_OrdersAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestCov100_OrdersAPI_WithSinceParam(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard.go: sectorExposureAPI / taxAnalysisAPI unauthenticated
// ===========================================================================

func TestCov100_SectorExposure_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_SectorExposure_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/sector-exposure", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_TaxAnalysis_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_TaxAnalysis_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/tax-analysis", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_SectorExposure_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_TaxAnalysis_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_SectorExposure_NoToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.manager.TokenStore().Delete("user@test.com")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_TaxAnalysis_NoToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.manager.TokenStore().Delete("user@test.com")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: selfDeleteAccount
// ===========================================================================

func TestCov100_SelfDeleteAccount_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/account/delete", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_SelfDeleteAccount_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// dashboard.go: alertsEnrichedAPI / pnlChartAPI / orderAttributionAPI branches
// ===========================================================================

func TestCov100_AlertsEnriched_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_AlertsEnriched_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts-enriched", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_PnlChart_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_PnlChart_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/pnl-chart", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_OrderAttribution_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/order-attribution", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_OrderAttribution_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/order-attribution", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov100_PnlChart_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// When alertDB is nil the handler gracefully returns 200 with empty data
	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov100_OrderAttribution_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Without order_id param the handler returns 400 (bad request)
	req := reqWithEmail(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// dashboard.go: selfManageCredentials branches
// ===========================================================================

func TestCov100_SelfCredentials_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPatch, "/dashboard/api/account/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_SelfCredentials_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/account/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// admin_render.go: usersToTemplateData with suspended and offboarded users
// ===========================================================================

func TestCov100_UsersToTemplateData_AllStatuses(t *testing.T) {
	t.Parallel()
	list := []*users.User{
		{Email: "admin@test.com", Role: "admin", Status: "active"},
		{Email: "user1@test.com", Role: "trader", Status: "active"},
		{Email: "user2@test.com", Role: "viewer", Status: "suspended"},
		{Email: "user3@test.com", Role: "trader", Status: "offboarded"},
	}
	data := usersToTemplateData(list, "admin@test.com")
	require.Len(t, data.Users, 4)

	// admin user
	assert.Equal(t, "purple", data.Users[0].RoleClass)
	assert.True(t, data.Users[0].IsSelf)
	assert.Equal(t, "green", data.Users[0].StatusClass)

	// active trader
	assert.Equal(t, "green", data.Users[1].RoleClass)
	assert.False(t, data.Users[1].IsSelf)

	// suspended
	assert.Equal(t, "red", data.Users[2].StatusClass)

	// offboarded
	assert.Equal(t, "amber", data.Users[3].StatusClass)
}

// ===========================================================================
// data.go: buildOverview and buildSessions branches
// ===========================================================================

func TestCov100_BuildOverview_NilMetrics(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // nil metrics
	overview := h.buildOverview()
	assert.Equal(t, "test-v1", overview.Version)
	assert.Equal(t, int64(0), overview.DailyUsers)
	assert.Empty(t, overview.ToolUsage)
}

func TestCov100_BuildAlertsForUser_WithAlerts(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAlertDB(t)
	// Add a test alert
	_, err := h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500.0, alerts.DirectionAbove)
	require.NoError(t, err)

	alertData := h.buildAlertsForUser("user@test.com")
	assert.NotEmpty(t, alertData.Alerts)
	assert.Contains(t, alertData.Alerts, "user@test.com")
}

func TestCov100_BuildSessionsForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	sessions := h.buildSessionsForUser("user@test.com")
	assert.Empty(t, sessions)
}

func TestCov100_BuildTickersForUser_Empty(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	tickers := h.buildTickersForUser("user@test.com")
	assert.Empty(t, tickers.Tickers)
}

func TestCov100_BuildOverviewForUser(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, "test-v1", overview.Version)
	assert.Equal(t, 0, overview.CachedTokens)
	assert.Equal(t, 0, overview.PerUserCredentials)
}

func TestCov100_BuildOverviewForUser_WithTokenAndCreds(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAlertDB(t)
	// Set credentials and token for user
	h.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "key", APISecret: "secret",
	})
	h.manager.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "token", StoredAt: time.Now(),
	})

	overview := h.buildOverviewForUser("user@test.com")
	assert.Equal(t, 1, overview.CachedTokens)
	assert.Equal(t, 1, overview.PerUserCredentials)
}

// ===========================================================================
// dashboard.go: billing page with authenticated user and billing store
// ===========================================================================

func TestCov100_BillingPage_Authenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	// Create a billing store with a subscription for the user
	store := &mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:             billing.TierPro,
				Status:           "active",
				MaxUsers:         5,
				StripeCustomerID: "cus_123",
			},
		},
	}
	d.SetBillingStore(store)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// ===========================================================================
// dashboard.go: RegisterRoutes — static CSS + fallback billing
// ===========================================================================

func TestCov100_StaticCSS(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}

func TestCov100_BillingFallback_NoBillingStore(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	// Don't set billing store — should use fallback handler
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Free Plan")
}

// ===========================================================================
// dashboard.go: writeJSONError encode error branch
// (this is a json.Encode error which only happens if the writer is broken;
// we cover the success path to get the main branch covered)
// ===========================================================================

func TestCov100_WriteJSONError(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))
	d := &DashboardHandler{logger: logger}

	rec := httptest.NewRecorder()
	d.writeJSONError(rec, http.StatusBadRequest, "test_error", "test message")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "test_error", resp["error"])
	assert.Equal(t, "test message", resp["message"])
}

// ===========================================================================
// dashboard_templates.go: InitTemplates, userContext, buildUserStatus
// ===========================================================================

func TestCov100_InitTemplates(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.InitTemplates()
	assert.NotNil(t, d.portfolioTmpl)
	assert.NotNil(t, d.activityTmpl)
	assert.NotNil(t, d.ordersTmpl)
	assert.NotNil(t, d.alertsTmpl)
	assert.NotNil(t, d.paperTmpl)
	assert.NotNil(t, d.safetyTmpl)
	assert.NotNil(t, d.fragmentTmpl)
}

func TestCov100_UserContext_NoEmail(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	email, role, tokenValid := d.userContext(req)
	assert.Equal(t, "", email)
	assert.Equal(t, "", role)
	assert.False(t, tokenValid)
}

func TestCov100_UserContext_Admin(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	req := reqWithEmail(http.MethodGet, "/", "admin@test.com")
	email, role, tokenValid := d.userContext(req)
	assert.Equal(t, "admin@test.com", email)
	assert.Equal(t, "admin", role)
	// Token stored is recent, so should be valid
	assert.True(t, tokenValid)
}

func TestCov100_BuildUserStatus_Admin(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	resp := d.buildUserStatus("admin@test.com")
	assert.Equal(t, "admin@test.com", resp.Email)
	assert.Equal(t, "admin", resp.Role)
	assert.True(t, resp.IsAdmin)
}

func TestCov100_BuildUserStatus_Trader(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	resp := d.buildUserStatus("user@test.com")
	assert.Equal(t, "user@test.com", resp.Email)
	assert.Equal(t, "trader", resp.Role)
	assert.False(t, resp.IsAdmin)
}

// ===========================================================================
// handler.go: registryHandler / registryItemHandler method not allowed
// ===========================================================================

func TestCov100_RegistryHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/registry", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov100_RegistryItemHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/registry/some-id", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// handler.go: credentials default branch
// ===========================================================================

func TestCov100_Credentials_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPut, "/admin/ops/api/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// overview_sse.go: sendAllAdminEvents with nil overviewTmpl and nil adminTmpl
// ===========================================================================

func TestCov100_SendAllAdminEvents_NilTemplates(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.overviewTmpl = nil
	h.adminTmpl = nil

	rec := httptest.NewRecorder()
	// Should not panic even with nil templates
	h.sendAllAdminEvents(rec, rec, "admin@test.com")
}

// ===========================================================================
// handler.go: New() with template parse errors (nil template branches)
// ===========================================================================

func TestCov100_ServePage_NilOpsTmpl(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.opsTmpl = nil

	rec := httptest.NewRecorder()
	req := requestWithEmail(http.MethodGet, "/admin/ops", "admin@test.com", nil)
	h.servePage(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// handler.go: logStream with SSE
// ===========================================================================

func TestCov100_LogStream_WithCancel(t *testing.T) {
	t.Parallel()
	h := newTestHandlerWithAudit(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Add a log entry to the buffer
	h.logBuffer.Add(LogEntry{Level: "info", Message: "test log", Time: time.Now()})

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil)
	req = req.WithContext(oauth.ContextWithEmail(ctx, "admin@test.com"))

	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("log stream did not close after context cancel")
	}

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// dashboard_templates.go: servePortfolioPage with nil template
// ===========================================================================

func TestCov100_ServePortfolioPage_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.portfolioTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should serve the fallback page
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR with nil template
// ===========================================================================

func TestCov100_ServeActivityPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.activityTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveOrdersPageSSR with nil template
// ===========================================================================

func TestCov100_ServeOrdersPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.ordersTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR with nil template
// ===========================================================================

func TestCov100_ServeAlertsPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.alertsTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePortfolioFragment with nil fragmentTmpl
// ===========================================================================

func TestCov100_ServePortfolioFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.fragmentTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePaperFragment with nil fragmentTmpl
// ===========================================================================

func TestCov100_ServePaperFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.fragmentTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: serveSafetyPageSSR with nil template
// ===========================================================================

func TestCov100_ServeSafetyPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.safetyTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// dashboard_templates.go: servePaperPageSSR with nil template
// ===========================================================================

func TestCov100_ServePaperPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.paperTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Helper: newTestHandlerWithAudit creates a Handler with audit store + admin
// ===========================================================================

func newTestHandlerWithAudit(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_api_key", "test_api_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
	)
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

	lb := NewLogBuffer(100)
	return New(mgr, nil, lb, logger, "test-v1", time.Now(), uStore, auditStore)
}

func newTestHandlerWithAlertDB(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_api_key", "test_api_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	lb := NewLogBuffer(100)
	return New(mgr, nil, lb, logger, "test-v1", time.Now(), mgr.UserStoreConcrete(), nil)
}

// Ensure all imports are used.
var (
	_ = io.Discard
	_ = billing.Subscription{}
)
