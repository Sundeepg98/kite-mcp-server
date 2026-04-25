package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


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
// handler.go: metricsAPI with alertDBPath set on Handler (db size branch)
// ===========================================================================
func TestMax_MetricsAPI_WithDBPath(t *testing.T) {
	t.Parallel()
	h := newHandlerWithAuditAndMetrics(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	// Set the DB path on the Handler directly (replaces a prior
	// t.Setenv("ALERT_DB_PATH", ...) — the env read moved to the app
	// wire-up layer which now plumbs Config.AlertDBPath into the
	// Handler via SetAlertDBPath, leaving tests free of t.Setenv and
	// safely t.Parallel-compatible).
	tmpFile := t.TempDir() + "/test.db"
	require.NoError(t, os.WriteFile(tmpFile, []byte("test"), 0644))
	h.SetAlertDBPath(tmpFile)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics?period=1h", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: metricsAPI period params
// ===========================================================================
func TestFinal_MetricsAPI_Periods(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		req := adminReq(http.MethodGet, "/admin/ops/api/metrics?period="+period, "")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "period=%s", period)
	}
}


func TestFinal_MetricsAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/metrics", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_MetricsAPI_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodGet, "/admin/ops/api/metrics", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_MetricsAPI_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t) // no audit store
	h.userStore = h.manager.UserStoreConcrete()
	if h.userStore != nil {
		h.userStore.EnsureAdmin("admin@test.com")
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/metrics", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}


// ===========================================================================
// handler.go: metricsFragment
// ===========================================================================
func TestFinal_MetricsFragment_Periods(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		req := adminReq(http.MethodGet, "/admin/ops/api/metrics-fragment?period="+period, "")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "period=%s", period)
	}
}


func TestFinal_MetricsFragment_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodPost, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_MetricsFragment_Forbidden(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandlerWithRiskGuard(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := userReq(http.MethodGet, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}


func TestFinal_MetricsFragment_NoAuditStore(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	h.userStore = h.manager.UserStoreConcrete()
	if h.userStore != nil {
		h.userStore.EnsureAdmin("admin@test.com")
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := adminReq(http.MethodGet, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
