package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// admin_render.go: metricsToTemplateData edge cases
// ---------------------------------------------------------------------------
func TestPush100_MetricsToTemplateData_NilStats(t *testing.T) {
	t.Parallel()
	result := metricsToTemplateData(nil, nil, 3600)
	// Nil stats: totalCalls=0, errorCount=0 → Cards[1]="0", Cards[2]="0.0%", Cards[3]="0ms"
	assert.Equal(t, "0", result.Cards[1].Value)      // Total Calls
	assert.Equal(t, "0.0%", result.Cards[2].Value)    // Error Rate
	assert.Equal(t, "0ms", result.Cards[3].Value)      // Avg Latency
	assert.Equal(t, "--", result.Cards[4].Value)       // Top Tool
}


func TestPush100_MetricsToTemplateData_ZeroTotalCalls(t *testing.T) {
	t.Parallel()
	stats := &audit.Stats{
		TotalCalls: 0,
		ErrorCount: 0,
	}
	result := metricsToTemplateData(stats, nil, 3600)
	assert.Equal(t, "0", result.Cards[1].Value)      // Total Calls
	assert.Equal(t, "0.0%", result.Cards[2].Value)    // Error Rate: 0/0 → 0%
}


// ---------------------------------------------------------------------------
// handler.go: metricsAPI with different period params
// ---------------------------------------------------------------------------
func TestPush100_MetricsAPI_30dPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics?period=30d", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_MetricsAPI_7dPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics?period=7d", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// handler.go: metricsFragment — all period variants
// ===========================================================================
func TestPush100_MetricsFragment_1hPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics-fragment?period=1h", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}


func TestPush100_MetricsFragment_DefaultPeriod(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_MetricsFragment_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodPost, "/admin/ops/api/metrics-fragment", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
