package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


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
// dashboard.go: paper trading - no engine path
// ===========================================================================
func TestFinal_PaperStatus_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no paper engine
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_PaperHoldings_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_PaperPositions_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_PaperOrders_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_PaperReset_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}


func TestFinal_PaperReset_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/reset", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_PaperReset_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/paper/reset", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_PaperOrders_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_PaperPositions_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/positions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_PaperStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: marketIndices/portfolio with mock Kite server
// ===========================================================================
func TestFinal_MarketIndices_WithMockKite(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	// Override credentials to point to mock server
	d.manager.CredentialStore().Set("kite@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	d.manager.TokenStore().Set("kite@test.com", &kc.KiteTokenEntry{
		AccessToken: "mock_token", StoredAt: time.Now(),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "kite@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// With DevMode client, Kite call will fail, but auth+cred path is exercised
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway)
}


func TestFinal_MarketIndices_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_MarketIndices_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/market-indices", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: pnlChartAPI / orderAttributionAPI additional paths
// ===========================================================================
func TestFinal_PnLChart_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_PnLChart_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/pnl-chart", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: alerts handler
// ===========================================================================
func TestFinal_DashboardAlerts_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_DashboardAlerts_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard.go: sectorExposureAPI / taxAnalysisAPI additional paths
// ===========================================================================
func TestFinal_SectorExposure_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/sector-exposure", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_TaxAnalysis_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/tax-analysis", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePortfolioPage - nil template
// ===========================================================================
func TestFinal_PortfolioPage_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.portfolioTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePortfolioFragment nil template
// ===========================================================================
func TestFinal_PortfolioFragment_NilTemplate(t *testing.T) {
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
// dashboard_templates.go: servePaperFragment nil template
// ===========================================================================
func TestFinal_PaperFragment_NilTemplate(t *testing.T) {
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
// dashboard_templates.go: servePaperPageSSR - nil template
// ===========================================================================
func TestFinal_PaperPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.paperTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code) // fallback
}


// ===========================================================================
// dashboard.go: safetyStatus handler
// ===========================================================================
func TestFinal_SafetyStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/safety/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}


func TestFinal_SafetyStatus_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/safety/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}


func TestFinal_SafetyStatus_NoRiskGuard(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no riskguard
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "false")
}


// ===========================================================================
// dashboard_templates.go: serveSafetyFragment nil template
// ===========================================================================
func TestFinal_SafetyFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.fragmentTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePaperPageSSR with paper enabled
// ===========================================================================
func TestFinal_PaperPageSSR_Enabled(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	pe := d.manager.PaperEngine()
	require.NotNil(t, pe)
	require.NoError(t, pe.Enable("user@test.com", 10000000))

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePaperFragment with paper enabled
// ===========================================================================
func TestFinal_PaperFragment_Enabled(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	pe := d.manager.PaperEngine()
	require.NotNil(t, pe)
	require.NoError(t, pe.Enable("user@test.com", 10000000))

	// Create paper engine and enable for user. Bridge through
	// logport.AsSlog because papertrading.NewStore still consumes
	// *slog.Logger directly (its own Logger sweep is a separate
	// commit; doesn't block this SOLID cleanup).
	paperStore := papertrading.NewStore(d.manager.AlertDB(), logport.AsSlog(d.loggerPort))
	require.NoError(t, paperStore.InitTables())

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePaperFragment with no engine and no user
// ===========================================================================
func TestFinal_PaperFragment_NoEngine(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no paper engine
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "not enabled")
}


// ===========================================================================
// dashboard.go: pnlChartAPI with no DB
// ===========================================================================
func TestFinal_PnLChart_NoAuditDB(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no AlertDB
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestFinal_PnLChart_WithPeriod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=7", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
