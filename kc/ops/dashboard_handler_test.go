package ops

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newTestDashboard creates a DashboardHandler backed by a real kc.Manager in dev mode.
func newTestDashboard(t *testing.T) *DashboardHandler {
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
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	d := NewDashboardHandler(mgr, logger, nil)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d
}

// ===========================================================================
// DashboardHandler.RegisterRoutes smoke test
// ===========================================================================

func TestDashboardHandler_RegisterRoutes(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	// Should not panic
	d.RegisterRoutes(mux, noopAuth)
}

// ===========================================================================
// status API
// ===========================================================================

func TestDashboardHandler_Status(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var status statusResponse
	err := json.NewDecoder(rec.Body).Decode(&status)
	require.NoError(t, err)
	assert.Equal(t, "user@test.com", status.Email)
	assert.Equal(t, "trader", status.Role)
	assert.False(t, status.IsAdmin)
	assert.True(t, status.DevMode)
}

func TestDashboardHandler_Status_Admin(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/status", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var status statusResponse
	err := json.NewDecoder(rec.Body).Decode(&status)
	require.NoError(t, err)
	assert.True(t, status.IsAdmin)
	assert.Equal(t, "admin", status.Role)
}

func TestDashboardHandler_Status_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboardHandler_Status_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// portfolio API (DevMode returns mock data)
// ===========================================================================

func TestDashboardHandler_Portfolio_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// User is authenticated but has no stored Kite credentials -> 401
	req := requestWithEmail(http.MethodGet, "/dashboard/api/portfolio", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "not_authenticated")
}

func TestDashboardHandler_Portfolio_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// No email in context -> 401
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/portfolio", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// orders API
// ===========================================================================

func TestDashboardHandler_Orders_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // auditStore is nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Orders API requires audit store -> 503
	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestDashboardHandler_Orders_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// alerts API
// ===========================================================================

func TestDashboardHandler_Alerts(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// market indices API
// ===========================================================================

func TestDashboardHandler_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// No credentials stored -> returns appropriate error
	req := requestWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// May return 401 (no creds) or other error codes
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// activity API (no audit store configured)
// ===========================================================================

func TestDashboardHandler_Activity_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // auditStore is nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestDashboardHandler_Activity_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// activity export (no audit store)
// ===========================================================================

func TestDashboardHandler_ActivityExport_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ===========================================================================
// safety status API
// ===========================================================================

func TestDashboardHandler_SafetyStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// paper trading API
// ===========================================================================

func TestDashboardHandler_PaperStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Paper trading may not be enabled or user may need auth
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// SSR page rendering
// ===========================================================================

func TestDashboardHandler_PortfolioPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "user@test.com")
}

func TestDashboardHandler_PortfolioPage_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// No email in context - page still renders (shows empty state)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestDashboardHandler_ActivityPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestDashboardHandler_OrdersPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestDashboardHandler_AlertsPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestDashboardHandler_SafetyPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestDashboardHandler_PaperPage(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// ===========================================================================
// billing page (no billing store)
// ===========================================================================

func TestDashboardHandler_BillingPage_NoBillingStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Free Plan")
}

// ===========================================================================
// Static assets
// ===========================================================================

func TestDashboardHandler_StaticCSS(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/css; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Cache-Control"), "public")
}

func TestDashboardHandler_StaticHTMX(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
}

// ===========================================================================
// self-manage credentials API
// ===========================================================================

func TestDashboardHandler_SelfCredentials_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/account/credentials", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDashboardHandler_SelfCredentials_GET(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboardHandler_SelfCredentials_PUT(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"test_key","api_secret":"test_secret"}`)
	req := requestWithEmail(http.MethodPut, "/dashboard/api/account/credentials", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDashboardHandler_SelfCredentials_DELETE(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// writeJSON and writeJSONError helper tests
// ===========================================================================

func TestDashboardHandler_WriteJSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.writeJSON(rec, map[string]string{"status": "ok"})

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var resp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp["status"])
}

func TestDashboardHandler_WriteJSONError(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.writeJSONError(rec, http.StatusBadRequest, "bad_request", "Invalid input")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]string
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "bad_request", resp["error"])
	assert.Equal(t, "Invalid input", resp["message"])
}

// ===========================================================================
// alerts enriched API
// ===========================================================================

func TestDashboardHandler_AlertsEnriched(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// sector exposure API
// ===========================================================================

func TestDashboardHandler_SectorExposure_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// No credentials -> auth error
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// tax analysis API
// ===========================================================================

func TestDashboardHandler_TaxAnalysis_NoCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// No credentials -> auth error
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// Paper trading endpoints
// ===========================================================================

func TestDashboardHandler_PaperHoldings(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Paper engine may not be initialized -> various codes are acceptable
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

func TestDashboardHandler_PaperPositions(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

func TestDashboardHandler_PaperOrders(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

func TestDashboardHandler_PaperReset_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper/reset", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// PnL chart API
// ===========================================================================

func TestDashboardHandler_PnLChart(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/pnl-chart", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should return valid response (empty data or error) but not panic
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// Order attribution API
// ===========================================================================

func TestDashboardHandler_OrderAttribution(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// Self-delete account
// ===========================================================================

func TestDashboardHandler_SelfDelete_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/account/delete", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestDashboardHandler_SelfDelete_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// OAuth context helper
// ===========================================================================

// Verify oauth.ContextWithEmail and EmailFromContext work in test context
func TestOAuthContextRoundtrip(t *testing.T) {
	t.Parallel()
	ctx := oauth.ContextWithEmail(httptest.NewRequest(http.MethodGet, "/", nil).Context(), "test@example.com")
	assert.Equal(t, "test@example.com", oauth.EmailFromContext(ctx))
}
