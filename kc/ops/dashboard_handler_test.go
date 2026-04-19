package ops

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/broker/zerodha"
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

// ===========================================================================
// Tests merged from factory_test.go (KiteClientFactory injection tests)
// ===========================================================================

// ── mock KiteClientFactory ───────────────────────────────────────────────────

// testKiteClientFactory returns zerodha.KiteSDK instances whose BaseURI
// points at the given mock server URL. The production factory returns
// the hexagonal port, so this test factory matches — SetBaseURI is part
// of the KiteSDK interface, so no concrete-type escape is needed.
type testKiteClientFactory struct {
	mockURL string
}

func (f *testKiteClientFactory) NewClient(apiKey string) zerodha.KiteSDK {
	sdk := zerodha.NewKiteSDK(apiKey)
	sdk.SetBaseURI(f.mockURL)
	return sdk
}

func (f *testKiteClientFactory) NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK {
	sdk := zerodha.NewKiteSDK(apiKey)
	sdk.SetAccessToken(accessToken)
	sdk.SetBaseURI(f.mockURL)
	return sdk
}

// ── mock Kite HTTP server for dashboard endpoints ────────────────────────────

func startDashboardMockKite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path

		env := func(data interface{}) string {
			b, _ := json.Marshal(map[string]interface{}{"status": "success", "data": data})
			return string(b)
		}

		switch {
		// user profile
		case p == "/user/profile":
			fmt.Fprint(w, env(map[string]any{
				"user_id": "DT1234", "user_name": "Dashboard User", "email": "dash@test.com",
			}))
		case strings.HasPrefix(p, "/user/margins"):
			fmt.Fprint(w, env(map[string]any{
				"equity": map[string]any{
					"enabled": true, "net": 500000.0,
					"available": map[string]any{"cash": 500000.0, "collateral": 0.0, "intraday_payin": 0.0},
					"utilised":  map[string]any{"debits": 0.0, "exposure": 0.0, "m2m_realised": 0.0, "m2m_unrealised": 0.0},
				},
			}))

		// portfolio
		case p == "/portfolio/holdings":
			fmt.Fprint(w, env([]map[string]any{
				{"tradingsymbol": "INFY", "exchange": "NSE", "isin": "INE009A01021", "quantity": 10, "average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0, "day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265},
				{"tradingsymbol": "RELIANCE", "exchange": "NSE", "isin": "INE002A01018", "quantity": 5, "average_price": 2500.0, "last_price": 2600.0, "pnl": 500.0, "day_change_percentage": 1.2, "product": "CNC", "instrument_token": 408065},
			}))
		case p == "/portfolio/positions":
			fmt.Fprint(w, env(map[string]any{
				"net": []map[string]any{
					{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 2, "average_price": 1550.0, "last_price": 1600.0, "pnl": 100.0, "product": "MIS"},
				},
				"day": []map[string]any{},
			}))

		// orders
		case p == "/orders" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "DASH-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))
		case strings.HasPrefix(p, "/orders/") && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "DASH-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))

		// trades
		case p == "/trades":
			fmt.Fprint(w, env([]map[string]any{
				{"trade_id": "T001", "order_id": "DASH-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0},
			}))

		// quote endpoints (used by market indices, alert enrichment)
		// NOTE: gokiteconnect SDK routes GetOHLC, GetLTP, and GetQuotes all
		// through /quote (URIGetQuote). The /quote/ohlc and /quote/ltp paths
		// are defined in the SDK but NOT used by the Go client methods.
		case p == "/quote":
			fmt.Fprint(w, env(map[string]any{
				"NSE:INFY":       map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
				"NSE:RELIANCE":   map[string]any{"instrument_token": 408065, "last_price": 2620.0, "ohlc": map[string]any{"open": 2580.0, "high": 2640.0, "low": 2570.0, "close": 2600.0}},
				"NSE:NIFTY 50":   map[string]any{"instrument_token": 100, "last_price": 22000.0, "ohlc": map[string]any{"open": 21900.0, "high": 22100.0, "low": 21800.0, "close": 21950.0}},
				"NSE:NIFTY BANK": map[string]any{"instrument_token": 200, "last_price": 48000.0, "ohlc": map[string]any{"open": 47800.0, "high": 48200.0, "low": 47700.0, "close": 47900.0}},
				"BSE:SENSEX":     map[string]any{"instrument_token": 300, "last_price": 72000.0, "ohlc": map[string]any{"open": 71800.0, "high": 72200.0, "low": 71700.0, "close": 71900.0}},
			}))
		// GTT
		case p == "/gtt/triggers" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{}))

		default:
			http.Error(w, `{"status":"error","message":"not found: `+p+`"}`, 404)
		}
	}))
}

// ── Dashboard + Manager setup with KiteClientFactory injection ───────────────

const dashTestEmail = "dash@test.com"

// newDashboardWithMockKite creates a DashboardHandler backed by a non-DevMode
// Manager whose KiteClientFactory has been replaced with one that routes
// all Kite API calls to the given mock server URL.
func newDashboardWithMockKite(t *testing.T, mockURL string) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}
	instrMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "dash_key",
		APISecret:          "dash_secret",
		Logger:             logger,
		InstrumentsManager: instrMgr,
		DevMode:            false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	// Inject mock KiteClientFactory so all NewClientWithToken calls
	// return clients pointing at the httptest server.
	mgr.SetKiteClientFactory(&testKiteClientFactory{mockURL: mockURL})

	// Seed credentials + tokens so dashboard handlers find them.
	mgr.CredentialStore().Set(dashTestEmail, &kc.KiteCredentialEntry{
		APIKey: "dash_key", APISecret: "dash_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set(dashTestEmail, &kc.KiteTokenEntry{
		AccessToken: "dash-access-token", StoredAt: time.Now(),
	})

	d := NewDashboardHandler(mgr, logger, nil)
	d.SetAdminCheck(func(email string) bool { return false })
	return d
}

// dashRequest creates an HTTP request with the test email in context.
func dashRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := oauth.ContextWithEmail(req.Context(), dashTestEmail)
	return req.WithContext(ctx)
}

// ── Tests: dashboard API success paths via KiteClientFactory ─────────────────

func TestFactoryDash_MarketIndices(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/market-indices"))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should contain NIFTY 50, NIFTY BANK, SENSEX
	assert.Contains(t, result, "NSE:NIFTY 50")
	assert.Contains(t, result, "NSE:NIFTY BANK")
	assert.Contains(t, result, "BSE:SENSEX")
}

func TestFactoryDash_Portfolio(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/portfolio"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have holdings and positions
	assert.Contains(t, result, "holdings")
	assert.Contains(t, result, "positions")
	assert.Contains(t, result, "summary")
}

func TestFactoryDash_SectorExposure(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/sector-exposure"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have sectors array
	assert.Contains(t, result, "sectors")
}

func TestFactoryDash_TaxAnalysis(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/tax-analysis"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have holdings array
	assert.Contains(t, result, "holdings")
}

func TestFactoryDash_Status(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/status"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, dashTestEmail, result["email"])
}

// ── Negative tests: no credentials / no token ────────────────────────────────

func TestFactoryDash_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	// Remove credentials to trigger the no-creds path
	d.manager.CredentialStore().Delete(dashTestEmail)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/market-indices"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFactoryDash_Portfolio_NoToken(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	// Remove token to trigger the no-token path
	d.manager.TokenStore().Delete(dashTestEmail)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/portfolio"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFactoryDash_Portfolio_NoAuth(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Request with no email in context
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/portfolio", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ── KiteClientFactory unit test ──────────────────────────────────────────────

func TestKiteClientFactory_NewClientWithToken(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()

	factory := &testKiteClientFactory{mockURL: ts.URL}
	client := factory.NewClientWithToken("key", "token")
	assert.NotNil(t, client)

	// Verify the mock server handles profile requests
	profile, err := client.GetUserProfile()
	require.NoError(t, err)
	assert.Equal(t, "DT1234", profile.UserID)
}

func TestKiteClientFactory_NewClient(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()

	factory := &testKiteClientFactory{mockURL: ts.URL}
	client := factory.NewClient("key")
	assert.NotNil(t, client)

	// GetHoldings should work against mock
	holdings, err := client.GetHoldings()
	require.NoError(t, err)
	assert.Len(t, holdings, 2)
}
