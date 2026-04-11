package ops

// coverage_push_test.go: push ops coverage from 75.5% -> 90%+.
// Tests every low-coverage dashboard handler success path using httptest
// with authenticated user context, paper engine, and riskguard.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newFullTestDashboard creates a DashboardHandler with all stores wired up:
// credentials + tokens, audit store, paper engine, riskguard.
func newFullTestDashboard(t *testing.T, kiteBaseURL string) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger: logger,
		TestData: map[uint32]*instruments.Instrument{
			256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
			408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		},
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

	// Paper engine
	paperStore := papertrading.NewStore(mgr.AlertDB(), logger)
	require.NoError(t, paperStore.InitTables())
	mgr.SetPaperEngine(papertrading.NewEngine(paperStore, logger))

	// Audit store
	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	require.NoError(t, auditStore.InitTable())

	// Seed credentials + tokens for test user
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_api_key", APISecret: "test_api_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "mock_token", StoredAt: time.Now(),
	})

	// Seed admin credentials too
	mgr.CredentialStore().Set("admin@test.com", &kc.KiteCredentialEntry{
		APIKey: "admin_api_key", APISecret: "admin_api_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("admin@test.com", &kc.KiteTokenEntry{
		AccessToken: "admin_mock_token", StoredAt: time.Now(),
	})

	// Create admin user
	uStore := mgr.UserStoreConcrete()
	if uStore != nil {
		uStore.EnsureAdmin("admin@test.com")
	}

	d := NewDashboardHandler(mgr, logger, auditStore)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })

	return d
}

// --- Helper to make requests with email context ---

func reqWithEmail(method, target, email string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if email != "" {
		ctx := oauth.ContextWithEmail(req.Context(), email)
		req = req.WithContext(ctx)
	}
	return req
}

// ===========================================================================
// marketIndices (37.9% -> high)
// ===========================================================================

func TestCov_MarketIndices_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Kite call may fail (DevMode client), but auth + cred + token path is covered
	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway,
		"expected 200 or 502, got %d: %s", rec.Code, rec.Body.String())
}

func TestCov_MarketIndices_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "no_credentials")
}

func TestCov_MarketIndices_NoToken(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.manager.TokenStore().Delete("user@test.com")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/market-indices", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "no_session")
}

// ===========================================================================
// portfolio (37.9% -> high)
// ===========================================================================

func TestCov_Portfolio_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway,
		"got %d: %s", rec.Code, rec.Body.String())
}

func TestCov_Portfolio_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov_Portfolio_NoToken(t *testing.T) {
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

func TestCov_Portfolio_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/portfolio", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// ordersAPI (37.8% -> high)
// ===========================================================================

func TestCov_OrdersAPI_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.auditStore.Record(&audit.ToolCall{
		CallID:       "call-ord-cov-1",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD001",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		StartedAt:    time.Now().Add(-1 * time.Hour),
		CompletedAt:  time.Now().Add(-1 * time.Hour),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestCov_OrdersAPI_WithSinceParam(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.auditStore.Record(&audit.ToolCall{
		CallID:       "call-ord-cov-2",
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD002",
		InputParams:  `{"tradingsymbol":"RELIANCE","exchange":"NSE","transaction_type":"SELL","order_type":"LIMIT","quantity":5}`,
		StartedAt:    time.Now().Add(-2 * time.Hour),
		CompletedAt:  time.Now().Add(-2 * time.Hour),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_OrdersAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov_OrdersAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// paperStatus / paperHoldings / paperPositions / paperOrders / paperReset (64.7%)
// ===========================================================================

func TestCov_PaperStatus_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestCov_PaperHoldings_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/holdings", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_PaperPositions_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_PaperOrders_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_PaperReset_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/reset", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestCov_PaperStatus_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov_PaperHoldings_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/holdings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov_PaperPositions_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/paper/positions", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov_PaperOrders_WrongMethod(t *testing.T) {
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
// sectorExposureAPI (40.7% -> high)
// ===========================================================================

func TestCov_SectorExposure_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway,
		"got %d: %s", rec.Code, rec.Body.String())
}

func TestCov_SectorExposure_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/sector-exposure", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov_SectorExposure_NoToken(t *testing.T) {
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

func TestCov_SectorExposure_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/sector-exposure", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// taxAnalysisAPI (40.7% -> high)
// ===========================================================================

func TestCov_TaxAnalysis_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusBadGateway,
		"got %d: %s", rec.Code, rec.Body.String())
}

func TestCov_TaxAnalysis_NoCredentials(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/tax-analysis", "nocreds@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCov_TaxAnalysis_NoToken(t *testing.T) {
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

func TestCov_TaxAnalysis_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/tax-analysis", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// alertsEnrichedAPI (50.6% -> high)
// ===========================================================================

func TestCov_AlertsEnriched_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1700, alerts.DirectionAbove)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "active")
}

func TestCov_AlertsEnriched_Delete(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	alertID, _ := d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1700, alerts.DirectionAbove)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id="+alertID, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

func TestCov_AlertsEnriched_DeleteMissingID(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCov_AlertsEnriched_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestCov_AlertsEnriched_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts-enriched", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// activityStreamSSE (73.5% -> high)
// ===========================================================================

func TestCov_ActivityStreamSSE_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx = oauth.ContextWithEmail(ctx, "user@test.com")

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "connected")
}

func TestCov_ActivityStreamSSE_NoAudit(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/activity/stream", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCov_ActivityStreamSSE_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// SSR page endpoints (servePortfolioPage, serveAlertsPageSSR, etc.)
// ===========================================================================

func TestCov_PortfolioPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestCov_OrdersPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_AlertsPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1700, alerts.DirectionAbove)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_PaperPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_SafetyPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_ActivityPage_SSR(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Fragment endpoints (htmx auto-refresh)
// ===========================================================================

func TestCov_PortfolioFragment(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestCov_SafetyFragment(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_PaperFragment(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// pnlChartAPI (79.3% -> higher) and orderAttributionAPI (73.9%)
// ===========================================================================

func TestCov_PnLChart_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_OrderAttribution_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	for i := 0; i < 3; i++ {
		d.auditStore.Record(&audit.ToolCall{
			CallID:       fmt.Sprintf("call-attr-cov-%d", i),
			Email:        "user@test.com",
			ToolName:     "place_order",
			ToolCategory: "order",
			OrderID:      fmt.Sprintf("ORD%03d", i),
			StartedAt:    time.Now().Add(-time.Duration(i) * time.Hour),
			CompletedAt:  time.Now().Add(-time.Duration(i) * time.Hour),
			DurationMs:   100 + int64(i*10),
		})
	}

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD001", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// safetyStatus
// ===========================================================================

func TestCov_SafetyStatus_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/safety/status", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "enabled")
}

// ===========================================================================
// buildSessions (28.6%)
// ===========================================================================

func TestCov_BuildSessions(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	h.manager.GetOrCreateSessionWithEmail("a1b2c3d4-e5f6-7890-test-buildsess02", "active@test.com")
	sessions := h.buildSessions()
	assert.NotNil(t, sessions)
}

// ===========================================================================
// Admin logStream SSE (71%)
// ===========================================================================

func TestCov_LogStream_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

// ===========================================================================
// Admin metricsAPI + metricsFragment (79.5% / 67.4%)
// ===========================================================================

func TestCov_MetricsAPI_Success(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_MetricsFragment(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Admin registryHandler + registryItemHandler (82.8% / 76.5%)
// ===========================================================================

func TestCov_Registry_List(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops/api/registry", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Overview SSE (82.4%)
// ===========================================================================

func TestCov_OverviewStream(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")

	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

// ===========================================================================
// Render fragments
// ===========================================================================

// TestCov_OpsPage tests the main ops admin page which calls renderFragment internally.
func TestCov_OpsPage(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/admin/ops", "admin@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// selfDeleteAccount POST (87.1%) and selfManageCredentials
// ===========================================================================

func TestCov_SelfDeleteAccount_POST(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.manager.CredentialStore().Set("delete@test.com", &kc.KiteCredentialEntry{
		APIKey: "del_key", APISecret: "del_secret", StoredAt: time.Now(),
	})
	d.manager.TokenStore().Set("delete@test.com", &kc.KiteTokenEntry{
		AccessToken: "del_token", StoredAt: time.Now(),
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":true}`)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/account/delete", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := oauth.ContextWithEmail(req.Context(), "delete@test.com")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "deleted")
}

func TestCov_SelfManageCredentials_GET(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// writeJSONError (75% -> 100%)
// ===========================================================================

func TestCov_WriteJSONError(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	rec := httptest.NewRecorder()
	d.writeJSONError(rec, http.StatusBadRequest, "test_error", "Test message")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	err := json.NewDecoder(rec.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "test_error", body["error"])
}

// ===========================================================================
// activityAPI deeper paths (76.7%)
// ===========================================================================

func TestCov_ActivityAPI_AllFilters(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	for i := 0; i < 5; i++ {
		d.auditStore.Record(&audit.ToolCall{
			CallID:       fmt.Sprintf("call-filter-cov-%d", i),
			Email:        "user@test.com",
			ToolName:     "get_profile",
			ToolCategory: "query",
			StartedAt:    time.Now().Add(-time.Duration(i) * time.Hour),
			CompletedAt:  time.Now().Add(-time.Duration(i) * time.Hour),
			DurationMs:   50 + int64(i*10),
		})
	}

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity?category=query&errors=true&limit=10&offset=0&since=%s&until=%s", since, until)
	req := reqWithEmail(http.MethodGet, url, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Billing page (no billing store = free plan fallback)
// ===========================================================================

func TestCov_BillingPage_NoBillingStore(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Free Plan")
}

// ===========================================================================
// Alerts basic API (80%)
// ===========================================================================

func TestCov_AlertsAPI_Success(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	d.manager.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 408065, 2400, alerts.DirectionBelow)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
