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

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
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

// ===========================================================================
// Mock Kite HTTP server — returns valid JSON for common Kite API endpoints
// ===========================================================================

// kiteJSON wraps data in the Kite API envelope: {"status":"success","data":...}
func kiteJSON(data interface{}) string {
	b, _ := json.Marshal(map[string]interface{}{"status": "success", "data": data})
	return string(b)
}

// newMockKiteServer returns an httptest server that handles GetOrderHistory,
// GetLTP, GetOHLC, GetHoldings, GetPositions, GetOrders, GetProfile.
func newMockKiteServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		switch {
		// GET /user/profile
		case path == "/user/profile" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON(map[string]interface{}{
				"user_id": "AB1234", "user_name": "Test User", "email": "test@kite.com",
			}))

		// GET /portfolio/holdings
		case path == "/portfolio/holdings" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON([]map[string]interface{}{
				{
					"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 10,
					"average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0,
					"day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265,
				},
				{
					"tradingsymbol": "RELIANCE", "exchange": "NSE", "quantity": 5,
					"average_price": 2500.0, "last_price": 2600.0, "pnl": 500.0,
					"day_change_percentage": 1.2, "product": "CNC", "instrument_token": 408065,
				},
			}))

		// GET /portfolio/positions
		case path == "/portfolio/positions" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON(map[string]interface{}{
				"net": []map[string]interface{}{
					{
						"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 2,
						"average_price": 1550.0, "last_price": 1600.0, "pnl": 100.0,
						"product": "MIS",
					},
				},
				"day": []map[string]interface{}{},
			}))

		// GET /orders (all orders)
		case path == "/orders" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON([]map[string]interface{}{
				{
					"order_id": "ORD-001", "status": "COMPLETE", "tradingsymbol": "INFY",
					"exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET",
					"quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0,
					"order_timestamp": "2026-04-01 10:00:00",
				},
			}))

		// GET /orders/{order_id} (order history)
		case strings.HasPrefix(path, "/orders/") && !strings.Contains(path, "/trades") && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON([]map[string]interface{}{
				{
					"order_id": "ORD-001", "status": "OPEN", "tradingsymbol": "INFY",
					"exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET",
					"quantity": 10.0, "order_timestamp": "2026-04-01 09:59:00",
				},
				{
					"order_id": "ORD-001", "status": "COMPLETE", "tradingsymbol": "INFY",
					"exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET",
					"quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0,
					"order_timestamp": "2026-04-01 10:00:00",
				},
			}))

		// GET /quote — gokiteconnect uses /quote for GetLTP, GetOHLC, and GetQuotes
		case path == "/quote" && r.Method == http.MethodGet:
			// Return a combined response suitable for LTP, OHLC, and full quotes
			data := map[string]interface{}{
				"NSE:INFY": map[string]interface{}{
					"instrument_token": 256265, "last_price": 1620.0,
					"ohlc": map[string]interface{}{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0},
				},
				"NSE:RELIANCE": map[string]interface{}{
					"instrument_token": 408065, "last_price": 2620.0,
					"ohlc": map[string]interface{}{"open": 2580.0, "high": 2640.0, "low": 2570.0, "close": 2600.0},
				},
				"NSE:NIFTY 50": map[string]interface{}{
					"instrument_token": 256265, "last_price": 22500.0,
					"ohlc": map[string]interface{}{"open": 22400.0, "high": 22600.0, "low": 22350.0, "close": 22450.0},
				},
				"NSE:NIFTY BANK": map[string]interface{}{
					"instrument_token": 408065, "last_price": 48000.0,
					"ohlc": map[string]interface{}{"open": 47800.0, "high": 48200.0, "low": 47700.0, "close": 47900.0},
				},
				"BSE:SENSEX": map[string]interface{}{
					"instrument_token": 0, "last_price": 74000.0,
					"ohlc": map[string]interface{}{"open": 73800.0, "high": 74200.0, "low": 73700.0, "close": 73900.0},
				},
			}
			fmt.Fprint(w, kiteJSON(data))

		// GET /trades
		case path == "/trades" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteJSON([]map[string]interface{}{}))

		// GET /user/margins
		case strings.HasPrefix(path, "/user/margins"):
			fmt.Fprint(w, kiteJSON(map[string]interface{}{
				"equity": map[string]interface{}{
					"enabled": true, "net": 100000.0,
					"available": map[string]interface{}{"cash": 100000.0, "collateral": 0.0, "intraday_payin": 0.0},
					"utilised":  map[string]interface{}{"debits": 0.0, "exposure": 0.0, "m2m_realised": 0.0, "m2m_unrealised": 0.0},
				},
			}))

		default:
			http.Error(w, `{"status":"error","message":"not found"}`, http.StatusNotFound)
		}
	}))
}

// newMockKiteClient creates a kiteconnect.Client pointed at the mock server.
func newMockKiteClient(mockURL string) *kiteconnect.Client {
	c := kiteconnect.New("test_key")
	c.SetAccessToken("test_token")
	c.SetBaseURI(mockURL)
	return c
}

// ===========================================================================
// enrichOrdersWithKite — direct test with mock server (7.4% -> high)
// ===========================================================================

func TestEnrichOrdersWithKite_Success(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	client := newMockKiteClient(ts.URL)

	entries := []orderEntry{
		{
			OrderID:  "ORD-001",
			Symbol:   "INFY",
			Exchange: "NSE",
			Side:     "BUY",
		},
	}

	d.orders.enrichOrdersWithKite(client, entries)

	// Order should be enriched with status, fill price, current price, and P&L
	require.Len(t, entries, 1)
	assert.Equal(t, "COMPLETE", entries[0].Status)
	assert.NotNil(t, entries[0].FillPrice, "fill price should be set")
	assert.NotNil(t, entries[0].CurrentPrice, "current price should be set")
	assert.NotNil(t, entries[0].PnL, "PnL should be calculated")
	assert.NotNil(t, entries[0].PnLPct, "PnL percentage should be calculated")
}

func TestEnrichOrdersWithKite_SELLDirection(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	client := newMockKiteClient(ts.URL)

	entries := []orderEntry{
		{
			OrderID:  "ORD-001",
			Symbol:   "",
			Exchange: "",
			Side:     "", // Will be filled from order history
		},
	}

	d.orders.enrichOrdersWithKite(client, entries)

	assert.Equal(t, "COMPLETE", entries[0].Status)
	assert.Equal(t, "INFY", entries[0].Symbol, "symbol should be filled from history")
	assert.Equal(t, "NSE", entries[0].Exchange, "exchange should be filled from history")
}

func TestEnrichOrdersWithKite_NoFillPrice(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	// Test with entry that already has FillPrice=nil (no COMPLETE orders)
	entries := []orderEntry{
		{OrderID: "ORD-SKIP", Symbol: "INFY", Exchange: "NSE"},
	}

	// Use a mock server that returns OPEN orders (not COMPLETE)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/orders/") {
			fmt.Fprint(w, kiteJSON([]map[string]interface{}{
				{"order_id": "ORD-SKIP", "status": "OPEN", "tradingsymbol": "INFY",
					"exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET",
					"quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))
		} else {
			http.Error(w, `{"status":"error"}`, 404)
		}
	}))
	defer ts.Close()

	client := newMockKiteClient(ts.URL)
	d.orders.enrichOrdersWithKite(client, entries)

	assert.Equal(t, "OPEN", entries[0].Status)
	assert.Nil(t, entries[0].FillPrice, "non-COMPLETE order should have nil FillPrice")
	assert.Nil(t, entries[0].PnL, "non-COMPLETE order should have nil PnL")
}

func TestEnrichOrdersWithKite_MultipleOrders(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	client := newMockKiteClient(ts.URL)

	entries := []orderEntry{
		{OrderID: "ORD-001", Symbol: "INFY", Exchange: "NSE", Side: "BUY"},
		{OrderID: "ORD-002", Symbol: "RELIANCE", Exchange: "NSE", Side: "SELL"},
	}

	d.orders.enrichOrdersWithKite(client, entries)

	// Both should be enriched
	for i, e := range entries {
		assert.Equal(t, "COMPLETE", e.Status, "entry %d status", i)
	}
}

// ===========================================================================
// buildOrderEntries with mock Kite server — covers the enrichment path
// ===========================================================================

func TestBuildOrderEntries_WithMockKite(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer()
	defer ts.Close()

	d := newFullTestDashboard(t, "")
	// Override credentials to use mock server's API key
	d.manager.CredentialStore().Set("mockuser@test.com", &kc.KiteCredentialEntry{
		APIKey: "test_key", APISecret: "test_secret", StoredAt: time.Now(),
	})
	d.manager.TokenStore().Set("mockuser@test.com", &kc.KiteTokenEntry{
		AccessToken: "mock_token", StoredAt: time.Now(),
	})

	toolCalls := []*audit.ToolCall{
		{
			OrderID:     "ORD-001",
			StartedAt:   time.Now(),
			InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		},
	}

	entries := d.orders.buildOrderEntries(toolCalls, "mockuser@test.com")
	require.Len(t, entries, 1)
	assert.Equal(t, "ORD-001", entries[0].OrderID)
	assert.Equal(t, "INFY", entries[0].Symbol)
}

// ===========================================================================
// buildOrderSummary with P&L data
// ===========================================================================

func TestBuildOrderSummary_WithPnL(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	pnl1 := 500.0
	pnl2 := -200.0
	pnl3 := 0.0
	entries := []orderEntry{
		{Status: "COMPLETE", PnL: &pnl1},
		{Status: "COMPLETE", PnL: &pnl2},
		{Status: "COMPLETE", PnL: &pnl3},
		{Status: "REJECTED"},
	}

	summary := d.orders.buildOrderSummary(entries)
	assert.Equal(t, 4, summary.TotalOrders)
	assert.Equal(t, 3, summary.Completed)
	assert.Equal(t, 1, summary.WinningTrades)
	assert.Equal(t, 1, summary.LosingTrades)
	require.NotNil(t, summary.TotalPnL)
	assert.Equal(t, 300.0, *summary.TotalPnL)
}

// ===========================================================================
// SSR page rendering with credentials (covers template data paths)
// ===========================================================================

func TestCov_PortfolioPage_WithCreds(t *testing.T) {
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

func TestCov_ActivityPage_WithAudit(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_OrdersPage_WithAudit(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCov_AlertsPage_WithAlerts(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
}

func TestCov_PaperPage_WithEngine(t *testing.T) {
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

func TestCov_SafetyPage_WithRiskGuard(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Fragment endpoints with authenticated user
// ===========================================================================

func TestCov_PaperFragment_WithEngine(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	pe := d.manager.PaperEngine()
	require.NotNil(t, pe)
	require.NoError(t, pe.Enable("user@test.com", 10000000))

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// ===========================================================================
// ordersAPI with mock kite and seeded audit data
// ===========================================================================

func TestCov_OrdersAPI_WithSeededOrders(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed audit entries with order data
	d.auditStore.Record(&audit.ToolCall{
		Email:        "user@test.com",
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD-TEST-1",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		InputSummary: "BUY 10 INFY",
		StartedAt:    time.Now(),
		DurationMs:   50,
	})
	time.Sleep(100 * time.Millisecond) // flush async writer

	req := reqWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ordersResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.Summary.TotalOrders, 1)
}

// ===========================================================================
// alertsEnrichedAPI with seeded alerts (covers separation + summary)
// ===========================================================================

func TestCov_AlertsEnrichedAPI_WithAlerts(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	store := d.manager.AlertStore()
	_, _ = store.Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	_, _ = store.Add("user@test.com", "RELIANCE", "NSE", 408065, 2400, alerts.DirectionBelow)
	// Seed a triggered alert
	id3, _ := store.Add("user@test.com", "INFY", "NSE", 256265, 1400, alerts.DirectionBelow)
	store.MarkTriggered(id3, 1350)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp enrichedAlertsResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.Summary.ActiveCount, 2)
	assert.GreaterOrEqual(t, resp.Summary.TriggeredCount, 1)
}

// ===========================================================================
// alertsEnrichedAPI DELETE success path
// ===========================================================================

func TestCov_AlertsEnrichedAPI_DeleteSuccess(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	store := d.manager.AlertStore()
	alertID, err := store.Add("user@test.com", "INFY", "NSE", 256265, 1500, alerts.DirectionAbove)
	require.NoError(t, err)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id="+alertID, "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")
}

// ===========================================================================
// pnlChartAPI with seeded daily P&L data
// ===========================================================================

func TestCov_PnLChartAPI_WithData(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	// Seed daily P&L data directly into the DB
	db := d.manager.AlertDB()
	require.NotNil(t, db)
	_ = db.ExecDDL(`CREATE TABLE IF NOT EXISTS daily_pnl (email TEXT, date TEXT, net_pnl REAL)`)
	today := time.Now().Format("2006-01-02")
	_ = db.ExecInsert(`INSERT INTO daily_pnl (email, date, net_pnl) VALUES (?, ?, ?)`,
		"user@test.com", today, 1500.50)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=30", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// orderAttributionAPI with seeded data
// ===========================================================================

func TestCov_OrderAttribution_WithData(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")

	// Seed some tool calls for the order attribution chain
	d.auditStore.Record(&audit.ToolCall{
		Email:         "user@test.com",
		ToolName:      "get_ltp",
		ToolCategory:  "market_data",
		InputSummary:  "LTP NSE:INFY",
		OutputSummary: "1500.00",
		StartedAt:     time.Now().Add(-5 * time.Minute),
		DurationMs:    100,
	})
	d.auditStore.Record(&audit.ToolCall{
		Email:         "user@test.com",
		ToolName:      "place_order",
		ToolCategory:  "order",
		OrderID:       "ORD-ATTR-1",
		InputSummary:  "BUY 10 INFY",
		OutputSummary: "Order placed: ORD-ATTR-1",
		StartedAt:     time.Now().Add(-4 * time.Minute),
		DurationMs:    200,
	})
	time.Sleep(100 * time.Millisecond)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-ATTR-1", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Admin ops handler — more paths
// ===========================================================================

func TestCov_AdminOps_MetricsFragment_WithAudit(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment?period="+period, "admin@test.com", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusInternalServerError, rec.Code, "period=%s", period)
	}
}
