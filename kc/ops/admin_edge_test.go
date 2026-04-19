package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
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


// strReaderPtr returns a *strings.Reader for use with requestWithEmail.
func strReaderPtr(s string) *strings.Reader {
	return strings.NewReader(s)
}


// ===========================================================================
// Tests merged from admin_coverage_test.go
// ===========================================================================

// newTestAdminOpsHandlerWithRiskGuard creates an ops Handler with audit store,
// user store, registry store, and riskguard enabled.
func newTestAdminOpsHandlerWithRiskGuard(t *testing.T) *Handler {
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

	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		userStore.EnsureAdmin("admin@test.com")
	}

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	// Seed some credentials and tokens for a regular user
	mgr.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "user_api_key", APISecret: "user_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set("user@test.com", &kc.KiteTokenEntry{
		AccessToken: "user_token", StoredAt: time.Now(),
	})

	lb := NewLogBuffer(100)
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), userStore, auditStore)
	return h
}


// adminReq creates an HTTP request with admin email context.
func adminReq(method, target string, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := oauth.ContextWithEmail(req.Context(), "admin@test.com")
	return req.WithContext(ctx)
}


// userReq creates an HTTP request with regular user email context.
func userReq(method, target string, body string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	ctx := oauth.ContextWithEmail(req.Context(), "user@test.com")
	return req.WithContext(ctx)
}

// Coverage ceiling: ~89% — ~60 unreachable lines, mostly behind Kite API calls.
// Categories: (1) Kite API enrichment paths (holdings, positions, OHLC, LTP),
// (2) SSE streaming with long-lived connections, (3) paper trading success paths
// requiring valid credentials, (4) writeJSONError encoding failure (unreachable).
