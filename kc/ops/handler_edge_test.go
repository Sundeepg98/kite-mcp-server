package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"context"
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
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.

func newPush100OpsHandler(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

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
	// Pass nil userStore to test nil-guard branches
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), nil, nil)
	return h
}


// newPush100OpsHandlerFull creates an ops handler with user store, audit store, and riskguard.
func newPush100OpsHandlerFull(t *testing.T) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

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
	auditStore.SetLoggerPort(logport.NewSlog(logger))
	_ = auditStore.InitTable()

	lb := NewLogBuffer(100)
	h := New(mgr, nil, lb, logger, "test-v1", time.Now(), userStore, auditStore)
	return h
}


func push100AdminReq(method, target string, body string) *http.Request {
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


// ===========================================================================
// DashboardHandler helpers for push100 tests
// ===========================================================================

// newPush100Dashboard creates a DashboardHandler with audit store for API tests.
func newPush100Dashboard(t *testing.T) (*DashboardHandler, *kc.Manager) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_api_key", "test_api_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	auditStore := audit.New(mgr.AlertDB())
	auditStore.SetLoggerPort(logport.NewSlog(logger))
	_ = auditStore.InitTable()

	d := NewDashboardHandler(mgr, logger, auditStore)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d, mgr
}


func push100DashReq(method, target, email string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if email != "" {
		req = req.WithContext(oauth.ContextWithEmail(req.Context(), email))
	}
	return req
}


func push100DashReqBody(method, target, email, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if email != "" {
		req = req.WithContext(oauth.ContextWithEmail(req.Context(), email))
	}
	return req
}


// ===========================================================================
// data.go: buildOverview â€” admin sees global counts
// ===========================================================================
func TestPush100_BuildOverview_Admin(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Seed alerts
	_, _ = h.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 256265, 1600, alerts.DirectionAbove)

	overview := h.buildOverview()
	assert.Equal(t, "test-v1", overview.Version)
	assert.GreaterOrEqual(t, overview.TotalAlerts, 1)
}


// ===========================================================================
// data.go: buildSessions â€” with real sessions containing KiteSessionData
// ===========================================================================
func TestPush100_BuildSessions_WithData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	// Create sessions with KiteSessionData
	sm := h.manager.SessionManager()
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "user1@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "user2@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: ""}) // orphan session â€” should be skipped

	sessions := h.buildSessions()
	assert.Equal(t, 2, len(sessions))
	emails := map[string]bool{}
	for _, s := range sessions {
		emails[s.Email] = true
	}
	assert.True(t, emails["user1@test.com"])
	assert.True(t, emails["user2@test.com"])
}


func TestPush100_BuildSessionsForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	sm := h.manager.SessionManager()
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "target@test.com"})
	_ = sm.GenerateWithData(&kc.KiteSessionData{Email: "other@test.com"})

	sessions := h.buildSessionsForUser("target@test.com")
	assert.Equal(t, 1, len(sessions))
	assert.Equal(t, "target@test.com", sessions[0].Email)
}


func TestPush100_BuildTickersForUser(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	tickers := h.buildTickersForUser("user@test.com")
	assert.Equal(t, 0, len(tickers.Tickers))
}
