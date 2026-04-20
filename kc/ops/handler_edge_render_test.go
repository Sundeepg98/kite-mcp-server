package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"context"
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
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// dashboard_templates.go: servePageFallback
// ---------------------------------------------------------------------------
func TestPush100_ServePageFallback(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "dashboard.html")
	// Should serve the static HTML file from templates.FS
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
}


func TestPush100_ServePageFallback_NonExistent(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "nonexistent.html")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard.go: serveBillingPage with Pro tier + Stripe
// ---------------------------------------------------------------------------
func TestPush100_ServeBillingPage_ProTierWithStripe(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return false })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:             billing.TierPro,
				Status:           "active",
				MaxUsers:         1,
				StripeCustomerID: "cus_12345",
			},
		},
	})
	d.InitTemplates() // ensure routes are available

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Pro")
	assert.Contains(t, body, "Stripe")
}


func TestPush100_ServeBillingPage_PremiumTierAdmin(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"admin@test.com": {
				Tier:     billing.TierPremium,
				Status:   "active",
				MaxUsers: 5,
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Premium")
	assert.Contains(t, body, "5 family member")
}


func TestPush100_ServeBillingPage_PastDueStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:   billing.TierPro,
				Status: "past_due",
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Past Due")
}


func TestPush100_ServeBillingPage_CanceledStatus(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				Tier:   billing.TierPro,
				Status: "canceled",
			},
		},
	})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Canceled")
}


func TestPush100_ServeBillingPage_FreeDefaultActive(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Free Plan")
	assert.Contains(t, body, "All tools are currently available for free")
}


// ---------------------------------------------------------------------------
// dashboard.go: serveBillingPage with family member (inherited tier)
// ---------------------------------------------------------------------------
func TestPush100_ServeBillingPage_FamilyMember(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"admin@test.com": {
				Tier:     billing.TierPro,
				Status:   "active",
				MaxUsers: 5,
			},
		},
	})

	// Set up user as family member of admin
	if us := d.manager.UserStore(); us != nil {
		us.EnsureUser("member@test.com", "", "", "")
		_ = us.SetAdminEmail("member@test.com", "admin@test.com")
	}

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "member@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard.go: tierDisplayName
// ---------------------------------------------------------------------------
func TestPush100_TierDisplayName_AllTiers(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Free", tierDisplayName(billing.TierFree))
	assert.Equal(t, "Pro", tierDisplayName(billing.TierPro))
	assert.Equal(t, "Premium", tierDisplayName(billing.TierPremium))
	assert.Equal(t, "Free", tierDisplayName(billing.Tier(99))) // unknown
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: serveSafetyPageSSR with riskguard
// ---------------------------------------------------------------------------
func TestPush100_ServeSafetyPageSSR_WithRiskGuard(t *testing.T) {
	t.Parallel()
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

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/safety", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: servePaperPageSSR with engine enabled
// ---------------------------------------------------------------------------
func TestPush100_ServePaperPageSSR_WithEngine(t *testing.T) {
	t.Parallel()
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

	// Enable paper trading
	paperStore := papertrading.NewStore(mgr.AlertDB(), logger)
	pe := papertrading.NewEngine(paperStore, logger)
	mgr.SetPaperEngine(pe)
	_ = pe.Enable("user@test.com", 10000000)

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/paper", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: serveAlertsPageSSR with alerts
// ---------------------------------------------------------------------------
func TestPush100_ServeAlertsPageSSR_WithAlerts(t *testing.T) {
	t.Parallel()
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

	// Add an alert
	_, _ = mgr.AlertStore().Add("user@test.com", "RELIANCE", "NSE", 0, 2500, alerts.DirectionAbove)

	d := NewDashboardHandler(mgr, logger, nil)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/alerts", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_ServeAlertsPageSSR_NoEmail(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/alerts", nil)
	// No email in context
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: serveOrdersPageSSR with audit data
// ---------------------------------------------------------------------------
func TestPush100_ServeOrdersPageSSR_WithAuditData(t *testing.T) {
	t.Parallel()
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
	auditStore.SetLogger(logger)
	_ = auditStore.InitTable()

	d := NewDashboardHandler(mgr, logger, auditStore)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/orders", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: serveOrdersPageSSR with no audit store
// ---------------------------------------------------------------------------
func TestPush100_ServeOrdersPageSSR_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/orders", nil)
	req = req.WithContext(oauth.ContextWithEmail(req.Context(), "user@test.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}


// ---------------------------------------------------------------------------
// handler.go: servePage (full ops page render with all data)
// ---------------------------------------------------------------------------
func TestPush100_ServePage_WithFullData(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := push100AdminReq(http.MethodGet, "/admin/ops", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should render the full ops page
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
}


// ---------------------------------------------------------------------------
// user_render.go: userDashboardFragmentTemplates and renderUserFragment
// ---------------------------------------------------------------------------
func TestPush100_UserDashboardFragmentTemplates(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}


func TestPush100_RenderUserFragment_OrdersTable(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	require.NoError(t, err)

	data := OrdersTableData{
		Orders: []OrderRow{
			{
				Symbol: "RELIANCE", Side: "BUY", SideClass: "side-buy",
				QuantityFmt: "100", FillPriceFmt: "2500.00",
				Status: "COMPLETE", StatusBadge: "status-complete",
			},
		},
	}
	result, err := renderUserFragment(tmpl, "user_orders_table", data)
	assert.NoError(t, err)
	assert.Contains(t, result, "RELIANCE")
}


func TestPush100_RenderUserFragment_AlertsActive(t *testing.T) {
	t.Parallel()
	tmpl, err := userDashboardFragmentTemplates()
	require.NoError(t, err)

	data := AlertsActiveData{
		Alerts: []ActiveAlertRow{
			{
				Tradingsymbol: "TCS", Direction: "above",
				DirBadge: "green", TargetFmt: "3500.00",
			},
		},
	}
	result, err := renderUserFragment(tmpl, "user_alerts_active", data)
	assert.NoError(t, err)
	assert.Contains(t, result, "TCS")
}


// ===========================================================================
// handler.go: overviewStream — cancel context
// ===========================================================================
func TestPush100_OverviewStream_Cancel(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/overview-stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		mux.ServeHTTP(rec, req)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	// Should have sent at least one event
	body := rec.Body.String()
	assert.Contains(t, body, "event:")
}


// ===========================================================================
// dashboard.go: RegisterRoutes — static file serving and billing no-store branch
// ===========================================================================
func TestPush100_StaticCSS(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard-base.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}


func TestPush100_StaticHTMX(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
}


// ===========================================================================
// dashboard_templates.go: serveActivityPageSSR — with audit data
// ===========================================================================
func TestPush100_ServeActivityPageSSR_WithData(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	_ = d.auditStore.Record(&audit.ToolCall{
		CallID:       "act1",
		Email:        "user@test.com",
		ToolName:     "get_holdings",
		ToolCategory: "portfolio",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now(),
	})

	req := push100DashReq(http.MethodGet, "/dashboard/activity", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: serveAlertsPageSSR — with triggered alerts
// ===========================================================================
func TestPush100_ServeAlertsPageSSR_WithTriggered(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	alertID, _ := mgr.AlertStore().Add("user@test.com", "TCS", "NSE", 0, 3500, alerts.DirectionAbove)
	_ = mgr.AlertStore().MarkTriggered(alertID, 3550)

	req := push100DashReq(http.MethodGet, "/dashboard/alerts", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePortfolioPage — no email redirect
// ===========================================================================
func TestPush100_ServePortfolioPage_NoEmail(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard", "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Renders a page even with empty email (status card data will be empty)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePaperFragment — various branches
// ===========================================================================
func TestPush100_ServePaperFragment_NoEngine(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// dashboard_templates.go: servePortfolioFragment — without creds
// ===========================================================================
func TestPush100_ServePortfolioFragment_NoCreds(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := push100DashReq(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


func TestPush100_ServeSafetyFragment(t *testing.T) {
	t.Parallel()
	d, mgr := newPush100Dashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	mgr.SetRiskGuard(riskguard.NewGuard(slog.Default()))

	req := push100DashReq(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
