package app

// app_coverage_test.go — targeted tests to boost coverage from ~78% to 90%+.
// Focuses on uncovered branches in: setupGracefulShutdown, initializeServices,
// initScheduler, paperLTPAdapter.GetLTP, setupMux, registerTelegramWebhook,
// RunServer, ExchangeWithCredentials, makeEventPersister, serveStatusPage,
// serveLegalPages, newRateLimiters, and startHybridServer/startStdIOServer.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// setupGracefulShutdown — exercise the inner goroutine's shutdown paths
// ===========================================================================

// TestSetupGracefulShutdown_WithAllComponents exercises the shutdown goroutine
// body by using context.WithCancel and manually triggering the cancel — which
// won't work directly since the function uses signal.NotifyContext.
// Instead, we test that the function sets up without panicking when the app
// has scheduler, auditStore, telegramBot, oauthHandler, and rateLimiters set.

func TestSetupGracefulShutdown_WithAllComponents(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	t.Cleanup(mgr.Shutdown)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := newTestApp(t)
	t.Cleanup(app.metrics.Shutdown)
	// Use shutdownCh so the spawned goroutine exits when the test ends;
	// otherwise it blocks on signal.NotifyContext forever and leaks for
	// the whole package run.
	app.shutdownCh = make(chan struct{})
	t.Cleanup(func() { close(app.shutdownCh) })

	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())
	app.auditStore.StartWorker()
	app.rateLimiters = newRateLimiters()

	// Set up OAuth handler so the oauthHandler close path is wired
	oauthCfg := &oauth.Config{
		JWTSecret:   "test-jwt-secret-at-least-32-chars-long!!",
		ExternalURL: "https://test.example.com",
		Logger:      testLogger(),
	}
	_ = oauthCfg.Validate()
	signer := &signerAdapter{signer: mgr.SessionSigner()}
	exchanger := &kiteExchangerAdapter{
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
	}
	app.oauthHandler = oauth.NewHandler(oauthCfg, signer, exchanger)
	t.Cleanup(app.oauthHandler.Close)

	listener, listErr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, listErr)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}

	// Wires the shutdown goroutine; close(app.shutdownCh) in t.Cleanup
	// triggers the graceful path so the goroutine exits before the test
	// completes.
	app.setupGracefulShutdown(srv, mgr)
}


// TestSetupGracefulShutdown_NilOptionalFields tests that shutdown doesn't panic
// when optional fields (scheduler, auditStore, telegramBot, oauthHandler, rateLimiters)
// are all nil.
func TestSetupGracefulShutdown_NilOptionalFields(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	t.Cleanup(mgr.Shutdown)

	app := newTestApp(t)
	t.Cleanup(app.metrics.Shutdown)
	// Ensure all optional fields are nil
	app.scheduler = nil
	app.auditStore = nil
	app.telegramBot = nil
	app.oauthHandler = nil
	app.rateLimiters = nil
	// Let the shutdown goroutine exit cleanly when the test ends.
	app.shutdownCh = make(chan struct{})
	t.Cleanup(func() { close(app.shutdownCh) })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	app.setupGracefulShutdown(srv, mgr)
}


// ===========================================================================
// paperLTPAdapter.GetLTP — test with non-nil but invalid session data
// ===========================================================================
func TestPaperLTPAdapter_SessionWithNonKiteData(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	sess := mgr.SessionManager()
	// Generate a session with non-KiteSessionData (a string)
	_ = sess.GenerateWithData("not a KiteSessionData")

	adapter := &paperLTPAdapter{manager: mgr}
	_, err := adapter.GetLTP("NSE:RELIANCE")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Kite client available")
}


func TestPaperLTPAdapter_SessionWithEmptyKiteData(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	sess := mgr.SessionManager()
	// Generate a session with KiteSessionData where Kite is nil
	_ = sess.GenerateWithData(&kc.KiteSessionData{})

	adapter := &paperLTPAdapter{manager: mgr}
	_, err := adapter.GetLTP("NSE:RELIANCE")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Kite client available")
}


// ===========================================================================
// provisionUser — suspended and offboarded paths
// ===========================================================================

// provisionUser suspended/offboarded tests are in app_test.go, no duplicates here.

// ===========================================================================
// makeEventPersister — successful append with payload verification
// ===========================================================================
func TestMakeEventPersister_OrderModifiedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Order", testLogger())

	event := domain.OrderModifiedEvent{
		OrderID:   "ORD-MOD-1",
		Email:     "trader@test.com",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "ORD-MOD-1", events[0].AggregateID)
	assert.Equal(t, "Order", events[0].AggregateType)
}


func TestMakeEventPersister_OrderCancelledEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Order", testLogger())

	event := domain.OrderCancelledEvent{
		OrderID:   "ORD-CAN-1",
		Email:     "trader@test.com",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "ORD-CAN-1", events[0].AggregateID)
}


func TestMakeEventPersister_PositionClosedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Position", testLogger())

	event := domain.PositionClosedEvent{
		OrderID:    "POS-CLS-1",
		Email:      "trader@test.com",
		Instrument: domain.NewInstrumentKey("NSE", "HDFC"),
		Product:    "CNC",
		Timestamp:  time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	// Positions use a natural aggregate key — (email, exchange, symbol, product) —
	// not the closing order ID, so the open and close events join on the same key.
	assert.Equal(t, "trader@test.com:NSE:HDFC:CNC", events[0].AggregateID)
	assert.Equal(t, "Position", events[0].AggregateType)
}


func TestMakeEventPersister_AlertTriggeredEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Alert", testLogger())

	event := domain.AlertTriggeredEvent{
		AlertID:   "ALERT-1",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "ALERT-1", events[0].AggregateID)
	assert.Equal(t, "Alert", events[0].AggregateType)
}


func TestMakeEventPersister_GlobalFreezeEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Global", testLogger())

	event := domain.GlobalFreezeEvent{
		By:        "admin@test.com",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "admin@test.com", events[0].AggregateID)
	assert.Equal(t, "Global", events[0].AggregateType)
}


func TestMakeEventPersister_FamilyInvitedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Family", testLogger())

	event := domain.FamilyInvitedEvent{
		AdminEmail: "admin@test.com",
		Timestamp:  time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "admin@test.com", events[0].AggregateID)
	assert.Equal(t, "Family", events[0].AggregateType)
}


func TestMakeEventPersister_RiskLimitBreachedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "RiskGuard", testLogger())

	event := domain.RiskLimitBreachedEvent{
		Email:     "trader@test.com",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "trader@test.com", events[0].AggregateID)
	assert.Equal(t, "RiskGuard", events[0].AggregateType)
}


func TestMakeEventPersister_SessionCreatedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "Session", testLogger())

	event := domain.SessionCreatedEvent{
		SessionID: "sess-xyz",
		Timestamp: time.Now().UTC(),
	}
	persister(event)

	events, err := store.LoadEventsSince(time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(events))
	assert.Equal(t, "sess-xyz", events[0].AggregateID)
	assert.Equal(t, "Session", events[0].AggregateType)
}


// ===========================================================================
// newRateLimiters — exercise cleanup goroutine by triggering Stop
// ===========================================================================
func TestNewRateLimiters_CleanupAndStop(t *testing.T) {
	rl := newRateLimiters()
	require.NotNil(t, rl)

	// Use the limiters to populate them
	rl.auth.getLimiter("1.1.1.1")
	rl.token.getLimiter("2.2.2.2")
	rl.mcp.getLimiter("3.3.3.3")

	// Manually trigger cleanup
	rl.auth.cleanup()
	rl.token.cleanup()
	rl.mcp.cleanup()

	rl.auth.mu.RLock()
	assert.Equal(t, 0, len(rl.auth.limiters))
	rl.auth.mu.RUnlock()

	rl.Stop()
}


// ===========================================================================
// getLimiter — race condition: double-check after write lock
// ===========================================================================
func TestGetLimiter_DoubleCheckAfterWriteLock(t *testing.T) {
	limiter := newIPRateLimiter(10, 20)

	// First call creates the limiter
	l1 := limiter.getLimiter("10.0.0.1")
	require.NotNil(t, l1)

	// Second call should return the same limiter (fast path via read lock)
	l2 := limiter.getLimiter("10.0.0.1")
	assert.Equal(t, l1, l2, "same limiter should be returned for same IP")
}


// ===========================================================================
// securityHeaders middleware
// ===========================================================================
func TestSecurityHeaders_Cov(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeaders(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "max-age=63072000")
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'self'")
	assert.Contains(t, rec.Header().Get("Permissions-Policy"), "camera=()")
}


// ===========================================================================
// configureAndStartServer — smoke test
// ===========================================================================
func TestConfigureAndStartServer_SetsHandler(t *testing.T) {
	app := newTestApp(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr}
	go app.configureAndStartServer(srv, mux)
	waitForServerReady(t, addr)

	resp, httpErr := http.Get("http://" + addr + "/test")
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		// Verify security headers were added
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}


// buildHealthzReport is the unit-testable core of handleHealthz. Exercising it
// directly (bypassing the mux + HTTP layer) keeps the latency-sensitive path
// small and makes edge cases easy to cover.
func TestBuildHealthzReport_AuditDropping(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	// Create the store WITHOUT InitTable — Record() will fail because the
	// tool_calls table doesn't exist. Without StartWorker the sync-fallback
	// path runs, which increments droppedCount when Record fails.
	auditStore := audit.New(db)
	auditStore.Enqueue(&audit.ToolCall{CallID: "dropped-test", ToolName: "x"})
	require.Greater(t, auditStore.DroppedCount(), int64(0),
		"test setup: expected Enqueue without a table to drop the entry")

	app := newTestApp(t)
	app.auditStore = auditStore
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	report := app.buildHealthzReport()

	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, "dropping", report.Components["audit"].Status)
	assert.Greater(t, report.Components["audit"].DroppedCount, int64(0))
	assert.NotEmpty(t, report.Components["audit"].Note)
}


func TestBuildHealthzReport_RiskGuardNil(t *testing.T) {
	app := newTestApp(t)
	app.auditStore = nil // already "disabled"
	app.riskGuard = nil  // never wired — should report defaults-only
	app.riskLimitsLoaded = true

	report := app.buildHealthzReport()

	assert.Equal(t, "degraded", report.Status)
	assert.Equal(t, "defaults-only", report.Components["riskguard"].Status)
	assert.NotEmpty(t, report.Components["riskguard"].Note)
	assert.Equal(t, "disabled", report.Components["audit"].Status)
}


// TestBuildHealthzReport_AnomalyCachePresent verifies the anomaly_cache
// component is surfaced in the rich report when the audit store is wired.
// Fresh store has no traffic (hit rate 0), which is treated as "ok" so we
// don't fire a false alarm during cold start right after a deploy.
func TestBuildHealthzReport_AnomalyCachePresent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())

	app := newTestApp(t)
	app.auditStore = auditStore
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	report := app.buildHealthzReport()

	cache, ok := report.Components["anomaly_cache"]
	require.True(t, ok, "anomaly_cache component must be present when auditStore is wired")
	assert.Equal(t, "ok", cache.Status,
		"fresh cache with no traffic should report ok (cold-start safe)")
	require.NotNil(t, cache.MaxEntries, "MaxEntries must be populated")
	assert.Equal(t, int64(audit.DefaultMaxStatsCacheEntries), *cache.MaxEntries,
		"MaxEntries should mirror the audit package default")
	// Fresh cache: no hits or misses yet, hit rate is zero.
	require.NotNil(t, cache.HitRate, "HitRate must be populated even when zero")
	assert.InDelta(t, 0.0, *cache.HitRate, 0.0001)
	// Top-level status is still ok — anomaly cache "ok" on cold start
	// does not degrade the overall report.
	assert.Equal(t, "ok", report.Status)
}


// TestBuildHealthzReport_AnomalyCacheOmittedWhenAuditNil verifies the
// anomaly_cache component is omitted (not surfaced as "disabled") when the
// audit store is nil. The audit component already reports "disabled" in
// that case — surfacing anomaly_cache separately would be noise.
func TestBuildHealthzReport_AnomalyCacheOmittedWhenAuditNil(t *testing.T) {
	app := newTestApp(t)
	app.auditStore = nil
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	report := app.buildHealthzReport()

	_, ok := report.Components["anomaly_cache"]
	assert.False(t, ok, "anomaly_cache must be omitted when auditStore is nil")
	// Audit itself is still surfaced as disabled.
	assert.Equal(t, "disabled", report.Components["audit"].Status)
}


// ===========================================================================
// initStatusPageTemplate — verify all three templates are set
// ===========================================================================
func TestInitStatusPageTemplate_AllTemplatesSet(t *testing.T) {
	app := newTestApp(t)
	err := app.initStatusPageTemplate()
	require.NoError(t, err)
	assert.NotNil(t, app.statusTemplate, "statusTemplate should be set")
	assert.NotNil(t, app.landingTemplate, "landingTemplate should be set")
	assert.NotNil(t, app.legalTemplate, "legalTemplate should be set")
}


// ===========================================================================
// buildServerURL
// ===========================================================================
func TestBuildServerURL_Cov(t *testing.T) {
	app := newTestApp(t)
	app.Config.AppHost = "0.0.0.0"
	app.Config.AppPort = "9090"
	assert.Equal(t, "0.0.0.0:9090", app.buildServerURL())
}


// ===========================================================================
// configureHTTPClient
// ===========================================================================
func TestConfigureHTTPClient_Cov(t *testing.T) {
	app := newTestApp(t)
	// Should not panic — just logs
	app.configureHTTPClient()
}


// ===========================================================================
// createHTTPServer
// ===========================================================================
func TestCreateHTTPServer_Cov(t *testing.T) {
	app := newTestApp(t)
	srv := app.createHTTPServer("127.0.0.1:8080")
	assert.Equal(t, "127.0.0.1:8080", srv.Addr)
	assert.Equal(t, 30*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 120*time.Second, srv.WriteTimeout)
}


// ===========================================================================
// getStatusData
// ===========================================================================
func TestGetStatusData_Cov(t *testing.T) {
	app := newTestApp(t)
	app.Version = "v1.5.0"
	app.Config.AppMode = ModeHybrid

	data := app.getStatusData()
	assert.Equal(t, "Status", data.Title)
	assert.Equal(t, "v1.5.0", data.Version)
	assert.Equal(t, ModeHybrid, data.Mode)
}


// ===========================================================================
// truncKey
// ===========================================================================
func TestTruncKey_Short(t *testing.T) {
	assert.Equal(t, "abc", truncKey("abc", 10))
}


func TestTruncKey_Exact_Cov(t *testing.T) {
	assert.Equal(t, "abcdef", truncKey("abcdef", 6))
}


func TestTruncKey_Long_Cov(t *testing.T) {
	assert.Equal(t, "abcde", truncKey("abcdefghij", 5))
}


// ===========================================================================
// LoadConfig — OAuth + ExternalURL requirement
// ===========================================================================
func TestLoadConfig_OAuthRequiresExternalURL(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test-key")
	t.Setenv("KITE_API_SECRET", "test-secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "")

	app := newTestApp(t)
	err := app.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EXTERNAL_URL is required")
}


// ===========================================================================
// LoadConfig — OAuth with ExternalURL succeeds
// ===========================================================================
func TestLoadConfig_OAuthWithExternalURL_Cov(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test-key")
	t.Setenv("KITE_API_SECRET", "test-secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := newTestApp(t)
	err := app.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "test-jwt-secret-at-least-32-chars-long!!", app.Config.OAuthJWTSecret)
	assert.Equal(t, "https://test.example.com", app.Config.ExternalURL)
}


// ===========================================================================
// LoadConfig — no credentials but with OAuth secret (zero-config mode)
// ===========================================================================
func TestLoadConfig_NoCredsWithOAuthSecret(t *testing.T) {
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := newTestApp(t)
	err := app.LoadConfig()
	require.NoError(t, err)
}


// ===========================================================================
// withSessionType — verify it wraps correctly
// ===========================================================================
func TestWithSessionType_Wraps(t *testing.T) {
	called := false
	inner := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}

	handler := withSessionType("mcp", inner)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// rateLimitFunc — convenience wrapper test
// ===========================================================================
func TestRateLimitFunc_Convenience(t *testing.T) {
	limiter := newIPRateLimiter(100, 100)
	handler := rateLimitFunc(limiter, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}


// ===========================================================================
// SetLogBuffer
// ===========================================================================
func TestSetLogBuffer_Cov(t *testing.T) {
	app := newTestApp(t)
	assert.Nil(t, app.logBuffer)
	// SetLogBuffer is a simple setter — just verify it doesn't panic
	app.SetLogBuffer(nil)
}


// ===========================================================================
// registryAdapter — exercising additional branches (main funcs tested in app_test.go)
// ===========================================================================

// ===========================================================================
// telegramManagerAdapter — covers adapter pass-through methods
// ===========================================================================
func TestTelegramManagerAdapter_AllMethods(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	adapter := &telegramManagerAdapter{m: mgr}

	// All adapter methods should not panic and should return the same
	// values as the underlying manager methods.
	// Some may be nil depending on config, we just verify no panics.
	_ = adapter.TelegramStore()
	_ = adapter.TelegramNotifier()
	_ = adapter.AlertStoreConcrete()
	_ = adapter.WatchlistStoreConcrete()
	assert.NotNil(t, adapter.InstrumentsManagerConcrete())
	_ = adapter.GetAPIKeyForEmail("nobody@test.com")
	_ = adapter.GetAccessTokenForEmail("nobody@test.com")
	assert.False(t, adapter.IsTokenValid("nobody@test.com"))
	_ = adapter.RiskGuard()
	_ = adapter.PaperEngineConcrete()
	_ = adapter.TickerServiceConcrete()
}


// ===========================================================================
// GetLTP — paper LTP adapter with valid session
// ===========================================================================
func TestPaperLTPAdapter_NoActiveSessions_Cov(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	adapter := &paperLTPAdapter{manager: mgr}
	_, err := adapter.GetLTP("NSE:INFY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active Kite sessions")
}


// ===========================================================================
// makeEventPersister — UserFrozenEvent and UserSuspendedEvent
// ===========================================================================
func TestMakeEventPersister_UserFrozenEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "User", testLogger())
	persister(domain.UserFrozenEvent{
		Email:     "frozen@test.com",
		FrozenBy:  "riskguard",
		Reason:    "circuit breaker",
		Timestamp: time.Now(),
	})

	events, err := store.LoadEvents("frozen@test.com")
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "user.frozen", events[0].EventType)
}


func TestMakeEventPersister_UserSuspendedEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "User", testLogger())
	persister(domain.UserSuspendedEvent{
		Email:     "suspended@test.com",
		Reason:    "terms violation",
		Timestamp: time.Now(),
	})

	events, err := store.LoadEvents("suspended@test.com")
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "user.suspended", events[0].EventType)
}


// ===========================================================================
// deriveAggregateID — unknown event type returns "unknown"
// ===========================================================================

type unknownTestEvent struct{}

func (unknownTestEvent) EventType() string      { return "test.unknown" }
func (unknownTestEvent) OccurredAt() time.Time  { return time.Now() }
func TestDeriveAggregateID_UnknownEvent(t *testing.T) {
	result := deriveAggregateID(unknownTestEvent{})
	assert.Equal(t, "unknown", result)
}


// ===========================================================================
// setupMux — SSE endpoints with and without OAuth
// ===========================================================================

// SSE endpoint registration is tested through TestRunServer_SSEMode_Cov
// (SSE endpoints are registered in startServer/startHybridServer, not setupMux)

// ===========================================================================
// instrumentsFreezeAdapter
// ===========================================================================
func TestInstrumentsFreezeAdapter_NotFound_Cov(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	_, ok := adapter.GetFreezeQuantity("NSE", "NONEXISTENT")
	assert.False(t, ok)
}


func TestInstrumentsFreezeAdapter_WithFreezeQty(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger: testLogger(),
		TestData: map[uint32]*instruments.Instrument{
			256265: {
				ID:              "NSE:INFY",
				InstrumentToken: 256265,
				Tradingsymbol:   "INFY",
				Exchange:        "NSE",
				FreezeQuantity:  5000,
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	qty, ok := adapter.GetFreezeQuantity("NSE", "INFY")
	assert.True(t, ok)
	assert.Equal(t, uint32(5000), qty)
}


// ===========================================================================
// GetCredentials — fallback to global credentials
// ===========================================================================
func TestGetCredentials_GlobalFallback_Cov(t *testing.T) {
	exchanger := &kiteExchangerAdapter{
		apiKey:          "global_key",
		apiSecret:       "global_secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
	}

	key, secret, ok := exchanger.GetCredentials("unknown@test.com")
	assert.True(t, ok)
	assert.Equal(t, "global_key", key)
	assert.Equal(t, "global_secret", secret)
}


func TestGetCredentials_NoCreds_Cov(t *testing.T) {
	exchanger := &kiteExchangerAdapter{
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
	}

	_, _, ok := exchanger.GetCredentials("unknown@test.com")
	assert.False(t, ok)
}


func TestGetCredentials_PerUserCredentials_Cov(t *testing.T) {
	exchanger := &kiteExchangerAdapter{
		apiKey:          "global_key",
		apiSecret:       "global_secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
	}
	exchanger.credentialStore.Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "user_key", APISecret: "user_secret",
	})

	key, secret, ok := exchanger.GetCredentials("user@test.com")
	assert.True(t, ok)
	assert.Equal(t, "user_key", key)
	assert.Equal(t, "user_secret", secret)
}


// ===========================================================================
// kiteExchangerAdapter.GetSecretByAPIKey
// ===========================================================================
func TestKiteExchangerAdapter_GetSecretByAPIKey(t *testing.T) {
	exchanger := &kiteExchangerAdapter{
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
	}

	// Store a credential
	exchanger.credentialStore.Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey: "user_key", APISecret: "user_secret",
	})

	secret, ok := exchanger.GetSecretByAPIKey("user_key")
	assert.True(t, ok)
	assert.Equal(t, "user_secret", secret)

	_, ok = exchanger.GetSecretByAPIKey("nonexistent_key")
	assert.False(t, ok)
}


// ===========================================================================
// configureAndStartServer — SSE mode
// ===========================================================================
func TestConfigureAndStartServer_WithSSE(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
	app.Config.AppMode = "sse"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln.Close()

	srv := &http.Server{Addr: ln.Addr().String()}

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	srv.Handler = mux

	// Just test that configureAndStartServer doesn't panic
	go func() {
		app.configureAndStartServer(srv, mux)
	}()
	waitForServerReady(t, srv.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
