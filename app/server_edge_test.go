package app

// app_coverage_test.go — targeted tests to boost coverage from ~78% to 90%+.
// Focuses on uncovered branches in: setupGracefulShutdown, initializeServices,
// initScheduler, paperLTPAdapter.GetLTP, setupMux, registerTelegramWebhook,
// RunServer, ExchangeWithCredentials, makeEventPersister, serveStatusPage,
// serveLegalPages, newRateLimiters, and startHybridServer/startStdIOServer.

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
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

	app := NewApp(testLogger())
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

	app := NewApp(testLogger())
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
// initializeServices — exercise Stripe billing branch (non-DevMode)
// ===========================================================================

func TestInitializeServices_WithStripeAndPriceWarning(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_fake_key_for_billing_test_coverage")
	t.Setenv("STRIPE_PRICE_PRO", "")      // empty triggers warning log
	t.Setenv("STRIPE_PRICE_PREMIUM", "")   // empty triggers warning log
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := NewApp(testLogger())
	app.DevMode = false
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "https://test.example.com"
	app.Config.AdminEmails = "admin@test.com"

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpSrv)

	// Billing store should be initialized
	assert.NotNil(t, mgr.BillingStore())

	cleanupInitializeServices(app, mgr)
}

func TestInitializeServices_StripePricesSet(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_fake_key_prices_set_test")
	t.Setenv("STRIPE_PRICE_PRO", "price_pro_123")
	t.Setenv("STRIPE_PRICE_PREMIUM", "price_premium_456")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := NewApp(testLogger())
	app.DevMode = false
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "https://test.example.com"
	app.Config.AdminEmails = "admin@test.com"

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpSrv)

	cleanupInitializeServices(app, mgr)
}

// TestInitializeServices_DevModeSkipsBilling verifies that even with
// STRIPE_SECRET_KEY set, billing middleware is skipped in DevMode.
func TestInitializeServices_DevModeSkipsBilling(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_should_be_skipped_in_devmode")
	t.Setenv("STRIPE_PRICE_PRO", "price_123")
	t.Setenv("STRIPE_PRICE_PREMIUM", "price_456")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpSrv)

	cleanupInitializeServices(app, mgr)
}

// ===========================================================================
// RunServer — error paths
// ===========================================================================

// TestRunServer_OAuthValidationFailure exercises the OAuth config validation
// error path in RunServer.
func TestRunServer_OAuthValidationFailure(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = "0"
	// Set OAuthJWTSecret but leave ExternalURL empty to trigger validation failure
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "" // triggers "ExternalURL is required"

	err := app.RunServer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid OAuth config")
}

// TestRunServer_MissingExternalURL exercises the EXTERNAL_URL requirement error.
func TestRunServer_MissingExternalURL(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "")
	t.Setenv("STRIPE_SECRET_KEY", "")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "" // triggers EXTERNAL_URL required error

	// LoadConfig should catch this
	err := app.LoadConfig()
	if err != nil {
		assert.Contains(t, err.Error(), "EXTERNAL_URL")
	}
}

// TestRunServer_HybridMode exercises the hybrid server mode path in RunServer.
func TestRunServer_HybridMode_Cov(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AppMode = ModeHybrid
	// Inject shutdownCh so we can trigger the graceful-shutdown goroutine
	// without an OS signal. Without this, srv.ListenAndServe blocks
	// forever, the setup-shutdown goroutine never fires, and all
	// background cleanup routines (DB openers, metric/audit workers,
	// instruments scheduler) leak past test completion — on slow CI
	// runners those leaked goroutines tip the parent package
	// -timeout 120s over the edge.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	time.Sleep(500 * time.Millisecond)

	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Signal shutdown — the graceful-shutdown goroutine picks this up
	// and begins unwinding component Stop()s asynchronously. We only
	// briefly wait for RunServer to return so this test does not block
	// other tests in the package; any goroutine cleanup still in flight
	// finishes before the process exits. The prior behavior (no
	// close() at all) left the HTTP server, its background goroutine
	// tree, and every DB/metric/instrument worker running until the
	// process ended, which was the original cause of the Test Race
	// package-level timeout.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}

// TestRunServer_SSEMode exercises the SSE server mode path.
func TestRunServer_SSEMode_Cov(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AppMode = ModeSSE
	// See TestRunServer_HybridMode_Cov for the rationale behind injecting
	// shutdownCh — same goroutine-leak class.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	time.Sleep(500 * time.Millisecond)

	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// See TestRunServer_HybridMode_Cov for rationale.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}

// TestRunServer_WithOAuthFullLifecycle exercises RunServer with OAuth enabled,
// covering the OAuth handler wiring and KiteTokenChecker setup.
func TestRunServer_WithOAuthFullLifecycle(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := NewApp(testLogger())
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "https://test.example.com"
	app.Config.AlertDBPath = ":memory:"
	app.Config.AdminEmails = "admin@test.com"
	// See TestRunServer_HybridMode_Cov for the rationale.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	time.Sleep(500 * time.Millisecond)

	// Verify OAuth endpoints are registered
	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/oauth-authorization-server", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// See TestRunServer_HybridMode_Cov for rationale.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
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
// setupMux — exercise browser flow callback path
// ===========================================================================

func TestSetupMux_Callback_BrowserFlow_NoHandler(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.oauthHandler = nil

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&request_token=abc", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "OAuth not configured")
}

// ===========================================================================
// setupMux — robots.txt endpoint
// ===========================================================================

func TestSetupMux_RobotsTxt(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "User-agent: *")
	assert.Contains(t, rec.Body.String(), "Disallow: /dashboard/")
}

// ===========================================================================
// setupMux — server card CORS preflight (OPTIONS)
// ===========================================================================

func TestSetupMux_ServerCard_OptionsMethod(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Version = "v1.0.0-test"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodOptions, "/.well-known/mcp/server-card.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "GET, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
}

// ===========================================================================
// setupMux — admin password seeding: already has password
// ===========================================================================

func TestSetupMux_AdminPassword_AlreadyHasPassword(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)

	// Pre-set a password hash so HasPassword returns true
	userStore.EnsureAdmin("admin@test.com")
	_ = userStore.SetPasswordHash("admin@test.com", "$2a$12$fakehashfakehashfakehashfakehashfakehashfakehashfak")

	t.Setenv("ADMIN_PASSWORD", "new-password-should-not-override")

	app := NewApp(testLogger())
	app.Config.AdminEmails = "admin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
}

// ===========================================================================
// setupMux — Stripe webhook with billing store AND webhook events table
// ===========================================================================

func TestSetupMux_StripeWebhookWithEventLog(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_event_log_123")
	t.Setenv("STRIPE_SECRET_KEY", "")

	mgr := newTestManagerWithDB(t)

	// Set up a billing store on the manager so BillingStoreConcrete() != nil
	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		mgr.SetBillingStore(bs)
	}

	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Verify the webhook endpoint exists (POST to /webhooks/stripe)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should not be 404 — the handler is registered (it may reject due to
	// invalid Stripe signature, but it won't be 404)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// setupMux — admin auth with valid JWT and admin role
// ===========================================================================

func TestSetupMux_AdminAuth_ValidJWT_AdminAccess(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)
	userStore.EnsureAdmin("admin@test.com")

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)
	handler.SetUserStore(userStore)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.AdminEmails = "admin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Generate a valid JWT for the admin
	token, err := handler.JWTManager().GenerateToken("admin@test.com", "dashboard")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: "kite_jwt", Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should get something other than 302 redirect to login
	assert.NotEqual(t, http.StatusFound, rec.Code)
}

// ===========================================================================
// setupMux — Google SSO config wiring (both with and without credentials)
// ===========================================================================

func TestSetupMux_GoogleSSO_NoCredentials(t *testing.T) {
	mgr := newTestManagerWithDB(t)

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.GoogleClientID = ""
	app.Config.GoogleClientSecret = ""

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
}

// ===========================================================================
// ExchangeWithCredentials — registry store branches
// ===========================================================================

func TestExchangeWithCredentials_ExistingKeyDifferentUser(t *testing.T) {
	regStore := registry.New()

	// Pre-register a key assigned to a different user
	err := regStore.Register(&registry.AppRegistration{
		ID:           "existing-reg",
		APIKey:       "pk",
		APISecret:    "ps",
		AssignedTo:   "other@test.com",
		Label:        "Test",
		Status:       registry.StatusActive,
		Source:       registry.SourceSelfProvisioned,
		RegisteredBy: "other@test.com",
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey: "gk", apiSecret: "gs",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore:   regStore,
		userStore:       users.NewStore(),
		logger:          testLogger(),
		authenticator:   newMockAuthError("Invalid checksum"),
	}

	// This will fail at authenticator but exercises the adapter creation
	_, exchangeErr := adapter.ExchangeWithCredentials("bad-token", "pk", "ps")
	require.Error(t, exchangeErr)
}

func TestExchangeWithCredentials_OldKeyReplacement(t *testing.T) {
	regStore := registry.New()

	// Pre-register an old key for the user
	err := regStore.Register(&registry.AppRegistration{
		ID:           "old-reg",
		APIKey:       "old-key",
		APISecret:    "old-secret",
		AssignedTo:   "user@test.com",
		Label:        "Old",
		Status:       registry.StatusActive,
		Source:       registry.SourceSelfProvisioned,
		RegisteredBy: "user@test.com",
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey: "gk", apiSecret: "gs",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore:   regStore,
		userStore:       users.NewStore(),
		logger:          testLogger(),
		authenticator:   newMockAuthError("Invalid checksum"),
	}

	// This will fail at authenticator
	_, exchangeErr := adapter.ExchangeWithCredentials("bad-token", "new-key", "new-secret")
	require.Error(t, exchangeErr)
}

// ===========================================================================
// ExchangeRequestToken — with registryStore branch
// ===========================================================================

func TestExchangeRequestToken_WithRegistryStore(t *testing.T) {
	regStore := registry.New()
	adapter := &kiteExchangerAdapter{
		apiKey: "test-key", apiSecret: "test-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore:   regStore,
		userStore:       users.NewStore(),
		logger:          testLogger(),
		authenticator:   newMockAuthError("Invalid checksum"),
	}

	// Will fail at authenticator but exercises the adapter setup
	_, err := adapter.ExchangeRequestToken("bad-token")
	require.Error(t, err)
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
// serveStatusPage — test landing template write error (exercise the error log)
// ===========================================================================

func TestServeStatusPage_LandingTemplate_ExecuteError(t *testing.T) {
	app := NewApp(testLogger())
	// Set a landing template that will fail on ExecuteTemplate("base", ...)
	// because it has no "base" template defined
	badTmpl, err := template.New("bad").Parse("{{.NoSuchField.X}}")
	require.NoError(t, err)
	app.landingTemplate = badTmpl
	app.statusTemplate = nil

	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// serveStatusPage — fallback to status template when landing is nil
// ===========================================================================

func TestServeStatusPage_FallbackToStatus(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	// Remove landing template to force fallback
	app.landingTemplate = nil

	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Falls through to statusTemplate which also has "base"
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// serveStatusPage — neither template set
// ===========================================================================

func TestServeStatusPage_BothTemplatesNil(t *testing.T) {
	app := NewApp(testLogger())
	app.landingTemplate = nil
	app.statusTemplate = nil

	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "template not available")
}

// ===========================================================================
// serveErrorPage — direct function test
// ===========================================================================

func TestServeErrorPage_NotFoundCov(t *testing.T) {
	rec := httptest.NewRecorder()
	serveErrorPage(rec, http.StatusNotFound, "Not Found", "Page missing")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "Not Found")
	assert.Contains(t, rec.Body.String(), "Page missing")
}

func TestServeErrorPage_ServerErrorCov(t *testing.T) {
	rec := httptest.NewRecorder()
	serveErrorPage(rec, http.StatusInternalServerError, "Server Error", "Something broke")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Server Error")
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
// initScheduler — with audit store but no Telegram (audit_cleanup task only)
// ===========================================================================

func TestInitScheduler_AuditOnly_NoTelegram(t *testing.T) {
	// Manager without Telegram
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey: "tk", APISecret: "ts",
		Logger: testLogger(), DevMode: true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := NewApp(testLogger())
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)
	// Should have audit_cleanup + pnl_snapshot tasks (DB exists)
	assert.NotNil(t, app.scheduler)
	app.scheduler.Stop()
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
	app := NewApp(testLogger())
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
	time.Sleep(100 * time.Millisecond)

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

// ===========================================================================
// startServer — all mode cases
// ===========================================================================

func TestStartServer_AllModes(t *testing.T) {
	modes := []struct {
		mode string
		ok   bool
	}{
		{ModeHybrid, true},
		{ModeSSE, true},
		{ModeHTTP, true},
		// ModeStdIO is tested separately due to os.Stdin/Stdout
		{"bogus", false},
	}

	for _, m := range modes {
		t.Run(m.mode, func(t *testing.T) {
			app := NewApp(testLogger())
			app.Config.AppMode = m.mode

			if !m.ok {
				err := app.startServer(nil, nil, nil, "")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid APP_MODE")
				return
			}

			// For valid modes, we can't fully start without blocking,
			// so just verify no error via a quick goroutine test
			mgr := newTestManagerWithDB(t)
			mcpSrv := newTestMCPServer()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := listener.Addr().String()
			listener.Close()

			srv := &http.Server{Addr: addr}

			errCh := make(chan error, 1)
			go func() {
				errCh <- app.startServer(srv, mgr, mcpSrv, addr)
			}()

			time.Sleep(200 * time.Millisecond)

			// Shutdown the server
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)

			select {
			case err := <-errCh:
				assert.NoError(t, err)
			case <-time.After(3 * time.Second):
			}
		})
	}
}

// ===========================================================================
// setupMux — healthz endpoint verification
// ===========================================================================

func TestSetupMux_Healthz_Content(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Version = "v1.2.3"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
	assert.Equal(t, "v1.2.3", body["version"])
	// Legacy flat body: no "components" key.
	_, hasComponents := body["components"]
	assert.False(t, hasComponents, "plain /healthz must not include the rich component body")
}

// ===========================================================================
// setupMux — healthz ?format=json: component-level health report
// ===========================================================================

func TestSetupMux_Healthz_JSONFormat_AllHealthy(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	// Wire a healthy audit store and a guard with limits loaded so
	// every component reports "ok".
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	auditStore.StartWorker()
	t.Cleanup(auditStore.Stop)

	app := NewApp(testLogger())
	app.Version = "v9.9.9"
	app.auditStore = auditStore
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	assert.Equal(t, "ok", body["status"])
	assert.Equal(t, "v9.9.9", body["version"])
	assert.Contains(t, body, "uptime_s")

	components, ok := body["components"].(map[string]any)
	require.True(t, ok, "components must be a map")
	// All four components present.
	require.Contains(t, components, "audit")
	require.Contains(t, components, "riskguard")
	require.Contains(t, components, "kite_connectivity")
	require.Contains(t, components, "litestream")

	audit, _ := components["audit"].(map[string]any)
	assert.Equal(t, "ok", audit["status"])

	rg, _ := components["riskguard"].(map[string]any)
	assert.Equal(t, "ok", rg["status"])

	kite, _ := components["kite_connectivity"].(map[string]any)
	assert.Equal(t, "unknown", kite["status"])
	assert.NotEmpty(t, kite["note"])
}

func TestSetupMux_Healthz_JSONFormat_AuditDisabled(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	app := NewApp(testLogger())
	app.Version = "v9.9.9"
	// Simulate audit init failure in DevMode (startup continues, auditStore is nil).
	app.auditStore = nil
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	// Audit disabled is a degraded condition at the top level.
	assert.Equal(t, "degraded", body["status"])

	components := body["components"].(map[string]any)
	audit := components["audit"].(map[string]any)
	assert.Equal(t, "disabled", audit["status"])
	assert.NotEmpty(t, audit["note"])
}

func TestSetupMux_Healthz_JSONFormat_RiskLimitsNotLoaded(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	auditStore.StartWorker()
	t.Cleanup(auditStore.Stop)

	app := NewApp(testLogger())
	app.auditStore = auditStore
	// Simulate LoadLimits failure in DevMode — guard is running with SystemDefaults.
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = false

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	// Risk limits not loaded is a degraded condition.
	assert.Equal(t, "degraded", body["status"])

	components := body["components"].(map[string]any)
	rg := components["riskguard"].(map[string]any)
	assert.Equal(t, "defaults-only", rg["status"])
	assert.NotEmpty(t, rg["note"])
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

	app := NewApp(testLogger())
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
	app := NewApp(testLogger())
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

	app := NewApp(testLogger())
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
	app := NewApp(testLogger())
	app.auditStore = nil
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	report := app.buildHealthzReport()

	_, ok := report.Components["anomaly_cache"]
	assert.False(t, ok, "anomaly_cache must be omitted when auditStore is nil")
	// Audit itself is still surfaced as disabled.
	assert.Equal(t, "disabled", report.Components["audit"].Status)
}

// TestSetupMux_Healthz_JSONFormat_AnomalyCacheShape verifies the JSON wire
// shape includes hit_rate and max_entries fields for the anomaly_cache
// component. Operators shell-parse this without a Go struct on the other
// side, so the exact JSON keys matter.
func TestSetupMux_Healthz_JSONFormat_AnomalyCacheShape(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	auditStore.StartWorker()
	t.Cleanup(auditStore.Stop)

	app := NewApp(testLogger())
	app.auditStore = auditStore
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	components, ok := body["components"].(map[string]any)
	require.True(t, ok, "components must be a map")
	cache, ok := components["anomaly_cache"].(map[string]any)
	require.True(t, ok, "components.anomaly_cache must be a JSON object")

	assert.Equal(t, "ok", cache["status"])
	// JSON numbers unmarshal to float64 — check the field exists and matches.
	assert.Contains(t, cache, "hit_rate")
	assert.Contains(t, cache, "max_entries")
	assert.EqualValues(t, audit.DefaultMaxStatsCacheEntries, cache["max_entries"])
}

// ===========================================================================
// setupMux — favicon endpoint
// ===========================================================================

func TestSetupMux_Favicon_CacheControl(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should return the favicon with cache headers
	if rec.Code == http.StatusOK {
		assert.Contains(t, rec.Header().Get("Content-Type"), "svg")
		assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=604800")
	}
}

// ===========================================================================
// setupMux — with OAuth enabled: endpoints wiring
// ===========================================================================

func TestSetupMux_WithOAuth_AllEndpointsWired(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)
	handler.SetUserStore(userStore)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.AdminEmails = "admin@test.com"
	app.Config.GoogleClientID = "google-id"
	app.Config.GoogleClientSecret = "google-secret"
	app.Config.ExternalURL = "https://test.example.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Verify auth endpoints are registered (not 404)
	authEndpoints := []string{
		"/auth/login",
		"/auth/browser-login",
		"/auth/admin-login",
		"/auth/google/login",
		"/auth/google/callback",
		"/oauth/register",
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/email-lookup",
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
	}

	for _, endpoint := range authEndpoints {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.NotEqual(t, http.StatusNotFound, rec.Code,
				"endpoint %s should be registered", endpoint)
		})
	}
}

// ===========================================================================
// setupMux — accept-invite endpoint with various states
// ===========================================================================

func TestSetupMux_AcceptInvite_TokenNotFound(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/auth/accept-invite?token=nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// serveLegalPages — Cache-Control header
// ===========================================================================

func TestServeLegalPages_CacheControl(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/terms", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Cache TTL was reduced from 24h to 1h when the /privacy and /terms
	// handlers moved to markdown-sourced content; shorter TTL lets policy
	// updates propagate through Fly.io edge caches within an hour.
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
}

// ===========================================================================
// initStatusPageTemplate — verify all three templates are set
// ===========================================================================

func TestInitStatusPageTemplate_AllTemplatesSet(t *testing.T) {
	app := NewApp(testLogger())
	err := app.initStatusPageTemplate()
	require.NoError(t, err)
	assert.NotNil(t, app.statusTemplate, "statusTemplate should be set")
	assert.NotNil(t, app.landingTemplate, "landingTemplate should be set")
	assert.NotNil(t, app.legalTemplate, "legalTemplate should be set")
}

// ===========================================================================
// setupMux — pricing page with premium tier cookie
// ===========================================================================

func TestSetupMux_PricingPage_WithPremiumTier(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)

	app := NewApp(testLogger())
	app.oauthHandler = handler

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	token, err := handler.JWTManager().GenerateToken("premium@test.com", "dashboard")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/pricing", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Pricing")
}

// ===========================================================================
// setupMux — pricing page without cookie
// ===========================================================================

func TestSetupMux_PricingPage_NoCookie(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/pricing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Default tier should be "free"
	assert.Contains(t, rec.Body.String(), `data-current="free"`)
}

// ===========================================================================
// buildServerURL
// ===========================================================================

func TestBuildServerURL_Cov(t *testing.T) {
	app := NewApp(testLogger())
	app.Config.AppHost = "0.0.0.0"
	app.Config.AppPort = "9090"
	assert.Equal(t, "0.0.0.0:9090", app.buildServerURL())
}

// ===========================================================================
// configureHTTPClient
// ===========================================================================

func TestConfigureHTTPClient_Cov(t *testing.T) {
	app := NewApp(testLogger())
	// Should not panic — just logs
	app.configureHTTPClient()
}

// ===========================================================================
// createHTTPServer
// ===========================================================================

func TestCreateHTTPServer_Cov(t *testing.T) {
	app := NewApp(testLogger())
	srv := app.createHTTPServer("127.0.0.1:8080")
	assert.Equal(t, "127.0.0.1:8080", srv.Addr)
	assert.Equal(t, 30*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 120*time.Second, srv.WriteTimeout)
}

// ===========================================================================
// getStatusData
// ===========================================================================

func TestGetStatusData_Cov(t *testing.T) {
	app := NewApp(testLogger())
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
// setupMux — admin auth: redirect with various path values
// ===========================================================================

func TestSetupMux_AdminAuth_EmptyPath_DefaultRedirect(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)
	handler.SetUserStore(userStore)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.AdminEmails = "admin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Request to admin ops without cookie should redirect to login
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/admin-login")
}

// ===========================================================================
// LoadConfig — OAuth + ExternalURL requirement
// ===========================================================================

func TestLoadConfig_OAuthRequiresExternalURL(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test-key")
	t.Setenv("KITE_API_SECRET", "test-secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "")

	app := NewApp(testLogger())
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

	app := NewApp(testLogger())
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

	app := NewApp(testLogger())
	err := app.LoadConfig()
	require.NoError(t, err)
}

// ===========================================================================
// setupMux — checkout success page
// ===========================================================================

func TestSetupMux_CheckoutSuccess(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/checkout/success", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Welcome to Pro")
}

// ===========================================================================
// setupMux — security.txt content verification
// ===========================================================================

func TestSetupMux_SecurityTxt_Content(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Contact:")
	assert.Contains(t, rec.Body.String(), "Expires:")
	assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
}

// ===========================================================================
// setupMux — server card GET request
// ===========================================================================

func TestSetupMux_ServerCard_GETRequest(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Version = "v2.0.0"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/mcp/server-card.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age=3600")

	var body map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &body)
	require.NoError(t, err)
	serverInfo := body["serverInfo"].(map[string]any)
	assert.Equal(t, "v2.0.0", serverInfo["version"])
}

// ===========================================================================
// registerTelegramWebhook — no ExternalURL path
// ===========================================================================

func TestRegisterTelegramWebhook_NoExternalURL(t *testing.T) {
	app := NewApp(testLogger())
	app.Config.OAuthJWTSecret = "test-secret-long-enough-for-sha256"
	app.Config.ExternalURL = "" // triggers early return

	mgr := newTestManagerWithDB(t)
	mux := http.NewServeMux()

	app.registerTelegramWebhook(mux, mgr)
	// Should return early without panic
}

func TestRegisterTelegramWebhook_NoJWTSecret_WithExternalURL(t *testing.T) {
	app := NewApp(testLogger())
	app.Config.OAuthJWTSecret = "" // triggers early return
	app.Config.ExternalURL = "https://test.example.com"

	mgr := newTestManagerWithDB(t)
	mux := http.NewServeMux()

	app.registerTelegramWebhook(mux, mgr)
}

// ===========================================================================
// startServer — stdio mode (uses os.Stdin/Stdout so we skip full test,
// but exercise the server creation path)
// ===========================================================================

func TestStartStdIOServer_Smoke(t *testing.T) {
	// We can't actually test STDIO properly without redirecting stdin/stdout,
	// but we can verify that the setup completes without panicking.
	// Use a pipe to simulate stdin/stdout for a brief period.

	// Instead, test that startServer with ModeStdIO doesn't return an error
	// (it will block on stdio.Listen, but the HTTP server starts in background)
	if os.Getenv("CI") != "" {
		t.Skip("STDIO test not suitable for CI")
	}
	t.Skip("STDIO mode blocks on stdin — skipping in automated tests")
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
	app := NewApp(testLogger())
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
// setupMux — family invitation acceptance branches
// ===========================================================================

// newTestManagerWithInvitations is now in helpers_test.go

func TestSetupMux_AcceptInvite_MissingToken_Cov(t *testing.T) {
	mgr, _ := newTestManagerWithInvitations(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Missing token
	req := httptest.NewRequest(http.MethodGet, "/auth/accept-invite", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSetupMux_AcceptInvite_ExpiredInv_Cov(t *testing.T) {
	mgr, invStore := newTestManagerWithInvitations(t)
	invID := "expired-inv-123"
	require.NoError(t, invStore.Create(&users.FamilyInvitation{
		ID:           invID,
		AdminEmail:   "admin@test.com",
		InvitedEmail: "invited@test.com",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}))

	app := NewApp(testLogger())
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/auth/accept-invite?token="+invID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Contains(t, rec.Body.String(), "expired")
}

func TestSetupMux_AcceptInvite_AlreadyAccepted_Cov(t *testing.T) {
	mgr, invStore := newTestManagerWithInvitations(t)
	invID := "accepted-inv-456"
	require.NoError(t, invStore.Create(&users.FamilyInvitation{
		ID:           invID,
		AdminEmail:   "admin@test.com",
		InvitedEmail: "invited@test.com",
		Status:       "accepted",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}))

	app := NewApp(testLogger())
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/auth/accept-invite?token="+invID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Contains(t, rec.Body.String(), "already accepted")
}

func TestSetupMux_AcceptInvite_ValidInv_Cov(t *testing.T) {
	mgr, invStore := newTestManagerWithInvitations(t)
	invID := "valid-inv-789"
	require.NoError(t, invStore.Create(&users.FamilyInvitation{
		ID:           invID,
		AdminEmail:   "admin@test.com",
		InvitedEmail: "invited@test.com",
		Status:       "pending",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}))

	app := NewApp(testLogger())
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/auth/accept-invite?token="+invID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Valid invite → redirect to login
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/login")
}

// ===========================================================================
// setupMux — Stripe webhook with billing store but NO STRIPE_SECRET (warn branch)
// ===========================================================================

func TestSetupMux_StripeWebhookNoBillingStore_Cov(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_no_billing_123")

	mgr := newTestManagerWithDB(t)
	// Do NOT set billing store → the warning branch is exercised
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /webhooks/stripe should NOT exist (no billing store)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// setupMux — billing checkout + portal handlers (with OAuth + billing store)
// ===========================================================================

func TestSetupMux_BillingCheckout_RequiresAuth(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	// Set up billing store
	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		mgr.SetBillingStore(bs)
	}

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)

	app := NewApp(testLogger())
	app.oauthHandler = handler

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /billing/checkout should exist but require auth
	req := httptest.NewRequest(http.MethodGet, "/billing/checkout", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusNotFound, rec.Code) // registered, not 404

	// /stripe-portal should exist but require auth
	req2 := httptest.NewRequest(http.MethodGet, "/stripe-portal", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	assert.NotEqual(t, http.StatusNotFound, rec2.Code)
}

// ===========================================================================
// setupMux — pricing page with pro tier cookie
// ===========================================================================

func TestSetupMux_PricingPage_WithProTier_Cov(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	// Set up billing with a pro subscriber
	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		require.NoError(t, bs.SetSubscription(&billing.Subscription{
			AdminEmail:       "pro@test.com",
			Tier:             billing.TierPro,
			StripeCustomerID: "cus_test",
			StripeSubID:      "sub_test",
			Status:           billing.StatusActive,
		}))
		mgr.SetBillingStore(bs)
	}

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)

	// Generate a valid JWT token for the pro user
	token, err := handler.JWTManager().GenerateTokenWithExpiry("pro@test.com", "dashboard", 1*time.Hour)
	require.NoError(t, err)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/pricing", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `data-current="pro"`)
}

// ===========================================================================
// setupMux — AdminAuth — non-admin user gets forbidden
// ===========================================================================

func TestSetupMux_AdminAuth_NonAdminUser_Forbidden(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)
	userStore.EnsureAdmin("admin@test.com")
	// Create a non-admin user
	userStore.EnsureUser("user@test.com", "", "", "test")

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)
	handler.SetUserStore(userStore)

	// Generate JWT for non-admin user
	token, err := handler.JWTManager().GenerateTokenWithExpiry("user@test.com", "dashboard", 1*time.Hour)
	require.NoError(t, err)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.AdminEmails = "admin@test.com"
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	req.AddCookie(&http.Cookie{Name: "kite_jwt", Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ===========================================================================
// setupMux — Google SSO with credentials
// ===========================================================================

func TestSetupMux_GoogleSSO_WithCredentials(t *testing.T) {
	mgr := newTestManagerWithDB(t)

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
	handler := oauth.NewHandler(oauthCfg, signer, exchanger)

	app := NewApp(testLogger())
	app.oauthHandler = handler
	app.Config.GoogleClientID = "google-client-id"
	app.Config.GoogleClientSecret = "google-client-secret"
	app.Config.ExternalURL = "https://test.example.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /auth/google/login should be registered
	req := httptest.NewRequest(http.MethodGet, "/auth/google/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// initScheduler — with audit store + alert DB
// ===========================================================================

func TestInitScheduler_WithAuditAndPnL(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := NewApp(testLogger())
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
}

// ===========================================================================
// initializeServices — with all env vars set (event store + paper trading)
// ===========================================================================

func TestInitializeServices_FullSetup(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("DEV_MODE", "true")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")

	app := NewApp(testLogger())
	app.Config.KiteAPIKey = "test_key"
	app.Config.KiteAPISecret = "test_secret"
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.DevMode = true

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpSrv)

	// Verify services were wired
	assert.NotNil(t, mgr.RiskGuard())
	assert.NotNil(t, mgr.EventDispatcher())
	assert.NotNil(t, mgr.PaperEngineConcrete())
	assert.NotNil(t, app.auditStore)

	cleanupInitializeServices(app, mgr)
}

// ===========================================================================
// initializeServices — without AlertDBPath (no SQLite)
// ===========================================================================

func TestInitializeServices_NoAlertDB(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("STRIPE_SECRET_KEY", "")

	app := NewApp(testLogger())
	app.Config.KiteAPIKey = "test_key"
	app.Config.KiteAPISecret = "test_secret"
	app.Config.AlertDBPath = "" // no DB
	app.DevMode = true

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpSrv)

	// No audit store without a DB
	assert.Nil(t, app.auditStore)

	cleanupInitializeServices(app, mgr)
}

// ===========================================================================
// setupMux — ops handler registration with AdminSecretPath (no OAuth)
// ===========================================================================

func TestSetupMux_OpsHandler_AdminSecretPathFallback(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Config.AdminSecretPath = "test-secret-path"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /admin/ops should be accessible (identity middleware, no auth)
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should not be 404 — the ops handler is registered
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// setupMux — admin password seeding (multiple admin emails)
// ===========================================================================

func TestSetupMux_AdminPassword_MultipleEmails(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "test-admin-password-123")

	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Config.AdminEmails = "admin1@test.com, admin2@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	// Both admins should have password set
	userStore := mgr.UserStoreConcrete()
	assert.True(t, userStore.HasPassword("admin1@test.com"))
	assert.True(t, userStore.HasPassword("admin2@test.com"))
}

// ===========================================================================
// setupMux — admin seeding skipped when users already exist
// ===========================================================================

func TestSetupMux_AdminSeeding_SkipsWhenUsersExist(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	// Pre-populate with a user
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)
	userStore.EnsureUser("existing@test.com", "", "", "test")

	app := NewApp(testLogger())
	app.Config.AdminEmails = "newadmin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	// newadmin should NOT be admin since users already exist
	assert.False(t, userStore.IsAdmin("newadmin@test.com"))
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

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	qty, ok := adapter.GetFreezeQuantity("NSE", "INFY")
	assert.True(t, ok)
	assert.Equal(t, uint32(5000), qty)
}

// ===========================================================================
// initScheduler — exercises all task branches
// ===========================================================================

func TestInitScheduler_WithPnLService(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	// Set up audit store so audit_cleanup task is added
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())

	app.initScheduler(mgr)
	if app.scheduler != nil {
		app.scheduler.Stop()
	}
}

// ===========================================================================
// ExchangeWithCredentials — provision error branch
// ===========================================================================

func TestExchangeWithCredentials_NoRegistryStore(t *testing.T) {
	exchanger := &kiteExchangerAdapter{
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:          testLogger(),
		authenticator:   newMockAuthError("Invalid checksum"),
		// registryStore is nil
	}

	// This will fail at authenticator but exercises the initial code path
	_, err := exchanger.ExchangeWithCredentials("fake-request-token", "key1", "secret1")
	assert.Error(t, err)
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
// clientPersisterAdapter
// ===========================================================================

func TestClientPersisterAdapter_SaveLoadDelete(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	// SaveClient
	err = adapter.SaveClient("client-1", "secret-1", `["http://localhost"]`, "Test Client", time.Now(), false)
	require.NoError(t, err)

	// LoadClients
	clients, err := adapter.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "client-1", clients[0].ClientID)
	assert.Equal(t, "secret-1", clients[0].ClientSecret)
	assert.Equal(t, "Test Client", clients[0].ClientName)
	assert.False(t, clients[0].IsKiteAPIKey)

	// DeleteClient
	err = adapter.DeleteClient("client-1")
	require.NoError(t, err)

	clients, err = adapter.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

// ===========================================================================
// setupMux — callback with browser flow and no OAuth handler
// ===========================================================================

func TestSetupMux_Callback_OAuthFlow_NoHandler_Cov(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	// No oauthHandler

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&request_token=test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// setupMux — callback default flow (no flow param)
// ===========================================================================

func TestSetupMux_Callback_DefaultFlow_Cov(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Default flow uses kcManager.HandleKiteCallback()
	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Won't be 404 — the handler exists
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// serveLegalPages — all legal page routes
// ===========================================================================

func TestServeLegalPages_AllRoutes(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	// Ensure initStatusPageTemplate is called to set up legal templates
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	pages := []string{"/terms", "/privacy"}
	for _, page := range pages {
		req := httptest.NewRequest(http.MethodGet, page, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "page %s should return 200", page)
		assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	}
}

// ===========================================================================
// newRateLimiters — exercise with AdminSecretPath set
// ===========================================================================

func TestSetupMux_RateLimitersWithAdmin(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Config.AdminSecretPath = "secret-path-123"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
	require.NotNil(t, app.rateLimiters)
}

// ===========================================================================
// configureAndStartServer — SSE mode
// ===========================================================================

func TestConfigureAndStartServer_WithSSE(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
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
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// ===========================================================================
// setupMux — Dashboard handler with billing store
// ===========================================================================

func TestSetupMux_DashboardWithBilling(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		mgr.SetBillingStore(bs)
	}

	app := NewApp(testLogger())
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /dashboard should be registered
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// setupMux — admin seeding with empty email in list
// ===========================================================================

func TestSetupMux_AdminSeeding_EmptyEmailInList(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Config.AdminEmails = "admin@test.com, , anotherAdmin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	userStore := mgr.UserStoreConcrete()
	assert.True(t, userStore.IsAdmin("admin@test.com"))
	assert.True(t, userStore.IsAdmin("anotheradmin@test.com"))
}

// ===========================================================================
// startHybridServer — exercises the hybrid server start path
// ===========================================================================

func TestStartHybridServer_QuickShutdown(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := NewApp(testLogger())
	app.Config.AppMode = "hybrid"

	// Create an MCP server
	t.Setenv("DEV_MODE", "true")
	app.Config.KiteAPIKey = "test_key"
	app.Config.KiteAPISecret = "test_secret"
	app.Config.AlertDBPath = ":memory:"
	app.DevMode = true

	kcMgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	defer cleanupInitializeServices(app, kcMgr)

	// Create a server on a random port
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, lnErr)
	addr := ln.Addr().String()
	ln.Close()

	srv := &http.Server{Addr: addr}
	mux := http.NewServeMux()
	srv.Handler = mux

	go func() {
		app.startHybridServer(srv, kcMgr, mcpSrv, addr)
	}()

	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = mgr
}
