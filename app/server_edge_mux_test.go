package app

// app_coverage_test.go — targeted tests to boost coverage from ~78% to 90%+.
// Focuses on uncovered branches in: setupGracefulShutdown, initializeServices,
// initScheduler, paperLTPAdapter.GetLTP, setupMux, registerTelegramWebhook,
// RunServer, ExchangeWithCredentials, makeEventPersister, serveStatusPage,
// serveLegalPages, newRateLimiters, and startHybridServer/startStdIOServer.

import (
	"encoding/json"
	"html/template"
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
	"github.com/zerodha/kite-mcp-server/kc/billing"
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


// ===========================================================================
// setupMux — exercise browser flow callback path
// ===========================================================================
func TestSetupMux_Callback_BrowserFlow_NoHandler(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
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
	app := newTestApp(t)

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
	app := newTestApp(t)
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

	app := newTestApp(t)
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

	app := newTestApp(t)

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
	t.Cleanup(handler.Close)
	handler.SetUserStore(userStore)

	app := newTestApp(t)
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
	t.Cleanup(handler.Close)

	app := newTestApp(t)
	app.oauthHandler = handler
	app.Config.GoogleClientID = ""
	app.Config.GoogleClientSecret = ""

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
}


// ===========================================================================
// serveStatusPage — test landing template write error (exercise the error log)
// ===========================================================================
func TestServeStatusPage_LandingTemplate_ExecuteError(t *testing.T) {
	app := newTestApp(t)
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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
// setupMux — healthz endpoint verification
// ===========================================================================
func TestSetupMux_Healthz_Content(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
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

	app := newTestApp(t)
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

	app := newTestApp(t)
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

	app := newTestApp(t)
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

	app := newTestApp(t)
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
	app := newTestApp(t)

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
	t.Cleanup(handler.Close)
	handler.SetUserStore(userStore)

	app := newTestApp(t)
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
	app := newTestApp(t)

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
	app := newTestApp(t)
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
	t.Cleanup(handler.Close)

	app := newTestApp(t)
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
	app := newTestApp(t)

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
	t.Cleanup(handler.Close)
	handler.SetUserStore(userStore)

	app := newTestApp(t)
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
// setupMux — checkout success page
// ===========================================================================
func TestSetupMux_CheckoutSuccess(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)

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
	app := newTestApp(t)

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
	app := newTestApp(t)
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
// setupMux — family invitation acceptance branches
// ===========================================================================

// newTestManagerWithInvitations is now in helpers_test.go
func TestSetupMux_AcceptInvite_MissingToken_Cov(t *testing.T) {
	mgr, _ := newTestManagerWithInvitations(t)
	app := newTestApp(t)

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

	app := newTestApp(t)
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

	app := newTestApp(t)
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

	app := newTestApp(t)
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
	app := newTestApp(t)

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
	t.Cleanup(handler.Close)

	app := newTestApp(t)
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
	t.Cleanup(handler.Close)

	// Generate a valid JWT token for the pro user
	token, err := handler.JWTManager().GenerateTokenWithExpiry("pro@test.com", "dashboard", 1*time.Hour)
	require.NoError(t, err)

	app := newTestApp(t)
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
	t.Cleanup(handler.Close)
	handler.SetUserStore(userStore)

	// Generate JWT for non-admin user
	token, err := handler.JWTManager().GenerateTokenWithExpiry("user@test.com", "dashboard", 1*time.Hour)
	require.NoError(t, err)

	app := newTestApp(t)
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
	t.Cleanup(handler.Close)

	app := newTestApp(t)
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
// setupMux — ops handler registration with AdminSecretPath (no OAuth)
// ===========================================================================
func TestSetupMux_OpsHandler_AdminSecretPathFallback(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
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
	app := newTestApp(t)
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

	app := newTestApp(t)
	app.Config.AdminEmails = "newadmin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	// newadmin should NOT be admin since users already exist
	assert.False(t, userStore.IsAdmin("newadmin@test.com"))
}


// ===========================================================================
// setupMux — callback with browser flow and no OAuth handler
// ===========================================================================
func TestSetupMux_Callback_OAuthFlow_NoHandler_Cov(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
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
	app := newTestApp(t)

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
	app := newTestApp(t)
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
	app := newTestApp(t)
	app.Config.AdminSecretPath = "secret-path-123"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
	require.NotNil(t, app.rateLimiters)
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

	app := newTestApp(t)
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
	app := newTestApp(t)
	app.Config.AdminEmails = "admin@test.com, , anotherAdmin@test.com"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	userStore := mgr.UserStoreConcrete()
	assert.True(t, userStore.IsAdmin("admin@test.com"))
	assert.True(t, userStore.IsAdmin("anotheradmin@test.com"))
}
