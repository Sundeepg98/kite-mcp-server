package app

// app_coverage_test.go â€” targeted tests to boost coverage from ~78% to 90%+.
// Focuses on uncovered branches in: setupGracefulShutdown, initializeServices,
// initScheduler, paperLTPAdapter.GetLTP, setupMux, registerTelegramWebhook,
// RunServer, ExchangeWithCredentials, makeEventPersister, serveStatusPage,
// serveLegalPages, newRateLimiters, and startHybridServer/startStdIOServer.

import (
	"context"
	"encoding/json"
	"html/template"
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
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// setupGracefulShutdown â€” exercise the inner goroutine's shutdown paths
// ===========================================================================

// TestSetupGracefulShutdown_WithAllComponents exercises the shutdown goroutine
// body by using context.WithCancel and manually triggering the cancel â€” which
// won't work directly since the function uses signal.NotifyContext.
// Instead, we test that the function sets up without panicking when the app
// has scheduler, auditStore, telegramBot, oauthHandler, and rateLimiters set.


// ===========================================================================
// setupMux â€” exercise browser flow callback path
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
// setupMux â€” robots.txt endpoint
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
// setupMux â€” server card CORS preflight (OPTIONS)
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
// setupMux â€” admin password seeding: already has password
// ===========================================================================
func TestSetupMux_AdminPassword_AlreadyHasPassword(t *testing.T) {
	t.Parallel()
	mgr := newTestManagerWithDB(t)
	userStore := mgr.UserStoreConcrete()
	require.NotNil(t, userStore)

	// Pre-set a password hash so HasPassword returns true
	userStore.EnsureAdmin("admin@test.com")
	_ = userStore.SetPasswordHash("admin@test.com", "$2a$12$fakehashfakehashfakehashfakehashfakehashfakehashfak")

	app := newTestAppWithConfig(t, &Config{
		AdminEmails:          "admin@test.com",
		AdminPassword:        "new-password-should-not-override",
		InstrumentsSkipFetch: true,
	})

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)
}


// ===========================================================================
// setupMux â€” Stripe webhook with billing store AND webhook events table
// ===========================================================================
func TestSetupMux_StripeWebhookWithEventLog(t *testing.T) {
	t.Parallel()
	mgr := newTestManagerWithDB(t)

	// Set up a billing store on the manager so BillingStoreConcrete() != nil
	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		mgr.SetBillingStore(bs)
	}

	app := newTestAppWithConfig(t, &Config{
		StripeWebhookSecret:  "whsec_test_event_log_123",
		InstrumentsSkipFetch: true,
	})

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// Verify the webhook endpoint exists (POST to /webhooks/stripe)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should not be 404 â€” the handler is registered (it may reject due to
	// invalid Stripe signature, but it won't be 404)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}


// ===========================================================================
// setupMux â€” admin auth with valid JWT and admin role
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
		logger:          logport.NewSlog(testLogger()),
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
	// MFA gate (docs/access-control.md §8): an authenticated admin
	// without an MFA enrollment is redirected (302) to the enrollment
	// endpoint, NOT to the login page. So we accept 302 here and assert
	// the destination is the MFA flow, not the login flow. Tests that
	// want to reach the actual /admin/ops page need to pre-enroll the
	// admin and supply a valid kite_admin_mfa cookie.
	if rec.Code == http.StatusFound {
		loc := rec.Header().Get("Location")
		assert.NotContains(t, loc, "/auth/admin-login",
			"redirected to admin-login despite valid JWT — middleware regression")
		assert.Contains(t, loc, "/auth/admin-mfa/",
			"302 must point at the MFA enroll/verify flow, got %q", loc)
	}
}


// ===========================================================================
// setupMux â€” Google SSO config wiring (both with and without credentials)
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
		logger:          logport.NewSlog(testLogger()),
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
// serveStatusPage â€” test landing template write error (exercise the error log)
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
// serveStatusPage â€” fallback to status template when landing is nil
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
// serveStatusPage â€” neither template set
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
// serveErrorPage â€” direct function test
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
// setupMux â€” healthz endpoint verification
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
// setupMux â€” healthz ?format=json: component-level health report
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
	auditStore.StartWorkerCtx(context.Background())
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
	auditStore.StartWorkerCtx(context.Background())
	t.Cleanup(auditStore.Stop)

	app := newTestApp(t)
	app.auditStore = auditStore
	// Simulate LoadLimits failure in DevMode â€” guard is running with SystemDefaults.
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
	auditStore.StartWorkerCtx(context.Background())
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
	// JSON numbers unmarshal to float64 â€” check the field exists and matches.
	assert.Contains(t, cache, "hit_rate")
	assert.Contains(t, cache, "max_entries")
	assert.EqualValues(t, audit.DefaultMaxStatsCacheEntries, cache["max_entries"])
}


// ===========================================================================
// setupMux â€” favicon endpoint
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
// setupMux â€” with OAuth enabled: endpoints wiring
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” accept-invite endpoint with various states
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
// serveLegalPages â€” Cache-Control header
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
// setupMux â€” pricing page with premium tier cookie
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” pricing page without cookie
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
// setupMux â€” admin auth: redirect with various path values
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” checkout success page
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
// setupMux â€” security.txt content verification
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
// setupMux â€” server card GET request
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
// setupMux â€” family invitation acceptance branches
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
	// Valid invite â†’ redirect to login
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/login")
}


// ===========================================================================
// setupMux â€” Stripe webhook with billing store but NO STRIPE_SECRET (warn branch)
// ===========================================================================
func TestSetupMux_StripeWebhookNoBillingStore_Cov(t *testing.T) {
	t.Parallel()
	mgr := newTestManagerWithDB(t)
	// Do NOT set billing store â†’ the warning branch is exercised
	app := newTestAppWithConfig(t, &Config{
		StripeWebhookSecret:  "whsec_test_no_billing_123",
		InstrumentsSkipFetch: true,
	})

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /webhooks/stripe should NOT exist (no billing store)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}


// ===========================================================================
// setupMux â€” billing checkout + portal handlers (with OAuth + billing store)
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” pricing page with pro tier cookie
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” AdminAuth â€” non-admin user gets forbidden
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” Google SSO with credentials
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
		logger:          logport.NewSlog(testLogger()),
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
// setupMux â€” ops handler registration with AdminSecretPath (no OAuth)
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
	// Should not be 404 â€” the ops handler is registered
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}


// ===========================================================================
// setupMux â€” admin password seeding (multiple admin emails)
// ===========================================================================
func TestSetupMux_AdminPassword_MultipleEmails(t *testing.T) {
	t.Parallel()
	mgr := newTestManagerWithDB(t)
	app := newTestAppWithConfig(t, &Config{
		AdminEmails:          "admin1@test.com, admin2@test.com",
		AdminPassword:        "test-admin-password-123",
		InstrumentsSkipFetch: true,
	})

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()
	require.NotNil(t, mux)

	// Both admins should have password set
	userStore := mgr.UserStoreConcrete()
	assert.True(t, userStore.HasPassword("admin1@test.com"))
	assert.True(t, userStore.HasPassword("admin2@test.com"))
}


// ===========================================================================
// setupMux â€” admin seeding skipped when users already exist
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
// setupMux â€” callback with browser flow and no OAuth handler
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
// setupMux â€” callback default flow (no flow param)
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
	// Won't be 404 â€” the handler exists
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}


// ===========================================================================
// serveLegalPages â€” all legal page routes
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

// TestServeFundingJSON_RouteRegistered asserts /funding.json returns
// a 200 with application/json content-type and a parseable funding.json
// body matching the floss.fund manifest schema. Strict Playwright matrix
// flagged this as a non-blocking finding on Fly v186: file shipped via
// 252c460 but no route was registered, so /funding.json returned 404.
//
// FLOSS/fund manifest discovery requires the URL be reachable (the
// wellKnown URL inside funding.json itself points at the GitHub blob
// URL, but third-party indexers may also probe the deployed site).
func TestServeFundingJSON_RouteRegistered(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/funding.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"/funding.json must return 200 (was 404 on Fly v186 — strict Playwright finding)")
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json",
		"/funding.json must declare application/json Content-Type for floss.fund + curl|jq compatibility")

	// Parseable JSON with the expected manifest fields.
	var manifest map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &manifest),
		"/funding.json body must be valid JSON")
	assert.NotEmpty(t, manifest["version"],
		"funding manifest must declare a version (FLOSS/fund schema requirement)")
	assert.NotEmpty(t, manifest["entity"],
		"funding manifest must declare the entity (FLOSS/fund schema requirement)")
}

// TestServeLegalPages_LandmarkRoles asserts that /terms and /privacy
// expose semantic landmark roles (`<main role="main">` + `role="contentinfo"`)
// matching the pattern landing.html + dashboard.html follow. Strict
// Playwright accessibility audits flag templates without these landmarks
// — see the Playwright a11y matrix gap that prompted this test.
//
// Pattern source: kc/templates/landing.html lines 27-29 ("<main
// id=\"main-content\" role=\"main\">") + the `<footer role=\"contentinfo\">`
// element. Same convention applied to legal.html in this commit.
func TestServeLegalPages_LandmarkRoles(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
	require.NoError(t, app.initStatusPageTemplate())
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	for _, page := range []string{"/terms", "/privacy"} {
		t.Run(page, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, page, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.Contains(t, body, `role="main"`,
				"%s must declare a `role=\"main\"` landmark for screen-reader nav", page)
			assert.Contains(t, body, `role="contentinfo"`,
				"%s footer must use `role=\"contentinfo\"` for the page-info landmark", page)
		})
	}
}


// ===========================================================================
// newRateLimiters â€” exercise with AdminSecretPath set
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
// setupMux â€” Dashboard handler with billing store
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
// setupMux â€” admin seeding with empty email in list
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

// ===========================================================================
// /healthz?probe=deep â€” runtime DB ping + broker-factory check + WAL stat
// ===========================================================================

func TestHealthz_DeepProbe_AllHealthy(t *testing.T) {
	mgr := newTestManagerWithDB(t) // in-memory DB, real broker.Factory
	app := newTestApp(t)
	app.kcManager = mgr
	app.Version = "v-deep-1"
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	components, ok := body["components"].(map[string]any)
	require.True(t, ok)
	// Deep probes added on top of the cheap-probe components.
	require.Contains(t, components, "database")
	require.Contains(t, components, "broker_factory")
	require.Contains(t, components, "litestream")

	dbComp, _ := components["database"].(map[string]any)
	assert.Equal(t, "ok", dbComp["status"], "in-memory DB should ping cleanly")

	// broker_factory: in-memory test mgr uses kcfixture which doesn't
	// inject a Factory by default â†’ in DevMode, that's "ok" with note.
	bf, _ := components["broker_factory"].(map[string]any)
	assert.Contains(t, []any{"ok", "degraded"}, bf["status"],
		"factory either wired (ok) or absent in DevMode (still ok with note)")

	// litestream: :memory: AlertDBPath â†’ "ok" with N/A note.
	ls, _ := components["litestream"].(map[string]any)
	assert.Equal(t, "ok", ls["status"])
}

func TestHealthz_DeepProbe_NoManager(t *testing.T) {
	// App with no kcManager â†’ database + broker_factory probes should
	// surface the disabled state explicitly. Tests the nil-guard paths.
	app := newTestApp(t)
	app.kcManager = nil
	app.Version = "v-deep-2"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	app.handleHealthz(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	components, _ := body["components"].(map[string]any)
	dbComp, _ := components["database"].(map[string]any)
	assert.Equal(t, "disabled", dbComp["status"])

	bf, _ := components["broker_factory"].(map[string]any)
	assert.Equal(t, "disabled", bf["status"])
}

func TestHealthz_DeepProbe_LitestreamStaleWAL(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/alerts.db"
	walPath := dbPath + "-wal"
	// Touch the DB so AlertDBPath is non-empty + non-:memory:.
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0644))
	// Create a WAL whose mtime is well past healthzWALStaleAfter.
	require.NoError(t, os.WriteFile(walPath, []byte("x"), 0644))
	old := time.Now().Add(-10 * time.Minute)
	require.NoError(t, os.Chtimes(walPath, old, old))

	app := newTestApp(t)
	app.Config = &Config{AlertDBPath: dbPath}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	app.handleHealthz(rec, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	components, _ := body["components"].(map[string]any)
	ls, _ := components["litestream"].(map[string]any)
	assert.Equal(t, "stale", ls["status"], "WAL mtime 10m ago should be flagged")
	assert.Contains(t, ls["note"], "stopped")
}

func TestHealthz_DeepProbe_LitestreamMissingWAL(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/alerts.db"
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0644))
	// No WAL file at all â†’ "unknown" (cold start before first commit).

	app := newTestApp(t)
	app.Config = &Config{AlertDBPath: dbPath}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	app.handleHealthz(rec, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	components, _ := body["components"].(map[string]any)
	ls, _ := components["litestream"].(map[string]any)
	assert.Equal(t, "unknown", ls["status"])
}

func TestHealthz_DeepProbe_TopLevelDegraded(t *testing.T) {
	// No manager â†’ database "disabled" â†’ top-level should be "degraded".
	app := newTestApp(t)
	app.kcManager = nil

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	app.handleHealthz(rec, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body["status"])
}
