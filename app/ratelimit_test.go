package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/oauth"
	"golang.org/x/time/rate"
)

// ===========================================================================
// ipRateLimiter tests
// ===========================================================================

func TestNewIPRateLimiter(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 20)
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.limiters)
	assert.Equal(t, rate.Limit(10), rl.rate)
	assert.Equal(t, 20, rl.burst)
}

func TestIPRateLimiter_GetLimiter(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 20)

	// First call creates a new limiter
	l1 := rl.getLimiter("192.168.1.1")
	assert.NotNil(t, l1)

	// Second call returns the same limiter
	l2 := rl.getLimiter("192.168.1.1")
	assert.Same(t, l1, l2)

	// Different IP gets a different limiter
	l3 := rl.getLimiter("192.168.1.2")
	assert.NotNil(t, l3)
	assert.NotSame(t, l1, l3)
}

func TestIPRateLimiter_Cleanup(t *testing.T) {
	rl := newIPRateLimiter(rate.Limit(10), 20)

	_ = rl.getLimiter("192.168.1.1")
	_ = rl.getLimiter("192.168.1.2")

	// Cleanup clears all limiters
	rl.cleanup()

	// After cleanup, getting a limiter creates a new one
	rl.mu.RLock()
	count := len(rl.limiters)
	rl.mu.RUnlock()
	assert.Equal(t, 0, count)
}

// ===========================================================================
// rateLimiters (the composite struct) tests
// ===========================================================================

func TestNewRateLimiters(t *testing.T) {
	rl := newRateLimiters()
	require.NotNil(t, rl)
	assert.NotNil(t, rl.auth)
	assert.NotNil(t, rl.token)
	assert.NotNil(t, rl.mcp)
	assert.NotNil(t, rl.done)

	// Stop the background goroutine
	rl.Stop()
}

func TestNewRateLimiters_Stop(t *testing.T) {
	rl := newRateLimiters()
	// Stop should not panic even when called immediately
	rl.Stop()
}

// ===========================================================================
// rateLimit middleware tests
// ===========================================================================

func TestRateLimit_AllowsRequests(t *testing.T) {
	limiter := newIPRateLimiter(rate.Limit(100), 200)
	handler := rateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRateLimit_BlocksExcessRequests(t *testing.T) {
	// Very tight rate limit: 1 request per second, burst of 1
	limiter := newIPRateLimiter(rate.Limit(1), 1)
	handler := rateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request (immediately after) should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
}

// ===========================================================================
// userRateLimiter tests
// ===========================================================================

func TestNewUserRateLimiter(t *testing.T) {
	rl := newUserRateLimiter(rate.Limit(10), 20)
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.limiters)
	assert.Equal(t, rate.Limit(10), rl.rate)
	assert.Equal(t, 20, rl.burst)
}

func TestUserRateLimiter_GetLimiter(t *testing.T) {
	rl := newUserRateLimiter(rate.Limit(10), 20)

	// Same email returns the same limiter
	l1 := rl.getLimiter("alice@example.com")
	l2 := rl.getLimiter("alice@example.com")
	assert.Same(t, l1, l2)

	// Different email returns a different limiter
	l3 := rl.getLimiter("bob@example.com")
	assert.NotSame(t, l1, l3)
}

func TestUserRateLimiter_Cleanup(t *testing.T) {
	rl := newUserRateLimiter(rate.Limit(10), 20)
	_ = rl.getLimiter("a@x.com")
	_ = rl.getLimiter("b@x.com")
	rl.cleanup()
	rl.mu.RLock()
	count := len(rl.limiters)
	rl.mu.RUnlock()
	assert.Equal(t, 0, count)
}

// rateLimitUser must pass through when there is no authenticated email in ctx
// (fail open on the user scope — the IP scope remains in effect upstream).
func TestRateLimitUser_NoEmailPassesThrough(t *testing.T) {
	limiter := newUserRateLimiter(rate.Limit(1), 1)
	handler := rateLimitUser(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Five back-to-back requests with no email context: all must pass.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should pass without email", i)
	}
}

// rateLimitUser must block when the same authenticated user hammers the
// endpoint, regardless of source IP (this is the botnet/VPN defense scenario).
func TestRateLimitUser_BlocksSameUserAcrossIPs(t *testing.T) {
	limiter := newUserRateLimiter(rate.Limit(1), 1)
	handler := rateLimitUser(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from IP1 as alice: ok.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "1.1.1.1:1000"
	req1 = req1.WithContext(oauth.ContextWithEmail(req1.Context(), "alice@example.com"))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request from a completely different IP as alice: blocked with
	// X-RateLimit-Scope=user header so clients can distinguish the cause.
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "9.9.9.9:2000"
	req2 = req2.WithContext(oauth.ContextWithEmail(req2.Context(), "alice@example.com"))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Equal(t, "user", rec2.Header().Get("X-RateLimit-Scope"))

	// Third request as bob: fresh limiter, still ok.
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.RemoteAddr = "9.9.9.9:2000"
	req3 = req3.WithContext(oauth.ContextWithEmail(req3.Context(), "bob@example.com"))
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
}

// Confirms that the composite rateLimiters struct exposes the per-user
// limiters with matching defaults (parity with IP-layer tiers).
func TestNewRateLimiters_IncludesUserLimiters(t *testing.T) {
	rl := newRateLimiters()
	defer rl.Stop()
	assert.NotNil(t, rl.authUser)
	assert.NotNil(t, rl.tokenUser)
	assert.NotNil(t, rl.mcpUser)
	assert.Equal(t, rate.Limit(2), rl.authUser.rate)
	assert.Equal(t, 5, rl.authUser.burst)
	assert.Equal(t, rate.Limit(5), rl.tokenUser.rate)
	assert.Equal(t, 10, rl.tokenUser.burst)
	assert.Equal(t, rate.Limit(20), rl.mcpUser.rate)
	assert.Equal(t, 40, rl.mcpUser.burst)
}

func TestRateLimit_UsesFlyClientIP(t *testing.T) {
	limiter := newIPRateLimiter(rate.Limit(1), 1)
	handler := rateLimit(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from IP A via Fly-Client-IP header succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	req1.Header.Set("Fly-Client-IP", "1.2.3.4")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request from same Fly-Client-IP should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	req2.Header.Set("Fly-Client-IP", "1.2.3.4")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)

	// Different Fly-Client-IP should succeed (different rate limiter)
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.RemoteAddr = "127.0.0.1:12345"
	req3.Header.Set("Fly-Client-IP", "5.6.7.8")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
}

// ===========================================================================
// Pricing page HTML content tests
// ===========================================================================

func TestPricingPageHTML_ContainsTiers(t *testing.T) {
	assert.Contains(t, pricingPageHTML, "Free")
	assert.Contains(t, pricingPageHTML, "Solo Pro")
	assert.Contains(t, pricingPageHTML, "Family Pro")
	assert.Contains(t, pricingPageHTML, "Premium")
}

func TestPricingPageHTML_ContainsPrices(t *testing.T) {
	assert.Contains(t, pricingPageHTML, "\u20B9199")
	assert.Contains(t, pricingPageHTML, "\u20B9349")
	assert.Contains(t, pricingPageHTML, "\u20B9699")
	assert.Contains(t, pricingPageHTML, "\u20B90")
}

func TestPricingPageHTML_ContainsFeatures(t *testing.T) {
	assert.Contains(t, pricingPageHTML, "Live order execution")
	assert.Contains(t, pricingPageHTML, "GTT orders")
	assert.Contains(t, pricingPageHTML, "Price alerts")
	assert.Contains(t, pricingPageHTML, "Trailing stops")
	assert.Contains(t, pricingPageHTML, "Backtesting")
	assert.Contains(t, pricingPageHTML, "Options strategies")
}

func TestPricingPageHTML_IsValidHTML(t *testing.T) {
	assert.True(t, strings.Contains(pricingPageHTML, "<!DOCTYPE html>"))
	assert.True(t, strings.Contains(pricingPageHTML, "</html>"))
	assert.True(t, strings.Contains(pricingPageHTML, "<title>"))
}

func TestPricingPageHTML_ContainsCheckoutFunction(t *testing.T) {
	assert.Contains(t, pricingPageHTML, "function checkout(plan)")
}

// ===========================================================================
// Checkout success page HTML content tests
// ===========================================================================

func TestCheckoutSuccessHTML_ContainsTitle(t *testing.T) {
	assert.Contains(t, checkoutSuccessHTML, "Welcome to Pro")
}

func TestCheckoutSuccessHTML_ContainsDashboardLink(t *testing.T) {
	assert.Contains(t, checkoutSuccessHTML, "Go to Dashboard")
	assert.Contains(t, checkoutSuccessHTML, `/dashboard"`)
}

func TestCheckoutSuccessHTML_ContainsManageLink(t *testing.T) {
	assert.Contains(t, checkoutSuccessHTML, "Manage Subscription")
	assert.Contains(t, checkoutSuccessHTML, `/dashboard/billing"`)
}

func TestCheckoutSuccessHTML_ContainsFeatures(t *testing.T) {
	assert.Contains(t, checkoutSuccessHTML, "Live order execution")
	assert.Contains(t, checkoutSuccessHTML, "GTT orders")
	assert.Contains(t, checkoutSuccessHTML, "Price alerts")
	assert.Contains(t, checkoutSuccessHTML, "family members")
}

func TestCheckoutSuccessHTML_IsValidHTML(t *testing.T) {
	assert.True(t, strings.Contains(checkoutSuccessHTML, "<!DOCTYPE html>"))
	assert.True(t, strings.Contains(checkoutSuccessHTML, "</html>"))
}

// ===========================================================================
// Legal content tests
// ===========================================================================

func TestTermsHTML_ContainsKeyContent(t *testing.T) {
	s := string(termsHTML)
	assert.Contains(t, s, "Terms of Service")
	assert.Contains(t, s, "kite-mcp-server")
	assert.Contains(t, s, "SEBI")
	assert.Contains(t, s, "Limitation of liability")
	assert.Contains(t, s, "Governing law")
	assert.Contains(t, s, "Bengaluru")
}

func TestPrivacyHTML_ContainsKeyContent(t *testing.T) {
	s := string(privacyHTML)
	assert.Contains(t, s, "Privacy Notice")
	assert.Contains(t, s, "Data Fiduciary")
	assert.Contains(t, s, "AES-256-GCM")
	assert.Contains(t, s, "DPDP Act")
	assert.Contains(t, s, "Erase")
	assert.Contains(t, s, "Mumbai")
}

// ===========================================================================
// Config defaults and loading tests
// ===========================================================================

func TestLoadConfig_OAuthWithoutExternalURL(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		OAuthJWTSecret: "test-jwt-secret",
	})
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when OAUTH_JWT_SECRET is set without EXTERNAL_URL")
	}
	assert.Contains(t, err.Error(), "EXTERNAL_URL")
}

func TestLoadConfig_OAuthWithExternalURL(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		OAuthJWTSecret: "test-jwt-secret",
		ExternalURL:    "https://example.com",
	})
	err := app.LoadConfig()

	// Should succeed: OAuth mode with per-user credentials
	assert.NoError(t, err)
}

func TestLoadConfig_CustomPortAndHost(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
		AppPort:       "9090",
		AppHost:       "0.0.0.0",
		AppMode:       "sse",
	})
	err := app.LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "9090", app.Config.AppPort)
	assert.Equal(t, "0.0.0.0", app.Config.AppHost)
	assert.Equal(t, "sse", app.Config.AppMode)
}

func TestSetLogBuffer(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})
	// SetLogBuffer should not panic with nil
	app.SetLogBuffer(nil)
	assert.Nil(t, app.logBuffer)
}

func TestConstants(t *testing.T) {
	// Verify server mode constants are defined correctly
	assert.Equal(t, "sse", ModeSSE)
	assert.Equal(t, "stdio", ModeStdIO)
	assert.Equal(t, "http", ModeHTTP)
	assert.Equal(t, "hybrid", ModeHybrid)
	assert.Equal(t, "8080", DefaultPort)
	assert.Equal(t, "localhost", DefaultHost)
	assert.Equal(t, "http", DefaultAppMode)
}

func TestCookieName(t *testing.T) {
	assert.Equal(t, "kite_jwt", cookieName)
}

// ===========================================================================
// buildServerURL tests
// ===========================================================================

func TestBuildServerURL(t *testing.T) {
	app := newTestApp(t)
	app.Config.AppHost = "0.0.0.0"
	app.Config.AppPort = "9090"
	assert.Equal(t, "0.0.0.0:9090", app.buildServerURL())
}

func TestBuildServerURL_Default(t *testing.T) {
	t.Parallel()
	// Phase E.2 Task #42: config literal replaces t.Setenv. Defaults
	// applied via WithDefaults so AppHost/AppPort get their production
	// fallbacks — that's the point of "default" in this test.
	app := newTestAppWithConfig(t, (&Config{
		KiteAPIKey:    "k",
		KiteAPISecret: "s",
	}).WithDefaults())
	assert.Equal(t, "localhost:8080", app.buildServerURL())
}

// ===========================================================================
// createHTTPServer tests
// ===========================================================================

func TestCreateHTTPServer(t *testing.T) {
	app := newTestApp(t)
	srv := app.createHTTPServer("localhost:8080")
	assert.NotNil(t, srv)
	assert.Equal(t, "localhost:8080", srv.Addr)
	assert.True(t, srv.ReadHeaderTimeout > 0)
	assert.True(t, srv.WriteTimeout > 0)
}

// ===========================================================================
// securityHeaders middleware test
// ===========================================================================

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "max-age=")
	assert.NotEmpty(t, rec.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
	assert.NotEmpty(t, rec.Header().Get("Permissions-Policy"))
}

// ===========================================================================
// configureHTTPClient smoke test
// ===========================================================================

func TestConfigureHTTPClient(t *testing.T) {
	app := newTestApp(t)
	// Should not panic
	app.configureHTTPClient()
}

// ===========================================================================
// startServer additional modes
// ===========================================================================

func TestStartServer_HybridMode_Invalid(t *testing.T) {
	// Hybrid mode with nil manager should return an error, not panic
	// We only test invalid mode here (other modes need full setup)
	app := &App{
		Config: &Config{AppMode: "unknown_mode"},
		logger: testLogger(),
	}
	err := app.startServer(nil, nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid APP_MODE")
}

// ===========================================================================
// DevMode tests
// ===========================================================================

func TestLoadConfig_DevMode(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		// Empty Kite credentials — DevMode allows this.
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	err := app.LoadConfig()
	// DevMode allows missing credentials
	assert.NoError(t, err)
}

// ===========================================================================
// StatusPageData struct test
// ===========================================================================

func TestStatusPageData(t *testing.T) {
	data := StatusPageData{
		Title:        "Kite MCP Server",
		Version:      "v1.0.0",
		Mode:         "http",
		OAuthEnabled: true,
		ToolCount:    80,
	}
	assert.Equal(t, "v1.0.0", data.Version)
	assert.Equal(t, 80, data.ToolCount)
}

// ===========================================================================
// App version and init tests
// ===========================================================================

func TestAppStartTime(t *testing.T) {
	app := newTestApp(t)
	assert.False(t, app.startTime.IsZero())
}

// TestAppDevMode_FromConfig verifies the Config.DevMode → App.DevMode
// wiring. cfg.DevMode is now the single source of truth (populated
// upstream by ConfigFromMap reading DEV_MODE from the env), so tests
// drop t.Setenv and run with t.Parallel.
func TestAppDevMode_FromConfig(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{DevMode: true, InstrumentsSkipFetch: true})
	assert.True(t, app.DevMode)
}

// TestAppDevMode_FromConfig_FalseDefault verifies the zero value is
// honoured: a Config with DevMode unset means the App is NOT in dev mode.
func TestAppDevMode_FromConfig_FalseDefault(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})
	assert.False(t, app.DevMode)
}

// ===========================================================================
// httpClient package-level variable test
// ===========================================================================

func TestHttpClientTimeout(t *testing.T) {
	// Verify the package-level HTTP client has a timeout
	assert.True(t, httpClient.Timeout > 0)
}

// ===========================================================================
// truncKey tests
// ===========================================================================

func TestTruncKey(t *testing.T) {
	assert.Equal(t, "abc", truncKey("abcdef", 3))
	assert.Equal(t, "ab", truncKey("ab", 5))
	assert.Equal(t, "", truncKey("", 3))
	assert.Equal(t, "hello", truncKey("hello", 5))
	assert.Equal(t, "he", truncKey("hello", 2))
}

// ===========================================================================
// serveErrorPage tests
// ===========================================================================

func TestServeErrorPage_404(t *testing.T) {
	rec := httptest.NewRecorder()
	serveErrorPage(rec, http.StatusNotFound, "Page Not Found", "Doesn't exist")

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "Page Not Found")
	assert.Contains(t, rec.Body.String(), "Doesn't exist")
}

func TestServeErrorPage_500(t *testing.T) {
	rec := httptest.NewRecorder()
	serveErrorPage(rec, http.StatusInternalServerError, "Server Error", "Something went wrong")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Server Error")
	assert.Contains(t, rec.Body.String(), "Something went wrong")
	assert.Contains(t, rec.Body.String(), "Home")
}

// TestServeErrorPage_500_UsesDashboardBaseCSS asserts the 500 path renders
// the styled template (referencing /static/dashboard-base.css) rather than
// the plain-text http.Error fallback. Prevents regression to bare
// "Internal server error" text on HTML-rendering paths.
func TestServeErrorPage_500_UsesDashboardBaseCSS(t *testing.T) {
	rec := httptest.NewRecorder()
	serveErrorPage(rec, http.StatusInternalServerError, "Server Error", "Something went wrong")

	body := rec.Body.String()
	assert.Contains(t, body, "/static/dashboard-base.css",
		"500 page must reference the design-system stylesheet")
	assert.Contains(t, body, "var(--text-0)",
		"500 page must use design-system color tokens, not hardcoded colors")
	assert.Contains(t, body, "var(--accent)",
		"500 page must use design-system color tokens, not hardcoded colors")
	assert.Contains(t, body, "<!DOCTYPE html>",
		"500 page must be valid HTML, not plain text")
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html",
		"500 page must declare HTML content-type")
}

// TestServeErrorPage_500_StatusCodes ensures the helper handles the full
// 5xx range — Show-HN traffic spikes can trigger 502/503/504 from upstream
// load balancers as well as 500 from in-process panics.
func TestServeErrorPage_500_StatusCodes(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{
		{http.StatusInternalServerError, "Server Error"},
		{http.StatusBadGateway, "Bad Gateway"},
		{http.StatusServiceUnavailable, "Service Unavailable"},
		{http.StatusGatewayTimeout, "Gateway Timeout"},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			rec := httptest.NewRecorder()
			serveErrorPage(rec, c.status, c.title, "Test")
			assert.Equal(t, c.status, rec.Code)
			assert.Contains(t, rec.Body.String(), c.title)
			assert.Contains(t, rec.Body.String(), "/static/dashboard-base.css")
		})
	}
}

// ===========================================================================
// withSessionType tests
// ===========================================================================

func TestWithSessionType(t *testing.T) {
	var capturedSessionType string
	handler := withSessionType("test-session", func(w http.ResponseWriter, r *http.Request) {
		// The session type is set in context via mcp.WithSessionType
		// We just verify the handler was called
		capturedSessionType = "called"
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "called", capturedSessionType)
}

// ===========================================================================
// LoadConfig edge cases
// ===========================================================================

// TestLoadConfig_AllFields verifies LoadConfig accepts a fully-populated
// Config (env values would normally land here via ConfigFromMap; this test
// exercises the LoadConfig branch on a Config built directly).
//
// Migrated from TestLoadConfig_AllEnvVars: t.Setenv removed, Config built
// via newTestAppWithConfig. Behaviour identical — LoadConfig is a pure
// function that reads from app.Config (no env reads of its own), so it
// already supports parallel testing once the env-read step is hoisted to
// the constructor. This test is now t.Parallel.
func TestLoadConfig_AllFields(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "key",
		KiteAPISecret:        "secret",
		KiteAccessToken:      "token",
		AppMode:              "hybrid",
		AppPort:              "3000",
		AppHost:              "0.0.0.0",
		OAuthJWTSecret:       "jwt-secret",
		ExternalURL:          "https://example.com",
		TelegramBotToken:     "bot-token",
		AlertDBPath:          "/tmp/test.db",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	err := app.LoadConfig()
	assert.NoError(t, err)

	assert.Equal(t, "key", app.Config.KiteAPIKey)
	assert.Equal(t, "secret", app.Config.KiteAPISecret)
	assert.Equal(t, "token", app.Config.KiteAccessToken)
	assert.Equal(t, "hybrid", app.Config.AppMode)
	assert.Equal(t, "3000", app.Config.AppPort)
	assert.Equal(t, "0.0.0.0", app.Config.AppHost)
	assert.Equal(t, "jwt-secret", app.Config.OAuthJWTSecret)
	assert.Equal(t, "https://example.com", app.Config.ExternalURL)
	assert.Equal(t, "bot-token", app.Config.TelegramBotToken)
	assert.Equal(t, "/tmp/test.db", app.Config.AlertDBPath)
	assert.Equal(t, "admin@test.com", app.Config.AdminEmails)
}

// TestConfigFromMap_AllFields exercises every field of the pure parser.
// This is the parallel-safe replacement for the env→Config wiring tests
// that previously needed t.Setenv. Tests pass a literal map; the parser
// returns a fully-populated Config without touching process env.
func TestConfigFromMap_AllFields(t *testing.T) {
	t.Parallel()
	cfg := ConfigFromMap(map[string]string{
		"KITE_API_KEY":               "key",
		"KITE_API_SECRET":            "secret",
		"KITE_ACCESS_TOKEN":          "token",
		"APP_MODE":                   "hybrid",
		"APP_PORT":                   "3000",
		"APP_HOST":                   "0.0.0.0",
		"OAUTH_JWT_SECRET":           "jwt-secret",
		"EXTERNAL_URL":               "https://example.com",
		"TELEGRAM_BOT_TOKEN":         "bot-token",
		"ALERT_DB_PATH":              "/tmp/test.db",
		"ADMIN_EMAILS":               "admin@test.com",
		"ADMIN_ENDPOINT_SECRET_PATH": "/secret/path",
		"GOOGLE_CLIENT_ID":           "google-id",
		"GOOGLE_CLIENT_SECRET":       "google-secret",
		"ENABLE_TRADING":             "true",
		"INSTRUMENTS_SKIP_FETCH":     "true",
		"ADMIN_PASSWORD":             "admin-pw",
		"STRIPE_WEBHOOK_SECRET":      "whsec",
		"STRIPE_SECRET_KEY":          "sk_test",
		"STRIPE_PRICE_PRO":           "price_pro",
		"STRIPE_PRICE_PREMIUM":       "price_prem",
	})
	assert.Equal(t, "key", cfg.KiteAPIKey)
	assert.Equal(t, "secret", cfg.KiteAPISecret)
	assert.Equal(t, "token", cfg.KiteAccessToken)
	assert.Equal(t, "hybrid", cfg.AppMode)
	assert.Equal(t, "3000", cfg.AppPort)
	assert.Equal(t, "0.0.0.0", cfg.AppHost)
	assert.Equal(t, "jwt-secret", cfg.OAuthJWTSecret)
	assert.Equal(t, "https://example.com", cfg.ExternalURL)
	assert.Equal(t, "bot-token", cfg.TelegramBotToken)
	assert.Equal(t, "/tmp/test.db", cfg.AlertDBPath)
	assert.Equal(t, "admin@test.com", cfg.AdminEmails)
	assert.Equal(t, "/secret/path", cfg.AdminSecretPath)
	assert.Equal(t, "google-id", cfg.GoogleClientID)
	assert.Equal(t, "google-secret", cfg.GoogleClientSecret)
	assert.True(t, cfg.EnableTrading)
	assert.True(t, cfg.InstrumentsSkipFetch)
	assert.Equal(t, "admin-pw", cfg.AdminPassword)
	assert.Equal(t, "whsec", cfg.StripeWebhookSecret)
	assert.Equal(t, "sk_test", cfg.StripeSecretKey)
	assert.Equal(t, "price_pro", cfg.StripePricePro)
	assert.Equal(t, "price_prem", cfg.StripePricePremium)
}

// TestConfigFromMap_BoolParsing covers the bool-flag parsing branch that
// EqualFold("true") triggers — variants with different casing all enable.
func TestConfigFromMap_BoolParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"True mixed", "True", true},
		{"empty disables", "", false},
		{"false explicit", "false", false},
		{"random word disables", "yes", false},
		{"1 disables (must be 'true')", "1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := ConfigFromMap(map[string]string{"ENABLE_TRADING": tc.raw})
			assert.Equal(t, tc.want, cfg.EnableTrading)
		})
	}
}

// ===========================================================================
// getStatusData tests
// ===========================================================================

func TestGetStatusData(t *testing.T) {
	app := newTestApp(t)
	app.Version = "v2.0.0"
	app.Config.AppMode = "hybrid"

	data := app.getStatusData()
	assert.Equal(t, "Status", data.Title)
	assert.Equal(t, "v2.0.0", data.Version)
	assert.Equal(t, "hybrid", data.Mode)
	assert.GreaterOrEqual(t, data.ToolCount, 0) // may be 0 if tools not registered
}

// ===========================================================================
// legalPageData struct test
// ===========================================================================

func TestLegalPageData(t *testing.T) {
	data := legalPageData{
		Title:   "Terms of Service",
		Content: "<h1>Terms</h1>",
	}
	assert.Equal(t, "Terms of Service", data.Title)
	assert.Contains(t, string(data.Content), "Terms")
}

// TestConfigFromMap_PartialFields verifies the parser handles a sparse
// map (most env vars unset) — every field defaults to its zero value
// without errors. Replaces TestNewApp_ConfigFromEnv (which tested the
// env→Config wiring); the wiring is now covered by ConfigFromEnv's
// trivial os.Getenv → ConfigFromMap delegation. Behaviour-per-field is
// here.
func TestConfigFromMap_PartialFields(t *testing.T) {
	t.Parallel()
	cfg := ConfigFromMap(map[string]string{
		"KITE_API_KEY":               "env_key",
		"KITE_API_SECRET":            "env_secret",
		"ADMIN_ENDPOINT_SECRET_PATH": "/secret/path",
		"GOOGLE_CLIENT_ID":           "google-id",
		"GOOGLE_CLIENT_SECRET":       "google-secret",
		// All other fields unset → zero values.
	})
	assert.Equal(t, "env_key", cfg.KiteAPIKey)
	assert.Equal(t, "env_secret", cfg.KiteAPISecret)
	assert.Equal(t, "/secret/path", cfg.AdminSecretPath)
	assert.Equal(t, "google-id", cfg.GoogleClientID)
	assert.Equal(t, "google-secret", cfg.GoogleClientSecret)
	// Unset fields default to zero
	assert.Equal(t, "", cfg.AppMode)
	assert.Equal(t, "", cfg.OAuthJWTSecret)
	assert.False(t, cfg.EnableTrading)
}

// ===========================================================================
// Merged from adapters_coverage_test.go — rate limiter concurrent test
// ===========================================================================

func TestGetLimiter_ConcurrentDoubleCheck_Push100Extra(t *testing.T) {
	limiter := newIPRateLimiter(10, 20)

	const ip = "192.168.1.100"
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			limiter.getLimiter(ip)
		}()
	}
	wg.Wait()

	l := limiter.getLimiter(ip)
	assert.NotNil(t, l)
}
