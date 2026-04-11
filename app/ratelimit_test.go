package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Contains(t, s, "Kite MCP Server")
	assert.Contains(t, s, "SEBI")
	assert.Contains(t, s, "Limitation of Liability")
	assert.Contains(t, s, "Governing Law")
	assert.Contains(t, s, "Chennai, Tamil Nadu, India")
}

func TestPrivacyHTML_ContainsKeyContent(t *testing.T) {
	s := string(privacyHTML)
	assert.Contains(t, s, "Privacy Policy")
	assert.Contains(t, s, "Data Fiduciary")
	assert.Contains(t, s, "AES-256-GCM")
	assert.Contains(t, s, "DPDP Act")
	assert.Contains(t, s, "Right to Erasure")
	assert.Contains(t, s, "Mumbai")
}

// ===========================================================================
// Config defaults and loading tests
// ===========================================================================

func TestLoadConfig_OAuthWithoutExternalURL(t *testing.T) {
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret")
	t.Setenv("EXTERNAL_URL", "")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when OAUTH_JWT_SECRET is set without EXTERNAL_URL")
	}
	assert.Contains(t, err.Error(), "EXTERNAL_URL")
}

func TestLoadConfig_OAuthWithExternalURL(t *testing.T) {
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret")
	t.Setenv("EXTERNAL_URL", "https://example.com")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	// Should succeed: OAuth mode with per-user credentials
	assert.NoError(t, err)
}

func TestLoadConfig_CustomPortAndHost(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("APP_PORT", "9090")
	t.Setenv("APP_HOST", "0.0.0.0")
	t.Setenv("APP_MODE", "sse")

	app := NewApp(testLogger())
	err := app.LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "9090", app.Config.AppPort)
	assert.Equal(t, "0.0.0.0", app.Config.AppHost)
	assert.Equal(t, "sse", app.Config.AppMode)
}

func TestSetLogBuffer(t *testing.T) {
	app := NewApp(testLogger())
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
	app := NewApp(testLogger())
	app.Config.AppHost = "0.0.0.0"
	app.Config.AppPort = "9090"
	assert.Equal(t, "0.0.0.0:9090", app.buildServerURL())
}

func TestBuildServerURL_Default(t *testing.T) {
	t.Setenv("KITE_API_KEY", "k")
	t.Setenv("KITE_API_SECRET", "s")
	app := NewApp(testLogger())
	_ = app.LoadConfig()
	assert.Equal(t, "localhost:8080", app.buildServerURL())
}

// ===========================================================================
// createHTTPServer tests
// ===========================================================================

func TestCreateHTTPServer(t *testing.T) {
	app := NewApp(testLogger())
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
	app := NewApp(testLogger())
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
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
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
	app := NewApp(testLogger())
	assert.False(t, app.startTime.IsZero())
}

func TestAppDevMode(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	app := NewApp(testLogger())
	assert.True(t, app.DevMode)
}

func TestAppDevMode_False(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	app := NewApp(testLogger())
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

func TestLoadConfig_AllEnvVars(t *testing.T) {
	t.Setenv("KITE_API_KEY", "key")
	t.Setenv("KITE_API_SECRET", "secret")
	t.Setenv("KITE_ACCESS_TOKEN", "token")
	t.Setenv("APP_MODE", "hybrid")
	t.Setenv("APP_PORT", "3000")
	t.Setenv("APP_HOST", "0.0.0.0")
	t.Setenv("OAUTH_JWT_SECRET", "jwt-secret")
	t.Setenv("EXTERNAL_URL", "https://example.com")
	t.Setenv("TELEGRAM_BOT_TOKEN", "bot-token")
	t.Setenv("ALERT_DB_PATH", "/tmp/test.db")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")

	app := NewApp(testLogger())
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

// ===========================================================================
// getStatusData tests
// ===========================================================================

func TestGetStatusData(t *testing.T) {
	app := NewApp(testLogger())
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

func TestNewApp_ConfigFromEnv(t *testing.T) {
	t.Setenv("KITE_API_KEY", "env_key")
	t.Setenv("KITE_API_SECRET", "env_secret")
	t.Setenv("ADMIN_ENDPOINT_SECRET_PATH", "/secret/path")
	t.Setenv("GOOGLE_CLIENT_ID", "google-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "google-secret")

	app := NewApp(testLogger())
	assert.Equal(t, "env_key", app.Config.KiteAPIKey)
	assert.Equal(t, "env_secret", app.Config.KiteAPISecret)
	assert.Equal(t, "/secret/path", app.Config.AdminSecretPath)
	assert.Equal(t, "google-id", app.Config.GoogleClientID)
	assert.Equal(t, "google-secret", app.Config.GoogleClientSecret)
}
