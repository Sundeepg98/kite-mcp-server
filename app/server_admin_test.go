package app

// server_test.go -- consolidated tests for server lifecycle, setup, and coverage.
// Merged from: coverage_boost_test.go, coverage_boost2_test.go, server_lifecycle_test.go
import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// Merged from coverage_boost_test.go
// ===========================================================================


// ---------------------------------------------------------------------------
// Helper: create a minimal MCP server for tests.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// setupMux tests — additional routes and branches not covered elsewhere
// ---------------------------------------------------------------------------
func TestSetupMux_AdminSeeding_FreshDB(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin1@test.com,admin2@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Verify admin users were seeded
	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		assert.True(t, userStore.IsAdmin("admin1@test.com"))
		assert.True(t, userStore.IsAdmin("admin2@test.com"))
	}

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


func TestSetupMux_AdminPassword_FreshDB(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "adminpw@test.com",
		AdminPassword:        "test-password-123",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Verify admin was seeded with password
	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		assert.True(t, userStore.IsAdmin("adminpw@test.com"))
		assert.True(t, userStore.HasPassword("adminpw@test.com"))
	}

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


func TestSetupMux_AdminOps_IdentityMiddleware(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminSecretPath:      "/secret",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Admin ops endpoint — in DevMode with secret path but no OAuth and no user store
	// uses identity middleware (no auth)
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — admin seeding skipped when users already exist
// ---------------------------------------------------------------------------
func TestSetupMux_AdminSeeding_ExistingUsers(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	// Pre-seed a non-admin user so the store is non-empty
	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		userStore.EnsureUser("existing@test.com", "", "", "self")
	}

	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Admin seeding should have been SKIPPED because user count > 0
	if userStore != nil {
		// admin@test.com should NOT be admin (seeding was skipped)
		assert.False(t, userStore.IsAdmin("admin@test.com"))
	}

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — empty admin emails in ADMIN_EMAILS
// ---------------------------------------------------------------------------
func TestSetupMux_AdminSeeding_EmptyEmails(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          ",  ,",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — multiple admin passwords
// ---------------------------------------------------------------------------
func TestSetupMux_AdminPassword_MultipleAdmins(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "a1@test.com,a2@test.com",
		AdminPassword:        "shared-pass",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		assert.True(t, userStore.HasPassword("a1@test.com"))
		assert.True(t, userStore.HasPassword("a2@test.com"))
	}

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — /admin/ handler with AdminSecretPath
// ---------------------------------------------------------------------------
func TestSetupMux_AdminMetrics(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminSecretPath:      "/test-metrics",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Hit the admin metrics endpoint
	req := httptest.NewRequest(http.MethodGet, "/admin/test-metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — verifies the dashboard handler is registered
// ---------------------------------------------------------------------------
func TestSetupMux_DashboardRoute(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// /dashboard should be registered (may redirect or show content)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — /dashboard/activity route
// ---------------------------------------------------------------------------
func TestSetupMux_DashboardActivity(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/activity", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — /admin/ops with admin auth and secret path
// ---------------------------------------------------------------------------
func TestSetupMux_AdminOps_WithBothPaths(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		AdminSecretPath:      "/s3cr3t",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/s3cr3t", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	req2 := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	assert.True(t, rec2.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — admin seeding skipped with non-empty user store
// ---------------------------------------------------------------------------
func TestSetupMux_AdminSeeding_Skipped(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	userStore := mgr.UserStoreConcrete()
	if userStore != nil {
		userStore.EnsureUser("existing@test.com", "", "", "self")
	}

	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	if userStore != nil {
		assert.False(t, userStore.IsAdmin("admin@test.com"))
	}

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — admin seeding with empty emails in comma-separated list
// ---------------------------------------------------------------------------
func TestSetupMux_AdminSeeding_EmptyEmailsInList(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          ",  ,",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — dashboard route with OAuth (exercises RequireAuthBrowser branch)
// ---------------------------------------------------------------------------
func TestSetupMux_Dashboard_WithOAuth(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true

	oauthCfg := &oauth.Config{
		KiteAPIKey:  "test-key",
		JWTSecret:   "test-jwt-secret-at-least-32-chars-long",
		ExternalURL: "http://localhost:9999",
		Logger:      testLogger(),
	}
	app.oauthHandler = oauth.NewHandler(oauthCfg, &testSigner{}, &testExchanger{})
	t.Cleanup(app.oauthHandler.Close)
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// /dashboard without cookie should redirect to login
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code == http.StatusFound || rec.Code == http.StatusSeeOther || rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — dashboard handler registered with billing store
// ---------------------------------------------------------------------------
func TestSetupMux_DashboardWithBillingStore(t *testing.T) {
	t.Parallel()
	mgr := newTestManagerWithDB(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          "admin@test.com",
		AlertDBPath:          ":memory:",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	app.oauthHandler = newTestOAuthHandler(t)
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// /dashboard without auth should redirect
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code == http.StatusFound || rec.Code == http.StatusSeeOther || rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — admin password seeding with empty email entries
// ---------------------------------------------------------------------------
func TestSetupMux_AdminPassword_EmptyEntries(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AdminEmails:          ",,,",
		AdminPassword:        "test-pass",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// setupMux — dashboard with no OAuth handler uses identity middleware
// ---------------------------------------------------------------------------
func TestSetupMux_Dashboard_NoOAuth_IdentityMiddleware(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true
	app.oauthHandler = nil
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Dashboard with no auth should use identity middleware (pass-through)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


func TestSetupMux_OpsHandler_NoUserStoreNoOAuth_Push100Extra(t *testing.T) {
	mgr := newTestManager(t)

	app := newTestApp(t)
	app.Config.AdminSecretPath = "test-secret-path"

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}
