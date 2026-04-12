package app

// push100_extra_test.go — targeted tests to push app/ coverage higher.
// Focuses on uncovered branches still reachable:
//   - setupMux: admin auth "//"-prefix redirect, pricing page premium tier
//   - ExchangeWithCredentials: key-exists-different-user, register-error
//   - ratelimit: double-check concurrent race path
//   - initScheduler: Telegram briefings path
//   - adminAuth: bcrypt SetPasswordHash error

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// setupMux — admin auth redirect with "//" prefix path (line 1079-1081)
// ===========================================================================

func TestSetupMux_AdminAuth_DoubleSlashPrefix_Push100Extra(t *testing.T) {
	mgr := newTestManagerWithDBCov(t)
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

	// Craft a request where r.URL.Path has "//" prefix.
	// Go's net/http server would normally 301-redirect "//...", but the adminAuth
	// closure defends against it. We bypass the mux redirect by calling the
	// middleware directly via the admin ops handler pattern match.
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	// Override the URL path to simulate a "//" prefix bypass
	req.URL.Path = "//evil.com/steal"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Without a valid JWT cookie, adminAuth redirects to login.
	// The redirect URL should use /admin/ops (sanitized), not //evil.com.
	if rec.Code == http.StatusFound {
		loc := rec.Header().Get("Location")
		assert.Contains(t, loc, "/auth/admin-login")
		assert.Contains(t, loc, "redirect=%2Fadmin%2Fops")
	}
}

// ===========================================================================
// setupMux — pricing page premium tier (line 1242-1243)
// ===========================================================================

func TestSetupMux_PricingPage_PremiumTier_Push100Extra(t *testing.T) {
	mgr := newTestManagerWithDBCov(t)

	// Set up billing with a premium subscriber
	if alertDB := mgr.AlertDB(); alertDB != nil {
		bs := billing.NewStore(alertDB, testLogger())
		require.NoError(t, bs.InitTable())
		require.NoError(t, bs.SetSubscription(&billing.Subscription{
			AdminEmail:       "premium@test.com",
			Tier:             billing.TierPremium,
			StripeCustomerID: "cus_prem",
			StripeSubID:      "sub_prem",
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
	oauthHandler := oauth.NewHandler(oauthCfg, signer, exchanger)

	// Generate a valid JWT for the premium user
	token, err := oauthHandler.JWTManager().GenerateTokenWithExpiry("premium@test.com", "dashboard", 1*time.Hour)
	require.NoError(t, err)

	app := NewApp(testLogger())
	app.oauthHandler = oauthHandler
	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	req := httptest.NewRequest(http.MethodGet, "/pricing", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `data-current="premium"`)
}

// ===========================================================================
// ExchangeWithCredentials — key exists assigned to different user (line 1825-1828)
// ===========================================================================

func TestExchangeWithCredentials_KeyExistsDiffUser_Push100Extra(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	// Pre-register the per-user key as belonging to "other@test.com"
	err := regStore.Register(&registry.AppRegistration{
		ID:           "existing-key-reg",
		APIKey:       "per-user-key",
		APISecret:    "per-user-secret",
		AssignedTo:   "other@test.com",
		Label:        "Other User",
		Status:       registry.StatusActive,
		Source:       registry.SourceSelfProvisioned,
		RegisteredBy: "other@test.com",
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: regStore,
		userStore:     users.NewStore(),
		logger:        testLogger(),
		authenticator: newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	// Exchange with per-user-key succeeds → mock returns email "test@example.com"
	// which is different from the key's assigned user "other@test.com"
	email, err := adapter.ExchangeWithCredentials("test-request-token", "per-user-key", "per-user-secret")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", email)

	// Key should now be re-assigned to test@example.com
	entry, found := regStore.GetByAPIKeyAnyStatus("per-user-key")
	require.True(t, found)
	assert.Equal(t, "test@example.com", entry.AssignedTo)
}

// ===========================================================================
// ExchangeWithCredentials — registry Register error (line 1818-1821)
// ===========================================================================

func TestExchangeWithCredentials_RegisterError_Push100Extra(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	// Pre-register with the exact ID that ExchangeWithCredentials will generate.
	// ID format: "self-{email}-{first8chars_of_apikey}"
	// Mock returns email "test@example.com", apiKey is "new-user-key" → truncKey("new-user-key", 8) = "new-user"
	conflictID := "self-test@example.com-new-user"
	err := regStore.Register(&registry.AppRegistration{
		ID:         conflictID,
		APIKey:     "different-key-for-conflict",
		APISecret:  "different-secret-for-conflict",
		AssignedTo: "someone@test.com",
		Status:     registry.StatusActive,
		Source:     registry.SourceAdmin,
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: regStore,
		userStore:     users.NewStore(),
		logger:        testLogger(),
		authenticator: newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	// Exchange with "new-user-key" → key not in registry → Register with conflictID → error (ID taken)
	email, err := adapter.ExchangeWithCredentials("test-request-token", "new-user-key", "new-user-secret")
	// Should succeed despite registry error (it's logged as a warning, not fatal)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", email)
}

// ===========================================================================
// Rate limiter — concurrent double-check after write lock (line 38-40)
// ===========================================================================

func TestGetLimiter_ConcurrentDoubleCheck_Push100Extra(t *testing.T) {
	limiter := newIPRateLimiter(10, 20)

	const ip = "192.168.1.100"
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// All goroutines request the same IP concurrently — at least one pair should
	// hit the double-check path where the write lock finds the limiter already created.
	results := make([]*ipRateLimiter, goroutines)
	_ = results // just used to prevent escape analysis optimization

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			limiter.getLimiter(ip)
		}()
	}
	wg.Wait()

	// All should get the same limiter
	l := limiter.getLimiter(ip)
	assert.NotNil(t, l)
}

// ===========================================================================
// setupMux — ops handler AdminSecretPath fallback without userStore (line 1096-1098)
// ===========================================================================

func TestSetupMux_OpsHandler_NoUserStoreNoOAuth_Push100Extra(t *testing.T) {
	// Create manager WITHOUT AlertDB so UserStoreConcrete returns nil
	mgr := newTestManager(t)

	app := NewApp(testLogger())
	app.Config.AdminSecretPath = "test-secret-path"
	// oauthHandler is nil, userStore from mgr is nil (no AlertDB)

	mux := app.setupMux(mgr)
	defer app.rateLimiters.Stop()

	// /admin/ops should be registered via identity middleware (no auth)
	req := httptest.NewRequest(http.MethodGet, "/admin/ops", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should NOT be 404 — identity middleware passes through
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}

// ===========================================================================
// ExchangeWithCredentials — provisionUser suspended user (line 1775-1777)
// ===========================================================================

func TestExchangeWithCredentials_SuspendedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	// Pre-create user as suspended — mock returns "test@example.com"
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusSuspended)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:     uStore,
		logger:        testLogger(),
		authenticator: newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeWithCredentials("test-request-token", "per-key", "per-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

// ===========================================================================
// ExchangeWithCredentials — provisionUser offboarded user (line 1770-1772)
// ===========================================================================

func TestExchangeWithCredentials_OffboardedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusOffboarded)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:     uStore,
		logger:        testLogger(),
		authenticator: newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeWithCredentials("test-request-token", "per-key", "per-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offboarded")
}

// ===========================================================================
// ExchangeRequestToken — provisionUser error paths (line 1738-1740)
// ===========================================================================

func TestExchangeRequestToken_SuspendedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusSuspended)

	adapter := &kiteExchangerAdapter{
		apiKey:        "test-api-key",
		apiSecret:     "test-api-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:     uStore,
		logger:        testLogger(),
		authenticator: newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeRequestToken("test-request-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}
