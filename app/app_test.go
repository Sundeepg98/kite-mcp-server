package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// testLogger creates a discard logger for tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadConfig_MissingAPIKey(t *testing.T) {
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API key/secret are missing")
	}
}

func TestLoadConfig_MissingAPISecret(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API secret is missing")
	}
}

func TestLoadConfig_ValidCredentials(t *testing.T) {
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error with valid credentials, got: %v", err)
	}

	if app.Config.KiteAPIKey != "test_key" {
		t.Errorf("Expected API key 'test_key', got '%s'", app.Config.KiteAPIKey)
	}
	if app.Config.KiteAPISecret != "test_secret" {
		t.Errorf("Expected API secret 'test_secret', got '%s'", app.Config.KiteAPISecret)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	t.Setenv("APP_MODE", "")
	t.Setenv("APP_PORT", "")
	t.Setenv("APP_HOST", "")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	app := NewApp(testLogger())
	err := app.LoadConfig()

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if app.Config.AppMode != DefaultAppMode {
		t.Errorf("Expected default app mode '%s', got '%s'", DefaultAppMode, app.Config.AppMode)
	}
	if app.Config.AppPort != DefaultPort {
		t.Errorf("Expected default port '%s', got '%s'", DefaultPort, app.Config.AppPort)
	}
	if app.Config.AppHost != DefaultHost {
		t.Errorf("Expected default host '%s', got '%s'", DefaultHost, app.Config.AppHost)
	}
}

func TestStartServer_InvalidMode(t *testing.T) {
	app := &App{
		Config: &Config{
			AppMode: "invalid_mode",
		},
	}

	err := app.startServer(nil, nil, nil, "")

	if err == nil {
		t.Error("Expected error for invalid APP_MODE")
	}

	expectedMsg := "invalid APP_MODE: invalid_mode"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestNewApp(t *testing.T) {
	app := NewApp(testLogger())

	if app == nil {
		t.Error("Expected non-nil app")
		return
	}
	if app.Config == nil {
		t.Error("Expected non-nil config")
	}
	if app.Version != "v0.0.0" {
		t.Errorf("Expected default version 'v0.0.0', got '%s'", app.Version)
	}
}

func TestSetVersion(t *testing.T) {
	app := NewApp(testLogger())
	testVersion := "v1.2.3"

	app.SetVersion(testVersion)

	if app.Version != testVersion {
		t.Errorf("Expected version '%s', got '%s'", testVersion, app.Version)
	}
}

func TestDeriveAggregateID(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		event    domain.Event
		expected string
	}{
		{
			name:     "OrderPlacedEvent uses OrderID",
			event:    domain.OrderPlacedEvent{OrderID: "ORD-123", Timestamp: now},
			expected: "ORD-123",
		},
		{
			name:     "OrderModifiedEvent uses OrderID",
			event:    domain.OrderModifiedEvent{OrderID: "ORD-456", Timestamp: now},
			expected: "ORD-456",
		},
		{
			name:     "OrderCancelledEvent uses OrderID",
			event:    domain.OrderCancelledEvent{OrderID: "ORD-789", Timestamp: now},
			expected: "ORD-789",
		},
		{
			name:     "PositionClosedEvent uses OrderID",
			event:    domain.PositionClosedEvent{OrderID: "ORD-POS-1", Timestamp: now},
			expected: "ORD-POS-1",
		},
		{
			name:     "AlertTriggeredEvent uses AlertID",
			event:    domain.AlertTriggeredEvent{AlertID: "ALERT-42", Timestamp: now},
			expected: "ALERT-42",
		},
		{
			name:     "UserFrozenEvent uses Email",
			event:    domain.UserFrozenEvent{Email: "user@example.com", Timestamp: now},
			expected: "user@example.com",
		},
		{
			name:     "UserSuspendedEvent uses Email",
			event:    domain.UserSuspendedEvent{Email: "suspended@example.com", Timestamp: now},
			expected: "suspended@example.com",
		},
		{
			name:     "GlobalFreezeEvent uses By (admin email)",
			event:    domain.GlobalFreezeEvent{By: "admin@example.com", Timestamp: now},
			expected: "admin@example.com",
		},
		{
			name:     "FamilyInvitedEvent uses AdminEmail",
			event:    domain.FamilyInvitedEvent{AdminEmail: "family-admin@example.com", Timestamp: now},
			expected: "family-admin@example.com",
		},
		{
			name:     "RiskLimitBreachedEvent uses Email",
			event:    domain.RiskLimitBreachedEvent{Email: "risky@example.com", Timestamp: now},
			expected: "risky@example.com",
		},
		{
			name:     "SessionCreatedEvent uses SessionID",
			event:    domain.SessionCreatedEvent{SessionID: "sess-abc", Timestamp: now},
			expected: "sess-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAggregateID(tt.event)
			if got != tt.expected {
				t.Errorf("deriveAggregateID() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ===========================================================================
// initStatusPageTemplate tests
// ===========================================================================

func TestInitStatusPageTemplate_Success(t *testing.T) {
	app := NewApp(testLogger())
	err := app.initStatusPageTemplate()
	// Should succeed since templates are embedded
	assert.NoError(t, err)
	assert.NotNil(t, app.statusTemplate)
	assert.NotNil(t, app.landingTemplate)
	assert.NotNil(t, app.legalTemplate)
}

// ===========================================================================
// serveLegalPages tests
// ===========================================================================

func TestServeLegalPages_NilTemplate(t *testing.T) {
	app := NewApp(testLogger())
	app.legalTemplate = nil
	mux := http.NewServeMux()
	// Should not panic
	app.serveLegalPages(mux)
	// /terms should not be registered
	req := httptest.NewRequest(http.MethodGet, "/terms", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestServeLegalPages_WithTemplate(t *testing.T) {
	app := NewApp(testLogger())
	err := app.initStatusPageTemplate()
	require.NoError(t, err)

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/terms", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "Terms of Service")

	req2 := httptest.NewRequest(http.MethodGet, "/privacy", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "Privacy Policy")
}

// ===========================================================================
// serveStatusPage tests
// ===========================================================================

func TestServeStatusPage_NonRootPath(t *testing.T) {
	app := NewApp(testLogger())
	_ = app.initStatusPageTemplate()
	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "Page Not Found")
}

func TestServeStatusPage_Root_NoTemplates(t *testing.T) {
	app := NewApp(testLogger())
	app.landingTemplate = nil
	app.statusTemplate = nil
	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Kite MCP Server")
}

func TestServeStatusPage_Root_WithLandingTemplate(t *testing.T) {
	app := NewApp(testLogger())
	err := app.initStatusPageTemplate()
	require.NoError(t, err)
	app.Config.AppMode = "http"
	app.Version = "v1.2.3"

	mux := http.NewServeMux()
	app.serveStatusPage(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

// ===========================================================================
// provisionUser adapter tests
// ===========================================================================

func TestProvisionUser_NilUserStore(t *testing.T) {
	adapter := &kiteExchangerAdapter{
		userStore: nil,
		logger:    testLogger(),
	}
	err := adapter.provisionUser("test@example.com", "UID123", "Test User")
	assert.NoError(t, err)
}

func TestProvisionUser_SuspendedUser(t *testing.T) {
	store := users.NewStore()
	store.EnsureUser("suspended@example.com", "", "", "self")
	_ = store.UpdateStatus("suspended@example.com", users.StatusSuspended)

	adapter := &kiteExchangerAdapter{
		userStore: store,
		logger:    testLogger(),
	}
	err := adapter.provisionUser("suspended@example.com", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

func TestProvisionUser_OffboardedUser(t *testing.T) {
	store := users.NewStore()
	store.EnsureUser("offboarded@example.com", "", "", "self")
	_ = store.UpdateStatus("offboarded@example.com", users.StatusOffboarded)

	adapter := &kiteExchangerAdapter{
		userStore: store,
		logger:    testLogger(),
	}
	err := adapter.provisionUser("offboarded@example.com", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "offboarded")
}

func TestProvisionUser_NewUser(t *testing.T) {
	store := users.NewStore()
	adapter := &kiteExchangerAdapter{
		userStore: store,
		logger:    testLogger(),
	}
	err := adapter.provisionUser("new@example.com", "UID789", "New User")
	assert.NoError(t, err)

	u, ok := store.Get("new@example.com")
	assert.True(t, ok)
	assert.Equal(t, "new@example.com", u.Email)
	assert.Equal(t, "UID789", u.KiteUID)
}

// ===========================================================================
// GetCredentials adapter tests
// ===========================================================================

func TestGetCredentials_FromCredentialStore(t *testing.T) {
	credStore := kc.NewKiteCredentialStore()
	credStore.Set("user@example.com", &kc.KiteCredentialEntry{
		APIKey:    "per-user-key",
		APISecret: "per-user-secret",
	})
	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		credentialStore: credStore,
		logger:          testLogger(),
	}
	key, secret, ok := adapter.GetCredentials("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, "per-user-key", key)
	assert.Equal(t, "per-user-secret", secret)
}

func TestGetCredentials_FallbackToGlobal(t *testing.T) {
	credStore := kc.NewKiteCredentialStore()
	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		credentialStore: credStore,
		logger:          testLogger(),
	}
	key, secret, ok := adapter.GetCredentials("unknown@example.com")
	assert.True(t, ok)
	assert.Equal(t, "global-key", key)
	assert.Equal(t, "global-secret", secret)
}

func TestGetCredentials_NoCredentials(t *testing.T) {
	credStore := kc.NewKiteCredentialStore()
	adapter := &kiteExchangerAdapter{
		apiKey:          "",
		apiSecret:       "",
		credentialStore: credStore,
		logger:          testLogger(),
	}
	_, _, ok := adapter.GetCredentials("unknown@example.com")
	assert.False(t, ok)
}

// ===========================================================================
// GetSecretByAPIKey adapter tests
// ===========================================================================

func TestGetSecretByAPIKey_Found(t *testing.T) {
	credStore := kc.NewKiteCredentialStore()
	credStore.Set("user@example.com", &kc.KiteCredentialEntry{
		APIKey:    "mykey",
		APISecret: "mysecret",
	})
	adapter := &kiteExchangerAdapter{
		credentialStore: credStore,
		logger:          testLogger(),
	}
	secret, ok := adapter.GetSecretByAPIKey("mykey")
	assert.True(t, ok)
	assert.Equal(t, "mysecret", secret)
}

func TestGetSecretByAPIKey_NotFound(t *testing.T) {
	credStore := kc.NewKiteCredentialStore()
	adapter := &kiteExchangerAdapter{
		credentialStore: credStore,
		logger:          testLogger(),
	}
	_, ok := adapter.GetSecretByAPIKey("nonexistent")
	assert.False(t, ok)
}

// ===========================================================================
// registryAdapter tests
// ===========================================================================

func TestRegistryAdapter_HasEntries_Empty(t *testing.T) {
	store := registry.New()
	adapter := &registryAdapter{store: store}
	assert.False(t, adapter.HasEntries())
}

func TestRegistryAdapter_HasEntries_WithData(t *testing.T) {
	store := registry.New()
	_ = store.Register(&registry.AppRegistration{
		ID:        "test-1",
		APIKey:    "key123",
		APISecret: "secret123",
	})
	adapter := &registryAdapter{store: store}
	assert.True(t, adapter.HasEntries())
}

func TestRegistryAdapter_GetByEmail_NotFound(t *testing.T) {
	store := registry.New()
	adapter := &registryAdapter{store: store}
	_, found := adapter.GetByEmail("nobody@example.com")
	assert.False(t, found)
}

func TestRegistryAdapter_GetByEmail_Found(t *testing.T) {
	store := registry.New()
	_ = store.Register(&registry.AppRegistration{
		ID:           "test-1",
		APIKey:       "key123",
		APISecret:    "secret123",
		AssignedTo:   "user@example.com",
		RegisteredBy: "admin@example.com",
	})
	adapter := &registryAdapter{store: store}
	entry, found := adapter.GetByEmail("user@example.com")
	assert.True(t, found)
	assert.Equal(t, "key123", entry.APIKey)
	assert.Equal(t, "secret123", entry.APISecret)
	assert.Equal(t, "admin@example.com", entry.RegisteredBy)
}

func TestRegistryAdapter_GetSecretByAPIKey_NotFound(t *testing.T) {
	store := registry.New()
	adapter := &registryAdapter{store: store}
	_, ok := adapter.GetSecretByAPIKey("nonexistent")
	assert.False(t, ok)
}

func TestRegistryAdapter_GetSecretByAPIKey_Found(t *testing.T) {
	store := registry.New()
	_ = store.Register(&registry.AppRegistration{
		ID:        "test-1",
		APIKey:    "key123",
		APISecret: "secret123",
	})
	adapter := &registryAdapter{store: store}
	secret, ok := adapter.GetSecretByAPIKey("key123")
	assert.True(t, ok)
	assert.Equal(t, "secret123", secret)
}

// ===========================================================================
// signerAdapter tests
// ===========================================================================

func TestSignerAdapter_RoundTrip(t *testing.T) {
	signer, err := kc.NewSessionSigner()
	require.NoError(t, err)
	adapter := &signerAdapter{signer: signer}

	signed := adapter.Sign("test-data")
	assert.NotEmpty(t, signed)
	assert.NotEqual(t, "test-data", signed)

	original, err := adapter.Verify(signed)
	assert.NoError(t, err)
	assert.Equal(t, "test-data", original)
}

func TestSignerAdapter_VerifyInvalid(t *testing.T) {
	signer, err := kc.NewSessionSigner()
	require.NoError(t, err)
	adapter := &signerAdapter{signer: signer}

	_, err = adapter.Verify("invalid-signed-data")
	assert.Error(t, err)
}

// ===========================================================================
// briefingTokenAdapter tests
// ===========================================================================

func TestBriefingTokenAdapter_GetToken_NotFound(t *testing.T) {
	store := kc.NewKiteTokenStore()
	adapter := &briefingTokenAdapter{store: store}

	_, _, ok := adapter.GetToken("nobody@example.com")
	assert.False(t, ok)
}

func TestBriefingTokenAdapter_GetToken_Found(t *testing.T) {
	store := kc.NewKiteTokenStore()
	store.Set("user@example.com", &kc.KiteTokenEntry{
		AccessToken: "test-token",
		UserID:      "UID123",
	})
	adapter := &briefingTokenAdapter{store: store}

	token, storedAt, ok := adapter.GetToken("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, "test-token", token)
	assert.False(t, storedAt.IsZero())
}

func TestBriefingTokenAdapter_IsExpired(t *testing.T) {
	store := kc.NewKiteTokenStore()
	adapter := &briefingTokenAdapter{store: store}

	// A recently stored token should not be expired
	assert.False(t, adapter.IsExpired(time.Now()))
}

// ===========================================================================
// briefingCredAdapter tests
// ===========================================================================

func TestBriefingCredAdapter_GetAPIKey(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             testLogger(),
		DevMode:            true,
		InstrumentsManager: instrMgr,
	})
	require.NoError(t, err)
	defer mgr.Shutdown()

	adapter := &briefingCredAdapter{manager: mgr}
	// For a user with no per-user credentials, returns the global key
	key := adapter.GetAPIKey("someone@example.com")
	assert.Equal(t, "test_key", key)
}

// ===========================================================================
// instrumentsFreezeAdapter tests
// ===========================================================================

func TestInstrumentsFreezeAdapter_NotFound(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	_, ok := adapter.GetFreezeQuantity("NSE", "RELIANCE")
	assert.False(t, ok)
}
