package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

func TestLoadConfig_MissingAPIKey(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{})
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API key/secret are missing")
	}
}

func TestLoadConfig_MissingAPISecret(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{KiteAPIKey: "test_key"})
	err := app.LoadConfig()

	if err == nil {
		t.Error("Expected error when API secret is missing")
	}
}

func TestLoadConfig_ValidCredentials(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
	})
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
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
	})
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
	t.Parallel()
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
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})

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
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{InstrumentsSkipFetch: true})
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
			name: "PositionClosedEvent uses natural aggregate key",
			event: domain.PositionClosedEvent{
				Email:      "alice@example.com",
				OrderID:    "ORD-POS-1",
				Instrument: domain.NewInstrumentKey("NSE", "HDFC"),
				Product:    "CNC",
				Timestamp:  now,
			},
			expected: "alice@example.com:NSE:HDFC:CNC",
		},
		{
			name: "PositionOpenedEvent uses natural aggregate key",
			event: domain.PositionOpenedEvent{
				Email:      "alice@example.com",
				PositionID: "ORD-OPEN-1",
				Instrument: domain.NewInstrumentKey("NSE", "HDFC"),
				Product:    "CNC",
				Timestamp:  now,
			},
			expected: "alice@example.com:NSE:HDFC:CNC",
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
		// ES pilot: watchlist aggregate uses WatchlistID as the natural key
		// so all four lifecycle events (created/deleted/item_added/item_removed)
		// for the same watchlist sort under one aggregate stream.
		{
			name:     "WatchlistCreatedEvent uses WatchlistID",
			event:    domain.WatchlistCreatedEvent{WatchlistID: "wl-1", Email: "u@t.com", Name: "Tech", Timestamp: now},
			expected: "wl-1",
		},
		{
			name:     "WatchlistDeletedEvent uses WatchlistID",
			event:    domain.WatchlistDeletedEvent{WatchlistID: "wl-2", Email: "u@t.com", Timestamp: now},
			expected: "wl-2",
		},
		{
			name:     "WatchlistItemAddedEvent uses WatchlistID",
			event:    domain.WatchlistItemAddedEvent{WatchlistID: "wl-3", Email: "u@t.com", Instrument: domain.NewInstrumentKey("NSE", "INFY"), Timestamp: now},
			expected: "wl-3",
		},
		{
			name:     "WatchlistItemRemovedEvent uses WatchlistID",
			event:    domain.WatchlistItemRemovedEvent{WatchlistID: "wl-4", Email: "u@t.com", ItemID: "it-1", Timestamp: now},
			expected: "wl-4",
		},
		// ES: telegram subscription aggregate keyed by email under the
		// "telegram:" prefix so it stays disjoint from other per-email
		// aggregate streams (UserFrozenEvent, riskguard:*, anomaly:*).
		{
			name:     "TelegramSubscribedEvent uses TelegramSubscriptionAggregateID",
			event:    domain.TelegramSubscribedEvent{UserEmail: "alice@example.com", ChatID: 12345, Timestamp: now},
			expected: "telegram:alice@example.com",
		},
		{
			name:     "TelegramChatBoundEvent uses TelegramSubscriptionAggregateID",
			event:    domain.TelegramChatBoundEvent{UserEmail: "bob@example.com", OldChatID: 11111, NewChatID: 22222, Timestamp: now},
			expected: "telegram:bob@example.com",
		},
		// ES: riskguard counters aggregate keyed under "riskguard:<email>"
		// or "riskguard:global" for the kill-switch (system-scope) events.
		{
			name:     "RiskguardKillSwitchTrippedEvent (global) uses riskguard:global",
			event:    domain.RiskguardKillSwitchTrippedEvent{FrozenBy: "admin@example.com", Reason: "incident", Active: true, Timestamp: now},
			expected: "riskguard:global",
		},
		{
			name:     "RiskguardKillSwitchTrippedEvent (per-user) uses riskguard:<email>",
			event:    domain.RiskguardKillSwitchTrippedEvent{UserEmail: "scoped@example.com", Active: true, Timestamp: now},
			expected: "riskguard:scoped@example.com",
		},
		{
			name:     "RiskguardDailyCounterResetEvent uses riskguard:<email>",
			event:    domain.RiskguardDailyCounterResetEvent{UserEmail: "trader@example.com", Reason: "trading_day_boundary", Timestamp: now},
			expected: "riskguard:trader@example.com",
		},
		{
			name:     "RiskguardRejectionEvent uses riskguard:<email>",
			event:    domain.RiskguardRejectionEvent{UserEmail: "rejected@example.com", Reason: "order_value_limit", Timestamp: now},
			expected: "riskguard:rejected@example.com",
		},
		// ES: anomaly cache aggregate keyed under "anomaly:<email>" so the
		// per-user baseline / invalidation / eviction stream stays disjoint
		// from other per-email aggregates (riskguard:*, telegram:*, etc.).
		{
			name:     "AnomalyBaselineSnapshottedEvent uses anomaly:<email>",
			event:    domain.AnomalyBaselineSnapshottedEvent{UserEmail: "alice@example.com", Days: 30, Mean: 1000, Stdev: 200, Count: 12, Timestamp: now},
			expected: "anomaly:alice@example.com",
		},
		{
			name:     "AnomalyCacheInvalidatedEvent uses anomaly:<email>",
			event:    domain.AnomalyCacheInvalidatedEvent{UserEmail: "bob@example.com", Reason: "order_recorded", Timestamp: now},
			expected: "anomaly:bob@example.com",
		},
		{
			name:     "AnomalyCacheEvictedEvent uses anomaly:<email>",
			event:    domain.AnomalyCacheEvictedEvent{UserEmail: "carol@example.com", Days: 30, Reason: "ttl_expired", Timestamp: now},
			expected: "anomaly:carol@example.com",
		},
		{
			name:     "AnomalyCacheEvictedEvent (empty email) falls back to anomaly:unknown",
			event:    domain.AnomalyCacheEvictedEvent{UserEmail: "", Days: 30, Reason: "size_overflow", Timestamp: now},
			expected: "anomaly:unknown",
		},
		// ES: plugin watcher aggregate keyed under "plugin-watcher:<path>"
		// for per-plugin path mutations (registered, unregistered,
		// reload_triggered) and "plugin-watcher:global" for the watcher
		// lifecycle events (started, stopped) which have no path.
		{
			name:     "PluginRegisteredEvent uses plugin-watcher:<path>",
			event:    domain.PluginRegisteredEvent{PluginName: "p1", Path: "/abs/foo", Timestamp: now},
			expected: "plugin-watcher:/abs/foo",
		},
		{
			name:     "PluginUnregisteredEvent uses plugin-watcher:<path>",
			event:    domain.PluginUnregisteredEvent{PluginName: "p1", Path: "/abs/foo", Timestamp: now},
			expected: "plugin-watcher:/abs/foo",
		},
		{
			name:     "PluginReloadTriggeredEvent uses plugin-watcher:<path>",
			event:    domain.PluginReloadTriggeredEvent{PluginName: "p1", Path: "/abs/bar", Timestamp: now},
			expected: "plugin-watcher:/abs/bar",
		},
		{
			name:     "PluginWatcherStartedEvent uses plugin-watcher:global",
			event:    domain.PluginWatcherStartedEvent{Timestamp: now},
			expected: "plugin-watcher:global",
		},
		{
			name:     "PluginWatcherStoppedEvent uses plugin-watcher:global",
			event:    domain.PluginWatcherStoppedEvent{Timestamp: now},
			expected: "plugin-watcher:global",
		},
		// ES: OrderRejectedEvent — when the broker round-trip fails after
		// riskguard allowed the call. With OrderID present (modify/cancel
		// rejection), the event joins the existing order aggregate stream;
		// with OrderID empty (place_order failure, no broker ID issued),
		// it falls back to the synthetic "rejected:<email>:<ts>" key.
		{
			name:     "OrderRejectedEvent (modify) uses OrderID",
			event:    domain.OrderRejectedEvent{Email: "trader@example.com", OrderID: "ORD-MOD-1", ToolName: "modify_order", Reason: "ORDER_FROZEN", Timestamp: now},
			expected: "ORD-MOD-1",
		},
		{
			name:     "OrderRejectedEvent (place, empty OrderID) uses synthetic rejected:<email>:<ts>",
			event:    domain.OrderRejectedEvent{Email: "trader@example.com", OrderID: "", ToolName: "place_order", Reason: "RATE_LIMIT", Timestamp: now},
			expected: "rejected:trader@example.com:" + now.Format(time.RFC3339Nano),
		},
		// ES: PositionConvertedEvent — typed replacement for the prior
		// untyped appendAuxEvent. Keyed by OLD product so a
		// CNC->MIS->CNC sequence threads through a stable stream.
		{
			name:     "PositionConvertedEvent uses (email|exchange|symbol|oldProduct)",
			event:    domain.PositionConvertedEvent{Email: "trader@example.com", Instrument: domain.NewInstrumentKey("NSE", "RELIANCE"), OldProduct: "MIS", NewProduct: "CNC", Quantity: 10, Timestamp: now},
			expected: "trader@example.com|NSE|RELIANCE|MIS",
		},
		// ES: PaperOrderRejectedEvent — paper IDs are already process-
		// unique so no email prefix needed.
		{
			name:     "PaperOrderRejectedEvent uses OrderID directly",
			event:    domain.PaperOrderRejectedEvent{Email: "trader@example.com", OrderID: "PAPER_42", Reason: "insufficient cash", Source: "place_limit", Timestamp: now},
			expected: "PAPER_42",
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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
	app := newTestApp(t)
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

// After Block 1 / round-2: every kiteExchangerAdapter goes through the
// CQRS bus on every write. Tests build adapters by struct literal; the
// adapter's ensureBus() lazily constructs a local InMemoryBus with the
// same use case handlers production uses, so test setup stays a one-line
// struct literal and the no-bus fallback gates are gone.
func TestProvisionUser_NilUserStore(t *testing.T) {
	// Adapter with no userStore: the local-bus handler no-ops because the
	// usecases.UserProvisioner port is nil. Mirrors the dev-mode no-store
	// deployment behaviour exactly.
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

	adapter := &kiteExchangerAdapter{userStore: store, logger: testLogger()}
	err := adapter.provisionUser("suspended@example.com", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")

	// E1: sentinel chain preserved across the wrap so caller-side
	// errors.Is checks still match.
	assert.ErrorIs(t, err, usecases.ErrUserSuspended,
		"sentinel must propagate via %w wrap")

	// E4: email is hashed in the error string, not plaintext.
	assert.NotContains(t, err.Error(), "suspended@example.com",
		"plaintext email must NOT appear in error message")
	assert.Contains(t, err.Error(), audit.HashEmail("suspended@example.com"),
		"email_hash must appear so operators can correlate")
}

func TestProvisionUser_OffboardedUser(t *testing.T) {
	store := users.NewStore()
	store.EnsureUser("offboarded@example.com", "", "", "self")
	_ = store.UpdateStatus("offboarded@example.com", users.StatusOffboarded)

	adapter := &kiteExchangerAdapter{userStore: store, logger: testLogger()}
	err := adapter.provisionUser("offboarded@example.com", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "offboarded")

	// E1: sentinel chain preserved.
	assert.ErrorIs(t, err, usecases.ErrUserOffboarded)

	// E4: plaintext absent, hash present.
	assert.NotContains(t, err.Error(), "offboarded@example.com")
	assert.Contains(t, err.Error(), audit.HashEmail("offboarded@example.com"))
}

func TestProvisionUser_NewUser(t *testing.T) {
	store := users.NewStore()
	adapter := &kiteExchangerAdapter{userStore: store, logger: testLogger()}
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
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
	)
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
	t.Cleanup(instrMgr.Shutdown)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	_, ok := adapter.GetFreezeQuantity("NSE", "RELIANCE")
	assert.False(t, ok)
}
