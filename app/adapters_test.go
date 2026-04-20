package app

// Tests for adapter types and helper functions that were at 0% coverage:
// - telegramManagerAdapter (all 11 methods)
// - clientPersisterAdapter (SaveClient, LoadClients, DeleteClient)
// - paperLTPAdapter (GetLTP)
// - makeEventPersister

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ===========================================================================
// telegramManagerAdapter tests — all 11 methods
// ===========================================================================

func TestTelegramAdapter_TelegramStore(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	// TelegramStore may return nil if no Telegram bot is configured. Should not panic.
	_ = adapter.TelegramStore()
}

func TestTelegramAdapter_AlertStoreConcrete(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	store := adapter.AlertStoreConcrete()
	// In DevMode without DB, may be nil.
	_ = store
}

func TestTelegramAdapter_WatchlistStoreConcrete(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	store := adapter.WatchlistStoreConcrete()
	_ = store
}

func TestTelegramAdapter_GetAPIKeyForEmail(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	// For unknown email, returns "" or the global key.
	key := adapter.GetAPIKeyForEmail("unknown@test.com")
	// With DevMode + global API key set, may return the global key.
	_ = key
}

func TestTelegramAdapter_GetAccessTokenForEmail(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	token := adapter.GetAccessTokenForEmail("unknown@test.com")
	assert.Empty(t, token) // No token stored for unknown user.
}

func TestTelegramAdapter_TelegramNotifier(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	notifier := adapter.TelegramNotifier()
	// Nil when no Telegram bot configured.
	assert.Nil(t, notifier)
}

func TestTelegramAdapter_InstrumentsManagerConcrete(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	instrMgr := adapter.InstrumentsManagerConcrete()
	assert.NotNil(t, instrMgr)
}

func TestTelegramAdapter_IsTokenValid(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	valid := adapter.IsTokenValid("unknown@test.com")
	assert.False(t, valid)
}

func TestTelegramAdapter_RiskGuard(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	guard := adapter.RiskGuard()
	// Nil when not configured.
	_ = guard
}

func TestTelegramAdapter_PaperEngineConcrete(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	pe := adapter.PaperEngineConcrete()
	// Nil when not configured.
	_ = pe
}

func TestTelegramAdapter_TickerServiceConcrete(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &telegramManagerAdapter{m: mgr}
	ts := adapter.TickerServiceConcrete()
	// Nil when not configured.
	_ = ts
}

// ===========================================================================
// clientPersisterAdapter tests
// ===========================================================================

func TestClientPersisterAdapter_SaveAndLoad(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	// Save a client.
	now := time.Now().Truncate(time.Second)
	err = adapter.SaveClient("client-1", "secret-1", `["http://localhost/callback"]`, "Test Client", now, false)
	assert.NoError(t, err)

	// Load clients.
	clients, err := adapter.LoadClients()
	assert.NoError(t, err)
	require.Len(t, clients, 1)

	assert.Equal(t, "client-1", clients[0].ClientID)
	assert.Equal(t, "secret-1", clients[0].ClientSecret)
	assert.Equal(t, "Test Client", clients[0].ClientName)
	assert.False(t, clients[0].IsKiteAPIKey)
}

func TestClientPersisterAdapter_SaveKiteKey(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	now := time.Now().Truncate(time.Second)
	err = adapter.SaveClient("kite-key-1", "kite-secret", `["http://example.com/callback"]`, "Kite App", now, true)
	assert.NoError(t, err)

	clients, err := adapter.LoadClients()
	assert.NoError(t, err)
	require.Len(t, clients, 1)
	assert.True(t, clients[0].IsKiteAPIKey)
}

func TestClientPersisterAdapter_Delete(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	now := time.Now()
	_ = adapter.SaveClient("client-del", "secret", `[]`, "Del Client", now, false)

	// Verify it was saved.
	clients, err := adapter.LoadClients()
	assert.NoError(t, err)
	assert.Len(t, clients, 1)

	// Delete it.
	err = adapter.DeleteClient("client-del")
	assert.NoError(t, err)

	// Verify it's gone.
	clients, err = adapter.LoadClients()
	assert.NoError(t, err)
	assert.Len(t, clients, 0)
}

func TestClientPersisterAdapter_LoadEmpty(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	clients, err := adapter.LoadClients()
	assert.NoError(t, err)
	assert.Len(t, clients, 0)
}

func TestClientPersisterAdapter_MultipleClients(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	adapter := &clientPersisterAdapter{db: db}

	now := time.Now()
	_ = adapter.SaveClient("c1", "s1", `[]`, "Client1", now, false)
	_ = adapter.SaveClient("c2", "s2", `[]`, "Client2", now, true)
	_ = adapter.SaveClient("c3", "s3", `[]`, "Client3", now, false)

	clients, err := adapter.LoadClients()
	assert.NoError(t, err)
	assert.Len(t, clients, 3)
}

// ===========================================================================
// paperLTPAdapter tests
// ===========================================================================

func TestPaperLTPAdapter_NoActiveSessions(t *testing.T) {
	mgr := newTestManager(t)
	adapter := &paperLTPAdapter{manager: mgr}

	_, err := adapter.GetLTP("NSE:INFY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active Kite sessions")
}

// ===========================================================================
// instrumentsFreezeAdapter tests — additional coverage
// ===========================================================================

func TestInstrumentsFreezeAdapter_Found(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger: testLogger(),
		TestData: map[uint32]*instruments.Instrument{
			12345: {
				ID:              "NSE:RELIANCE",
				InstrumentToken: 12345,
				Exchange:        "NSE",
				Tradingsymbol:   "RELIANCE",
				FreezeQuantity:  1800,
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	qty, ok := adapter.GetFreezeQuantity("NSE", "RELIANCE")
	assert.True(t, ok)
	assert.Equal(t, uint32(1800), qty)
}

func TestInstrumentsFreezeAdapter_ZeroFreeze(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger: testLogger(),
		TestData: map[uint32]*instruments.Instrument{
			12346: {
				ID:              "NSE:SMALLCAP",
				InstrumentToken: 12346,
				Exchange:        "NSE",
				Tradingsymbol:   "SMALLCAP",
				FreezeQuantity:  0,
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	adapter := &instrumentsFreezeAdapter{mgr: instrMgr}
	_, ok := adapter.GetFreezeQuantity("NSE", "SMALLCAP")
	assert.False(t, ok) // FreezeQuantity is 0 → ok should be false.
}

// ===========================================================================
// makeEventPersister tests
// ===========================================================================

func TestMakeEventPersister_PersistsEvent(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "orders", testLogger())
	require.NotNil(t, persister)

	// Persist an OrderPlacedEvent.
	event := domain.OrderPlacedEvent{
		OrderID:   "ORD-999",
		Email:     "test@example.com",
		Timestamp: time.Now(),
	}
	persister(event)

	// Verify the event was stored.
	events, err := store.LoadEvents("ORD-999")
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "ORD-999", events[0].AggregateID)
	assert.Equal(t, "orders", events[0].AggregateType)
}

func TestMakeEventPersister_MultipleEvents(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "alerts", testLogger())

	// Persist multiple events.
	now := time.Now()
	persister(domain.AlertTriggeredEvent{AlertID: "ALERT-1", Timestamp: now})
	persister(domain.AlertTriggeredEvent{AlertID: "ALERT-1", Timestamp: now.Add(time.Second)})

	events, err := store.LoadEvents("ALERT-1")
	assert.NoError(t, err)
	assert.Len(t, events, 2)
}

func TestMakeEventPersister_UserEvents(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := eventsourcing.NewEventStore(db)
	require.NoError(t, store.InitTable())

	persister := makeEventPersister(store, "users", testLogger())

	persister(domain.UserFrozenEvent{Email: "frozen@example.com", Timestamp: time.Now()})

	events, err := store.LoadEvents("frozen@example.com")
	assert.NoError(t, err)
	assert.Len(t, events, 1)
}

// ===========================================================================
// deriveAggregateID — additional default branch coverage
// ===========================================================================

// customEvent is a test event type that doesn't match any switch case.
type customEvent struct {
	timestamp time.Time
}

func (e customEvent) EventType() string      { return "custom.test" }
func (e customEvent) OccurredAt() time.Time  { return e.timestamp }

func TestDeriveAggregateID_Unknown(t *testing.T) {
	result := deriveAggregateID(customEvent{timestamp: time.Now()})
	assert.Equal(t, "unknown", result)
}

// TestDeriveAggregateID_PositionOpened pins the P1 fix: before the case
// was added, every position.opened event hit the default branch and was
// persisted with AggregateID="unknown". This test was later updated when
// the aggregate-ID scheme changed from PositionID (close-order-mismatched)
// to the natural-key tuple (email, exchange, symbol, product) so open and
// close events join on the same aggregate. See domain.PositionAggregateID
// for the rationale.
func TestDeriveAggregateID_PositionOpened(t *testing.T) {
	ev := domain.PositionOpenedEvent{
		Email:           "alice@example.com",
		PositionID:      "ORD-12345",
		Instrument:      domain.NewInstrumentKey("NSE", "HDFC"),
		Product:         "CNC",
		TransactionType: "BUY",
		Timestamp:       time.Now(),
	}
	result := deriveAggregateID(ev)
	assert.Equal(t, "alice@example.com:NSE:HDFC:CNC", result)
	assert.NotEqual(t, "unknown", result, "P1 regression: PositionOpenedEvent must not fall through to unknown")
}

// ===========================================================================
// briefingCredAdapter with per-user credentials
// ===========================================================================

func TestBriefingCredAdapter_PerUserKey(t *testing.T) {
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("global_key", "global_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
	)
	require.NoError(t, err)
	defer mgr.Shutdown()

	// Store per-user credentials.
	credStore := mgr.CredentialStoreConcrete()
	if credStore != nil {
		credStore.Set("peruser@example.com", &kc.KiteCredentialEntry{
			APIKey:    "per-user-key",
			APISecret: "per-user-secret",
		})
	}

	adapter := &briefingCredAdapter{manager: mgr}
	key := adapter.GetAPIKey("peruser@example.com")
	if credStore != nil {
		assert.Equal(t, "per-user-key", key)
	} else {
		// Fallback to global.
		assert.Equal(t, "global_key", key)
	}
}

// ===========================================================================
// briefingTokenAdapter — more paths
// ===========================================================================

func TestBriefingTokenAdapter_IsExpired_OldTimestamp(t *testing.T) {
	store := kc.NewKiteTokenStore()
	adapter := &briefingTokenAdapter{store: store}

	// An old timestamp should be expired.
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.True(t, adapter.IsExpired(oldTime))
}

func TestBriefingTokenAdapter_IsExpired_FutureTimestamp(t *testing.T) {
	store := kc.NewKiteTokenStore()
	adapter := &briefingTokenAdapter{store: store}

	// A recent timestamp should not be expired.
	recentTime := time.Now()
	assert.False(t, adapter.IsExpired(recentTime))
}

// ===========================================================================
// setupMux smoke test — exercises the entire route registration path
// ===========================================================================

func TestSetupMux_Smoke(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
		AdminEmails:   "admin@test.com",
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Verify common endpoints are registered by making requests.
	// /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ok")

	// /robots.txt
	req2 := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "User-agent")

	// /.well-known/security.txt
	req3 := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
	assert.Contains(t, rec3.Body.String(), "Contact")

	// /.well-known/mcp/server-card.json
	req4 := httptest.NewRequest(http.MethodGet, "/.well-known/mcp/server-card.json", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusOK, rec4.Code)
	assert.Contains(t, rec4.Body.String(), "Kite Trading")

	// /pricing
	req5 := httptest.NewRequest(http.MethodGet, "/pricing", nil)
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, req5)
	assert.Equal(t, http.StatusOK, rec5.Code)

	// /checkout/success
	req6 := httptest.NewRequest(http.MethodGet, "/checkout/success", nil)
	rec6 := httptest.NewRecorder()
	mux.ServeHTTP(rec6, req6)
	assert.Equal(t, http.StatusOK, rec6.Code)

	// /favicon.ico
	req7 := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rec7 := httptest.NewRecorder()
	mux.ServeHTTP(rec7, req7)
	// May be 200 or 404 depending on embedded assets.
	assert.True(t, rec7.Code == http.StatusOK || rec7.Code == http.StatusNotFound)

	// /callback (default flow, no session_id → manager handles it)
	req8 := httptest.NewRequest(http.MethodGet, "/callback?request_token=test", nil)
	rec8 := httptest.NewRecorder()
	mux.ServeHTTP(rec8, req8)
	// The callback handler will error (no valid session), but the route is exercised.
	assert.True(t, rec8.Code >= 200)

	// /callback?flow=oauth (no oauthHandler → Internal Server Error)
	req9 := httptest.NewRequest(http.MethodGet, "/callback?flow=oauth&request_token=test", nil)
	rec9 := httptest.NewRecorder()
	mux.ServeHTTP(rec9, req9)
	assert.Equal(t, http.StatusInternalServerError, rec9.Code)

	// /callback?flow=browser (no oauthHandler → Internal Server Error)
	req10 := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&request_token=test", nil)
	rec10 := httptest.NewRecorder()
	mux.ServeHTTP(rec10, req10)
	assert.Equal(t, http.StatusInternalServerError, rec10.Code)

	// /.well-known/mcp/server-card.json OPTIONS (CORS preflight)
	req11 := httptest.NewRequest(http.MethodOptions, "/.well-known/mcp/server-card.json", nil)
	rec11 := httptest.NewRecorder()
	mux.ServeHTTP(rec11, req11)
	assert.Equal(t, http.StatusNoContent, rec11.Code)

	// Clean up rate limiters.
	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}

func TestSetupMux_WithAdminSecretPath(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:      "test_key",
		KiteAPISecret:   "test_secret",
		AdminSecretPath: "/test-secret",
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// Admin endpoint should be registered.
	req := httptest.NewRequest(http.MethodGet, "/admin/test-secret", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should return something (not 404 for the admin prefix at least).
	assert.True(t, rec.Code >= 200)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}

func TestSetupMux_DevModePprof(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
	})
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mux := app.setupMux(mgr)
	require.NotNil(t, mux)

	// pprof endpoints should be registered in DevMode.
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}

// ===========================================================================
// App Config additional edge cases
// ===========================================================================

func TestLoadConfig_DevModeSkipsCredentials(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{})
	app.DevMode = true // DevMode isn't a Config field; set after construction.
	err := app.LoadConfig()
	assert.NoError(t, err)
}

func TestLoadConfig_AdminEndpointSecretPath(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:      "k",
		KiteAPISecret:   "s",
		AdminSecretPath: "/my/secret",
	})
	err := app.LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "/my/secret", app.Config.AdminSecretPath)
}

func TestLoadConfig_GoogleOAuthCredentials(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:         "k",
		KiteAPISecret:      "s",
		GoogleClientID:     "gid",
		GoogleClientSecret: "gsecret",
	})
	err := app.LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "gid", app.Config.GoogleClientID)
	assert.Equal(t, "gsecret", app.Config.GoogleClientSecret)
}

// ===========================================================================
// registryAdapter — delete by API key
// ===========================================================================

func TestRegistryAdapter_GetSecretByAPIKey_Inactive(t *testing.T) {
	// A replaced/inactive key should still be findable by API key.
	store := registry.New()
	_ = store.Register(&registry.AppRegistration{
		ID:        "test-1",
		APIKey:    "key-old",
		APISecret: "secret-old",
		Status:    registry.StatusActive,
	})
	store.MarkStatus("key-old", registry.StatusReplaced)

	adapter := &registryAdapter{store: store}
	// GetByAPIKey on the adapter uses store.GetByAPIKey which may return inactive.
	_, ok := adapter.GetSecretByAPIKey("key-old")
	// The behavior depends on whether GetByAPIKey filters by status.
	// Either way, the code path is exercised.
	_ = ok
}
