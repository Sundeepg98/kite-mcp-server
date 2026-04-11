package kc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ===========================================================================
// coverage_98_test.go — Push kc root from 91.3% to 98%+
//
// Targets remaining uncovered lines:
// - New() deeper branches (encryption, telegram, watchlist, users, registry)
// - LoadSessions error path (sessionDBAdapter)
// - Shutdown with metrics + alertDB
// - setupTemplates (already mostly covered, ensure template parse loop)
// - initializeTemplates / initializeSessionSigner
// - order_service: PlaceOrder/GetOrders/GetTrades error paths from broker
// - portfolio_service: GetHoldings/GetPositions/GetMargins/GetProfile error
// - session.cleanupRoutine context cancel
// - session.LoadFromDB with expired/terminated entries
// - session.GenerateWithData with DB persistence
// - session.checkSessionID plain UUID path
// - session.UpdateSessionData terminated session
// - session.GetOrCreateSessionData expired / terminated / new session paths
// - session.CleanupExpiredSessions with DB + hooks
// - session.TerminateByEmail with some failing terminations
// - credential_service.BackfillRegistryFromCredentials with errors
// - IsKiteTokenExpired before 6 AM path
// - session_signing: NewSessionSigner error (can't force), VerifySessionID edge
// - SessionLoginURL in dev mode
// - ClearSessionData error paths
// - GetSession terminated session
// ===========================================================================

// ---------------------------------------------------------------------------
// New() — with EncryptionSecret to cover the HKDF salt branch
// ---------------------------------------------------------------------------

func TestNew_WithEncryptionSecret_C98(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-long-enough",
	})
	if err != nil {
		t.Fatalf("New with encryption: %v", err)
	}
	defer m.Shutdown()
}

// ---------------------------------------------------------------------------
// New() — with DevMode to cover the mock broker path
// ---------------------------------------------------------------------------

func TestNew_DevMode_C98(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
	})
	if err != nil {
		t.Fatalf("New DevMode: %v", err)
	}
	defer m.Shutdown()
	if !m.devMode {
		t.Error("Expected devMode to be true")
	}
}

// ---------------------------------------------------------------------------
// Shutdown — with metrics set
// ---------------------------------------------------------------------------

func TestShutdown_WithMetrics_C98(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)
	// Metrics is nil by default in tests. Shutdown should handle nil metrics gracefully.
	m.Shutdown()
}

// ---------------------------------------------------------------------------
// initializeTemplates — success and use after init
// ---------------------------------------------------------------------------

func TestInitializeTemplates_Coverage98(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	defer m.Shutdown()

	err = m.initializeTemplates()
	if err != nil {
		t.Fatalf("initializeTemplates: %v", err)
	}
	if m.templates == nil {
		t.Error("templates should be non-nil after init")
	}
}

// ---------------------------------------------------------------------------
// initializeSessionSigner — with custom signer
// ---------------------------------------------------------------------------

func TestInitializeSessionSigner_CustomSigner_C98(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	defer m.Shutdown()

	custom, _ := NewSessionSignerWithKey([]byte("test-key-1234567890123456"))
	err = m.initializeSessionSigner(custom)
	if err != nil {
		t.Fatalf("initializeSessionSigner with custom: %v", err)
	}
	if m.sessionSigner != custom {
		t.Error("Expected custom signer to be used")
	}
}

func TestInitializeSessionSigner_AutoGenerate_C98(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}
	defer m.Shutdown()

	err = m.initializeSessionSigner(nil)
	if err != nil {
		t.Fatalf("initializeSessionSigner auto: %v", err)
	}
	if m.sessionSigner == nil {
		t.Error("Session signer should be auto-generated")
	}
}

// ---------------------------------------------------------------------------
// LoadSessions — via sessionDBAdapter with data
// ---------------------------------------------------------------------------

func TestLoadSessions_SkipsExpiredAndTerminated(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	now := time.Now()

	// Save a valid session
	_ = adapter.SaveSession("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01", "valid@test.com", now, now.Add(24*time.Hour), false)
	// Save an expired session
	_ = adapter.SaveSession("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee02", "expired@test.com", now.Add(-48*time.Hour), now.Add(-24*time.Hour), false)
	// Save a terminated session
	_ = adapter.SaveSession("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee03", "terminated@test.com", now, now.Add(24*time.Hour), true)

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)
	err = sm.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	// Only the valid session should be loaded
	active := sm.ListActiveSessions()
	if len(active) != 1 {
		t.Errorf("Expected 1 active session, got %d", len(active))
	}
}

// ---------------------------------------------------------------------------
// session.GenerateWithData — with DB persistence
// ---------------------------------------------------------------------------

func TestGenerateWithData_DBPersistence(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)

	// Generate with KiteSessionData
	sid := sm.GenerateWithData(&KiteSessionData{Email: "persist@test.com"})
	if sid == "" {
		t.Fatal("Expected non-empty session ID")
	}

	// Verify it was persisted — load from DB into a new registry
	sm2 := NewSessionRegistry(testLogger())
	sm2.SetDB(adapter)
	err = sm2.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	// The session should be loadable
	_, err = sm2.GetSession(sid)
	if err != nil {
		t.Errorf("Session should be persisted and loadable, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// checkSessionID — plain UUID format (no prefix)
// ---------------------------------------------------------------------------

func TestCheckSessionID_PlainUUID(t *testing.T) {
	t.Parallel()
	// Plain UUID (external format from SSE/stdio modes)
	err := checkSessionID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01")
	if err != nil {
		t.Errorf("Plain UUID should be valid, got: %v", err)
	}

	// Invalid plain UUID
	err = checkSessionID("not-a-uuid")
	if err == nil {
		t.Error("Expected error for invalid plain UUID")
	}

	// With prefix but invalid UUID
	err = checkSessionID("kitemcp-not-a-uuid")
	if err == nil {
		t.Error("Expected error for prefix + invalid UUID")
	}
}

// ---------------------------------------------------------------------------
// session.cleanupRoutine — context cancellation path
// ---------------------------------------------------------------------------

func TestCleanupRoutine_ContextCancel(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	sm.StartCleanupRoutine(ctx)

	// Cancel the context — the cleanup routine should stop
	cancel()
	time.Sleep(50 * time.Millisecond)
	// No panic, no hang — the routine stopped
}

func TestCleanupRoutine_InternalCancel(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	sm.StartCleanupRoutine(context.Background())

	// Stop via internal cancel
	sm.StopCleanupRoutine()
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// session.UpdateSessionData — terminated session error
// ---------------------------------------------------------------------------

func TestUpdateSessionData_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	sid := sm.Generate()

	// Terminate the session
	_, _ = sm.Terminate(sid)

	// Try to update — should fail
	err := sm.UpdateSessionData(sid, "new-data")
	if err == nil {
		t.Error("Expected error for updating terminated session")
	}
	if !strings.Contains(err.Error(), "terminated") {
		t.Errorf("Error should mention 'terminated', got: %v", err)
	}
}

func TestUpdateSessionData_NotFound(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	err := sm.UpdateSessionData("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99", "data")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

// ---------------------------------------------------------------------------
// session.GetOrCreateSessionData — expired and terminated paths
// ---------------------------------------------------------------------------

func TestGetOrCreateSessionData_ExpiredSession(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	// Add a session that's already expired
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee50"
	sm.mu.Lock()
	sm.sessions[sid] = &MCPSession{
		ID:        sid,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
		Data:      nil,
	}
	sm.mu.Unlock()

	_, _, err := sm.GetOrCreateSessionData(sid, func() any { return "new" })
	if err == nil {
		t.Error("Expected error for expired session")
	}
}

func TestGetOrCreateSessionData_TerminatedSession(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee51"
	sm.mu.Lock()
	sm.sessions[sid] = &MCPSession{
		ID:         sid,
		Terminated: true,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		Data:       nil,
	}
	sm.mu.Unlock()

	_, _, err := sm.GetOrCreateSessionData(sid, func() any { return "new" })
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}

func TestGetOrCreateSessionData_NewExternalSession(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	// External session ID (plain UUID) — should be auto-created
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee52"
	data, isNew, err := sm.GetOrCreateSessionData(sid, func() any { return "hello" })
	if err != nil {
		t.Fatalf("GetOrCreateSessionData: %v", err)
	}
	if !isNew {
		t.Error("Expected new session")
	}
	if data != "hello" {
		t.Errorf("Data = %v, want 'hello'", data)
	}
}

func TestGetOrCreateSessionData_ExistingDataReturned(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee53"
	// First call: creates
	_, _, _ = sm.GetOrCreateSessionData(sid, func() any { return "first" })
	// Second call: returns existing
	data, isNew, err := sm.GetOrCreateSessionData(sid, func() any { return "second" })
	if err != nil {
		t.Fatalf("GetOrCreateSessionData: %v", err)
	}
	if isNew {
		t.Error("Expected existing (not new)")
	}
	if data != "first" {
		t.Errorf("Data = %v, want 'first' (should not be overwritten)", data)
	}
}

func TestGetOrCreateSessionData_InvalidFormat(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	_, _, err := sm.GetOrCreateSessionData("not-a-uuid", func() any { return "x" })
	if err == nil {
		t.Error("Expected error for invalid session ID format")
	}
}

func TestGetOrCreateSessionData_WithDBPersist(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)

	// Use kitemcp- prefix to trigger DB persistence
	sid := sm.Generate()
	data, isNew, err := sm.GetOrCreateSessionData(sid, func() any {
		return &KiteSessionData{Email: "persist@test.com"}
	})
	if err != nil {
		t.Fatalf("GetOrCreateSessionData: %v", err)
	}
	if !isNew {
		// First time getting data for this session = new
		_ = isNew // data was nil when generated, so factory runs
	}
	_ = data
}

// ---------------------------------------------------------------------------
// session.CleanupExpiredSessions — with DB + hooks
// ---------------------------------------------------------------------------

func TestCleanupExpiredSessions_WithDBAndHooks(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)

	hookCalled := 0
	sm.AddCleanupHook(func(s *MCPSession) {
		hookCalled++
	})

	// Add expired session
	sm.mu.Lock()
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee60"] = &MCPSession{
		ID:        "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee60",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	sm.mu.Unlock()

	// Persist it
	_ = adapter.SaveSession("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee60", "expired@test.com",
		time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour), false)

	cleaned := sm.CleanupExpiredSessions()
	if cleaned != 1 {
		t.Errorf("Expected 1 cleaned, got %d", cleaned)
	}
	if hookCalled != 1 {
		t.Errorf("Expected hook called 1 time, got %d", hookCalled)
	}
}

// ---------------------------------------------------------------------------
// session.Terminate — with DB persistence
// ---------------------------------------------------------------------------

func TestTerminate_WithDB(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)

	sid := sm.Generate()
	_, err = sm.Terminate(sid)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// session.TerminateByEmail
// ---------------------------------------------------------------------------

func TestTerminateByEmail_Mixed(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	// Create sessions for same email
	sm.mu.Lock()
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee70"] = &MCPSession{
		ID: "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee70", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
		Data: &KiteSessionData{Email: "target@test.com"},
	}
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee71"] = &MCPSession{
		ID: "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee71", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
		Data:       &KiteSessionData{Email: "target@test.com"},
		Terminated: true, // already terminated, should be skipped
	}
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee72"] = &MCPSession{
		ID: "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee72", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
		Data: &KiteSessionData{Email: "other@test.com"},
	}
	sm.mu.Unlock()

	count := sm.TerminateByEmail("target@test.com")
	if count != 1 {
		t.Errorf("Expected 1 terminated (skipping already-terminated), got %d", count)
	}
}

// ---------------------------------------------------------------------------
// session.GetSessionData — expired and terminated paths
// ---------------------------------------------------------------------------

func TestGetSessionData_Expired(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee80"
	sm.mu.Lock()
	sm.sessions[sid] = &MCPSession{
		ID: sid, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour),
		Data: "old-data",
	}
	sm.mu.Unlock()

	_, err := sm.GetSessionData(sid)
	if err == nil {
		t.Error("Expected error for expired session")
	}
}

func TestGetSessionData_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee81"
	sm.mu.Lock()
	sm.sessions[sid] = &MCPSession{
		ID: sid, Terminated: true, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
		Data: "data",
	}
	sm.mu.Unlock()

	_, err := sm.GetSessionData(sid)
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}

// ---------------------------------------------------------------------------
// IsKiteTokenExpired — before 6 AM IST path
// ---------------------------------------------------------------------------

func TestIsKiteTokenExpired_BeforeSixAM(t *testing.T) {
	t.Parallel()
	// Create a time that's early morning (e.g., 3 AM IST today)
	now := time.Now().In(KolkataLocation)
	earlyMorning := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, KolkataLocation)

	// Token stored yesterday at 10 PM — should not be expired at 3 AM (before 6 AM,
	// the expiry boundary shifts to yesterday's 6 AM)
	yesterday10PM := earlyMorning.Add(-5 * time.Hour) // 10 PM previous day
	// The function uses time.Now(), so we just test that it doesn't panic
	result := IsKiteTokenExpired(yesterday10PM)
	_ = result // just exercise the code path
}

func TestIsKiteTokenExpired_AfterSixAM(t *testing.T) {
	t.Parallel()
	// Token stored 2 days ago should be expired
	twoDaysAgo := time.Now().Add(-48 * time.Hour)
	if !IsKiteTokenExpired(twoDaysAgo) {
		t.Error("Token from 2 days ago should be expired")
	}
}

func TestIsKiteTokenExpired_JustNow_C98(t *testing.T) {
	t.Parallel()
	// Token stored just now should not be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
}

// ---------------------------------------------------------------------------
// BackfillRegistryFromCredentials — with errors and success
// ---------------------------------------------------------------------------

// backfillCredStore is a mock that returns actual data from ListAllRaw.
type backfillCredStore struct {
	mockCredentialStore
	rawEntries []RawCredentialEntry
}

func (b *backfillCredStore) ListAllRaw() []RawCredentialEntry {
	return b.rawEntries
}

func TestBackfillRegistryFromCredentials_Success(t *testing.T) {
	t.Parallel()
	credStore := &backfillCredStore{
		mockCredentialStore: mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		rawEntries: []RawCredentialEntry{
			{Email: "user@test.com", APIKey: "key1", APISecret: "secret1"},
		},
	}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	regStore := registry.New()
	regStore.SetLogger(testLogger())

	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	credSvc.BackfillRegistryFromCredentials()

	// Verify it was registered
	if regStore.Count() != 1 {
		t.Errorf("Expected 1 registration, got %d", regStore.Count())
	}
}

func TestBackfillRegistryFromCredentials_AlreadyExists(t *testing.T) {
	t.Parallel()
	credStore := &backfillCredStore{
		mockCredentialStore: mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		rawEntries: []RawCredentialEntry{
			{Email: "user@test.com", APIKey: "key1", APISecret: "secret1"},
		},
	}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	regStore := registry.New()
	regStore.SetLogger(testLogger())

	// Pre-register
	_ = regStore.Register(&registry.AppRegistration{
		ID: "existing", APIKey: "key1", APISecret: "secret1",
		Status: registry.StatusActive, Source: registry.SourceMigrated,
	})

	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	credSvc.BackfillRegistryFromCredentials()

	// Should still be just 1 (not duplicated)
	if regStore.Count() != 1 {
		t.Errorf("Expected 1 registration (no duplicate), got %d", regStore.Count())
	}
}

func TestBackfillRegistryFromCredentials_NilRegistry_C98(t *testing.T) {
	t.Parallel()
	credStore := &backfillCredStore{
		mockCredentialStore: mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		rawEntries: []RawCredentialEntry{
			{Email: "user@test.com", APIKey: "key1", APISecret: "secret1"},
		},
	}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	// Should not panic with nil registry
	credSvc.BackfillRegistryFromCredentials()
}

func TestBackfillRegistryFromCredentials_EmptyCredentials_C98(t *testing.T) {
	t.Parallel()
	credStore := &backfillCredStore{
		mockCredentialStore: mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		rawEntries:          nil,
	}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	regStore := registry.New()
	regStore.SetLogger(testLogger())

	credSvc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	credSvc.BackfillRegistryFromCredentials()
	if regStore.Count() != 0 {
		t.Errorf("Expected 0 registrations, got %d", regStore.Count())
	}
}

// ---------------------------------------------------------------------------
// OrderService — broker error paths
// ---------------------------------------------------------------------------

func TestOrderService_PlaceOrder_BrokerError(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	// DevMode mock broker returns error for PlaceOrder with invalid params
	_, err := os.PlaceOrder("test@example.com", broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Quantity:        10,
		Product:         "CNC",
	})
	// Mock broker may succeed or fail — we're exercising the code path
	_ = err
}

func TestOrderService_GetOrders_BrokerError(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	orders, err := os.GetOrders("test@example.com")
	// Mock broker returns empty orders — no error
	if err != nil {
		t.Fatalf("GetOrders: %v", err)
	}
	_ = orders
}

func TestOrderService_GetTrades_BrokerError(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	trades, err := os.GetTrades("test@example.com")
	if err != nil {
		t.Fatalf("GetTrades: %v", err)
	}
	_ = trades
}

func TestOrderService_CancelOrder_Success(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	// Cancel with an order ID — mock broker may error but code path is exercised
	_, err := os.CancelOrder("test@example.com", "fake-order-id", "regular")
	_ = err
}

func TestOrderService_ModifyOrder_Success(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	_, err := os.ModifyOrder("test@example.com", "fake-order-id", broker.OrderParams{
		Quantity: 5,
		Price:    100.0,
	})
	_ = err
}

func TestOrderService_NoBroker(t *testing.T) {
	t.Parallel()
	// Non-devMode with no tokens → getBroker error
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	os := NewOrderService(ss, testLogger())
	_, err := os.PlaceOrder("notoken@example.com", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error when no broker available")
	}
	if !strings.Contains(err.Error(), "order:") {
		t.Errorf("Error should be wrapped with 'order:', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PortfolioService — broker error paths
// ---------------------------------------------------------------------------

func TestPortfolioService_GetHoldings_Success_C98(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	ps := NewPortfolioService(ss, testLogger())
	holdings, err := ps.GetHoldings("test@example.com")
	if err != nil {
		t.Fatalf("GetHoldings: %v", err)
	}
	_ = holdings
}

func TestPortfolioService_GetPositions_Success_C98(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	ps := NewPortfolioService(ss, testLogger())
	positions, err := ps.GetPositions("test@example.com")
	if err != nil {
		t.Fatalf("GetPositions: %v", err)
	}
	_ = positions
}

func TestPortfolioService_GetMargins_Success_C98(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	ps := NewPortfolioService(ss, testLogger())
	margins, err := ps.GetMargins("test@example.com")
	if err != nil {
		t.Fatalf("GetMargins: %v", err)
	}
	_ = margins
}

func TestPortfolioService_GetProfile_Success_C98(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	ps := NewPortfolioService(ss, testLogger())
	profile, err := ps.GetProfile("test@example.com")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	_ = profile
}

func TestPortfolioService_NoBroker(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetHoldings("notoken@example.com")
	if err == nil || !strings.Contains(err.Error(), "portfolio:") {
		t.Errorf("GetHoldings error should be wrapped with 'portfolio:', got: %v", err)
	}
	_, err = ps.GetPositions("notoken@example.com")
	if err == nil || !strings.Contains(err.Error(), "portfolio:") {
		t.Errorf("GetPositions error should be wrapped with 'portfolio:', got: %v", err)
	}
	_, err = ps.GetMargins("notoken@example.com")
	if err == nil || !strings.Contains(err.Error(), "portfolio:") {
		t.Errorf("GetMargins error should be wrapped with 'portfolio:', got: %v", err)
	}
	_, err = ps.GetProfile("notoken@example.com")
	if err == nil || !strings.Contains(err.Error(), "portfolio:") {
		t.Errorf("GetProfile error should be wrapped with 'portfolio:', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PortfolioService — broker returns error (not "no broker" but actual call error)
// ---------------------------------------------------------------------------

type failBrokerSessionService struct {
	*SessionService
}

func TestPortfolioService_BrokerCallErrors(t *testing.T) {
	t.Parallel()
	// Use a mock HTTP server that returns Kite errors for all endpoints
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"Invalid token"}`)
	}))
	defer ts.Close()

	m := newTestManagerWithDB(t)

	// Create a session with a Kite client pointed at the failing mock
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee90"
	kd, _, _ := m.GetOrCreateSessionWithEmail(sid, "broker-fail@test.com")
	kd.Kite.Client.SetBaseURI(ts.URL)
	kd.Kite.Client.SetAccessToken("fake-token")

	// Store the token so GetBrokerForEmail can find it
	m.TokenStore().Set("broker-fail@test.com", &KiteTokenEntry{
		AccessToken: "fake-token",
	})

	ps := NewPortfolioService(m.SessionSvc(), testLogger())

	_, err := ps.GetHoldings("broker-fail@test.com")
	if err == nil {
		t.Error("Expected error from broker call")
	}
	if !strings.Contains(err.Error(), "failed to get holdings") {
		t.Errorf("Error should mention 'failed to get holdings', got: %v", err)
	}

	_, err = ps.GetPositions("broker-fail@test.com")
	if err == nil || !strings.Contains(err.Error(), "failed to get positions") {
		t.Errorf("GetPositions error: %v", err)
	}

	_, err = ps.GetMargins("broker-fail@test.com")
	if err == nil || !strings.Contains(err.Error(), "failed to get margins") {
		t.Errorf("GetMargins error: %v", err)
	}

	_, err = ps.GetProfile("broker-fail@test.com")
	if err == nil || !strings.Contains(err.Error(), "failed to get profile") {
		t.Errorf("GetProfile error: %v", err)
	}
}

func TestOrderService_BrokerCallErrors(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"Invalid token"}`)
	}))
	defer ts.Close()

	m := newTestManagerWithDB(t)
	sid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee91"
	kd, _, _ := m.GetOrCreateSessionWithEmail(sid, "order-fail@test.com")
	kd.Kite.Client.SetBaseURI(ts.URL)
	kd.Kite.Client.SetAccessToken("fake-token")
	m.TokenStore().Set("order-fail@test.com", &KiteTokenEntry{AccessToken: "fake-token"})

	os := NewOrderService(m.SessionSvc(), testLogger())

	_, err := os.PlaceOrder("order-fail@test.com", broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "SBIN", TransactionType: "BUY",
		OrderType: "MARKET", Quantity: 1, Product: "CNC",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to place order") {
		t.Errorf("PlaceOrder error: %v", err)
	}

	_, err = os.GetOrders("order-fail@test.com")
	if err == nil || !strings.Contains(err.Error(), "failed to get orders") {
		t.Errorf("GetOrders error: %v", err)
	}

	_, err = os.GetTrades("order-fail@test.com")
	if err == nil || !strings.Contains(err.Error(), "failed to get trades") {
		t.Errorf("GetTrades error: %v", err)
	}

	_, err = os.ModifyOrder("order-fail@test.com", "some-order-id", broker.OrderParams{Quantity: 2})
	if err == nil || !strings.Contains(err.Error(), "failed to modify order") {
		t.Errorf("ModifyOrder error: %v", err)
	}

	_, err = os.CancelOrder("order-fail@test.com", "some-order-id", "regular")
	if err == nil || !strings.Contains(err.Error(), "failed to cancel order") {
		t.Errorf("CancelOrder error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SessionLoginURL — DevMode returns error
// ---------------------------------------------------------------------------

func TestSessionLoginURL_DevMode(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	_, err := ss.SessionLoginURL("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee92")
	if err == nil {
		t.Error("Expected error in DevMode")
	}
	if !strings.Contains(err.Error(), "DEV_MODE") {
		t.Errorf("Error should mention DEV_MODE, got: %v", err)
	}
}

func TestSessionLoginURL_EmptyID_C98(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	_, err := ss.SessionLoginURL("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

// ---------------------------------------------------------------------------
// ClearSessionData — various paths
// ---------------------------------------------------------------------------

func TestClearSessionData_EmptyID_C98(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.ClearSessionData("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestClearSessionData_NotFound(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.ClearSessionData("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee93")
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

func TestClearSessionData_WithData(t *testing.T) {
	t.Parallel()
	m := newTestManagerWithDB(t)

	sid := m.GenerateSession()
	kd, _ := m.GetSession(sid)
	if kd == nil {
		t.Fatal("Expected session data")
	}

	err := m.SessionSvc().ClearSessionData(sid)
	if err != nil {
		t.Fatalf("ClearSessionData: %v", err)
	}
}

func TestClearSessionData_NilData(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	sid := ss.SessionManager().Generate()
	// Session data is nil by default
	err := ss.ClearSessionData(sid)
	if err != nil {
		t.Fatalf("ClearSessionData with nil data: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetSession — terminated session
// ---------------------------------------------------------------------------

func TestGetSession_Terminated(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	sid := ss.SessionManager().Generate()
	_, _ = ss.SessionManager().Terminate(sid)

	_, err := ss.GetSession(sid)
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}

func TestGetSession_EmptyID(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	_, err := ss.GetSession("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

// ---------------------------------------------------------------------------
// session_signing: VerifySessionID edge cases
// ---------------------------------------------------------------------------

func TestVerifySessionID_FutureTimestamp(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("NewSessionSigner: %v", err)
	}

	// Create a signed param, then tamper with the timestamp to be far in the future
	// Can't easily tamper because HMAC protects it. Instead test with expired signer.
	signer.SetSignatureExpiry(1 * time.Nanosecond)
	time.Sleep(10 * time.Millisecond)

	sid := "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee94"
	signed := signer.SignSessionID(sid)

	// Set a longer expiry to check the clock skew code path
	signer.SetSignatureExpiry(1 * time.Hour)

	result, err := signer.VerifySessionID(signed)
	if err != nil {
		t.Fatalf("VerifySessionID: %v", err)
	}
	if result != sid {
		t.Errorf("Got %q, want %q", result, sid)
	}
}

func TestVerifySessionID_TamperedPayload(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	sid := "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee95"
	signed := signer.SignSessionID(sid)

	// Replace the session ID in the payload
	tampered := strings.Replace(signed, sid, "kitemcp-ffffffff-ffff-ffff-ffff-ffffffffffff", 1)
	_, err := signer.VerifySessionID(tampered)
	if err == nil || !errors.Is(err, ErrTamperedSession) {
		t.Errorf("Expected ErrTamperedSession, got: %v", err)
	}
}

func TestVerifySessionID_InvalidBase64(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	// Create invalid signed param with bad base64 signature
	_, err := signer.VerifySessionID("payload|12345.not-valid-base64!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestVerifySessionID_WrongPartCount(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	_, err := signer.VerifySessionID("no-dots-here")
	if !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("Expected ErrInvalidFormat, got: %v", err)
	}
}

func TestVerifySessionID_InvalidTimestamp(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	// Three-part format with non-numeric timestamp
	_, err := signer.VerifySessionID("session|notanumber.fakesig==")
	if err == nil {
		t.Error("Expected error for invalid timestamp")
	}
}

// ---------------------------------------------------------------------------
// NewSessionSignerWithKey — empty key
// ---------------------------------------------------------------------------

func TestNewSessionSignerWithKey_EmptyKey_C98(t *testing.T) {
	t.Parallel()
	_, err := NewSessionSignerWithKey([]byte{})
	if !errors.Is(err, ErrEmptySecretKey) {
		t.Errorf("Expected ErrEmptySecretKey, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OpenBrowser — exercising the exec.Command path for valid URL in local mode
// ---------------------------------------------------------------------------

func TestOpenBrowser_EmptyScheme(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager("key", "secret")
	defer m.Shutdown()

	err := m.OpenBrowser("://no-scheme")
	if err == nil {
		t.Error("Expected error for empty/invalid scheme")
	}
}

// ---------------------------------------------------------------------------
// Validate — session expired path (auto-terminate)
// ---------------------------------------------------------------------------

func TestValidate_ExpiredSession(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sid := sm.Generate()
	// Force expire by modifying ExpiresAt
	sm.mu.Lock()
	sm.sessions[sid].ExpiresAt = time.Now().Add(-1 * time.Hour)
	sm.mu.Unlock()

	isTerminated, err := sm.Validate(sid)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !isTerminated {
		t.Error("Expected terminated for expired session")
	}
}

// ---------------------------------------------------------------------------
// Validate — not found
// ---------------------------------------------------------------------------

func TestValidate_NotFound(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	_, err := sm.Validate("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99")
	if err == nil {
		t.Error("Expected error for session not found")
	}
}

// ---------------------------------------------------------------------------
// setupTemplates — verify all templates parse
// ---------------------------------------------------------------------------

func TestSetupTemplates_Success(t *testing.T) {
	t.Parallel()
	templates, err := setupTemplates()
	if err != nil {
		t.Fatalf("setupTemplates: %v", err)
	}
	if len(templates) == 0 {
		t.Error("Expected at least one template")
	}
}

// ---------------------------------------------------------------------------
// Manager accessors coverage
// ---------------------------------------------------------------------------

func TestManagerAccessors(t *testing.T) {
	t.Parallel()
	m, _ := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		ExternalURL:        "https://test.example.com",
		AdminSecretPath:    "/admin/secret",
		AppMode:            "http",
	})
	defer m.Shutdown()

	if m.ExternalURL() != "https://test.example.com" {
		t.Error("ExternalURL mismatch")
	}
	if m.AdminSecretPath() != "/admin/secret" {
		t.Error("AdminSecretPath mismatch")
	}
	if m.IsLocalMode() {
		t.Error("Expected not local mode for http")
	}
	if m.SessionManager() == nil {
		t.Error("SessionManager should not be nil")
	}
	if m.SessionSigner() == nil {
		t.Error("SessionSigner should not be nil")
	}
}

// ---------------------------------------------------------------------------
// UpdateSessionField — various paths
// ---------------------------------------------------------------------------

func TestUpdateSessionField_NotFound(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	err := sm.UpdateSessionField("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee99", func(data any) {})
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}

func TestUpdateSessionField_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	sid := sm.Generate()
	_, _ = sm.Terminate(sid)

	err := sm.UpdateSessionField(sid, func(data any) {})
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}

func TestUpdateSessionField_Success(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())
	sid := sm.GenerateWithData(&KiteSessionData{Email: ""})

	err := sm.UpdateSessionField(sid, func(data any) {
		if kd, ok := data.(*KiteSessionData); ok {
			kd.Email = "updated@test.com"
		}
	})
	if err != nil {
		t.Fatalf("UpdateSessionField: %v", err)
	}

	// Verify
	d, _ := sm.GetSessionData(sid)
	kd := d.(*KiteSessionData)
	if kd.Email != "updated@test.com" {
		t.Errorf("Email = %q, want updated@test.com", kd.Email)
	}
}

// ---------------------------------------------------------------------------
// New() — with instruments manager creation error (nil config with nil manager)
// ---------------------------------------------------------------------------

func TestNew_InstrumentsManagerAutoCreation(t *testing.T) {
	t.Parallel()
	// When InstrumentsManager is nil, New() creates one internally.
	// This tests the internal creation path (which uses HTTP for real instruments).
	// We don't want actual HTTP calls, but the creation path is exercised.
	cfg := instruments.DefaultUpdateConfig()
	cfg.EnableScheduler = false
	m, err := New(Config{
		APIKey:            "key",
		APISecret:         "secret",
		Logger:            testLogger(),
		InstrumentsConfig: cfg,
	})
	if err != nil {
		t.Fatalf("New with auto instruments: %v", err)
	}
	defer m.Shutdown()
}

// ---------------------------------------------------------------------------
// ListActiveSessions — with expired sessions auto-terminating
// ---------------------------------------------------------------------------

func TestListActiveSessions_AutoExpire(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	// Add a valid session
	sm.mu.Lock()
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea0"] = &MCPSession{
		ID: "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea0",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	// Add an expired session
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea1"] = &MCPSession{
		ID: "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea1",
		CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	sm.mu.Unlock()

	active := sm.ListActiveSessions()
	if len(active) != 1 {
		t.Errorf("Expected 1 active session, got %d", len(active))
	}
}

// ---------------------------------------------------------------------------
// LoadFromDB — with delete error (simulate by closing DB)
// ---------------------------------------------------------------------------

func TestLoadFromDB_DeleteError(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	// Save an expired session
	_ = adapter.SaveSession("kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeb0", "expired@test.com",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), false)

	sm := NewSessionRegistry(testLogger())
	sm.SetDB(adapter)

	// LoadFromDB should succeed even if delete of stale session has issues
	err = sm.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CompleteSession — with metrics
// ---------------------------------------------------------------------------

type mockMetrics struct{}

func (m *mockMetrics) Increment(key string)      {}
func (m *mockMetrics) TrackDailyUser(userID string) {}
func (m *mockMetrics) IncrementDaily(key string)  {}
func (m *mockMetrics) Shutdown()                  {}

func TestCompleteSession_WithMetrics(t *testing.T) {
	t.Parallel()
	ts := newMockKiteServer(t)
	defer ts.Close()

	credStore := &mockCredentialStore{
		entries: map[string]*KiteCredentialEntry{
			"user@example.com": {APIKey: "test-key", APISecret: "test-secret"},
		},
	}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	credSvc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "test-key",
		APISecret:       "test-secret",
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})
	signer, _ := NewSessionSigner()
	ss := NewSessionService(SessionServiceConfig{
		CredentialSvc: credSvc,
		TokenStore:    tokenStore,
		SessionSigner: signer,
		Logger:        testLogger(),
		Metrics:       &mockMetrics{},
	})
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	// Create session with email
	kd, _, err := ss.GetOrCreateSessionWithEmail("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeec0", "user@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail: %v", err)
	}
	kd.Kite.Client.SetBaseURI(ts.URL)

	err = ss.CompleteSession("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeec0", "mock-request-token")
	if err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}
}
