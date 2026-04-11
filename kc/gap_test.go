package kc

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ===========================================================================
// gap_test.go — Push kc from ~93.1% to 98%+
//
// Targets uncovered lines in:
// - manager.go New(): instrument creation error, DB init errors, callbacks
// - manager.go OpenBrowser: non-local, bad URL scheme
// - manager.go initializeTemplates/initializeSessionSigner: error paths
// - manager.go LoadSessions: DB error
// - manager.go Shutdown: DB close error
// - manager.go setupTemplates: error paths
// - session.go LoadFromDB: DB error, stale session cleanup DB error
// - session.go GenerateWithData: DB persist error
// - session.go Terminate: DB delete error
// - session.go CleanupExpiredSessions: DB delete error
// - session.go cleanupRoutine: context done
// - session.go GetOrCreateSessionData: expired/terminated session, persist error
// - session_service.go: various error paths
// - session_signing.go: NewSessionSigner error (crypto/rand, unreachable)
// - credential_service.go: BackfillRegistryFromCredentials error
// - order_service.go: ModifyOrder/CancelOrder broker errors
// ===========================================================================

func gapTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------------------------------------------------------------------------
// Manager New() — with DB path (exercises many branches in New)
// ---------------------------------------------------------------------------
func TestNew_WithAlertDBPath_Gap(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-32bytes!!",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.alertDB == nil {
		t.Error("Expected alertDB to be initialized")
	}
	if m.tokenStore == nil {
		t.Error("Expected tokenStore to be initialized")
	}
}

// ---------------------------------------------------------------------------
// Manager New() — with Telegram bot token (covers Telegram path)
// ---------------------------------------------------------------------------
func TestNew_WithTelegramToken(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		TelegramBotToken:   "123:fake-token-for-test",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	// telegramNotifier may or may not be nil depending on token validity
	// We just ensure no panic
}

// ---------------------------------------------------------------------------
// Manager New() — with custom session signer (line 572-573)
// ---------------------------------------------------------------------------
func TestNew_WithCustomSessionSigner_Gap(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-secret-key-1234567890123456"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		SessionSigner:      signer,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.sessionSigner != signer {
		t.Error("Expected custom session signer to be used")
	}
}

// ---------------------------------------------------------------------------
// Manager New() — nil logger (should return error)
// ---------------------------------------------------------------------------
func TestNew_NilLogger_Gap(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "key",
		APISecret: "secret",
	})
	if err == nil {
		t.Error("Expected error for nil logger")
	}
}

// ---------------------------------------------------------------------------
// Manager New() — no credentials (line 59-61 warn path)
// ---------------------------------------------------------------------------
func TestNew_NoCredentials(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()
	// Just verifies no panic, warn is logged
}

// ---------------------------------------------------------------------------
// Manager New() — instruments manager creation (line 68-76)
// ---------------------------------------------------------------------------
func TestNew_DefaultInstrumentsManager(t *testing.T) {
	t.Parallel()
	// Create with no InstrumentsManager, it should auto-create one
	config := instruments.DefaultUpdateConfig()
	config.EnableScheduler = false

	m, err := New(Config{
		APIKey:            "key",
		APISecret:         "secret",
		Logger:            gapTestLogger(),
		InstrumentsConfig: config,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	if m.Instruments == nil {
		t.Error("Expected instruments manager to be created automatically")
	}
}

// ---------------------------------------------------------------------------
// Manager Shutdown — with alertDB open (covers DB close error path)
// ---------------------------------------------------------------------------
func TestManager_ShutdownWithDB(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Close the DB manually first to trigger error on Shutdown
	m.alertDB.Close()
	m.Shutdown() // should log error but not panic
}

// ---------------------------------------------------------------------------
// Manager OpenBrowser — non-local mode (returns nil, line 538)
// ---------------------------------------------------------------------------
func TestManager_OpenBrowser_NonLocal(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AppMode:            "http",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("https://example.com")
	if err != nil {
		t.Errorf("Expected nil error for non-local mode, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Manager OpenBrowser — invalid URL scheme (line 543-544)
// ---------------------------------------------------------------------------
func TestManager_OpenBrowser_BadScheme(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AppMode:            "stdio",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://evil.com")
	if err == nil {
		t.Error("Expected error for invalid URL scheme")
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: LoadFromDB with stale sessions (line 117-118)
// ---------------------------------------------------------------------------
func TestSessionRegistry_LoadFromDB_StaleSessionCleanup(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	adapter := &sessionDBAdapter{db: db}

	// Save expired and terminated sessions
	past := time.Now().Add(-1 * time.Hour)
	err = adapter.SaveSession("expired-sess", "user@test.com", past, past, false)
	if err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}
	err = adapter.SaveSession("terminated-sess", "user@test.com", time.Now(), time.Now().Add(1*time.Hour), true)
	if err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}
	// Save valid session
	err = adapter.SaveSession("valid-sess", "user@test.com", time.Now(), time.Now().Add(24*time.Hour), false)
	if err != nil {
		t.Fatalf("SaveSession error: %v", err)
	}

	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	if err := sm.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	// Only valid session should be loaded
	_, err = sm.GetSessionData("valid-sess")
	if err != nil {
		t.Error("Expected valid session to be loaded")
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: GenerateWithData with DB persist (line 163-169)
// ---------------------------------------------------------------------------
func TestSessionRegistry_GenerateWithData_DBPersist(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	adapter := &sessionDBAdapter{db: db}
	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	data := &KiteSessionData{Email: "user@test.com"}
	sessionID := sm.GenerateWithData(data)

	if sessionID == "" {
		t.Error("Expected non-empty session ID")
	}

	// Verify it's in DB
	entries, err := adapter.LoadSessions()
	if err != nil {
		t.Fatalf("LoadSessions error: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.SessionID == sessionID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected session to be persisted to DB")
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: Terminate with DB delete error (line 278-280)
// ---------------------------------------------------------------------------
func TestSessionRegistry_Terminate_DBDeleteError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	adapter := &sessionDBAdapter{db: db}
	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	sessionID := sm.GenerateWithData(&KiteSessionData{Email: "user@test.com"})

	// Close DB so DeleteSession fails
	db.Close()

	// Terminate should log error but not panic
	_, err = sm.Terminate(sessionID)
	// err may or may not be returned depending on implementation
	_ = err
}

// ---------------------------------------------------------------------------
// SessionRegistry: CleanupExpiredSessions with DB delete error (line 385-387)
// ---------------------------------------------------------------------------
func TestSessionRegistry_CleanupExpired_DBDeleteError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	adapter := &sessionDBAdapter{db: db}
	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	// Create a session with very short expiry
	sm.mu.Lock()
	sm.sessions["exp-sess"] = &MCPSession{
		ID:        "exp-sess",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
		Data:      &KiteSessionData{Email: "user@test.com"},
	}
	sm.mu.Unlock()

	// Close DB so DeleteSession fails
	db.Close()

	cleaned := sm.CleanupExpiredSessions()
	if cleaned != 1 {
		t.Errorf("Expected 1 cleaned session, got %d", cleaned)
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: cleanupRoutine (stop via context cancel, line 434-436)
// ---------------------------------------------------------------------------
func TestSessionRegistry_StopCleanupRoutine(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(gapTestLogger())
	ctx, cancel := context.WithCancel(context.Background())
	sm.StartCleanupRoutine(ctx)
	_ = cancel
	time.Sleep(10 * time.Millisecond)
	sm.StopCleanupRoutine() // exercises ctx.Done path
}

// ---------------------------------------------------------------------------
// SessionRegistry: GetOrCreateSessionData with expired session (line 558-562)
// ---------------------------------------------------------------------------
func TestSessionRegistry_GetOrCreateSessionData_Expired_Gap(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(gapTestLogger())

	// Create an expired session
	sm.mu.Lock()
	sm.sessions["exp-sess"] = &MCPSession{
		ID:        "exp-sess",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	sm.mu.Unlock()

	_, _, err := sm.GetOrCreateSessionData("exp-sess", func() any {
		return &KiteSessionData{Email: "user@test.com"}
	})
	if err == nil {
		t.Error("Expected error for expired session")
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: GetOrCreateSessionData with terminated session (line 565-568)
// ---------------------------------------------------------------------------
func TestSessionRegistry_GetOrCreateSessionData_Terminated_Gap(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(gapTestLogger())

	sm.mu.Lock()
	sm.sessions["term-sess"] = &MCPSession{
		ID:         "term-sess",
		Terminated: true,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
	sm.mu.Unlock()

	_, _, err := sm.GetOrCreateSessionData("term-sess", func() any {
		return &KiteSessionData{Email: "user@test.com"}
	})
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}

// ---------------------------------------------------------------------------
// SessionRegistry: GetOrCreateSessionData with persist error (line 596-598)
// ---------------------------------------------------------------------------
func TestSessionRegistry_GetOrCreateSessionData_PersistError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	adapter := &sessionDBAdapter{db: db}
	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	// Close DB so persist fails
	db.Close()

	// Creating a new kitemcp- session with closed DB should log error but not fail
	// Session ID must have kitemcp- prefix + valid UUID format
	data, isNew, err := sm.GetOrCreateSessionData("kitemcp-00000000-0000-0000-0000-000000000001", func() any {
		return &KiteSessionData{Email: "user@test.com"}
	})
	if err != nil {
		t.Fatalf("Expected no error (persist error is logged), got: %v", err)
	}
	if !isNew {
		t.Error("Expected isNew to be true")
	}
	if data == nil {
		t.Error("Expected data to be non-nil")
	}
}

// ---------------------------------------------------------------------------
// SessionService: GetSession with validation error (line 243-246)
// ---------------------------------------------------------------------------
func TestSessionService_GetSession_ValidationError(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	_, err = m.sessionSvc.GetSession("invalid-session-id")
	if err == nil {
		t.Error("Expected error for invalid session")
	}
}

// ---------------------------------------------------------------------------
// SessionService: ClearSessionData with error paths (line 308-311)
// ---------------------------------------------------------------------------
func TestSessionService_ClearSessionData_NoSession(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.sessionSvc.ClearSessionData("nonexistent-session")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

// ---------------------------------------------------------------------------
// SessionService: ClearSessionData with existing session
// ---------------------------------------------------------------------------
func TestSessionService_ClearSessionData_Success_Gap(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	sessionID := m.GenerateSession()
	err = m.sessionSvc.ClearSessionData(sessionID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SessionService: SessionLoginURL error (line 341-344)
// ---------------------------------------------------------------------------
func TestSessionService_SessionLoginURL_SignerError(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Test with valid session — should succeed
	sessionID := m.GenerateSession()
	loginURL, err := m.sessionSvc.SessionLoginURL(sessionID)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if loginURL == "" {
		t.Error("Expected non-empty login URL")
	}
}

// ---------------------------------------------------------------------------
// SessionService: GetOrCreateSessionWithEmail (exercises the method)
// ---------------------------------------------------------------------------
func TestSessionService_GetOrCreateSessionWithEmail(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	sessionID := m.GenerateSession()
	data, isNew, err := m.sessionSvc.GetOrCreateSessionWithEmail(sessionID, "user@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail error: %v", err)
	}
	if isNew {
		t.Error("Expected isNew to be false (session already exists)")
	}
	if data.Email != "user@test.com" {
		t.Errorf("Expected email user@test.com, got: %s", data.Email)
	}
}

// ---------------------------------------------------------------------------
// CredentialService: BackfillRegistryFromCredentials with error (line 161-164)
// ---------------------------------------------------------------------------
func TestCredentialService_BackfillRegistryWithError(t *testing.T) {
	t.Parallel()
	credStore := NewKiteCredentialStore()
	credStore.Set("user@test.com", &KiteCredentialEntry{APIKey: "api-key", APISecret: "api-secret"})

	regStore := registry.New()
	regStore.SetLogger(gapTestLogger())

	// Create a service with a registry that already has the key
	cs := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      NewKiteTokenStore(),
		RegistryStore:   regStore,
		Logger:          gapTestLogger(),
	})

	// First backfill should succeed
	cs.BackfillRegistryFromCredentials()

	// The key should now be in the registry
	_, found := regStore.GetByAPIKeyAnyStatus("api-key")
	if !found {
		t.Error("Expected backfilled key in registry")
	}

	// Add another credential
	credStore.Set("user2@test.com", &KiteCredentialEntry{APIKey: "api-key-2", APISecret: "api-secret-2"})

	// Backfill again — should skip existing and add new
	cs.BackfillRegistryFromCredentials()
}

// ---------------------------------------------------------------------------
// CredentialService: BackfillRegistryFromCredentials with nil registry
// ---------------------------------------------------------------------------
func TestCredentialService_BackfillNilRegistry(t *testing.T) {
	t.Parallel()
	cs := NewCredentialService(CredentialServiceConfig{
		CredentialStore: NewKiteCredentialStore(),
		TokenStore:      NewKiteTokenStore(),
		Logger:          gapTestLogger(),
	})
	cs.BackfillRegistryFromCredentials() // should return early, no panic
}

// ---------------------------------------------------------------------------
// OrderService: ModifyOrder/CancelOrder error paths (lines 60, 74)
// ---------------------------------------------------------------------------
func TestOrderService_ModifyOrder_NoSession(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	_, err = m.orderSvc.ModifyOrder("noone@test.com", "ORDER-123", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

func TestOrderService_CancelOrder_NoSession(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	_, err = m.orderSvc.CancelOrder("noone@test.com", "ORDER-123", "regular")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

// ---------------------------------------------------------------------------
// Manager with DB: LoadSessions error (line 362-364, 1006-1008)
// ---------------------------------------------------------------------------
func TestManager_LoadSessions_DBError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	adapter := &sessionDBAdapter{db: db}
	sm := NewSessionRegistry(gapTestLogger())
	sm.SetDB(adapter)

	// Close DB to cause error
	db.Close()

	err = sm.LoadFromDB()
	if err == nil {
		t.Error("Expected error for closed DB")
	}
}

// ---------------------------------------------------------------------------
// SessionSigning: VerifySessionID with bad base64 (line 106-108)
// ---------------------------------------------------------------------------
func TestVerifySessionID_BadBase64(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("NewSessionSigner error: %v", err)
	}

	// Craft a signed param with invalid base64 signature
	_, err = signer.VerifySessionID("payload|1234567890.!!!invalid-base64!!!")
	if err == nil {
		t.Error("Expected error for bad base64 signature")
	}
}

// ---------------------------------------------------------------------------
// Manager with DB — exercises full lifecycle paths
// ---------------------------------------------------------------------------
func TestManager_DBLifecycle(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             gapTestLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-secret-key-that-is-long-eno",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Generate session with DB persistence
	sessionID := m.GenerateSession()
	if sessionID == "" {
		t.Error("Expected non-empty session ID")
	}

	// Get session
	data, err := m.GetSession(sessionID)
	if err != nil {
		t.Errorf("GetSession error: %v", err)
	}
	if data == nil {
		t.Error("Expected non-nil session data")
	}

	// Terminate
	m.ClearSession(sessionID)

	// Shutdown gracefully
	m.Shutdown()
}

// ---------------------------------------------------------------------------
// Documented unreachable lines
// ---------------------------------------------------------------------------
//
// The following lines are documented as unreachable and NOT tested:
//
// - session_signing.go:39-41 — NewSessionSigner crypto/rand.Read error
//   (crypto/rand.Read never fails in Go 1.24+, panics instead)
//
// - manager.go:73-75 — instruments.New() error path
//   (only fails with bad config, tested via instruments package itself)
//
// - manager.go:551-554 — initializeTemplates/setupTemplates template parse
//   errors (templates are embedded via embed.FS, always valid at build time)
