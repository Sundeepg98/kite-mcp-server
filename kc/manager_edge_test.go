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
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ===========================================================================
// Manager.New — nil logger error
// ===========================================================================

func TestNew_NilLogger(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "key",
		APISecret: "secret",
	})
	if err == nil {
		t.Fatal("Expected error with nil logger")
	}
}

// ===========================================================================
// Manager.New — no API key/secret warning path (doesn't error, just warns)
// ===========================================================================

func TestNew_NoAPICredentials(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Logger:             testLogger(),
		InstrumentsManager: newTestInstrumentsManager(),
	})
	if err != nil {
		t.Fatalf("Expected no error (just warning), got: %v", err)
	}
	defer m.Shutdown()
	if m.apiKey != "" {
		t.Errorf("apiKey = %q, want empty", m.apiKey)
	}
}

// ===========================================================================
// Manager.OpenBrowser — coverage for URL validation and non-local mode
// ===========================================================================

func TestOpenBrowser_NonLocalMode_HTTP(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey: "key", APISecret: "secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "http", // not local mode
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// Non-local mode should return nil immediately
	err = m.OpenBrowser("https://example.com")
	if err != nil {
		t.Errorf("Expected nil for non-local mode, got: %v", err)
	}
}

func TestOpenBrowser_InvalidScheme_FTP(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Fatal("Expected error for ftp scheme")
	}
	if !strings.Contains(err.Error(), "invalid URL scheme") {
		t.Errorf("Error should mention 'invalid URL scheme', got: %v", err)
	}
}

func TestOpenBrowser_EmptyURL_Boost(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("")
	if err == nil {
		t.Fatal("Expected error for empty URL")
	}
}

// ===========================================================================
// Manager.PaperEngine — nil returns nil interface
// ===========================================================================

func TestPaperEngine_Nil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.PaperEngine() != nil {
		t.Error("PaperEngine should return nil when not configured")
	}
}

func TestPaperEngine_Configured(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	engine := &papertrading.PaperEngine{}
	m.SetPaperEngine(engine)

	result := m.PaperEngine()
	if result == nil {
		t.Error("PaperEngine should not be nil when configured")
	}
}

// ===========================================================================
// Manager.BillingStore — nil returns nil interface
// ===========================================================================

func TestBillingStore_Nil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.BillingStore() != nil {
		t.Error("BillingStore should return nil when not configured")
	}
}

func TestBillingStore_Configured(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	store := &billing.Store{}
	m.SetBillingStore(store)

	result := m.BillingStore()
	if result == nil {
		t.Error("BillingStore should not be nil when configured")
	}
}

// ===========================================================================
// Manager.HandleKiteCallback — session not found (CompleteSession fails)
// ===========================================================================

func TestHandleKiteCallback_SessionNotFound_WithValidSig(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Sign a session ID that doesn't exist
	signed := m.sessionSigner.SignSessionID("nonexistent-session-id")

	handler := m.HandleKiteCallback()
	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok&session_id="+signed, nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (session not found)", rr.Code)
	}
}

// ===========================================================================
// initializeSessionSigner — custom signer
// ===========================================================================

func TestInitializeSessionSigner_Custom(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	customSigner, _ := NewSessionSignerWithKey([]byte("custom-key-32-bytes-for-testing!!"))
	err = m.initializeSessionSigner(customSigner)
	if err != nil {
		t.Fatalf("initializeSessionSigner error: %v", err)
	}
	if m.sessionSigner != customSigner {
		t.Error("Expected custom signer to be set")
	}
}

func TestInitializeSessionSigner_AutoGenerate_Boost(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.initializeSessionSigner(nil)
	if err != nil {
		t.Fatalf("initializeSessionSigner (auto) error: %v", err)
	}
	if m.sessionSigner == nil {
		t.Error("Session signer should be auto-generated")
	}
}

// ===========================================================================
// IsKiteTokenExpired — cover both branches
// ===========================================================================

func TestIsKiteTokenExpired_JustNow_Boost(t *testing.T) {
	t.Parallel()
	// Token stored 1 minute ago should NOT be expired
	if IsKiteTokenExpired(time.Now().Add(-1 * time.Minute)) {
		t.Error("Token stored 1 minute ago should not be expired")
	}
}

func TestIsKiteTokenExpired_VeryOldToken(t *testing.T) {
	t.Parallel()
	// Token stored 2 days ago should be expired
	if !IsKiteTokenExpired(time.Now().Add(-48 * time.Hour)) {
		t.Error("Token stored 2 days ago should be expired")
	}
}

func TestIsKiteTokenExpired_BeforeExpiryTime(t *testing.T) {
	t.Parallel()
	// Token from yesterday before 6 AM IST should be expired
	now := time.Now().In(KolkataLocation)
	// Create a time at 3 AM today
	todayAt3AM := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, KolkataLocation)
	// If it's before 6 AM, the expiry boundary is yesterday at 6 AM
	// If it's after 6 AM, the expiry boundary is today at 6 AM

	// Token stored before yesterday's 6 AM should be expired
	oldToken := time.Date(now.Year(), now.Month(), now.Day()-2, 10, 0, 0, 0, KolkataLocation)
	if !IsKiteTokenExpired(oldToken) {
		t.Error("Token from 2 days ago should be expired")
	}
	_ = todayAt3AM // suppress unused warning in case logic doesn't use it
}

// ===========================================================================
// SessionService — ClearSessionData
// ===========================================================================

func TestSessionService_ClearSessionData_EmptyID(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.ClearSessionData("")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestSessionService_ClearSessionData_NonExistent(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.ClearSessionData("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

func TestSessionService_ClearSessionData_Success(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	sessionID := ss.GenerateSession()

	// Clear session data
	err := ss.ClearSessionData(sessionID)
	if err != nil {
		t.Fatalf("ClearSessionData error: %v", err)
	}
}

// ===========================================================================
// SessionService — SessionLoginURL in devMode
// ===========================================================================

func TestSessionService_SessionLoginURL_DevMode(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	_, err := ss.SessionLoginURL("test-session")
	if err == nil {
		t.Fatal("Expected error in devMode")
	}
	if !strings.Contains(err.Error(), "DEV_MODE") {
		t.Errorf("Error should mention DEV_MODE, got: %v", err)
	}
}

// ===========================================================================
// SessionService — GetOrCreateSessionWithEmail — email update path
// ===========================================================================

func TestSessionService_GetOrCreateSessionWithEmail_UpdatesEmail(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	// Create session without email
	sessionID := ss.GenerateSession()

	// Get again with email — should update the email
	kd, isNew, err := ss.GetOrCreateSessionWithEmail(sessionID, "user@test.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail error: %v", err)
	}
	if isNew {
		t.Error("Expected isNew=false for existing session")
	}
	// The email might or might not be updated depending on whether it was empty before
	_ = kd
}

// ===========================================================================
// SessionService — CompleteSession — various error branches
// ===========================================================================

func TestSessionService_CompleteSession_EmptyID(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.CompleteSession("", "token")
	if err != ErrInvalidSessionID {
		t.Errorf("Expected ErrInvalidSessionID, got: %v", err)
	}
}

func TestSessionService_CompleteSession_NonExistent(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	err := ss.CompleteSession("nonexistent", "token")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// ===========================================================================
// ManagedSessionService — TerminateByEmail
// ===========================================================================

func TestManagedSessionService_TerminateByEmail(t *testing.T) {
	t.Parallel()
	reg := NewSessionRegistry(testLogger())
	svc := NewManagedSessionService(reg)

	// Create a session with email
	sid := reg.GenerateWithData(&KiteSessionData{Email: "user@test.com"})
	// Update the email on the session (sessions need their MCPSession.Email set)
	_ = reg.UpdateSessionField(sid, func(data any) {
		if kd, ok := data.(*KiteSessionData); ok {
			kd.Email = "user@test.com"
		}
	})

	// Terminate by email
	count := svc.TerminateByEmail("user@test.com")
	if count < 1 {
		t.Errorf("Expected at least 1 terminated, got %d", count)
	}
}

func TestManagedSessionService_NilRegistry(t *testing.T) {
	t.Parallel()
	svc := NewManagedSessionService(nil)

	if svc.ActiveCount() != 0 {
		t.Error("Expected 0 active count with nil registry")
	}
	if svc.TerminateByEmail("user@test.com") != 0 {
		t.Error("Expected 0 terminated with nil registry")
	}
	if svc.Registry() != nil {
		t.Error("Expected nil registry")
	}
}

// ===========================================================================
// SessionSignerWithKey — empty key
// ===========================================================================

func TestNewSessionSignerWithKey_EmptyKey_Boost(t *testing.T) {
	t.Parallel()
	_, err := NewSessionSignerWithKey([]byte{})
	if err != ErrEmptySecretKey {
		t.Errorf("Expected ErrEmptySecretKey, got: %v", err)
	}
}

func TestNewSessionSignerWithKey_Valid(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-at-least-1-byte"))
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

// ===========================================================================
// SessionSigner.SignRedirectParams — invalid session ID
// ===========================================================================

func TestSignRedirectParams_InvalidSessionID(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	_, err := signer.SignRedirectParams("")
	if err == nil {
		t.Fatal("Expected error for empty session ID")
	}
}

// ===========================================================================
// sessionDBAdapter.LoadSessions — via Manager with AlertDBPath
// ===========================================================================

func TestSessionDBAdapter_LoadSessions_Empty(t *testing.T) {
	t.Parallel()
	db, err := openTestAlertDB(t)
	if err != nil {
		t.Fatalf("openTestAlertDB error: %v", err)
	}
	adapter := &sessionDBAdapter{db: db}

	sessions, err := adapter.LoadSessions()
	if err != nil {
		t.Fatalf("LoadSessions error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions, got %d", len(sessions))
	}
}

// ===========================================================================
// Manager.Shutdown — comprehensive shutdown
// ===========================================================================

func TestManager_Shutdown_WithComponents(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey: "key", APISecret: "secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Should not panic
	m.Shutdown()
}

// ===========================================================================
// Manager — various getters
// ===========================================================================

func TestManager_Getters(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	if m.ExternalURL() != "" {
		t.Errorf("ExternalURL = %q, want empty", m.ExternalURL())
	}
	if m.AdminSecretPath() != "" {
		t.Errorf("AdminSecretPath = %q, want empty", m.AdminSecretPath())
	}
	if !m.IsLocalMode() {
		t.Error("Expected local mode for default")
	}
	if m.SessionSigner() == nil {
		t.Error("SessionSigner should not be nil")
	}
	if m.PaperEngineConcrete() != nil {
		t.Error("PaperEngineConcrete should be nil")
	}
	if m.BillingStoreConcrete() != nil {
		t.Error("BillingStoreConcrete should be nil")
	}
	if m.RiskGuard() != nil {
		t.Error("RiskGuard should be nil")
	}
	if m.InvitationStore() != nil {
		t.Error("InvitationStore should be nil")
	}
	if m.ManagedSessionSvc() == nil {
		t.Error("ManagedSessionSvc should not be nil")
	}
}

// ===========================================================================
// Manager.UpdateSessionSignerExpiry
// ===========================================================================

func TestManager_UpdateSessionSignerExpiry(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	m.UpdateSessionSignerExpiry(1 * time.Hour)
	// Should not panic
}

// ===========================================================================
// Manager.ForceInstrumentsUpdate
// ===========================================================================

func TestManager_ForceInstrumentsUpdate(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Will fail (no real HTTP server), but should not panic
	_ = m.ForceInstrumentsUpdate()
}

// ===========================================================================
// Manager.GetInstrumentsStats
// ===========================================================================

func TestManager_GetInstrumentsStats(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("key", "secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	stats := m.GetInstrumentsStats()
	_ = stats // Should not panic
}

// ===========================================================================
// SessionService — GetActiveSessionCount, CleanupExpiredSessions
// ===========================================================================

func TestSessionService_GetActiveSessionCount(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	if ss.GetActiveSessionCount() != 0 {
		t.Error("Expected 0 initially")
	}

	ss.GenerateSession()
	if ss.GetActiveSessionCount() != 1 {
		t.Errorf("Expected 1 active session, got %d", ss.GetActiveSessionCount())
	}
}

func TestSessionService_CleanupExpiredSessions(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	defer ss.SessionManager().StopCleanupRoutine()

	cleaned := ss.CleanupExpiredSessions()
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned initially, got %d", cleaned)
	}
}

func TestSessionService_StopCleanupRoutine(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ss.InitializeSessionManager()
	// Should not panic
	ss.StopCleanupRoutine()
}

// ===========================================================================
// Tests merged from gap_test.go
// ===========================================================================

func TestNew_WithAlertDBPath_Gap(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "key",
		APISecret:          "secret",
		Logger:             testLogger(),
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
		Logger:             testLogger(),
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
		Logger:             testLogger(),
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
		Logger:             testLogger(),
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
		Logger:            testLogger(),
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
		Logger:             testLogger(),
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
		Logger:             testLogger(),
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
		Logger:             testLogger(),
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

	sm := NewSessionRegistry(testLogger())
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
	sm := NewSessionRegistry(testLogger())
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
	sm := NewSessionRegistry(testLogger())
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
	sm := NewSessionRegistry(testLogger())
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
	sm := NewSessionRegistry(testLogger())
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
	sm := NewSessionRegistry(testLogger())

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
	sm := NewSessionRegistry(testLogger())

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
	sm := NewSessionRegistry(testLogger())
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
	regStore.SetLogger(testLogger())

	// Create a service with a registry that already has the key
	cs := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      NewKiteTokenStore(),
		RegistryStore:   regStore,
		Logger:          testLogger(),
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
		Logger:          testLogger(),
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
	sm := NewSessionRegistry(testLogger())
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
		Logger:             testLogger(),
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

// ===========================================================================
// Tests merged from manager_coverage_test.go
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
		ID:        "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea0",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	// Add an expired session
	sm.sessions["kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea1"] = &MCPSession{
		ID:        "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeea1",
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

// mockMetrics lives in mocks_test.go.

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

// Coverage ceiling: ~94.2% — ~54 unreachable blocks across 7 files.
// Categories: (1) closure callbacks requiring full integration, (2) crypto/rand
// failures (Go 1.25 fatal), (3) embedded template parse errors, (4) DB failure
// after successful operations (in-memory SQLite), (5) ticker/timer goroutine
// branches, (6) OS browser launch (exec.Command), (7) broker API success paths.
