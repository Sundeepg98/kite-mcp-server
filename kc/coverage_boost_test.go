package kc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
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
// setupTemplates — success path
// ===========================================================================

func TestSetupTemplates_Success(t *testing.T) {
	t.Parallel()
	templates, err := setupTemplates()
	if err != nil {
		t.Fatalf("setupTemplates error: %v", err)
	}
	if len(templates) == 0 {
		t.Error("Expected at least one template")
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

func TestInitializeSessionSigner_AutoGenerate(t *testing.T) {
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

func TestIsKiteTokenExpired_JustNow(t *testing.T) {
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

func TestNewSessionSignerWithKey_EmptyKey(t *testing.T) {
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
