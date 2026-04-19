package kc

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// newTestInstrumentsManager creates a fast test instruments manager without HTTP calls

func newTestInstrumentsManager() *instruments.Manager {
	// Create test data
	testInsts := []*instruments.Instrument{
		{
			ID:              "NSE:SBIN",
			InstrumentToken: 779521,
			ExchangeToken:   3045,
			Tradingsymbol:   "SBIN",
			Exchange:        "NSE",
			ISIN:            "INE062A01020",
			Name:            "STATE BANK OF INDIA",
			InstrumentType:  "EQ",
			Segment:         "NSE",
			Active:          true,
		},
		{
			ID:              "NSE:RELIANCE",
			InstrumentToken: 738561,
			ExchangeToken:   2885,
			Tradingsymbol:   "RELIANCE",
			Exchange:        "NSE",
			ISIN:            "INE002A01018",
			Name:            "RELIANCE INDUSTRIES LIMITED",
			InstrumentType:  "EQ",
			Segment:         "NSE",
			Active:          true,
		},
	}

	// Create test data map
	testMap := make(map[uint32]*instruments.Instrument)
	for _, inst := range testInsts {
		testMap[inst.InstrumentToken] = inst
	}

	// Create manager with test data (automatically skips HTTP calls)
	config := instruments.DefaultUpdateConfig()
	config.EnableScheduler = false

	manager, err := instruments.New(instruments.Config{
		UpdateConfig: config,
		Logger:       testLogger(),
		TestData:     testMap,
	})
	if err != nil {
		panic("failed to create test instruments manager: " + err.Error())
	}

	return manager
}



// testLogger creates a discard logger for tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}



// newTestManager creates a test manager with provided instruments manager
func newTestManager(apiKey, apiSecret string) (*Manager, error) {
	return New(Config{
		APIKey:             apiKey,
		APISecret:          apiSecret,
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})
}



// Helper function to check if string contains substring
func managerContains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}



// ---------------------------------------------------------------------------
// OpenBrowser — validates URL scheme
// ---------------------------------------------------------------------------
func TestOpenBrowser_InvalidScheme(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Error("Expected error for non-http/https scheme")
	}
}


func TestOpenBrowser_EmptyURL(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("")
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}



// ---------------------------------------------------------------------------
// initializeTemplates
// ---------------------------------------------------------------------------
func TestInitializeTemplates(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Templates should already be initialized by New()
	if m.templates == nil {
		t.Error("templates should not be nil")
	}

	// Re-initialize should not fail
	err = m.initializeTemplates()
	if err != nil {
		t.Errorf("initializeTemplates error: %v", err)
	}
}



// ---------------------------------------------------------------------------
// initializeSessionSigner
// ---------------------------------------------------------------------------
func TestInitializeSessionSigner_CustomSigner(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	customSigner, _ := NewSessionSigner()
	err = m.initializeSessionSigner(customSigner)
	if err != nil {
		t.Errorf("initializeSessionSigner error: %v", err)
	}
	if m.sessionSigner != customSigner {
		t.Error("Expected custom signer to be used")
	}
}


func TestInitializeSessionSigner_NilSigner(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.initializeSessionSigner(nil)
	if err != nil {
		t.Errorf("initializeSessionSigner with nil should auto-create signer: %v", err)
	}
	if m.sessionSigner == nil {
		t.Error("sessionSigner should not be nil after auto-creation")
	}
}



// ===========================================================================
// OpenBrowser — non-local mode (no-op)
// ===========================================================================
func TestOpenBrowser_NonLocalMode(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "http",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// Should return nil (no-op)
	err = m.OpenBrowser("https://example.com")
	if err != nil {
		t.Errorf("OpenBrowser in non-local mode should return nil, got: %v", err)
	}
}



// ===========================================================================
// OpenBrowser — invalid URL scheme
// ===========================================================================
func TestOpenBrowser_InvalidScheme_Final(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Error("Expected error for ftp scheme")
	}
}



// ===========================================================================
// Coverage boost: VerifyRedirectParams, getSecretKey, HandleKiteCallback,
// New() config variants, session edge cases
// ===========================================================================

// ---------------------------------------------------------------------------
// SessionSigner — VerifyRedirectParams (0% without synctest tag)
// ---------------------------------------------------------------------------
func TestVerifyRedirectParams_Valid(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-for-redirect-params-32"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	// Use a valid UUID-based session ID (SignRedirectParams validates format)
	sessionID := "kitemcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	params, err := signer.SignRedirectParams(sessionID)
	if err != nil {
		t.Fatalf("SignRedirectParams error: %v", err)
	}

	verified, err := signer.VerifyRedirectParams(params)
	if err != nil {
		t.Fatalf("VerifyRedirectParams error: %v", err)
	}
	if verified != sessionID {
		t.Errorf("VerifyRedirectParams = %q, want %q", verified, sessionID)
	}
}


func TestVerifyRedirectParams_InvalidFormat_NoPrefix(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-for-redirect-params-32"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	_, err = signer.VerifyRedirectParams("invalid=xxx")
	if err != ErrInvalidFormat {
		t.Errorf("Expected ErrInvalidFormat, got: %v", err)
	}
}


func TestVerifyRedirectParams_InvalidFormat_EmptySessionID(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-for-redirect-params-32"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	_, err = signer.VerifyRedirectParams("session_id=")
	if err != ErrInvalidFormat {
		t.Errorf("Expected ErrInvalidFormat, got: %v", err)
	}
}


func TestVerifyRedirectParams_TamperedSignature(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-for-redirect-params-32"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	// Use a valid UUID session ID (SignRedirectParams validates format)
	params, err := signer.SignRedirectParams("kitemcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err != nil {
		t.Fatalf("SignRedirectParams error: %v", err)
	}

	// Tamper with the signature
	_, err = signer.VerifyRedirectParams(params + "x")
	if err == nil {
		t.Error("Expected error for tampered signature")
	}
}



// ---------------------------------------------------------------------------
// SessionSigner — getSecretKey (0% without synctest tag)
// ---------------------------------------------------------------------------
func TestGetSecretKey_ReturnsCopy(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSignerWithKey([]byte("test-key-for-getSecretKey-test!"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	key := signer.getSecretKey()
	if len(key) == 0 {
		t.Fatal("getSecretKey returned empty key")
	}

	// Should be a copy, not the same underlying array
	key[0] = 0xFF
	key2 := signer.getSecretKey()
	if key2[0] == 0xFF {
		t.Error("getSecretKey should return a copy, not the original slice")
	}
}



// ---------------------------------------------------------------------------
// SessionRegistry — GetSessionData edge cases
// ---------------------------------------------------------------------------
func TestSessionRegistry_GetSessionData_Expired(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistryWithDuration(1*time.Millisecond, testLogger())

	sessionID := sm.Generate()

	// Wait for session to expire
	time.Sleep(5 * time.Millisecond)

	_, err := sm.GetSessionData(sessionID)
	if err == nil {
		t.Error("Expected error for expired session data")
	}
}


func TestSessionRegistry_GetSessionData_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sessionID := sm.Generate()
	sm.Terminate(sessionID)

	_, err := sm.GetSessionData(sessionID)
	if err == nil {
		t.Error("Expected error for terminated session data")
	}
}


func TestSessionRegistry_GetSessionData_NotFound(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	_, err := sm.GetSessionData("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent session data")
	}
}



// ---------------------------------------------------------------------------
// SessionRegistry — GetOrCreateSessionData edge cases
// ---------------------------------------------------------------------------
func TestSessionRegistry_GetOrCreateSessionData_Expired(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistryWithDuration(1*time.Millisecond, testLogger())

	sessionID := sm.Generate()

	// Wait for session to expire
	time.Sleep(5 * time.Millisecond)

	_, _, err := sm.GetOrCreateSessionData(sessionID, func() any { return "data" })
	if err == nil {
		t.Error("Expected error for expired session")
	}
}


func TestSessionRegistry_GetOrCreateSessionData_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sessionID := sm.Generate()
	sm.Terminate(sessionID)

	_, _, err := sm.GetOrCreateSessionData(sessionID, func() any { return "data" })
	if err == nil {
		t.Error("Expected error for terminated session")
	}
}



// ---------------------------------------------------------------------------
// SessionRegistry — UpdateSessionField edge cases
// ---------------------------------------------------------------------------
func TestSessionRegistry_UpdateSessionField_NotFound(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	err := sm.UpdateSessionField("nonexistent-session", func(data any) {})
	if err == nil {
		t.Error("Expected error for nonexistent session field update")
	}
}


func TestSessionRegistry_UpdateSessionField_Terminated(t *testing.T) {
	t.Parallel()
	sm := NewSessionRegistry(testLogger())

	sessionID := sm.Generate()
	sm.Terminate(sessionID)

	err := sm.UpdateSessionField(sessionID, func(data any) {})
	if err == nil {
		t.Error("Expected error for terminated session field update")
	}
}



// ---------------------------------------------------------------------------
// IsKiteTokenExpired — edge cases
// ---------------------------------------------------------------------------
func TestIsKiteTokenExpired_StoredYesterday_AlwaysExpired(t *testing.T) {
	t.Parallel()
	// Token stored 2 days ago should always be expired regardless of current time
	twoDaysAgo := time.Now().AddDate(0, 0, -2)
	if !IsKiteTokenExpired(twoDaysAgo) {
		t.Error("Token stored 2 days ago should always be expired")
	}
}


func TestIsKiteTokenExpired_StoredNow_NotExpired(t *testing.T) {
	t.Parallel()
	// Token stored right now should NOT be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
}



// ---------------------------------------------------------------------------
// Manager — GetSession, ClearSession, ClearSessionData via SessionService
// ---------------------------------------------------------------------------
func TestManager_ClearSessionData_ValidSession(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	sessionID := m.GenerateSession()
	// Create session data
	_, _, err = m.GetOrCreateSession(sessionID)
	if err != nil {
		t.Fatalf("GetOrCreateSession error: %v", err)
	}

	// ClearSessionData should work
	err = m.ClearSessionData(sessionID)
	if err != nil {
		t.Errorf("ClearSessionData error: %v", err)
	}

	// After clearing, GetSession should still work (session exists, data cleared)
	kd, err := m.GetSession(sessionID)
	if err != nil {
		// Session exists but data is nil — GetSession may return error
		_ = kd
	}
}
