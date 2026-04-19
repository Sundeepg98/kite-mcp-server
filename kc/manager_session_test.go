package kc

import (
	"testing"

)

// newTestInstrumentsManager creates a fast test instruments manager without HTTP calls


func TestManagerGenerateSession(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	sessionID := manager.GenerateSession()

	if sessionID == "" {
		t.Error("Expected non-empty session ID")
	}

	// Verify session exists in session manager
	sessionData, err := manager.GetSession(sessionID)
	if err != nil {
		t.Errorf("Expected session to exist, got error: %v", err)
	}

	if sessionData == nil {
		t.Error("Expected non-nil session data")
		return
	}

	if sessionData.Kite == nil {
		t.Error("Expected Kite client to be initialized")
	}
}


func TestManagerGetSession(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Test empty session ID
	_, err = manager.GetSession("")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for empty session ID, got: %v", err)
	}

	// Test non-existent session
	_, err = manager.GetSession("non-existent-session")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for non-existent session, got: %v", err)
	}

	// Test valid session
	sessionID := manager.GenerateSession()
	sessionData, err := manager.GetSession(sessionID)
	if err != nil {
		t.Errorf("Expected no error for valid session, got: %v", err)
	}

	if sessionData == nil {
		t.Error("Expected non-nil session data")
	}

	// Test terminated session
	manager.ClearSession(sessionID)
	_, err = manager.GetSession(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for terminated session, got: %v", err)
	}
}


func TestClearSession(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Test empty session ID (should not panic)
	manager.ClearSession("")

	// Test valid session
	sessionID := manager.GenerateSession()

	// Verify session exists
	_, err = manager.GetSession(sessionID)
	if err != nil {
		t.Errorf("Expected session to exist before clearing, got error: %v", err)
	}

	// Clear session
	manager.ClearSession(sessionID)

	// Verify session is cleared
	_, err = manager.GetSession(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after clearing session, got: %v", err)
	}
}


func TestSessionLoginURL(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Test empty session ID
	_, err = manager.SessionLoginURL("")
	if err != ErrInvalidSessionID {
		t.Errorf("Expected ErrInvalidSessionID for empty session ID, got: %v", err)
	}

	// Test non-existent session
	_, err = manager.SessionLoginURL("non-existent-session")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for non-existent session, got: %v", err)
	}

	// Test valid session
	sessionID := manager.GenerateSession()
	loginURL, err := manager.SessionLoginURL(sessionID)
	if err != nil {
		t.Errorf("Expected no error for valid session, got: %v", err)
	}

	if loginURL == "" {
		t.Error("Expected non-empty login URL")
	}

	if !managerContains(loginURL, "session_id%3D"+sessionID) {
		t.Errorf("Expected login URL to contain URL-encoded session ID. URL: %s, SessionID: %s", loginURL, sessionID)
	}
}


func TestCompleteSession(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Test empty session ID
	err = manager.CompleteSession("", "test_token")
	if err != ErrInvalidSessionID {
		t.Errorf("Expected ErrInvalidSessionID for empty session ID, got: %v", err)
	}

	// Test non-existent session
	err = manager.CompleteSession("non-existent-session", "test_token")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for non-existent session, got: %v", err)
	}

	// Test valid session with invalid token (will fail at Kite API level)
	sessionID := manager.GenerateSession()
	err = manager.CompleteSession(sessionID, "invalid_token")
	if err == nil {
		t.Error("Expected error for invalid request token")
	}
}


func TestGetActiveSessionCount(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Initially should be 0
	count := manager.GetActiveSessionCount()
	if count != 0 {
		t.Errorf("Expected 0 active sessions initially, got %d", count)
	}

	// Create sessions
	id1 := manager.GenerateSession()
	id2 := manager.GenerateSession()

	count = manager.GetActiveSessionCount()
	if count != 2 {
		t.Errorf("Expected 2 active sessions, got %d", count)
	}

	// Clear one session
	manager.ClearSession(id1)

	count = manager.GetActiveSessionCount()
	if count != 1 {
		t.Errorf("Expected 1 active session after clearing one, got %d", count)
	}

	// Clear remaining session
	manager.ClearSession(id2)

	count = manager.GetActiveSessionCount()
	if count != 0 {
		t.Errorf("Expected 0 active sessions after clearing all, got %d", count)
	}
}


func TestManagerCleanupExpiredSessions(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Initially should clean 0 sessions
	cleaned := manager.CleanupExpiredSessions()
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned sessions initially, got %d", cleaned)
	}

	// Create some sessions
	manager.GenerateSession()
	manager.GenerateSession()

	// No sessions should be expired yet
	cleaned = manager.CleanupExpiredSessions()
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned sessions for fresh sessions, got %d", cleaned)
	}
}


func TestSessionManager(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	sessionManager := manager.SessionManager()
	if sessionManager == nil {
		t.Error("Expected non-nil session registry")
	}

	// Verify it's the same instance
	if sessionManager != manager.sessionManager {
		t.Error("Expected returned session manager to be the same instance")
	}
}


func TestStopCleanupRoutine(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// Should not panic
	manager.StopCleanupRoutine()
}


func TestGetOrCreateSession(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	sessionID := manager.GenerateSession()

	// Clear the data from the session to force creation of new data
	err = manager.sessionManager.UpdateSessionData(sessionID, nil)
	if err != nil {
		t.Fatalf("Failed to clear session data: %v", err)
	}

	// Test getting/creating session for the first time after clearing data
	kiteData, isNew, err := manager.GetOrCreateSession(sessionID)
	if err != nil {
		t.Errorf("Expected no error getting/creating session, got: %v", err)
	}

	if !isNew {
		t.Error("Expected isNew to be true for first call")
	}

	if kiteData == nil {
		t.Error("Expected non-nil KiteSessionData")
	}

	// Test getting the same session again
	kiteData2, isNew2, err := manager.GetOrCreateSession(sessionID)
	if err != nil {
		t.Errorf("Expected no error on second call, got: %v", err)
	}

	if isNew2 {
		t.Error("Expected isNew to be false on second call")
	}

	if kiteData2 == nil {
		t.Error("Expected non-nil KiteSessionData on second call")
	}
}



// TestExternalSessionIDFromErrorLog tests the exact session ID from the error log
func TestExternalSessionIDFromErrorLog(t *testing.T) {
	manager, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("Expected no error creating manager, got: %v", err)
	}

	// This is the exact session ID from the error log that was failing
	externalSessionID := "6f615000-2644-45a7-a27c-f579e20b5992"

	// Should be able to get or create session with external session ID
	kiteSession, isNew, err := manager.GetOrCreateSession(externalSessionID)
	if err != nil {
		t.Errorf("Expected no error for external session ID from error log, got: %v", err)
	}
	if !isNew {
		t.Error("Expected new session to be created for external session ID")
	}
	if kiteSession == nil {
		t.Error("Expected non-nil Kite session data")
	} else if kiteSession.Kite == nil {
		t.Error("Expected Kite client to be initialized")
	}

	// Subsequent call should reuse existing session
	kiteSession2, isNew2, err2 := manager.GetOrCreateSession(externalSessionID)
	if err2 != nil {
		t.Errorf("Expected no error on second call, got: %v", err2)
	}
	if isNew2 {
		t.Error("Expected existing session to be reused")
	}
	if kiteSession2 != kiteSession {
		t.Error("Expected same session instance to be returned")
	}
}
