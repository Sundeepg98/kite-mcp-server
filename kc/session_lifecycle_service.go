package kc

// SessionLifecycleService is a thin facade over SessionService that groups
// MCP-session lifecycle delegators (get/create/clear/complete). Manager keeps
// the old method names as delegators into this facade for backward
// compatibility with existing call sites.
type SessionLifecycleService struct {
	m *Manager
}

func newSessionLifecycleService(m *Manager) *SessionLifecycleService {
	return &SessionLifecycleService{m: m}
}

// GetOrCreateSession retrieves an existing Kite session or creates a new one.
func (s *SessionLifecycleService) GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error) {
	return s.m.sessionSvc.GetOrCreateSession(mcpSessionID)
}

// GetOrCreateSessionWithEmail retrieves or creates a Kite session with email context.
func (s *SessionLifecycleService) GetOrCreateSessionWithEmail(mcpSessionID, email string) (*KiteSessionData, bool, error) {
	return s.m.sessionSvc.GetOrCreateSessionWithEmail(mcpSessionID, email)
}

// GetSession retrieves an existing Kite session by MCP session ID.
func (s *SessionLifecycleService) GetSession(mcpSessionID string) (*KiteSessionData, error) {
	return s.m.sessionSvc.GetSession(mcpSessionID)
}

// ClearSession terminates a session, triggering cleanup hooks.
func (s *SessionLifecycleService) ClearSession(sessionID string) {
	s.m.sessionSvc.ClearSession(sessionID)
}

// ClearSessionData clears the session data without terminating the session.
func (s *SessionLifecycleService) ClearSessionData(sessionID string) error {
	return s.m.sessionSvc.ClearSessionData(sessionID)
}

// GenerateSession creates a new MCP session and returns its ID.
func (s *SessionLifecycleService) GenerateSession() string {
	return s.m.sessionSvc.GenerateSession()
}

// SessionLoginURL returns the Kite login URL for the given session.
func (s *SessionLifecycleService) SessionLoginURL(mcpSessionID string) (string, error) {
	return s.m.sessionSvc.SessionLoginURL(mcpSessionID)
}

// CompleteSession completes Kite authentication using the request token.
func (s *SessionLifecycleService) CompleteSession(mcpSessionID, kiteRequestToken string) error {
	return s.m.sessionSvc.CompleteSession(mcpSessionID, kiteRequestToken)
}

// GetActiveSessionCount returns the number of active sessions.
func (s *SessionLifecycleService) GetActiveSessionCount() int {
	return s.m.sessionSvc.GetActiveSessionCount()
}

// ---------------------------------------------------------------------------
// Manager-level delegators (moved from manager.go).
// ---------------------------------------------------------------------------

// SessionLifecycle returns the session lifecycle facade.
func (m *Manager) SessionLifecycle() *SessionLifecycleService { return m.sessionLifecycle }

// GetOrCreateSession retrieves an existing Kite session or creates a new one.
func (m *Manager) GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error) {
	return m.sessionLifecycle.GetOrCreateSession(mcpSessionID)
}

// GetOrCreateSessionWithEmail retrieves or creates a Kite session with email context.
func (m *Manager) GetOrCreateSessionWithEmail(mcpSessionID, email string) (*KiteSessionData, bool, error) {
	return m.sessionLifecycle.GetOrCreateSessionWithEmail(mcpSessionID, email)
}

// GetSession retrieves an existing Kite session by MCP session ID.
func (m *Manager) GetSession(mcpSessionID string) (*KiteSessionData, error) {
	return m.sessionLifecycle.GetSession(mcpSessionID)
}

// ClearSession terminates a session, triggering cleanup hooks.
func (m *Manager) ClearSession(sessionID string) { m.sessionLifecycle.ClearSession(sessionID) }

// ClearSessionData clears the session data without terminating the session.
func (m *Manager) ClearSessionData(sessionID string) error {
	return m.sessionLifecycle.ClearSessionData(sessionID)
}

// GenerateSession creates a new MCP session and returns its ID.
func (m *Manager) GenerateSession() string { return m.sessionLifecycle.GenerateSession() }

// SessionLoginURL returns the Kite login URL for the given session.
func (m *Manager) SessionLoginURL(mcpSessionID string) (string, error) {
	return m.sessionLifecycle.SessionLoginURL(mcpSessionID)
}

// CompleteSession completes Kite authentication using the request token.
func (m *Manager) CompleteSession(mcpSessionID, kiteRequestToken string) error {
	return m.sessionLifecycle.CompleteSession(mcpSessionID, kiteRequestToken)
}

// GetActiveSessionCount returns the number of active sessions.
func (m *Manager) GetActiveSessionCount() int { return m.sessionLifecycle.GetActiveSessionCount() }
