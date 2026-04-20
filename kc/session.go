package kc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionDB is an optional persistence backend for MCP sessions.
// Implemented by an adapter that wraps alerts.DB to avoid circular imports.
type SessionDB interface {
	SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error
	LoadSessions() ([]*SessionLoadEntry, error)
	DeleteSession(sessionID string) error
}

// SessionLoadEntry represents a session loaded from the database.
type SessionLoadEntry struct {
	SessionID  string
	Email      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Terminated bool
}

const (
	// Default session configuration
	DefaultSessionDuration = 12 * time.Hour
	DefaultCleanupInterval = 30 * time.Minute

	// Error messages
	errInvalidSessionIDFormat = "invalid session ID format"
	errSessionNotFound        = "session ID not found"
	errCannotUpdateTerminated = "cannot update terminated session"
	mcpSessionPrefix          = "kitemcp-"
)

type MCPSession struct {
	ID         string
	Terminated bool
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Data       any // Contains KiteSessionData

	// ClientHint is a free-form description of the MCP surface that created
	// the session (e.g. the raw User-Agent from the bearer-issuance HTTP
	// request, or a constant like "claude-code" / "claude-desktop"). Empty
	// when the registry was called through a code path that has no HTTP
	// request context (SessionIdManager.Generate(), SSE/stdio transports).
	// Rendered as "Unknown" by list_mcp_sessions when empty.
	ClientHint string
}

type SessionRegistry struct {
	sessions        map[string]*MCPSession
	mu              sync.RWMutex
	sessionDuration time.Duration
	cleanupHooks    []CleanupHook
	cleanupContext  context.Context
	cleanupCancel   context.CancelFunc
	// cleanupWG tracks the background cleanupRoutine goroutine. StartCleanupRoutine
	// adds to it, the goroutine calls Done() on exit, and StopCleanupRoutine waits
	// on it so callers (including goleak sentinels) can observe the routine has
	// actually terminated — not just signalled to stop.
	cleanupWG sync.WaitGroup
	// stopOnce guards cleanupCancel so StopCleanupRoutine is idempotent. The
	// production graceful-shutdown path and test cleanupInitializeServices
	// can both call without panic.
	stopOnce sync.Once
	logger   *slog.Logger
	db       SessionDB // optional persistence
}

// CleanupHook is called when a session is terminated or expires
type CleanupHook func(session *MCPSession)

// NewSessionRegistry creates a new registry that manages MCP sessions and their associated Kite data
func NewSessionRegistry(logger *slog.Logger) *SessionRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	return &SessionRegistry{
		sessions:        make(map[string]*MCPSession),
		sessionDuration: DefaultSessionDuration,
		cleanupHooks:    make([]CleanupHook, 0),
		cleanupContext:  ctx,
		cleanupCancel:   cancel,
		logger:          logger,
	}
}

// NewSessionRegistryWithDuration creates a new session registry with custom duration
func NewSessionRegistryWithDuration(duration time.Duration, logger *slog.Logger) *SessionRegistry {
	ctx, cancel := context.WithCancel(context.Background())
	return &SessionRegistry{
		sessions:        make(map[string]*MCPSession),
		sessionDuration: duration,
		cleanupHooks:    make([]CleanupHook, 0),
		cleanupContext:  ctx,
		cleanupCancel:   cancel,
		logger:          logger,
	}
}

// SetDB enables write-through persistence to the given session database.
func (sm *SessionRegistry) SetDB(db SessionDB) {
	sm.db = db
}

// LoadFromDB populates the in-memory session registry from the database.
// Expired and terminated sessions are skipped (and deleted from DB).
// Valid sessions are restored with Data set to &KiteSessionData{Email: email}.
func (sm *SessionRegistry) LoadFromDB() error {
	if sm.db == nil {
		return nil
	}
	entries, err := sm.db.LoadSessions()
	if err != nil {
		return err
	}
	now := time.Now()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	loaded := 0
	for _, e := range entries {
		// Skip expired or terminated sessions
		if e.Terminated || now.After(e.ExpiresAt) {
			// Best-effort cleanup from DB
			if delErr := sm.db.DeleteSession(e.SessionID); delErr != nil {
				sm.logger.Error("Failed to delete stale session from DB", "session_id", e.SessionID, "error", delErr)
			}
			continue
		}
		sm.sessions[e.SessionID] = &MCPSession{
			ID:         e.SessionID,
			Terminated: false,
			CreatedAt:  e.CreatedAt,
			ExpiresAt:  e.ExpiresAt,
			Data:       &KiteSessionData{Email: e.Email},
		}
		loaded++
	}
	sm.logger.Info("Loaded sessions from database", "loaded", loaded, "skipped", len(entries)-loaded)
	return nil
}

// Generate creates a new MCP session ID and stores it in memory
func (sm *SessionRegistry) Generate() string {
	return sm.GenerateWithData(nil)
}

// GenerateWithData creates a new MCP session ID with associated Kite data and stores it in memory.
// ClientHint is left empty. Callers with access to the originating HTTP request
// should use GenerateWithDataAndHint instead.
func (sm *SessionRegistry) GenerateWithData(data any) string {
	return sm.GenerateWithDataAndHint(data, "")
}

// GenerateWithDataAndHint creates a new MCP session ID with associated Kite
// data and a free-form client hint (typically the User-Agent of the HTTP
// request that caused the session to be issued). The hint is best-effort —
// empty is acceptable and renders as "Unknown" to consumers.
func (sm *SessionRegistry) GenerateWithDataAndHint(data any, clientHint string) string {
	sm.mu.Lock()

	sessionID := mcpSessionPrefix + uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(sm.sessionDuration)

	sm.sessions[sessionID] = &MCPSession{
		ID:         sessionID,
		Terminated: false,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		Data:       data,
		ClientHint: clientHint,
	}

	// Capture DB and values before releasing lock
	db := sm.db
	sm.mu.Unlock()

	sm.logger.Info("Generated new MCP session ID", "session_id", sessionID, "expires_at", expiresAt)

	// Persist outside the lock
	if db != nil {
		email := ""
		if kd, ok := data.(*KiteSessionData); ok && kd != nil {
			email = kd.Email
		}
		if err := db.SaveSession(sessionID, email, now, expiresAt, false); err != nil {
			sm.logger.Error("Failed to persist session", "session_id", sessionID, "error", err)
		}
	}

	return sessionID
}

// should be a valid uuid and start with the correct prefix.
// checkSessionID validates the format of a MCP session ID
// Accepts both internal format (kitemcp-<uuid>) and external format (plain uuid)
func checkSessionID(sessionID string) error {
	// Handle internal format with prefix
	if strings.HasPrefix(sessionID, mcpSessionPrefix) {
		if _, err := uuid.Parse(sessionID[len(mcpSessionPrefix):]); err != nil {
			return fmt.Errorf("%s: %w", errInvalidSessionIDFormat, err)
		}
		return nil
	}

	// Handle external format (plain UUID from SSE/stdio modes)
	if _, err := uuid.Parse(sessionID); err != nil {
		return fmt.Errorf("%s: %w", errInvalidSessionIDFormat, err)
	}
	return nil
}

// Validate checks if a MCP session ID is valid and not terminated.
// Uses a read lock for the common (non-expired) path and only upgrades
// to a write lock when the session needs to be marked as terminated.
func (sm *SessionRegistry) Validate(sessionID string) (isTerminated bool, err error) {
	// Log validation attempt
	sm.logger.Debug("Validating MCP session ID", "session_id", sessionID)

	if err := checkSessionID(sessionID); err != nil {
		return false, err
	}

	// Read lock for the common lookup path
	sm.mu.RLock()
	sm.logger.Debug("checking for session", "session_id", sessionID)
	sm.logger.Debug("sessions in map", "sessions", len(sm.sessions))
	session, exists := sm.sessions[sessionID]
	if !exists {
		sm.mu.RUnlock()
		sm.logger.Warn("MCP session ID not found", "session_id", sessionID)
		return false, errors.New(errSessionNotFound)
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		sm.mu.RUnlock()
		// Need write lock to mark as terminated
		sm.mu.Lock()
		// Re-fetch under write lock — the pointer captured under RLock may be stale
		if s, ok := sm.sessions[sessionID]; ok {
			sm.logger.Info("MCP session has expired", "session_id", sessionID, "expiry", s.ExpiresAt)
			s.Terminated = true
		}
		sm.mu.Unlock()
		return true, nil
	}

	// Log session status
	if session.Terminated {
		sm.logger.Debug("MCP session is already terminated", "session_id", sessionID)
	} else {
		sm.logger.Debug("MCP session is valid", "session_id", sessionID, "expires_at", session.ExpiresAt)
	}

	terminated := session.Terminated
	sm.mu.RUnlock()

	return terminated, nil
}

// Terminate marks a MCP session ID as terminated and cleans up associated Kite session
func (sm *SessionRegistry) Terminate(sessionID string) (isNotAllowed bool, err error) {
	var session *MCPSession
	var hooks []CleanupHook

	sm.mu.Lock()
	// Check if sessionID has the correct prefix and valid UUID format
	if err := checkSessionID(sessionID); err != nil {
		sm.mu.Unlock()
		return false, err
	}

	s, exists := sm.sessions[sessionID]
	if !exists {
		sm.mu.Unlock()
		return false, errors.New(errSessionNotFound)
	}

	s.Terminated = true
	session = s

	// Copy hooks and DB ref to use outside lock
	hooks = make([]CleanupHook, len(sm.cleanupHooks))
	copy(hooks, sm.cleanupHooks)
	db := sm.db
	sm.mu.Unlock()

	// Call cleanup hooks outside the lock to avoid deadlocks
	for _, hook := range hooks {
		hook(session)
	}

	// Delete from persistent store
	if db != nil {
		if err := db.DeleteSession(sessionID); err != nil {
			sm.logger.Error("Failed to delete persisted session", "session_id", sessionID, "error", err)
		}
	}

	return false, nil
}

// TerminateByEmail terminates all active sessions belonging to the given email.
// Used when offboarding a user to revoke all their sessions.
func (sm *SessionRegistry) TerminateByEmail(email string) int {
	email = strings.ToLower(email)
	sm.mu.Lock()
	var toTerminate []string
	for id, s := range sm.sessions {
		if s.Terminated {
			continue
		}
		if kd, ok := s.Data.(*KiteSessionData); ok && kd != nil && strings.ToLower(kd.Email) == email {
			toTerminate = append(toTerminate, id)
		}
	}
	sm.mu.Unlock()

	count := 0
	for _, id := range toTerminate {
		if _, err := sm.Terminate(id); err == nil {
			count++
		}
	}
	return count
}

// GetSession retrieves a MCP session by ID (helper method)
func (sm *SessionRegistry) GetSession(sessionID string) (*MCPSession, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, errors.New(errSessionNotFound)
	}

	return session, nil
}

// ListActiveSessions returns all non-terminated MCP sessions (helper method)
func (sm *SessionRegistry) ListActiveSessions() []*MCPSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var activeSessions []*MCPSession
	now := time.Now()

	for _, session := range sm.sessions {
		// Auto-expire sessions that have passed their expiration time
		if now.After(session.ExpiresAt) {
			session.Terminated = true
		}

		if !session.Terminated {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions
}

// Note: ExtendSession method has been removed to enforce fixed session durations

// CleanupExpiredSessions removes expired MCP sessions from memory and their associated Kite data
func (sm *SessionRegistry) CleanupExpiredSessions() int {
	// Collect expired sessions and hooks under lock
	sm.mu.Lock()
	now := time.Now()
	var toClean []*MCPSession
	var toDelete []string

	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			if !session.Terminated {
				session.Terminated = true
				toClean = append(toClean, session)
			}
			toDelete = append(toDelete, sessionID)
		}
	}

	for _, sessionID := range toDelete {
		delete(sm.sessions, sessionID)
	}

	hooks := make([]CleanupHook, len(sm.cleanupHooks))
	copy(hooks, sm.cleanupHooks)
	db := sm.db
	sm.mu.Unlock()

	// Call cleanup hooks outside the lock to avoid deadlocks
	for _, session := range toClean {
		for _, hook := range hooks {
			hook(session)
		}
	}

	// Delete from persistent store
	if db != nil {
		for _, sessionID := range toDelete {
			if err := db.DeleteSession(sessionID); err != nil {
				sm.logger.Error("Failed to delete expired session from DB", "session_id", sessionID, "error", err)
			}
		}
	}

	return len(toDelete)
}

// GetSessionDuration returns the configured MCP session duration
func (sm *SessionRegistry) GetSessionDuration() time.Duration {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionDuration
}

// SetSessionDuration updates the MCP session duration for new sessions
func (sm *SessionRegistry) SetSessionDuration(duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionDuration = duration
}

// AddCleanupHook adds a cleanup function for the Kite session to be called when MCP sessions are terminated
func (sm *SessionRegistry) AddCleanupHook(hook CleanupHook) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cleanupHooks = append(sm.cleanupHooks, hook)
}

// StartCleanupRoutine starts background cleanup goroutines for expired MCP sessions
func (sm *SessionRegistry) StartCleanupRoutine(ctx context.Context) {
	sm.cleanupWG.Add(1)
	go sm.cleanupRoutine(ctx)
}

// StopCleanupRoutine stops background cleanup goroutines for MCP sessions and
// waits for the cleanupRoutine goroutine to exit before returning. Safe to
// call multiple times — the sync.Once guard absorbs double-close of the
// internal cancel context. Waiting (rather than returning after a signal)
// lets goleak-style sentinels observe the goroutine has actually terminated.
func (sm *SessionRegistry) StopCleanupRoutine() {
	sm.stopOnce.Do(func() {
		if sm.cleanupCancel != nil {
			sm.cleanupCancel()
		}
	})
	// Always wait — even on the second call — so the second caller also sees
	// the goroutine-exited postcondition. cleanupWG is only Add'd inside
	// StartCleanupRoutine, so Wait is a no-op when the routine was never started.
	sm.cleanupWG.Wait()
}

// cleanupRoutine runs periodic cleanup of expired MCP sessions and their Kite data
func (sm *SessionRegistry) cleanupRoutine(ctx context.Context) {
	defer sm.cleanupWG.Done()
	ticker := time.NewTicker(DefaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sm.logger.Info("Session cleanup routine stopped")
			return
		case <-sm.cleanupContext.Done():
			sm.logger.Info("Session cleanup routine cancelled")
			return
		case <-ticker.C:
			cleaned := sm.CleanupExpiredSessions()
			if cleaned > 0 {
				sm.logger.Info("Cleaned up expired sessions", "count", cleaned)
			}
		}
	}
}

// UpdateSessionData updates the Kite data for an existing MCP session
func (sm *SessionRegistry) UpdateSessionData(sessionID string, data any) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return errors.New(errSessionNotFound)
	}

	if session.Terminated {
		return errors.New(errCannotUpdateTerminated)
	}

	session.Data = data
	return nil
}

// UpdateSessionField updates a field within the session data under the registry lock.
// The mutator function is called with the session's Data pointer while holding the write lock,
// ensuring no concurrent reads or writes can race on session fields.
func (sm *SessionRegistry) UpdateSessionField(sessionID string, mutator func(data any)) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return errors.New(errSessionNotFound)
	}

	if session.Terminated {
		return errors.New(errCannotUpdateTerminated)
	}

	mutator(session.Data)
	return nil
}

// GetSessionData retrieves the Kite data for a MCP session
func (sm *SessionRegistry) GetSessionData(sessionID string) (any, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sm.logger.Debug("Getting data for session ID", "session_id", sessionID)

	session, exists := sm.sessions[sessionID]
	if !exists {
		sm.logger.Warn("Session data not found for ID", "session_id", sessionID)
		return nil, errors.New(errSessionNotFound)
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		sm.logger.Info("Session has expired, cannot get data", "session_id", sessionID)
		return nil, errors.New(errSessionNotFound)
	}

	if session.Terminated {
		sm.logger.Info("Session is terminated, cannot get data", "session_id", sessionID)
		return nil, errors.New(errSessionNotFound)
	}

	sm.logger.Debug("Successfully retrieved data for session ID", "session_id", sessionID)
	return session.Data, nil
}

// GetOrCreateSessionData atomically validates session and retrieves/creates data to eliminate TOCTOU races
func (sm *SessionRegistry) GetOrCreateSessionData(sessionID string, createDataFn func() any) (data any, isNew bool, err error) {
	sm.mu.Lock()

	sm.logger.Debug("Getting or creating data for session ID", "session_id", sessionID)

	// Check session ID format
	if err := checkSessionID(sessionID); err != nil {
		sm.mu.Unlock()
		return nil, false, err
	}

	// Track whether we need to persist a newly created session
	var needsPersist bool
	var persistCreatedAt, persistExpiresAt time.Time

	session, exists := sm.sessions[sessionID]
	if !exists {
		// Create a new session for external session IDs (from SSE/stdio modes)
		sm.logger.Info("Creating new session for external session ID", "session_id", sessionID)
		now := time.Now()
		expiresAt := now.Add(sm.sessionDuration)

		session = &MCPSession{
			ID:         sessionID,
			Terminated: false,
			CreatedAt:  now,
			ExpiresAt:  expiresAt,
			Data:       nil,
		}
		sm.sessions[sessionID] = session

		// Only persist kitemcp- prefixed sessions (our sessions)
		if strings.HasPrefix(sessionID, mcpSessionPrefix) {
			needsPersist = true
			persistCreatedAt = now
			persistExpiresAt = expiresAt
		}
	}

	now := time.Now()

	// Check if session has expired
	if now.After(session.ExpiresAt) {
		sm.logger.Info("Session has expired", "session_id", sessionID, "expiry", session.ExpiresAt)
		session.Terminated = true
		sm.mu.Unlock()
		return nil, false, errors.New(errSessionNotFound)
	}

	if session.Terminated {
		sm.logger.Info("Session is terminated, cannot get/create data", "session_id", sessionID)
		sm.mu.Unlock()
		return nil, false, errors.New(errSessionNotFound)
	}

	// If data exists and is valid, return it. Capture the reference under the
	// lock so the return expression does not touch session.Data after Unlock —
	// without this, the race detector flags a read-after-unlock against a
	// concurrent UpdateSessionData write even though interface assignment is
	// atomic (the race is on session.Data's memory word, not on what it points
	// to). See TestConcurrentSessionModification (kc/session_test.go).
	if session.Data != nil {
		data := session.Data
		sm.logger.Debug("Successfully retrieved existing data for session ID", "session_id", sessionID)
		sm.mu.Unlock()
		return data, false, nil
	}

	// Create new data using the provided function
	sm.logger.Debug("Creating new data for session ID", "session_id", sessionID)
	newData := createDataFn()
	session.Data = newData

	// Capture email for persistence
	persistEmail := ""
	if kd, ok := newData.(*KiteSessionData); ok && kd != nil {
		persistEmail = kd.Email
	}

	db := sm.db
	sm.mu.Unlock()

	sm.logger.Debug("Successfully created new data for session ID", "session_id", sessionID)

	// Persist outside the lock
	if needsPersist && db != nil {
		if err := db.SaveSession(sessionID, persistEmail, persistCreatedAt, persistExpiresAt, false); err != nil {
			sm.logger.Error("Failed to persist session", "session_id", sessionID, "error", err)
		}
	}

	return newData, true, nil
}
