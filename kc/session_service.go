package kc

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/mock"
	zerodha "github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// SessionService owns MCP session lifecycle: creation, retrieval, validation,
// login URL generation, and session completion. Extracted from Manager as part
// of Clean Architecture / SOLID refactoring.
//
// Dependencies use interface types (Dependency Inversion Principle), enabling
// mock injection for testing.
type SessionService struct {
	credentialSvc  *CredentialService
	tokenStore     TokenStoreInterface
	sessionManager *SessionRegistry
	sessionSigner  *SessionSigner
	auditStore     AuditStoreInterface  // optional: for synthetic events
	events         *domain.EventDispatcher // optional: dispatches SessionCreatedEvent on new sessions
	logger         *slog.Logger
	metrics        metricsTracker       // thin interface to avoid importing metrics package
	devMode        bool                 // when true, inject mock broker instead of real Kite client
	brokerFactory  broker.Factory       // creates broker clients; defaults to Zerodha if nil
}

// metricsTracker is a minimal interface for metrics tracking within session service.
type metricsTracker interface {
	Increment(key string)
	TrackDailyUser(userID string)
}

// SessionServiceConfig holds dependencies for creating a SessionService.
type SessionServiceConfig struct {
	CredentialSvc *CredentialService
	TokenStore    TokenStoreInterface
	SessionSigner *SessionSigner
	AuditStore    AuditStoreInterface
	Logger        *slog.Logger
	Metrics       metricsTracker
	DevMode       bool
	BrokerFactory broker.Factory // optional: defaults to Zerodha factory if nil
}

// NewSessionService creates a new SessionService.
// The SessionRegistry is created internally; use SetDB to wire persistence.
func NewSessionService(cfg SessionServiceConfig) *SessionService {
	ss := &SessionService{
		credentialSvc: cfg.CredentialSvc,
		tokenStore:    cfg.TokenStore,
		sessionSigner: cfg.SessionSigner,
		auditStore:    cfg.AuditStore,
		logger:        cfg.Logger,
		metrics:       cfg.Metrics,
		devMode:       cfg.DevMode,
		brokerFactory: cfg.BrokerFactory,
	}
	return ss
}

// InitializeSessionManager creates and configures the session registry with cleanup hooks.
func (ss *SessionService) InitializeSessionManager() {
	sessionManager := NewSessionRegistry(ss.logger)
	sessionManager.AddCleanupHook(ss.kiteSessionCleanupHook)
	sessionManager.StartCleanupRoutine(context.Background())
	ss.sessionManager = sessionManager
}

// SessionManager returns the underlying SessionRegistry.
func (ss *SessionService) SessionManager() *SessionRegistry {
	return ss.sessionManager
}

// SetSessionManager allows injecting an already-configured SessionRegistry (used by Manager).
func (ss *SessionService) SetSessionManager(sm *SessionRegistry) {
	ss.sessionManager = sm
}

// SetAuditStore wires the audit store for synthetic session events.
func (ss *SessionService) SetAuditStore(store AuditStoreInterface) {
	ss.auditStore = store
}

// SetBrokerFactory overrides the broker factory used by GetBrokerForEmail.
// Intended for tests that need to inject a mock broker.Factory.
func (ss *SessionService) SetBrokerFactory(f broker.Factory) {
	ss.brokerFactory = f
}

// HasBrokerFactory reports whether an explicit broker.Factory is wired.
// Used by /healthz?probe=deep to surface mis-wired deployments where
// session creation would fail later under load. A nil factory is fine
// in DevMode (the session lifecycle falls through to a lazy default);
// production deployments should always wire one.
func (ss *SessionService) HasBrokerFactory() bool {
	return ss.brokerFactory != nil
}

// SetEventDispatcher wires the domain event dispatcher so the service can
// emit SessionCreatedEvent on every new MCP session. Optional — a nil
// dispatcher disables the side-effect (existing behavior). Called from the
// Manager after its dispatcher is built.
func (ss *SessionService) SetEventDispatcher(d *domain.EventDispatcher) {
	ss.events = d
}

// createKiteSessionData creates new KiteSessionData for a session.
// If email is provided and a cached token exists, it is applied automatically.
// In DevMode, a mock broker is injected and no real Kite client is created.
func (ss *SessionService) createKiteSessionData(sessionID, email string) *KiteSessionData {
	ss.logger.Debug("Creating new Kite session data for MCP session ID", "session_id", sessionID, "email", email)

	// DEV_MODE: use mock broker — no real Kite login required.
	// Create a stub KiteConnect with a dead base URI so session.Kite is non-nil.
	// This lets tool handlers execute their body (returning API errors from the stub)
	// instead of panicking on nil dereference — critical for test coverage.
	if ss.devMode {
		mockClient := mock.NewDemoClient()
		if email == "" {
			email = "demo@kitemcp.dev"
		}
		stubKite := NewKiteConnect("dev_key")
		stubKite.Client.SetBaseURI("http://localhost:1/dev-stub")
		ss.logger.Info("DEV_MODE: created mock broker session with stub Kite client", "session_id", sessionID, "email", email)
		return &KiteSessionData{
			Kite:   stubKite,
			Broker: mockClient,
			Email:  email,
		}
	}

	apiKey := ss.credentialSvc.GetAPIKeyForEmail(email)

	kc := NewKiteConnect(apiKey)
	kd := &KiteSessionData{
		Kite:   kc,
		Broker: zerodha.NewFromSDK(kc.Client),
		Email:  email,
	}

	// Priority 1: Per-email cached token (Fly.io multi-user)
	if email != "" {
		if entry, ok := ss.tokenStore.Get(email); ok {
			kd.Kite.Client.SetAccessToken(entry.AccessToken)
			ss.logger.Debug("Applied cached Kite token for user", "session_id", sessionID, "email", email, "user", entry.UserName)
			return kd
		}
	}

	// Priority 2: Global pre-auth token (local dev / env var)
	if ss.credentialSvc.HasPreAuth() {
		kd.Kite.Client.SetAccessToken(ss.credentialSvc.accessToken)
		ss.logger.Debug("Pre-set access token for session", "session_id", sessionID)
	}
	return kd
}

// extractKiteSessionData safely extracts KiteSessionData from any.
func (ss *SessionService) extractKiteSessionData(data any, sessionID string) (*KiteSessionData, error) {
	kiteData, ok := data.(*KiteSessionData)
	if !ok || kiteData == nil {
		ss.logger.Warn("Invalid Kite data type for MCP session ID", "session_id", sessionID)
		return nil, ErrSessionNotFound
	}
	return kiteData, nil
}

// kiteSessionCleanupHook handles cleanup when a session is terminated.
func (ss *SessionService) kiteSessionCleanupHook(session *MCPSession) {
	if kiteData, ok := session.Data.(*KiteSessionData); ok && kiteData != nil && kiteData.Kite != nil {
		ss.logger.Debug("Cleaning up Kite session for MCP session ID", "session_id", session.ID)
		if _, err := kiteData.Kite.Client.InvalidateAccessToken(); err != nil {
			ss.logger.Warn("Failed to invalidate access token", "session_id", session.ID, "error", err)
		}
	}
}

// GetOrCreateSession retrieves an existing Kite session or creates a new one atomically.
// For email-aware session creation (Fly.io with OAuth), use GetOrCreateSessionWithEmail.
func (ss *SessionService) GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error) {
	return ss.GetOrCreateSessionWithEmail(mcpSessionID, "")
}

// GetOrCreateSessionWithEmail retrieves or creates a Kite session with email context.
// If email is provided and a cached Kite token exists for that email, it is auto-applied.
func (ss *SessionService) GetOrCreateSessionWithEmail(mcpSessionID, email string) (*KiteSessionData, bool, error) {
	if err := validateSessionID(mcpSessionID); err != nil {
		ss.logger.Warn("GetOrCreateSession called with empty MCP session ID")
		return nil, false, err
	}

	// Use atomic GetOrCreateSessionData to eliminate TOCTOU race condition
	data, isNew, err := ss.sessionManager.GetOrCreateSessionData(mcpSessionID, func() any {
		return ss.createKiteSessionData(mcpSessionID, email)
	})

	if err != nil {
		ss.logger.Error("Failed to get or create session data", "error", err)
		return nil, false, ErrSessionNotFound
	}

	kiteData, err := ss.extractKiteSessionData(data, mcpSessionID)
	if err != nil {
		return nil, false, err
	}

	// Restore Kite client for sessions loaded from DB (Data.Kite is nil after restart).
	// In DEV_MODE, Kite has a stub client (non-nil) so this branch is never entered.
	if kiteData.Kite == nil && !ss.devMode {
		resolvedEmail := email
		if resolvedEmail == "" {
			resolvedEmail = kiteData.Email
		}
		ss.logger.Info("Restoring Kite client for persisted session", "session_id", mcpSessionID, "email", resolvedEmail)
		kiteData.Kite = NewKiteConnect(ss.credentialSvc.GetAPIKeyForEmail(resolvedEmail))
		kiteData.Broker = zerodha.NewFromSDK(kiteData.Kite.Client)
		// Apply cached token if available
		if resolvedEmail != "" {
			if entry, ok := ss.tokenStore.Get(resolvedEmail); ok {
				kiteData.Kite.Client.SetAccessToken(entry.AccessToken)
				ss.logger.Debug("Applied cached token to restored session", "session_id", mcpSessionID, "email", resolvedEmail)
			}
		} else if ss.credentialSvc.HasPreAuth() {
			kiteData.Kite.Client.SetAccessToken(ss.credentialSvc.accessToken)
		}
		// Treat as new session so WithSession runs the auth check
		isNew = true
	}

	// Update email on existing sessions if not already set (under registry lock to avoid data race)
	if !isNew && email != "" && kiteData.Email == "" {
		_ = ss.sessionManager.UpdateSessionField(mcpSessionID, func(data any) {
			if kd, ok := data.(*KiteSessionData); ok && kd != nil {
				kd.Email = email
			}
		})
	}

	if isNew {
		ss.logger.Debug("Successfully created new Kite data for MCP session ID", "session_id", mcpSessionID)
		// Dispatch SessionCreatedEvent so the audit log gets a durable record
		// of session establishment. Nil-safe — if no dispatcher wired (tests,
		// early boot), silently skip. The app/wire.go subscribes this event
		// via makeEventPersister("Session", ...).
		if ss.events != nil {
			effectiveEmail := email
			if effectiveEmail == "" {
				effectiveEmail = kiteData.Email
			}
			brokerName := "zerodha"
			if ss.devMode {
				brokerName = "mock"
			}
			ss.events.Dispatch(domain.SessionCreatedEvent{
				Email:     effectiveEmail,
				SessionID: mcpSessionID,
				Broker:    brokerName,
				Timestamp: time.Now(),
			})
		}
	} else {
		ss.logger.Debug("Successfully retrieved existing Kite data for MCP session ID", "session_id", mcpSessionID)
	}

	return kiteData, isNew, nil
}

// GetSession retrieves an existing Kite session by MCP session ID.
func (ss *SessionService) GetSession(mcpSessionID string) (*KiteSessionData, error) {
	if err := validateSessionID(mcpSessionID); err != nil {
		ss.logger.Warn("GetSession called with empty MCP session ID")
		return nil, ErrSessionNotFound
	}

	// Validate session first
	if err := ss.validateSession(mcpSessionID); err != nil {
		ss.logger.Error("MCP session validation failed", "error", err)
		return nil, err
	}

	ss.logger.Debug("Getting Kite data for MCP session ID", "session_id", mcpSessionID)
	data, err := ss.sessionManager.GetSessionData(mcpSessionID)
	if err != nil {
		ss.logger.Error("Failed to get Kite data", "error", err)
		return nil, ErrSessionNotFound
	}

	kiteData, err := ss.extractKiteSessionData(data, mcpSessionID)
	if err != nil {
		return nil, err
	}

	ss.logger.Debug("Successfully retrieved Kite data for MCP session ID", "session_id", mcpSessionID)
	return kiteData, nil
}

// validateSession checks if a MCP session is valid and active.
func (ss *SessionService) validateSession(sessionID string) error {
	isTerminated, err := ss.sessionManager.Validate(sessionID)
	if err != nil {
		ss.logger.Error("MCP session validation failed", "session_id", sessionID, "error", err)
		return ErrSessionNotFound
	}
	if isTerminated {
		ss.logger.Warn("MCP session is terminated", "session_id", sessionID)
		return ErrSessionNotFound
	}
	return nil
}

// GenerateSession creates a new MCP session with Kite data and returns the session ID.
func (ss *SessionService) GenerateSession() string {
	ss.logger.Info("Generating new MCP session with Kite data")
	sessionID := ss.sessionManager.GenerateWithData(ss.createKiteSessionData("", ""))
	ss.logger.Debug("Generated new MCP session with ID", "session_id", sessionID)
	return sessionID
}

// ClearSession terminates a session, triggering cleanup hooks.
func (ss *SessionService) ClearSession(sessionID string) {
	if err := validateSessionID(sessionID); err != nil {
		return
	}

	if _, err := ss.sessionManager.Terminate(sessionID); err != nil {
		ss.logger.Error("Error terminating session", "session_id", sessionID, "error", err)
	} else {
		ss.logger.Debug("Cleaning up Kite session for MCP session ID", "session_id", sessionID)
	}
}

// ClearSessionData clears the session data without terminating the session.
func (ss *SessionService) ClearSessionData(sessionID string) error {
	if err := validateSessionID(sessionID); err != nil {
		return err
	}

	session, err := ss.sessionManager.GetSession(sessionID)
	if err != nil {
		ss.logger.Error("Failed to get session for data cleanup", "error", err)
		return err
	}

	if session.Data != nil {
		ss.kiteSessionCleanupHook(session)
	}

	if err := ss.sessionManager.UpdateSessionData(sessionID, nil); err != nil {
		ss.logger.Error("Error clearing session data", "session_id", sessionID, "error", err)
		return err
	}

	ss.logger.Debug("Cleared session data for MCP session ID", "session_id", sessionID)
	return nil
}

// SessionLoginURL returns the Kite login URL for the given session.
// Returns an error in DEV_MODE since there is no real Kite client to generate a login URL.
func (ss *SessionService) SessionLoginURL(mcpSessionID string) (string, error) {
	if ss.devMode {
		return "", fmt.Errorf("login is not required in DEV_MODE — mock broker is active")
	}

	if err := validateSessionID(mcpSessionID); err != nil {
		ss.logger.Warn("SessionLoginURL called with empty MCP session ID")
		return "", err
	}

	ss.logger.Debug("Retrieving or creating Kite data for MCP session ID", "session_id", mcpSessionID)
	kiteData, isNew, err := ss.GetOrCreateSession(mcpSessionID)
	if err != nil {
		ss.logger.Error("Failed to get or create Kite data", "error", err)
		return "", err
	}

	if isNew {
		ss.logger.Debug("Created new Kite session for MCP session ID", "session_id", mcpSessionID)
	}

	signedParams, err := ss.sessionSigner.SignRedirectParams(mcpSessionID)
	if err != nil {
		ss.logger.Error("Failed to sign redirect params for session", "session_id", mcpSessionID, "error", err)
		return "", fmt.Errorf("failed to create secure login URL: %w", err)
	}

	redirectParams := url.QueryEscape(signedParams)
	loginURL := kiteData.Kite.Client.GetLoginURL() + "&redirect_params=" + redirectParams
	ss.logger.Debug("Generated Kite login URL for MCP session", "session_id", mcpSessionID)

	return loginURL, nil
}

// CompleteSession completes Kite authentication using the request token.
//
// Back-compat shim around CompleteSessionAndRotate. New callers should
// use CompleteSessionAndRotate directly to receive the post-auth
// rotated session ID — that's the OWASP A07 (session fixation) defence.
// This wrapper discards the new ID and returns only the error so the
// pre-G99 `error`-only signature continues to compile.
//
// In-tree callers (the HTTP callback handler in kc/callback_handler.go)
// have been migrated; the handful of test fixtures that still call this
// method don't care about the rotated ID.
func (ss *SessionService) CompleteSession(mcpSessionID, kiteRequestToken string) error {
	_, err := ss.CompleteSessionAndRotate(mcpSessionID, kiteRequestToken)
	return err
}

// CompleteSessionAndRotate completes Kite authentication AND rotates the
// MCP session ID — OWASP A07 (Session Fixation) defence.
//
// The flow:
//  1. Validate the supplied (possibly attacker-influenced) session ID.
//  2. Exchange Kite request token for the access token.
//  3. Generate a fresh session ID via SessionRegistry.Generate (which
//     uses crypto/rand-backed UUIDv4 — same RNG as the original
//     session-issuance path).
//  4. Migrate the Kite session data (token, email, user id) onto the
//     new ID.
//  5. Terminate the old ID so Validate() rejects it.
//
// The new ID is returned to the caller, which is responsible for
// surfacing it back to the legitimate MCP client (e.g. via a signed
// cookie on the callback response, or a server-side mapping keyed
// by the user's email).
//
// On any pre-rotation failure the OLD session is left untouched —
// nothing was authenticated, nothing to invalidate. Callers seeing a
// non-nil error should NOT treat the old ID as terminated.
func (ss *SessionService) CompleteSessionAndRotate(mcpSessionID, kiteRequestToken string) (string, error) {
	if err := validateSessionID(mcpSessionID); err != nil {
		ss.logger.Warn("CompleteSessionAndRotate called with empty MCP session ID")
		return "", err
	}

	ss.logger.Debug("Completing Kite auth for MCP session", "session_id", mcpSessionID, "request_token", kiteRequestToken)

	kiteData, err := ss.GetSession(mcpSessionID)
	if err != nil {
		ss.logger.Error("Failed to complete session", "session_id", mcpSessionID, "error", err)
		return "", ErrSessionNotFound
	}

	apiSecret := ss.credentialSvc.GetAPISecretForEmail(kiteData.Email)
	if apiSecret == "" {
		ss.logger.Error("No API secret configured", "session_id", mcpSessionID, "email", kiteData.Email)
		return "", fmt.Errorf("no Kite API secret configured")
	}

	ss.logger.Debug("Generating Kite session with request token")
	userSess, err := kiteData.Kite.Client.GenerateSession(kiteRequestToken, apiSecret)
	if err != nil {
		ss.logger.Error("Failed to generate Kite session", "error", err)
		return "", fmt.Errorf("failed to generate Kite session: %w", err)
	}

	ss.logger.Debug("Setting Kite access token for MCP session", "session_id", mcpSessionID)
	kiteData.Kite.Client.SetAccessToken(userSess.AccessToken)

	// Cache the token for future sessions by this user
	if kiteData.Email != "" {
		ss.tokenStore.Set(kiteData.Email, &KiteTokenEntry{
			AccessToken: userSess.AccessToken,
			UserID:      userSess.UserID,
			UserName:    userSess.UserName,
		})
		ss.logger.Debug("Cached Kite token for user", "email", kiteData.Email, "user_id", userSess.UserID)
	}

	// G99 — rotate the MCP session ID. Generate a fresh ID, migrate
	// the just-authenticated KiteSessionData onto it, and terminate
	// the old ID so Validate() rejects subsequent requests bearing it.
	// Order: GenerateWithData first (always succeeds for valid input),
	// then Terminate (best-effort — logs but doesn't fail rotation).
	newID := ss.sessionManager.GenerateWithData(kiteData)
	if _, termErr := ss.sessionManager.Terminate(mcpSessionID); termErr != nil {
		// Old-session termination failed — log but continue. The new
		// session is still authoritative for the legitimate user; the
		// old session staying valid is a known partial-rotation case
		// that the cleanup goroutine will sweep.
		ss.logger.Warn("Failed to terminate old session during rotation",
			"old_session_id", mcpSessionID, "new_session_id", newID, "error", termErr)
	}

	// Compliance log for successful login
	ss.logger.Info("COMPLIANCE: User login completed successfully",
		"event", "user_login_success",
		"user_id", userSess.UserID,
		"old_session_id", mcpSessionID,
		"new_session_id", newID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"user_name", userSess.UserName,
		"user_type", userSess.UserType,
	)

	// Track successful login
	if ss.metrics != nil {
		ss.metrics.TrackDailyUser(userSess.UserID)
		ss.metrics.Increment("user_logins")
	}

	return newID, nil
}

// GetActiveSessionCount returns the number of active sessions.
func (ss *SessionService) GetActiveSessionCount() int {
	return len(ss.sessionManager.ListActiveSessions())
}

// CleanupExpiredSessions manually triggers cleanup of expired MCP sessions.
func (ss *SessionService) CleanupExpiredSessions() int {
	return ss.sessionManager.CleanupExpiredSessions()
}

// StopCleanupRoutine stops the background cleanup routine.
func (ss *SessionService) StopCleanupRoutine() {
	ss.sessionManager.StopCleanupRoutine()
}

// validateSessionID checks if a session ID is empty and returns appropriate error.
// Package-level function so both SessionService and Manager can use it.
func validateSessionID(sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	return nil
}

// GetBrokerForEmail resolves a broker.Client for the given email.
// It first checks for an active session with a broker (preserves custom base URI
// and avoids creating redundant clients). In DevMode, returns a mock broker.
// Otherwise, falls back to creating a new client from cached credentials.
func (ss *SessionService) GetBrokerForEmail(email string) (broker.Client, error) {
	if ss.devMode {
		return mock.NewDemoClient(), nil
	}
	// Try to reuse an existing session's broker for this email.
	if ss.sessionManager != nil {
		for _, s := range ss.sessionManager.ListActiveSessions() {
			if kd, ok := s.Data.(*KiteSessionData); ok && kd != nil && kd.Email == email && kd.Broker != nil {
				return kd.Broker, nil
			}
		}
	}
	apiKey := ss.credentialSvc.GetAPIKeyForEmail(email)
	accessToken := ss.credentialSvc.GetAccessTokenForEmail(email)
	if accessToken == "" {
		return nil, fmt.Errorf("no Kite access token for %s", email)
	}
	// Use injected factory if available, else fall back to Zerodha.
	if ss.brokerFactory != nil {
		return ss.brokerFactory.CreateWithToken(apiKey, accessToken)
	}
	kc := NewKiteConnect(apiKey)
	kc.Client.SetAccessToken(accessToken)
	return zerodha.NewFromSDK(kc.Client), nil
}
