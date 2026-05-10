package kc

import (
	"context"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/app/metrics"
)

// SchedulingService groups background scheduling and cleanup concerns:
// session cleanup routines, the Kite session cleanup hook, and operational
// metrics recording (which drives internal daily/cleanup routines on the
// metrics manager). Manager holds a *SchedulingService field and exposes thin
// delegators so existing callers continue to work.
//
// Tier 1.3 (Path A.28 — final facade back-pointer elimination, follows
// Tier 1.1 brokers + Tier 1.2 eventing): the back-pointer to *Manager has
// been replaced with closures over the underlying fields. Each closure
// dereferences the source-of-truth Manager field at call time, preserving
// observable behaviour identical to the prior `s.m.X` access.
//
// initialize() needs the closure-with-write-back variant for sessionManager
// because the registry is constructed inside the service then handed back
// to Manager as the source of truth. Read-only closures (Logger, SessionSvc,
// metrics) follow the same closure-by-reference idiom that landed in Tier
// 1.1 + 1.2.
type SchedulingService struct {
	// Logger is read by initialize() (NewSessionRegistry takes it) and by
	// kiteSessionCleanupHook (Debug/Warn during cleanup).
	getLogger func() *slog.Logger

	// sessionManager is WRITTEN by initialize() — the only "trickier"
	// closure pair in this facade. The service constructs the registry
	// then hands it back to Manager via setSessionManager so subsequent
	// init phases (initFocusedServices' SessionSvc construction) read
	// it from m.sessionManager directly.
	setSessionManager func(*SessionRegistry)

	// SessionSvc is read by CleanupExpiredSessions + StopCleanupRoutine.
	// Like the Wave D use-case fields in eventing_service, SessionSvc is
	// nil at newSchedulingService() time and only populated later by
	// initFocusedServices' NewSessionService call. Closures-by-reference
	// observe the populated value at delegator call time.
	getSessionSvc func() *SessionService

	// metrics is read by HasMetrics + IncrementMetric + TrackDailyUser +
	// IncrementDailyMetric. May be nil throughout if cfg.Metrics was nil.
	getMetrics func() *metrics.Manager
}

// newSchedulingService constructs SchedulingService with closures over the
// given Manager's fields. Call exactly once at Manager init; the closures
// permit subsequent Manager mutations (e.g., initFocusedServices populating
// SessionSvc, initialize itself populating sessionManager) to remain
// observable through the facade.
func newSchedulingService(m *Manager) *SchedulingService {
	return &SchedulingService{
		getLogger:         func() *slog.Logger { return m.Logger },
		setSessionManager: func(sm *SessionRegistry) { m.sessionManager = sm },
		getSessionSvc:     func() *SessionService { return m.SessionSvc },
		getMetrics:        func() *metrics.Manager { return m.metrics },
	}
}

// initialize creates and configures the session registry with its cleanup
// hook and background cleanup routine. Called once from Manager bootstrap
// (initFocusedServices, Phase 13). After this method returns,
// m.sessionManager is non-nil and subsequent phases (NewSessionService) can
// consume it.
func (s *SchedulingService) initialize() {
	sessionManager := NewSessionRegistry(s.getLogger())
	sessionManager.AddCleanupHook(s.kiteSessionCleanupHook)
	sessionManager.StartCleanupRoutine(context.Background())
	s.setSessionManager(sessionManager)
}

// kiteSessionCleanupHook invalidates the Kite access token when an MCP
// session is cleaned up.
func (s *SchedulingService) kiteSessionCleanupHook(session *MCPSession) {
	logger := s.getLogger()
	if kiteData, ok := session.Data.(*KiteSessionData); ok && kiteData != nil && kiteData.Kite != nil {
		logger.Debug("Cleaning up Kite session for MCP session ID", "session_id", session.ID)
		if _, err := kiteData.Kite.InvalidateAccessToken(); err != nil {
			logger.Warn("Failed to invalidate access token", "session_id", session.ID, "error", err)
		}
	}
}

// CleanupExpiredSessions manually triggers cleanup of expired MCP sessions.
func (s *SchedulingService) CleanupExpiredSessions() int {
	return s.getSessionSvc().CleanupExpiredSessions()
}

// StopCleanupRoutine stops the background cleanup routine.
func (s *SchedulingService) StopCleanupRoutine() {
	s.getSessionSvc().StopCleanupRoutine()
}

// HasMetrics returns true if a metrics manager is available.
func (s *SchedulingService) HasMetrics() bool {
	return s.getMetrics() != nil
}

// IncrementMetric increments a metric counter by 1.
func (s *SchedulingService) IncrementMetric(key string) {
	if m := s.getMetrics(); m != nil {
		m.Increment(key)
	}
}

// TrackDailyUser records a unique user interaction for today's counter.
func (s *SchedulingService) TrackDailyUser(userID string) {
	if m := s.getMetrics(); m != nil {
		m.TrackDailyUser(userID)
	}
}

// IncrementDailyMetric increments a daily metric counter by 1.
func (s *SchedulingService) IncrementDailyMetric(key string) {
	if m := s.getMetrics(); m != nil {
		m.IncrementDaily(key)
	}
}

// ---------------------------------------------------------------------------
// Manager-level delegators (moved from manager.go).
// ---------------------------------------------------------------------------

// Scheduling returns the scheduling service.
func (m *Manager) Scheduling() *SchedulingService { return m.scheduling }

// CleanupExpiredSessions manually triggers cleanup of expired MCP sessions.
func (m *Manager) CleanupExpiredSessions() int { return m.scheduling.CleanupExpiredSessions() }

// StopCleanupRoutine stops the background cleanup routine.
func (m *Manager) StopCleanupRoutine() { m.scheduling.StopCleanupRoutine() }

// HasMetrics returns true if metrics manager is available.
func (m *Manager) HasMetrics() bool { return m.scheduling.HasMetrics() }

// IncrementMetric increments a metric counter by 1.
func (m *Manager) IncrementMetric(key string) { m.scheduling.IncrementMetric(key) }

// TrackDailyUser records a unique user interaction for today's counter.
func (m *Manager) TrackDailyUser(userID string) { m.scheduling.TrackDailyUser(userID) }

// IncrementDailyMetric increments a daily metric counter by 1.
func (m *Manager) IncrementDailyMetric(key string) { m.scheduling.IncrementDailyMetric(key) }
