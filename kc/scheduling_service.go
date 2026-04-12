package kc

import (
	"context"
)

// SchedulingService groups background scheduling and cleanup concerns:
// session cleanup routines, the Kite session cleanup hook, and operational
// metrics recording (which drives internal daily/cleanup routines on the
// metrics manager). Manager holds a *SchedulingService field and exposes thin
// delegators so existing callers continue to work.
type SchedulingService struct {
	m *Manager
}

func newSchedulingService(m *Manager) *SchedulingService {
	return &SchedulingService{m: m}
}

// initialize creates and configures the session registry with its cleanup
// hook and background cleanup routine. Called once from Manager bootstrap.
func (s *SchedulingService) initialize() {
	sessionManager := NewSessionRegistry(s.m.Logger)
	sessionManager.AddCleanupHook(s.kiteSessionCleanupHook)
	sessionManager.StartCleanupRoutine(context.Background())
	s.m.sessionManager = sessionManager
}

// kiteSessionCleanupHook invalidates the Kite access token when an MCP
// session is cleaned up.
func (s *SchedulingService) kiteSessionCleanupHook(session *MCPSession) {
	if kiteData, ok := session.Data.(*KiteSessionData); ok && kiteData != nil && kiteData.Kite != nil {
		s.m.Logger.Debug("Cleaning up Kite session for MCP session ID", "session_id", session.ID)
		if _, err := kiteData.Kite.Client.InvalidateAccessToken(); err != nil {
			s.m.Logger.Warn("Failed to invalidate access token", "session_id", session.ID, "error", err)
		}
	}
}

// CleanupExpiredSessions manually triggers cleanup of expired MCP sessions.
func (s *SchedulingService) CleanupExpiredSessions() int {
	return s.m.sessionSvc.CleanupExpiredSessions()
}

// StopCleanupRoutine stops the background cleanup routine.
func (s *SchedulingService) StopCleanupRoutine() {
	s.m.sessionSvc.StopCleanupRoutine()
}

// HasMetrics returns true if a metrics manager is available.
func (s *SchedulingService) HasMetrics() bool {
	return s.m.metrics != nil
}

// IncrementMetric increments a metric counter by 1.
func (s *SchedulingService) IncrementMetric(key string) {
	if s.m.metrics != nil {
		s.m.metrics.Increment(key)
	}
}

// TrackDailyUser records a unique user interaction for today's counter.
func (s *SchedulingService) TrackDailyUser(userID string) {
	if s.m.metrics != nil {
		s.m.metrics.TrackDailyUser(userID)
	}
}

// IncrementDailyMetric increments a daily metric counter by 1.
func (s *SchedulingService) IncrementDailyMetric(key string) {
	if s.m.metrics != nil {
		s.m.metrics.IncrementDaily(key)
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
