package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// SessionDataClearer abstracts the session-data clearing operation. Narrow
// port (one method) so the use case does not pull in the full SessionPort /
// SessionProvider surface just to perform a single lifecycle write. The kc
// package's SessionService satisfies this natively via its ClearSessionData
// method, so no adapter is required at the wiring site.
type SessionDataClearer interface {
	ClearSessionData(sessionID string) error
}

// EventAppender is a narrow port over eventsourcing.EventStore that the
// use cases use to write domain events to the audit log. The full store
// exposes LoadEvents / LoadEventsSince which are read-model concerns; the
// use case only needs to append and ask for the next sequence number.
// kc/eventsourcing.EventStore satisfies this natively.
type EventAppender interface {
	Append(events ...eventsourcing.StoredEvent) error
	NextSequence(aggregateID string) (int64, error)
}

// ClearSessionDataUseCase clears the Kite session data attached to an MCP
// session without terminating the session itself. Owns the persistence
// step — the handler in kc/manager_commands_setup.go invokes Execute, and
// mcp/ tool handlers must not reach past the bus to call ClearSessionData
// directly (Round-5 Phase B contract for sessions).
type ClearSessionDataUseCase struct {
	sessions   SessionDataClearer
	eventStore EventAppender
	logger     *slog.Logger
}

// NewClearSessionDataUseCase creates a ClearSessionDataUseCase with the
// session clearer injected via the narrow SessionDataClearer port. sessions
// may be nil during partial bootstrap; Execute returns an error in that case
// so a missing dependency surfaces rather than silently succeeding.
func NewClearSessionDataUseCase(sessions SessionDataClearer, logger *slog.Logger) *ClearSessionDataUseCase {
	return &ClearSessionDataUseCase{sessions: sessions, logger: logger}
}

// SetEventStore wires the domain audit-log appender. Optional — a nil
// appender disables the append-after-clear side effect (existing behavior).
// Called from app/wire.go once the eventsourcing store is constructed.
func (uc *ClearSessionDataUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute clears the session data for the command's SessionID. Reason is
// logged at Info level so audit trails can correlate the clear with the
// lifecycle narrative (post-credential-register vs profile-check-failed).
//
// On successful SQL write the use case appends a session.cleared event to
// the domain audit log (Phase C event sourcing). The append is best-effort —
// the SQL write is the source of truth, and an audit-log failure must not
// break the login flow that drove the clear.
func (uc *ClearSessionDataUseCase) Execute(ctx context.Context, cmd cqrs.ClearSessionDataCommand) error {
	if cmd.SessionID == "" {
		return fmt.Errorf("usecases: session_id is required")
	}
	if uc.sessions == nil {
		return fmt.Errorf("usecases: session clearer not configured")
	}
	if err := uc.sessions.ClearSessionData(cmd.SessionID); err != nil {
		return fmt.Errorf("usecases: clear session data: %w", err)
	}
	reason := cmd.Reason
	if reason == "" {
		reason = "unspecified"
	}
	if uc.logger != nil {
		uc.logger.Info("Session data cleared via command bus", "session_id", cmd.SessionID, "reason", reason)
	}
	uc.appendClearedEvent(cmd.SessionID, reason)
	return nil
}

// appendClearedEvent writes a session.cleared StoredEvent to the audit log.
// Failures are logged and swallowed: the ClearSessionData SQL write is the
// source of truth and has already succeeded by the time this runs.
func (uc *ClearSessionDataUseCase) appendClearedEvent(sessionID, reason string) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(sessionID)
	if err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store NextSequence failed on session.cleared", "session_id", sessionID, "error", err)
		}
		return
	}
	payload, err := eventsourcing.MarshalPayload(map[string]string{
		"session_id": sessionID,
		"reason":     reason,
	})
	if err != nil { // COVERAGE: unreachable — map[string]string always marshals
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   sessionID,
		AggregateType: "Session",
		EventType:     "session.cleared",
		Payload:       payload,
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store Append failed on session.cleared", "session_id", sessionID, "error", err)
		}
	}
}
