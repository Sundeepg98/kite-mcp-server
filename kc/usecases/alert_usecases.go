package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// AlertReader abstracts alert read/delete operations for use cases.
type AlertReader interface {
	List(email string) []*alerts.Alert
	Delete(email, alertID string) error
}

// --- List Alerts ---

// ListAlertsUseCase retrieves all alerts for a user.
type ListAlertsUseCase struct {
	store  AlertReader
	logger *slog.Logger
}

// NewListAlertsUseCase creates a ListAlertsUseCase with dependencies injected.
func NewListAlertsUseCase(store AlertReader, logger *slog.Logger) *ListAlertsUseCase {
	return &ListAlertsUseCase{store: store, logger: logger}
}

// Execute retrieves all alerts for the given user.
func (uc *ListAlertsUseCase) Execute(ctx context.Context, query cqrs.GetAlertsQuery) ([]*alerts.Alert, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	return uc.store.List(query.Email), nil
}

// --- Delete Alert ---

// DeleteAlertUseCase deletes a specific alert.
type DeleteAlertUseCase struct {
	store      AlertReader
	events     *domain.EventDispatcher
	eventStore EventAppender
	logger     *slog.Logger
}

// NewDeleteAlertUseCase creates a DeleteAlertUseCase with dependencies injected.
func NewDeleteAlertUseCase(store AlertReader, logger *slog.Logger) *DeleteAlertUseCase {
	return &DeleteAlertUseCase{store: store, logger: logger}
}

// SetEventDispatcher wires an event dispatcher so AlertDeletedEvent is
// emitted on successful deletion. Dispatcher drives the Projector (read
// model). Audit-log persistence is handled separately by SetEventStore —
// the dispatcher→persister path for alert.deleted was dropped in Phase C
// to prevent double-emit. Optional — unset dispatcher skips the dispatch.
func (uc *DeleteAlertUseCase) SetEventDispatcher(d *domain.EventDispatcher) {
	uc.events = d
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends an alert.deleted StoredEvent directly after successful deletion.
// Phase C event sourcing. Nil-safe.
func (uc *DeleteAlertUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// Execute deletes an alert by ID.
func (uc *DeleteAlertUseCase) Execute(ctx context.Context, cmd cqrs.DeleteAlertCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.AlertID == "" {
		return fmt.Errorf("usecases: alert_id is required")
	}
	if err := uc.store.Delete(cmd.Email, cmd.AlertID); err != nil {
		uc.logger.Error("Failed to delete alert", "email", cmd.Email, "alert_id", cmd.AlertID, "error", err)
		return fmt.Errorf("usecases: delete alert: %w", err)
	}
	now := time.Now()
	if uc.events != nil {
		uc.events.Dispatch(domain.AlertDeletedEvent{
			Email:     cmd.Email,
			AlertID:   cmd.AlertID,
			Timestamp: now,
		})
	}
	uc.appendDeletedEvent(cmd.Email, cmd.AlertID, now)
	return nil
}

// appendDeletedEvent writes an alert.deleted StoredEvent to the audit log.
// Failures are logged and swallowed — the SQL delete is source of truth.
func (uc *DeleteAlertUseCase) appendDeletedEvent(email, alertID string, occurredAt time.Time) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(alertID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on alert.deleted", "alert_id", alertID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(map[string]string{
		"email":    email,
		"alert_id": alertID,
	})
	if err != nil { // COVERAGE: unreachable — map[string]string marshals cleanly
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   alertID,
		AggregateType: "Alert",
		EventType:     "alert.deleted",
		Payload:       payload,
		OccurredAt:    occurredAt.UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		uc.logger.Warn("event store Append failed on alert.deleted", "alert_id", alertID, "error", err)
	}
}
