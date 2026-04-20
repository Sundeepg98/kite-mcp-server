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

// AlertStore is the interface needed by CreateAlertUseCase.
// It matches the subset of kc.AlertStoreInterface used here.
type AlertStore interface {
	Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction) (string, error)
	AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction, referencePrice float64) (string, error)
}

// InstrumentResolver looks up instrument tokens by exchange and symbol.
type InstrumentResolver interface {
	GetInstrumentToken(exchange, tradingsymbol string) (uint32, error)
}

// CreateAlertUseCase creates a new price alert for a user.
type CreateAlertUseCase struct {
	alertStore  AlertStore
	instruments InstrumentResolver
	events      *domain.EventDispatcher
	eventStore  EventAppender
	logger      *slog.Logger
}

// NewCreateAlertUseCase creates a CreateAlertUseCase with all dependencies injected.
func NewCreateAlertUseCase(
	store AlertStore,
	instruments InstrumentResolver,
	logger *slog.Logger,
) *CreateAlertUseCase {
	return &CreateAlertUseCase{
		alertStore:  store,
		instruments: instruments,
		logger:      logger,
	}
}

// SetEventDispatcher wires an event dispatcher so AlertCreatedEvent is
// emitted on successful creation. Dispatcher feeds the Projector (read
// model) and runtime subscribers. Audit-log persistence is handled
// separately by SetEventStore — the dispatcher path for alert.created is
// no longer subscribed to the persister in wire.go (Phase C: use case
// owns the audit write to avoid double-emit). Optional — callers without
// a dispatcher skip the dispatch step.
func (uc *CreateAlertUseCase) SetEventDispatcher(d *domain.EventDispatcher) {
	uc.events = d
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends an alert.created StoredEvent directly after a successful insert.
// Phase C event sourcing. Nil-safe — unset event stores skip the append.
func (uc *CreateAlertUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// Execute creates an alert and returns the alert ID.
func (uc *CreateAlertUseCase) Execute(ctx context.Context, cmd cqrs.CreateAlertCommand) (string, error) {
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return "", fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.Direction == "" {
		return "", fmt.Errorf("usecases: direction is required")
	}
	// Delegate threshold + percentage/ref-price rules to the domain. Caller
	// preserves "target_price must be positive" error substring via wrap.
	if err := domain.ValidateAlertSpec(domain.Direction(cmd.Direction), cmd.TargetPrice, cmd.ReferencePrice); err != nil {
		if cmd.TargetPrice <= 0 {
			return "", fmt.Errorf("usecases: target_price must be positive: %w", err)
		}
		return "", fmt.Errorf("usecases: %w", err)
	}

	// Resolve instrument token.
	token, err := uc.instruments.GetInstrumentToken(cmd.Exchange, cmd.Tradingsymbol)
	if err != nil {
		return "", fmt.Errorf("usecases: resolve instrument: %w", err)
	}

	direction := alerts.Direction(cmd.Direction)

	// Use reference price variant if provided.
	var alertID string
	if cmd.ReferencePrice > 0 {
		alertID, err = uc.alertStore.AddWithReferencePrice(
			cmd.Email, cmd.Tradingsymbol, cmd.Exchange,
			token, cmd.TargetPrice, direction, cmd.ReferencePrice,
		)
	} else {
		alertID, err = uc.alertStore.Add(
			cmd.Email, cmd.Tradingsymbol, cmd.Exchange,
			token, cmd.TargetPrice, direction,
		)
	}
	if err != nil {
		uc.logger.Error("Failed to create alert",
			"email", cmd.Email,
			"tradingsymbol", cmd.Tradingsymbol,
			"error", err,
		)
		return "", fmt.Errorf("usecases: create alert: %w", err)
	}

	uc.logger.Info("Alert created",
		"email", cmd.Email,
		"alert_id", alertID,
		"tradingsymbol", cmd.Tradingsymbol,
		"target_price", cmd.TargetPrice,
		"direction", cmd.Direction,
	)

	now := time.Now()
	if uc.events != nil {
		uc.events.Dispatch(domain.AlertCreatedEvent{
			Email:       cmd.Email,
			AlertID:     alertID,
			Instrument:  domain.NewInstrumentKey(cmd.Exchange, cmd.Tradingsymbol),
			TargetPrice: domain.NewINR(cmd.TargetPrice),
			Direction:   cmd.Direction,
			Timestamp:   now,
		})
	}
	uc.appendCreatedEvent(alertID, cmd, now)

	return alertID, nil
}

// appendCreatedEvent writes an alert.created StoredEvent to the audit log.
// Failures are logged and swallowed — the SQL insert is source of truth
// and has already succeeded. Uses AlertCreatedPayload so LoadAlertFromEvents
// round-trips the record cleanly.
func (uc *CreateAlertUseCase) appendCreatedEvent(alertID string, cmd cqrs.CreateAlertCommand, occurredAt time.Time) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(alertID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on alert.created", "alert_id", alertID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(eventsourcing.AlertCreatedPayload{
		Email:       cmd.Email,
		Symbol:      cmd.Tradingsymbol,
		Exchange:    cmd.Exchange,
		TargetPrice: cmd.TargetPrice,
		Direction:   cmd.Direction,
	})
	if err != nil { // COVERAGE: unreachable — struct marshals cleanly
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   alertID,
		AggregateType: "Alert",
		EventType:     "alert.created",
		Payload:       payload,
		OccurredAt:    occurredAt.UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		uc.logger.Warn("event store Append failed on alert.created", "alert_id", alertID, "error", err)
	}
}
