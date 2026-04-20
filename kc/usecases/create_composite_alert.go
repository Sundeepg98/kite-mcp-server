package usecases

// create_composite_alert.go — business-logic for creating composite alerts.
// Mirrors CreateAlertUseCase but operates on a slice of conditions, resolves
// an instrument token per leg, and delegates persistence to the composite
// branch of the alert store (Option B — shared `alerts` table with an
// alert_type discriminator).
//
// Validation responsibilities:
//   - Name / logic / legs count (2..10)
//   - Per-leg: exchange, tradingsymbol, operator, value, reference_price
//     (required for percentage operators, and percentage value <= 100)
//   - Instrument resolution per leg (bubbled with leg index)
//
// The store enforces persistence invariants (MaxAlertsPerUser quota, row
// writes) and surfaces errors; the use case wraps them with a stable
// prefix so downstream audit tooling can match on "create composite alert".

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// CompositeAlertStore is the subset of kc.AlertStoreInterface needed to
// create composite alerts. Scoped narrowly per Interface Segregation.
type CompositeAlertStore interface {
	AddComposite(email, name string, logic domain.CompositeLogic, conds []domain.CompositeCondition) (string, error)
}

// Composite-alert validation bounds. Kept here (not in the command type)
// so the limits live next to the code that enforces them.
const (
	compositeMinLegs = 2
	compositeMaxLegs = 10
)

// CreateCompositeAlertUseCase creates a composite alert for a user.
type CreateCompositeAlertUseCase struct {
	store       CompositeAlertStore
	instruments InstrumentResolver
	eventStore  EventAppender
	logger      *slog.Logger
}

// NewCreateCompositeAlertUseCase wires the use case with its dependencies.
func NewCreateCompositeAlertUseCase(
	store CompositeAlertStore,
	instruments InstrumentResolver,
	logger *slog.Logger,
) *CreateCompositeAlertUseCase {
	return &CreateCompositeAlertUseCase{
		store:       store,
		instruments: instruments,
		logger:      logger,
	}
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends an alert.created StoredEvent after successful persistence. Phase C ES.
func (uc *CreateCompositeAlertUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// Execute validates the command, resolves instrument tokens for every leg,
// and dispatches the composite write to the store. Returns the alert ID.
func (uc *CreateCompositeAlertUseCase) Execute(ctx context.Context, cmd cqrs.CreateCompositeAlertCommand) (string, error) {
	// Top-level validation.
	if strings.TrimSpace(cmd.Email) == "" {
		return "", fmt.Errorf("usecases: email is required")
	}
	if strings.TrimSpace(cmd.Name) == "" {
		return "", fmt.Errorf("usecases: name is required")
	}

	// Normalize logic — accept case-insensitive input so the use case can
	// be invoked by non-MCP callers (e.g. admin tools) without relying on
	// the tool handler pre-uppercasing.
	logic := domain.CompositeLogic(strings.ToUpper(strings.TrimSpace(cmd.Logic)))
	if !domain.ValidCompositeLogics[logic] {
		return "", fmt.Errorf("usecases: logic must be AND or ANY, got %q", cmd.Logic)
	}

	// Leg-count validation.
	if len(cmd.Conditions) < compositeMinLegs {
		return "", fmt.Errorf("usecases: composite alert requires at least %d conditions", compositeMinLegs)
	}
	if len(cmd.Conditions) > compositeMaxLegs {
		return "", fmt.Errorf("usecases: composite alert supports at most %d conditions", compositeMaxLegs)
	}

	// Per-leg validation + token resolution. Errors carry the leg index so
	// the caller can point at the offending input.
	conds := make([]domain.CompositeCondition, 0, len(cmd.Conditions))
	for i, spec := range cmd.Conditions {
		cond, err := uc.validateAndResolve(i, spec)
		if err != nil {
			return "", err
		}
		conds = append(conds, cond)
	}

	id, err := uc.store.AddComposite(cmd.Email, cmd.Name, logic, conds)
	if err != nil {
		uc.logger.Error("Failed to create composite alert",
			"email", cmd.Email,
			"name", cmd.Name,
			"logic", logic,
			"error", err,
		)
		return "", fmt.Errorf("usecases: create composite alert: %w", err)
	}

	uc.logger.Info("Composite alert created",
		"email", cmd.Email,
		"alert_id", id,
		"name", cmd.Name,
		"logic", logic,
		"legs", len(conds),
	)

	uc.appendCreatedEvent(id, cmd.Email, cmd.Name, logic, len(conds))

	return id, nil
}

// validateAndResolve checks a single leg spec and turns it into the
// domain CompositeCondition (with resolved instrument token). Errors are
// prefixed with the leg index so callers can pinpoint bad input.
func (uc *CreateCompositeAlertUseCase) validateAndResolve(idx int, spec cqrs.CompositeConditionSpec) (domain.CompositeCondition, error) {
	exchange := strings.ToUpper(strings.TrimSpace(spec.Exchange))
	if exchange == "" {
		return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: exchange is required", idx)
	}

	symbol := strings.TrimSpace(spec.Tradingsymbol)
	if symbol == "" {
		return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: tradingsymbol is required", idx)
	}

	operator := alerts.Direction(strings.ToLower(strings.TrimSpace(spec.Operator)))
	if !alerts.ValidDirections[operator] {
		return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: operator %q must be one of above, below, drop_pct, rise_pct", idx, spec.Operator)
	}

	if spec.Value <= 0 {
		return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: value must be > 0", idx)
	}

	// Percentage operators need a reference price and value <= 100.
	if alerts.IsPercentageDirection(operator) {
		if spec.ReferencePrice <= 0 {
			return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: reference_price is required (and > 0) for %s", idx, operator)
		}
		if spec.Value > 100 {
			return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: percentage value cannot exceed 100", idx)
		}
	}

	// Instrument resolution. Surfaced errors include leg index + the raw
	// exchange:symbol tuple the caller supplied so they can correct it.
	token, err := uc.instruments.GetInstrumentToken(exchange, symbol)
	if err != nil {
		return domain.CompositeCondition{}, fmt.Errorf("usecases: conditions[%d]: resolve instrument %s:%s: %w", idx, exchange, symbol, err)
	}

	return domain.CompositeCondition{
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		InstrumentToken: token,
		Operator:        operator,
		Value:           spec.Value,
		ReferencePrice:  spec.ReferencePrice,
	}, nil
}

// appendCreatedEvent writes an alert.created StoredEvent to the audit log
// for composite alerts. Reuses the AlertCreatedPayload shape so both simple
// and composite alerts round-trip through LoadAlertFromEvents (composite
// alerts have no per-leg symbol/target_price — the Name field is stored in
// Symbol and TargetPrice is 0 to signal composite). Best-effort: SQL insert
// is source of truth.
func (uc *CreateCompositeAlertUseCase) appendCreatedEvent(alertID, email, name string, logic domain.CompositeLogic, legs int) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(alertID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on composite alert.created", "alert_id", alertID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(map[string]any{
		"email":    email,
		"name":     name,
		"logic":    string(logic),
		"legs":     legs,
		"kind":     "composite",
	})
	if err != nil { // COVERAGE: unreachable
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   alertID,
		AggregateType: "Alert",
		EventType:     "alert.created",
		Payload:       payload,
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		uc.logger.Warn("event store Append failed on composite alert.created", "alert_id", alertID, "error", err)
	}
}
