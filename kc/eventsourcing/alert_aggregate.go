package eventsourcing

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Alert status constants.
const (
	AlertStatusActive    = "ACTIVE"
	AlertStatusTriggered = "TRIGGERED"
	AlertStatusDeleted   = "DELETED"
)

// AlertAggregate models the lifecycle of a price alert through events.
// State is only mutated via Apply, which processes domain events.
//
// NOTE: Not instantiated in production. Alert state is managed by alerts.Store
// (CRUD). This aggregate exists for testing event replay correctness.
type AlertAggregate struct {
	BaseAggregate
	Email       string
	Instrument  domain.InstrumentKey
	TargetPrice domain.Money
	Direction   string // above, below, drop_pct, rise_pct
	Status      string // ACTIVE, TRIGGERED, DELETED
	CreatedAt   time.Time
	TriggeredAt time.Time
	DeletedAt   time.Time
}

// NewAlertAggregate creates a new alert aggregate.
func NewAlertAggregate(id string) *AlertAggregate {
	return &AlertAggregate{
		BaseAggregate: BaseAggregate{id: id},
		Status:        AlertStatusActive,
	}
}

// AggregateType returns "Alert".
func (a *AlertAggregate) AggregateType() string { return "Alert" }

// --- Command methods ---

// AlertCreatedPayload is the JSON payload for an AlertCreated event.
type AlertCreatedPayload struct {
	Email       string  `json:"email"`
	Symbol      string  `json:"symbol"`
	Exchange    string  `json:"exchange"`
	TargetPrice float64 `json:"target_price"`
	Direction   string  `json:"direction"`
}

// AlertTriggeredPayload is the JSON payload for an AlertTriggered event.
type AlertTriggeredPayload struct {
	CurrentPrice float64 `json:"current_price"`
}

// AlertDeletedPayload is the JSON payload for an AlertDeleted event.
type AlertDeletedPayload struct{}

// Create emits an AlertCreated event.
func (a *AlertAggregate) Create(email, symbol, exchange string, targetPrice float64, direction string) error {
	if a.Version() > 0 {
		return fmt.Errorf("eventsourcing: alert already created")
	}
	if email == "" {
		return fmt.Errorf("eventsourcing: email is required")
	}
	if symbol == "" {
		return fmt.Errorf("eventsourcing: symbol is required")
	}
	if targetPrice <= 0 {
		return fmt.Errorf("eventsourcing: target price must be positive, got %f", targetPrice)
	}

	now := time.Now().UTC()
	event := &alertCreatedEvent{
		alertID:     a.id,
		email:       email,
		instrument:  domain.NewInstrumentKey(exchange, symbol),
		targetPrice: domain.NewINR(targetPrice),
		direction:   direction,
		timestamp:   now,
	}
	a.Apply(event)
	a.raise(event)
	return nil
}

// Trigger emits an AlertTriggered event.
func (a *AlertAggregate) Trigger(currentPrice float64) error {
	if err := a.CanTrigger(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}

	now := time.Now().UTC()
	event := &alertTriggeredEvent{
		alertID:      a.id,
		currentPrice: currentPrice,
		timestamp:    now,
	}
	a.Apply(event)
	a.raise(event)
	return nil
}

// Delete emits an AlertDeleted event.
func (a *AlertAggregate) Delete() error {
	if err := a.CanDelete(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}

	now := time.Now().UTC()
	event := &alertDeletedEvent{
		alertID:   a.id,
		timestamp: now,
	}
	a.Apply(event)
	a.raise(event)
	return nil
}

// --- Invariant query methods ---

// CanTrigger returns an error if the alert cannot be triggered.
func (a *AlertAggregate) CanTrigger() error {
	if a.Status != AlertStatusActive {
		return fmt.Errorf("alert not active, got %s", a.Status)
	}
	return nil
}

// CanDelete returns an error if the alert cannot be deleted.
func (a *AlertAggregate) CanDelete() error {
	if a.Status == AlertStatusDeleted {
		return fmt.Errorf("alert already deleted")
	}
	return nil
}

// --- Apply (state reconstitution) ---

// Apply processes a domain event and updates aggregate state.
func (a *AlertAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case *alertCreatedEvent:
		a.Email = e.email
		a.Instrument = e.instrument
		a.TargetPrice = e.targetPrice
		a.Direction = e.direction
		a.Status = AlertStatusActive
		a.CreatedAt = e.timestamp
	case *alertTriggeredEvent:
		a.Status = AlertStatusTriggered
		a.TriggeredAt = e.timestamp
	case *alertDeletedEvent:
		a.Status = AlertStatusDeleted
		a.DeletedAt = e.timestamp
	}
	a.incrementVersion()
}

// --- Internal event types ---

type alertCreatedEvent struct {
	alertID     string
	email       string
	instrument  domain.InstrumentKey
	targetPrice domain.Money
	direction   string
	timestamp   time.Time
}

func (e *alertCreatedEvent) EventType() string    { return "AlertCreated" }
func (e *alertCreatedEvent) OccurredAt() time.Time { return e.timestamp }

type alertTriggeredEvent struct {
	alertID      string
	currentPrice float64
	timestamp    time.Time
}

func (e *alertTriggeredEvent) EventType() string    { return "AlertTriggered" }
func (e *alertTriggeredEvent) OccurredAt() time.Time { return e.timestamp }

type alertDeletedEvent struct {
	alertID   string
	timestamp time.Time
}

func (e *alertDeletedEvent) EventType() string    { return "AlertDeleted" }
func (e *alertDeletedEvent) OccurredAt() time.Time { return e.timestamp }

// --- Reconstitution from stored events ---

// LoadAlertFromEvents replays a sequence of stored events to reconstitute
// an AlertAggregate.
func LoadAlertFromEvents(events []StoredEvent) (*AlertAggregate, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("eventsourcing: no events to load alert from")
	}

	agg := NewAlertAggregate(events[0].AggregateID)

	for _, stored := range events {
		domainEvent, err := deserializeAlertEvent(stored)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: deserialize event %s: %w", stored.EventType, err)
		}
		agg.Apply(domainEvent)
	}

	agg.ClearPendingEvents()
	return agg, nil
}

func deserializeAlertEvent(stored StoredEvent) (domain.Event, error) {
	switch stored.EventType {
	case "AlertCreated":
		var p AlertCreatedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &alertCreatedEvent{
			alertID:     stored.AggregateID,
			email:       p.Email,
			instrument:  domain.NewInstrumentKey(p.Exchange, p.Symbol),
			targetPrice: domain.NewINR(p.TargetPrice),
			direction:   p.Direction,
			timestamp:   stored.OccurredAt,
		}, nil

	case "AlertTriggered":
		var p AlertTriggeredPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &alertTriggeredEvent{
			alertID:      stored.AggregateID,
			currentPrice: p.CurrentPrice,
			timestamp:    stored.OccurredAt,
		}, nil

	case "AlertDeleted":
		return &alertDeletedEvent{
			alertID:   stored.AggregateID,
			timestamp: stored.OccurredAt,
		}, nil

	default:
		return nil, fmt.Errorf("unknown alert event type: %s", stored.EventType)
	}
}

// ToAlertStoredEvents converts pending domain events from an AlertAggregate
// into StoredEvents ready for persistence.
func ToAlertStoredEvents(agg *AlertAggregate, startSequence int64) ([]StoredEvent, error) {
	var stored []StoredEvent
	for i, event := range agg.PendingEvents() {
		var payload []byte
		var err error

		switch e := event.(type) {
		case *alertCreatedEvent:
			payload, err = MarshalPayload(AlertCreatedPayload{
				Email:       e.email,
				Symbol:      e.instrument.Tradingsymbol,
				Exchange:    e.instrument.Exchange,
				TargetPrice: e.targetPrice.Amount,
				Direction:   e.direction,
			})
		case *alertTriggeredEvent:
			payload, err = MarshalPayload(AlertTriggeredPayload{
				CurrentPrice: e.currentPrice,
			})
		case *alertDeletedEvent:
			payload, err = MarshalPayload(AlertDeletedPayload{})
		default:
			return nil, fmt.Errorf("eventsourcing: unknown event type %T", event)
		}
		if err != nil { // COVERAGE: unreachable — all payload types are plain structs that json.Marshal cannot fail on
			return nil, err
		}

		stored = append(stored, StoredEvent{
			AggregateID:   agg.AggregateID(),
			AggregateType: agg.AggregateType(),
			EventType:     event.EventType(),
			Payload:       payload,
			OccurredAt:    event.OccurredAt(),
			Sequence:      startSequence + int64(i),
		})
	}
	return stored, nil
}
