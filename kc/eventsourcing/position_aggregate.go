package eventsourcing

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Position status constants.
const (
	PositionStatusOpen   = "OPEN"
	PositionStatusClosed = "CLOSED"
)

// PositionAggregate models the lifecycle of a trading position through events.
// State is only mutated via Apply, which processes domain events.
//
// NOTE: Not instantiated in production. Position state comes from broker API
// (GetPositions). This aggregate exists for testing event replay correctness.
type PositionAggregate struct {
	BaseAggregate
	Email           string
	Instrument      domain.InstrumentKey
	Product         string // MIS, CNC, NRML — part of natural aggregate key
	TransactionType string // original direction: BUY or SELL
	Quantity        domain.Quantity
	AvgPrice        domain.Money
	Status          string // OPEN, CLOSED
	OpenedAt        time.Time
	ClosedAt        time.Time
}

// NewPositionAggregate creates a new position aggregate in the OPEN state.
func NewPositionAggregate(id string) *PositionAggregate {
	return &PositionAggregate{
		BaseAggregate: BaseAggregate{id: id},
		Status:        PositionStatusOpen,
	}
}

// AggregateType returns "Position".
func (p *PositionAggregate) AggregateType() string { return "Position" }

// --- Command methods ---

// PositionOpenedPayload is the JSON payload for a PositionOpened event.
type PositionOpenedPayload struct {
	Email           string  `json:"email"`
	Symbol          string  `json:"symbol"`
	Exchange        string  `json:"exchange"`
	TransactionType string  `json:"transaction_type"`
	Quantity        int     `json:"quantity"`
	AvgPrice        float64 `json:"avg_price"`
}

// PositionClosedPayload is the JSON payload for a PositionClosed event.
type PositionClosedPayload struct {
	CloseOrderID    string `json:"close_order_id"`
	TransactionType string `json:"transaction_type"` // opposite direction
}

// Open emits a PositionOpened event.
func (p *PositionAggregate) Open(email, symbol, exchange, txnType string, qty int, avgPrice float64) error {
	if p.Version() > 0 {
		return fmt.Errorf("eventsourcing: position already opened")
	}
	if email == "" {
		return fmt.Errorf("eventsourcing: email is required")
	}
	if symbol == "" {
		return fmt.Errorf("eventsourcing: symbol is required")
	}
	q, err := domain.NewQuantity(qty)
	if err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}

	now := time.Now().UTC()
	event := &positionOpenedEvent{
		positionID:      p.id,
		email:           email,
		instrument:      domain.NewInstrumentKey(exchange, symbol),
		transactionType: txnType,
		quantity:        q,
		avgPrice:        domain.NewINR(avgPrice),
		timestamp:       now,
	}
	p.Apply(event)
	p.raise(event)
	return nil
}

// Close emits a PositionClosed event after validating the position can be closed.
func (p *PositionAggregate) Close(closeOrderID, closeTxnType string) error {
	if err := p.CanClose(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}

	now := time.Now().UTC()
	event := &positionClosedEvent{
		positionID:      p.id,
		closeOrderID:    closeOrderID,
		transactionType: closeTxnType,
		timestamp:       now,
	}
	p.Apply(event)
	p.raise(event)
	return nil
}

// --- Invariant query methods ---

// CanClose returns an error if the position cannot be closed in its current state.
func (p *PositionAggregate) CanClose() error {
	if p.Status == PositionStatusClosed {
		return fmt.Errorf("position already closed")
	}
	if p.Status != PositionStatusOpen {
		return fmt.Errorf("position not in OPEN state, got %s", p.Status)
	}
	return nil
}

// --- Apply (state reconstitution) ---

// Apply processes a domain event and updates aggregate state.
//
// Both internal event types (emitted by Open/Close command methods) and the
// public domain.*Event types dispatched on the domain.EventDispatcher are
// handled. The latter lets the projection pipeline feed live position events
// from the bus into the aggregate directly.
func (p *PositionAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case *positionOpenedEvent:
		p.Email = e.email
		p.Instrument = e.instrument
		p.TransactionType = e.transactionType
		p.Quantity = e.quantity
		p.AvgPrice = e.avgPrice
		p.Status = PositionStatusOpen
		p.OpenedAt = e.timestamp
	case *positionClosedEvent:
		p.Status = PositionStatusClosed
		p.Quantity = domain.Quantity{} // zero value
		p.ClosedAt = e.timestamp
	case domain.PositionOpenedEvent:
		p.Email = e.Email
		p.Instrument = e.Instrument
		p.Product = e.Product
		p.TransactionType = e.TransactionType
		p.Quantity = e.Qty
		p.AvgPrice = e.AvgPrice
		p.Status = PositionStatusOpen
		p.OpenedAt = e.Timestamp
		p.ClosedAt = time.Time{} // reset on re-open (multi-lifecycle)
	case domain.PositionClosedEvent:
		p.Status = PositionStatusClosed
		p.Quantity = domain.Quantity{} // zero value
		p.ClosedAt = e.Timestamp
		if a := (domain.InstrumentKey{}); p.Instrument == a {
			p.Instrument = e.Instrument
		}
		if p.Product == "" {
			p.Product = e.Product
		}
		if p.Email == "" {
			p.Email = e.Email
		}
	}
	p.incrementVersion()
}

// --- Internal event types ---

type positionOpenedEvent struct {
	positionID      string
	email           string
	instrument      domain.InstrumentKey
	transactionType string
	quantity        domain.Quantity
	avgPrice        domain.Money
	timestamp       time.Time
}

func (e *positionOpenedEvent) EventType() string    { return "PositionOpened" }
func (e *positionOpenedEvent) OccurredAt() time.Time { return e.timestamp }

type positionClosedEvent struct {
	positionID      string
	closeOrderID    string
	transactionType string
	timestamp       time.Time
}

func (e *positionClosedEvent) EventType() string    { return "PositionClosed" }
func (e *positionClosedEvent) OccurredAt() time.Time { return e.timestamp }

// --- Reconstitution from stored events ---

// LoadPositionFromEvents replays a sequence of stored events to reconstitute
// a PositionAggregate.
func LoadPositionFromEvents(events []StoredEvent) (*PositionAggregate, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("eventsourcing: no events to load position from")
	}

	agg := NewPositionAggregate(events[0].AggregateID)

	for _, stored := range events {
		domainEvent, err := deserializePositionEvent(stored)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: deserialize event %s: %w", stored.EventType, err)
		}
		agg.Apply(domainEvent)
	}

	agg.ClearPendingEvents()
	return agg, nil
}

// deserializePositionEvent converts a StoredEvent back into the concrete domain event type.
// Handles two wire formats:
//
//   1. Legacy "PositionOpened" / "PositionClosed" (PascalCase) — internal
//      *positionOpenedEvent / *positionClosedEvent types with
//      PositionOpenedPayload / PositionClosedPayload JSON shape. Used by
//      ToPositionStoredEvents + the aggregate command API in tests.
//   2. Production "position.opened" / "position.closed" (dotted) — public
//      domain.PositionOpenedEvent / domain.PositionClosedEvent types
//      serialized directly via MarshalPayload. This is what the
//      makeEventPersister in app/adapters.go writes, so production events
//      must deserialize through this path.
//
// Without path 2, production-persisted events would fail reconstitution
// with "unknown position event type: position.opened" — the hidden bug
// that the path-to-100 research flagged for Position and that silently
// affected Order and Alert reconstitution too (fixed in parallel).
func deserializePositionEvent(stored StoredEvent) (domain.Event, error) {
	switch stored.EventType {
	case "PositionOpened":
		var p PositionOpenedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		qty, _ := domain.NewQuantity(p.Quantity)
		return &positionOpenedEvent{
			positionID:      stored.AggregateID,
			email:           p.Email,
			instrument:      domain.NewInstrumentKey(p.Exchange, p.Symbol),
			transactionType: p.TransactionType,
			quantity:        qty,
			avgPrice:        domain.NewINR(p.AvgPrice),
			timestamp:       stored.OccurredAt,
		}, nil

	case "PositionClosed":
		var p PositionClosedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &positionClosedEvent{
			positionID:      stored.AggregateID,
			closeOrderID:    p.CloseOrderID,
			transactionType: p.TransactionType,
			timestamp:       stored.OccurredAt,
		}, nil

	case "position.opened":
		var e domain.PositionOpenedEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil

	case "position.closed":
		var e domain.PositionClosedEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil

	default:
		return nil, fmt.Errorf("unknown position event type: %s", stored.EventType)
	}
}

// ToPositionStoredEvents converts pending domain events from a PositionAggregate
// into StoredEvents ready for persistence.
func ToPositionStoredEvents(agg *PositionAggregate, startSequence int64) ([]StoredEvent, error) {
	var stored []StoredEvent
	for i, event := range agg.PendingEvents() {
		var payload []byte
		var err error

		switch e := event.(type) {
		case *positionOpenedEvent:
			payload, err = MarshalPayload(PositionOpenedPayload{
				Email:           e.email,
				Symbol:          e.instrument.Tradingsymbol,
				Exchange:        e.instrument.Exchange,
				TransactionType: e.transactionType,
				Quantity:        e.quantity.Int(),
				AvgPrice:        e.avgPrice.Amount,
			})
		case *positionClosedEvent:
			payload, err = MarshalPayload(PositionClosedPayload{
				CloseOrderID:    e.closeOrderID,
				TransactionType: e.transactionType,
			})
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
