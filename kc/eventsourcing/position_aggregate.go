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
type PositionAggregate struct {
	BaseAggregate
	Email           string
	Symbol          string
	Exchange        string
	TransactionType string // original direction: BUY or SELL
	Quantity        int
	AvgPrice        float64
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
	if qty <= 0 {
		return fmt.Errorf("eventsourcing: quantity must be positive, got %d", qty)
	}

	now := time.Now().UTC()
	event := &positionOpenedEvent{
		positionID:      p.id,
		email:           email,
		symbol:          symbol,
		exchange:        exchange,
		transactionType: txnType,
		quantity:        qty,
		avgPrice:        avgPrice,
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
func (p *PositionAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case *positionOpenedEvent:
		p.Email = e.email
		p.Symbol = e.symbol
		p.Exchange = e.exchange
		p.TransactionType = e.transactionType
		p.Quantity = e.quantity
		p.AvgPrice = e.avgPrice
		p.Status = PositionStatusOpen
		p.OpenedAt = e.timestamp
	case *positionClosedEvent:
		p.Status = PositionStatusClosed
		p.Quantity = 0
		p.ClosedAt = e.timestamp
	}
	p.incrementVersion()
}

// --- Internal event types ---

type positionOpenedEvent struct {
	positionID      string
	email           string
	symbol          string
	exchange        string
	transactionType string
	quantity        int
	avgPrice        float64
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
func deserializePositionEvent(stored StoredEvent) (domain.Event, error) {
	switch stored.EventType {
	case "PositionOpened":
		var p PositionOpenedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &positionOpenedEvent{
			positionID:      stored.AggregateID,
			email:           p.Email,
			symbol:          p.Symbol,
			exchange:        p.Exchange,
			transactionType: p.TransactionType,
			quantity:        p.Quantity,
			avgPrice:        p.AvgPrice,
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
				Symbol:          e.symbol,
				Exchange:        e.exchange,
				TransactionType: e.transactionType,
				Quantity:        e.quantity,
				AvgPrice:        e.avgPrice,
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
