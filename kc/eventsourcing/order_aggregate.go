package eventsourcing

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Order status constants model the lifecycle states.
const (
	OrderStatusNew       = "NEW"
	OrderStatusPlaced    = "PLACED"
	OrderStatusFilled    = "FILLED"
	OrderStatusCancelled = "CANCELLED"
)

// OrderAggregate models the full lifecycle of a trading order through events.
// State is never set directly — only via Apply, which processes domain events.
type OrderAggregate struct {
	BaseAggregate
	Status          string
	Email           string
	Tradingsymbol   string
	Exchange        string
	TransactionType string
	OrderType       string
	Product         string
	Quantity        int
	Price           float64
	FilledPrice     float64
	FilledQuantity  int
	PlacedAt        time.Time
	CancelledAt     time.Time
	FilledAt        time.Time
}

// NewOrderAggregate creates a new order aggregate in the NEW state.
func NewOrderAggregate(id string) *OrderAggregate {
	return &OrderAggregate{
		BaseAggregate: BaseAggregate{id: id},
		Status:        OrderStatusNew,
	}
}

// AggregateType returns "Order".
func (o *OrderAggregate) AggregateType() string { return "Order" }

// --- Command methods ---

// OrderPlacedPayload is the JSON payload for an OrderPlaced event.
type OrderPlacedPayload struct {
	Email           string  `json:"email"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	OrderType       string  `json:"order_type"`
	Product         string  `json:"product"`
	Quantity        int     `json:"quantity"`
	Price           float64 `json:"price"`
}

// OrderCancelledPayload is the JSON payload for an OrderCancelled event.
type OrderCancelledPayload struct {
	Reason string `json:"reason,omitempty"`
}

// OrderFilledPayload is the JSON payload for an OrderFilled event.
type OrderFilledPayload struct {
	FilledPrice    float64 `json:"filled_price"`
	FilledQuantity int     `json:"filled_quantity"`
}

// Place emits an OrderPlaced event after validating the order is in NEW state.
func (o *OrderAggregate) Place(params broker.OrderParams, email string) error {
	if o.Status != OrderStatusNew {
		return fmt.Errorf("eventsourcing: cannot place order in %s state", o.Status)
	}
	if params.Quantity <= 0 {
		return fmt.Errorf("eventsourcing: quantity must be positive, got %d", params.Quantity)
	}
	if params.Tradingsymbol == "" {
		return fmt.Errorf("eventsourcing: tradingsymbol is required")
	}
	if email == "" {
		return fmt.Errorf("eventsourcing: email is required")
	}

	now := time.Now().UTC()
	event := &orderPlacedEvent{
		orderID:         o.id,
		email:           email,
		exchange:        params.Exchange,
		tradingsymbol:   params.Tradingsymbol,
		transactionType: params.TransactionType,
		orderType:       params.OrderType,
		product:         params.Product,
		quantity:        params.Quantity,
		price:           params.Price,
		timestamp:       now,
	}
	o.Apply(event)
	o.raise(event)
	return nil
}

// Cancel emits an OrderCancelled event after validating the order is in PLACED state.
func (o *OrderAggregate) Cancel() error {
	if o.Status != OrderStatusPlaced {
		return fmt.Errorf("eventsourcing: cannot cancel order in %s state", o.Status)
	}

	now := time.Now().UTC()
	event := &orderCancelledEvent{
		orderID:   o.id,
		timestamp: now,
	}
	o.Apply(event)
	o.raise(event)
	return nil
}

// Fill emits an OrderFilled event after validating the order is in PLACED state.
func (o *OrderAggregate) Fill(price float64, qty int) error {
	if o.Status != OrderStatusPlaced {
		return fmt.Errorf("eventsourcing: cannot fill order in %s state", o.Status)
	}
	if qty <= 0 {
		return fmt.Errorf("eventsourcing: fill quantity must be positive, got %d", qty)
	}
	if price <= 0 {
		return fmt.Errorf("eventsourcing: fill price must be positive, got %f", price)
	}

	now := time.Now().UTC()
	event := &orderFilledEvent{
		orderID:        o.id,
		filledPrice:    price,
		filledQuantity: qty,
		timestamp:      now,
	}
	o.Apply(event)
	o.raise(event)
	return nil
}

// --- Apply (state reconstitution) ---

// Apply processes a domain event and updates aggregate state.
// This is the only method that mutates fields — called during both command
// execution and historical replay.
func (o *OrderAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case *orderPlacedEvent:
		o.Status = OrderStatusPlaced
		o.Email = e.email
		o.Exchange = e.exchange
		o.Tradingsymbol = e.tradingsymbol
		o.TransactionType = e.transactionType
		o.OrderType = e.orderType
		o.Product = e.product
		o.Quantity = e.quantity
		o.Price = e.price
		o.PlacedAt = e.timestamp
	case *orderCancelledEvent:
		o.Status = OrderStatusCancelled
		o.CancelledAt = e.timestamp
	case *orderFilledEvent:
		o.Status = OrderStatusFilled
		o.FilledPrice = e.filledPrice
		o.FilledQuantity = e.filledQuantity
		o.FilledAt = e.timestamp
	}
	o.incrementVersion()
}

// --- Internal event types ---

type orderPlacedEvent struct {
	orderID         string
	email           string
	exchange        string
	tradingsymbol   string
	transactionType string
	orderType       string
	product         string
	quantity        int
	price           float64
	timestamp       time.Time
}

func (e *orderPlacedEvent) EventType() string    { return "OrderPlaced" }
func (e *orderPlacedEvent) OccurredAt() time.Time { return e.timestamp }

type orderCancelledEvent struct {
	orderID   string
	timestamp time.Time
}

func (e *orderCancelledEvent) EventType() string    { return "OrderCancelled" }
func (e *orderCancelledEvent) OccurredAt() time.Time { return e.timestamp }

type orderFilledEvent struct {
	orderID        string
	filledPrice    float64
	filledQuantity int
	timestamp      time.Time
}

func (e *orderFilledEvent) EventType() string    { return "OrderFilled" }
func (e *orderFilledEvent) OccurredAt() time.Time { return e.timestamp }

// --- Reconstitution from stored events ---

// LoadOrderFromEvents replays a sequence of stored events to reconstitute
// an OrderAggregate. The aggregate ID is taken from the first event.
func LoadOrderFromEvents(events []StoredEvent) (*OrderAggregate, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("eventsourcing: no events to load order from")
	}

	agg := NewOrderAggregate(events[0].AggregateID)

	for _, stored := range events {
		domainEvent, err := deserializeOrderEvent(stored)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: deserialize event %s: %w", stored.EventType, err)
		}
		agg.Apply(domainEvent)
	}

	// After replay, there are no pending events — the aggregate is clean.
	agg.ClearPendingEvents()
	return agg, nil
}

// deserializeOrderEvent converts a StoredEvent back into the concrete domain event type.
func deserializeOrderEvent(stored StoredEvent) (domain.Event, error) {
	switch stored.EventType {
	case "OrderPlaced":
		var p OrderPlacedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &orderPlacedEvent{
			orderID:         stored.AggregateID,
			email:           p.Email,
			exchange:        p.Exchange,
			tradingsymbol:   p.Tradingsymbol,
			transactionType: p.TransactionType,
			orderType:       p.OrderType,
			product:         p.Product,
			quantity:        p.Quantity,
			price:           p.Price,
			timestamp:       stored.OccurredAt,
		}, nil

	case "OrderCancelled":
		return &orderCancelledEvent{
			orderID:   stored.AggregateID,
			timestamp: stored.OccurredAt,
		}, nil

	case "OrderFilled":
		var p OrderFilledPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return &orderFilledEvent{
			orderID:        stored.AggregateID,
			filledPrice:    p.FilledPrice,
			filledQuantity: p.FilledQuantity,
			timestamp:      stored.OccurredAt,
		}, nil

	default:
		return nil, fmt.Errorf("unknown order event type: %s", stored.EventType)
	}
}

// ToStoredEvents converts pending domain events from an OrderAggregate into
// StoredEvents ready for persistence. startSequence is the first sequence
// number to assign.
func ToStoredEvents(agg *OrderAggregate, startSequence int64) ([]StoredEvent, error) {
	var stored []StoredEvent
	for i, event := range agg.PendingEvents() {
		var payload []byte
		var err error

		switch e := event.(type) {
		case *orderPlacedEvent:
			payload, err = MarshalPayload(OrderPlacedPayload{
				Email:           e.email,
				Exchange:        e.exchange,
				Tradingsymbol:   e.tradingsymbol,
				TransactionType: e.transactionType,
				OrderType:       e.orderType,
				Product:         e.product,
				Quantity:        e.quantity,
				Price:           e.price,
			})
		case *orderCancelledEvent:
			payload, err = MarshalPayload(OrderCancelledPayload{})
		case *orderFilledEvent:
			payload, err = MarshalPayload(OrderFilledPayload{
				FilledPrice:    e.filledPrice,
				FilledQuantity: e.filledQuantity,
			})
		default:
			return nil, fmt.Errorf("eventsourcing: unknown event type %T", event)
		}
		if err != nil {
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
