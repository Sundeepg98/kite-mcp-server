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
	OrderStatusModified  = "MODIFIED"
	OrderStatusFilled    = "FILLED"
	OrderStatusCancelled = "CANCELLED"
)

// OrderAggregate models the full lifecycle of a trading order through events.
// State is never set directly — only via Apply, which processes domain events.
//
// NOTE: Not instantiated in production. PlaceOrderUseCase calls broker.Client
// directly and dispatches domain events to the audit log. This aggregate exists
// for testing event replay correctness and modeling order state machine invariants.
type OrderAggregate struct {
	BaseAggregate
	Status          string
	Email           string
	Instrument      domain.InstrumentKey
	TransactionType string
	OrderType       string
	Product         string
	Quantity        domain.Quantity
	Price           domain.Money
	FilledPrice     domain.Money
	FilledQuantity  domain.Quantity
	ModifyCount     int
	PlacedAt        time.Time
	ModifiedAt      time.Time
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

// OrderModifiedPayload is the JSON payload for an OrderModified event.
type OrderModifiedPayload struct {
	NewQuantity int     `json:"new_quantity,omitempty"`
	NewPrice    float64 `json:"new_price,omitempty"`
	NewOrderType string `json:"new_order_type,omitempty"`
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
	qty, err := domain.NewQuantity(params.Quantity)
	if err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
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
		instrument:      domain.NewInstrumentKey(params.Exchange, params.Tradingsymbol),
		transactionType: params.TransactionType,
		orderType:       params.OrderType,
		product:         params.Product,
		quantity:        qty,
		price:           domain.NewINR(params.Price),
		timestamp:       now,
	}
	o.Apply(event)
	o.raise(event)
	return nil
}

// Modify emits an OrderModified event after validating the order can be modified.
// At least one of newQty or newPrice must differ from current values.
func (o *OrderAggregate) Modify(newQty int, newPrice float64, newOrderType string) error {
	if err := o.CanModify(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}
	qty, err := domain.NewQuantity(newQty)
	if err != nil {
		return fmt.Errorf("eventsourcing: modify: %w", err)
	}
	price := domain.NewINR(newPrice)
	if newQty == o.Quantity.Int() && newPrice == o.Price.Amount && (newOrderType == "" || newOrderType == o.OrderType) {
		return fmt.Errorf("eventsourcing: modify must change at least one field")
	}

	now := time.Now().UTC()
	effectiveOrderType := newOrderType
	if effectiveOrderType == "" {
		effectiveOrderType = o.OrderType
	}
	event := &orderModifiedEvent{
		orderID:      o.id,
		newQuantity:  qty,
		newPrice:     price,
		newOrderType: effectiveOrderType,
		timestamp:    now,
	}
	o.Apply(event)
	o.raise(event)
	return nil
}

// --- Invariant query methods ---

// CanModify returns an error if the order cannot be modified in its current state.
func (o *OrderAggregate) CanModify() error {
	switch o.Status {
	case OrderStatusNew:
		return fmt.Errorf("cannot modify order in NEW state (not yet placed)")
	case OrderStatusCancelled:
		return fmt.Errorf("cannot modify cancelled order")
	case OrderStatusFilled:
		return fmt.Errorf("cannot modify filled order")
	}
	return nil
}

// CanCancel returns an error if the order cannot be cancelled in its current state.
func (o *OrderAggregate) CanCancel() error {
	switch o.Status {
	case OrderStatusNew:
		return fmt.Errorf("cannot cancel order in NEW state")
	case OrderStatusCancelled:
		return fmt.Errorf("order already cancelled")
	case OrderStatusFilled:
		return fmt.Errorf("cannot cancel filled order")
	}
	return nil
}

// CanFill returns an error if the order cannot be filled in its current state.
func (o *OrderAggregate) CanFill() error {
	switch o.Status {
	case OrderStatusNew:
		return fmt.Errorf("cannot fill order in NEW state")
	case OrderStatusCancelled:
		return fmt.Errorf("cannot fill cancelled order")
	case OrderStatusFilled:
		return fmt.Errorf("order already filled")
	}
	return nil
}

// Cancel emits an OrderCancelled event after validating the order is in PLACED or MODIFIED state.
func (o *OrderAggregate) Cancel() error {
	if err := o.CanCancel(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
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

// Fill emits an OrderFilled event after validating the order is in PLACED or MODIFIED state.
func (o *OrderAggregate) Fill(price float64, qty int) error {
	if err := o.CanFill(); err != nil {
		return fmt.Errorf("eventsourcing: %w", err)
	}
	filledQty, err := domain.NewQuantity(qty)
	if err != nil {
		return fmt.Errorf("eventsourcing: fill: %w", err)
	}
	if price <= 0 {
		return fmt.Errorf("eventsourcing: fill price must be positive, got %f", price)
	}

	now := time.Now().UTC()
	event := &orderFilledEvent{
		orderID:        o.id,
		filledPrice:    domain.NewINR(price),
		filledQuantity: filledQty,
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
//
// Both internal event types (emitted by Place/Modify/Cancel/Fill command
// methods) and the public domain.*Event types dispatched on the
// domain.EventDispatcher by production use cases are handled. This lets the
// projection pipeline feed live order events from the bus into the aggregate
// without constructing internal events.
func (o *OrderAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case *orderPlacedEvent:
		o.Status = OrderStatusPlaced
		o.Email = e.email
		o.Instrument = e.instrument
		o.TransactionType = e.transactionType
		o.OrderType = e.orderType
		o.Product = e.product
		o.Quantity = e.quantity
		o.Price = e.price
		o.PlacedAt = e.timestamp
	case *orderModifiedEvent:
		o.Status = OrderStatusModified
		o.Quantity = e.newQuantity
		o.Price = e.newPrice
		o.OrderType = e.newOrderType
		o.ModifyCount++
		o.ModifiedAt = e.timestamp
	case *orderCancelledEvent:
		o.Status = OrderStatusCancelled
		o.CancelledAt = e.timestamp
	case *orderFilledEvent:
		o.Status = OrderStatusFilled
		o.FilledPrice = e.filledPrice
		o.FilledQuantity = e.filledQuantity
		o.FilledAt = e.timestamp
	case domain.OrderPlacedEvent:
		o.Status = OrderStatusPlaced
		o.Email = e.Email
		o.Instrument = e.Instrument
		o.TransactionType = e.TransactionType
		o.Quantity = e.Qty
		o.Price = e.Price
		o.PlacedAt = e.Timestamp
	case domain.OrderModifiedEvent:
		o.Status = OrderStatusModified
		o.ModifyCount++
		o.ModifiedAt = e.Timestamp
	case domain.OrderCancelledEvent:
		o.Status = OrderStatusCancelled
		o.CancelledAt = e.Timestamp
	case domain.OrderFilledEvent:
		o.Status = OrderStatusFilled
		o.FilledPrice = e.FilledPrice
		o.FilledQuantity = e.FilledQty
		o.FilledAt = e.Timestamp
	}
	o.incrementVersion()
}

// --- Internal event types ---

type orderPlacedEvent struct {
	orderID         string
	email           string
	instrument      domain.InstrumentKey
	transactionType string
	orderType       string
	product         string
	quantity        domain.Quantity
	price           domain.Money
	timestamp       time.Time
}

func (e *orderPlacedEvent) EventType() string    { return "OrderPlaced" }
func (e *orderPlacedEvent) OccurredAt() time.Time { return e.timestamp }

type orderModifiedEvent struct {
	orderID      string
	newQuantity  domain.Quantity
	newPrice     domain.Money
	newOrderType string
	timestamp    time.Time
}

func (e *orderModifiedEvent) EventType() string    { return "OrderModified" }
func (e *orderModifiedEvent) OccurredAt() time.Time { return e.timestamp }

type orderCancelledEvent struct {
	orderID   string
	timestamp time.Time
}

func (e *orderCancelledEvent) EventType() string    { return "OrderCancelled" }
func (e *orderCancelledEvent) OccurredAt() time.Time { return e.timestamp }

type orderFilledEvent struct {
	orderID        string
	filledPrice    domain.Money
	filledQuantity domain.Quantity
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
		qty, _ := domain.NewQuantity(p.Quantity)
		return &orderPlacedEvent{
			orderID:         stored.AggregateID,
			email:           p.Email,
			instrument:      domain.NewInstrumentKey(p.Exchange, p.Tradingsymbol),
			transactionType: p.TransactionType,
			orderType:       p.OrderType,
			product:         p.Product,
			quantity:        qty,
			price:           domain.NewINR(p.Price),
			timestamp:       stored.OccurredAt,
		}, nil

	case "OrderModified":
		var p OrderModifiedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		qty, _ := domain.NewQuantity(p.NewQuantity)
		return &orderModifiedEvent{
			orderID:      stored.AggregateID,
			newQuantity:  qty,
			newPrice:     domain.NewINR(p.NewPrice),
			newOrderType: p.NewOrderType,
			timestamp:    stored.OccurredAt,
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
		filledQty, _ := domain.NewQuantity(p.FilledQuantity)
		return &orderFilledEvent{
			orderID:        stored.AggregateID,
			filledPrice:    domain.NewINR(p.FilledPrice),
			filledQuantity: filledQty,
			timestamp:      stored.OccurredAt,
		}, nil

	// Public domain event formats persisted directly by app/adapters.go
	// makeEventPersister. See kc/eventsourcing/position_aggregate.go
	// deserializePositionEvent for the detailed rationale — same dual-
	// format requirement applies to Orders.
	case "order.placed":
		var e domain.OrderPlacedEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil
	case "order.modified":
		var e domain.OrderModifiedEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil
	case "order.cancelled":
		var e domain.OrderCancelledEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil
	case "order.filled":
		var e domain.OrderFilledEvent
		if err := json.Unmarshal(stored.Payload, &e); err != nil {
			return nil, err
		}
		return e, nil

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
				Exchange:        e.instrument.Exchange,
				Tradingsymbol:   e.instrument.Tradingsymbol,
				TransactionType: e.transactionType,
				OrderType:       e.orderType,
				Product:         e.product,
				Quantity:        e.quantity.Int(),
				Price:           e.price.Amount,
			})
		case *orderModifiedEvent:
			payload, err = MarshalPayload(OrderModifiedPayload{
				NewQuantity:  e.newQuantity.Int(),
				NewPrice:     e.newPrice.Amount,
				NewOrderType: e.newOrderType,
			})
		case *orderCancelledEvent:
			payload, err = MarshalPayload(OrderCancelledPayload{})
		case *orderFilledEvent:
			payload, err = MarshalPayload(OrderFilledPayload{
				FilledPrice:    e.filledPrice.Amount,
				FilledQuantity: e.filledQuantity.Int(),
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
