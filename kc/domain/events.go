package domain

import (
	"sync"
	"time"
)

// Event is the interface all domain events must satisfy.
type Event interface {
	// EventType returns a unique string identifier for the event kind.
	EventType() string
	// OccurredAt returns the timestamp when the event was created.
	OccurredAt() time.Time
}

// --- Concrete domain events ---

// OrderPlacedEvent is emitted after an order is successfully placed.
type OrderPlacedEvent struct {
	Email           string
	OrderID         string
	Instrument      InstrumentKey
	Qty             Quantity
	Price           Money
	TransactionType string // "BUY" or "SELL"
	Timestamp       time.Time
}

func (e OrderPlacedEvent) EventType() string    { return "order.placed" }
func (e OrderPlacedEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderModifiedEvent is emitted after an order is successfully modified.
type OrderModifiedEvent struct {
	Email     string
	OrderID   string
	Timestamp time.Time
}

func (e OrderModifiedEvent) EventType() string    { return "order.modified" }
func (e OrderModifiedEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderCancelledEvent is emitted after an order is successfully cancelled.
type OrderCancelledEvent struct {
	Email     string
	OrderID   string
	Timestamp time.Time
}

func (e OrderCancelledEvent) EventType() string    { return "order.cancelled" }
func (e OrderCancelledEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionClosedEvent is emitted after a position is closed via close_position.
type PositionClosedEvent struct {
	Email           string
	OrderID         string
	Instrument      InstrumentKey
	Qty             Quantity
	TransactionType string // opposite direction used to close
	Timestamp       time.Time
}

func (e PositionClosedEvent) EventType() string    { return "position.closed" }
func (e PositionClosedEvent) OccurredAt() time.Time { return e.Timestamp }

// AlertTriggeredEvent is emitted when a price alert fires.
type AlertTriggeredEvent struct {
	Email        string
	AlertID      string
	Instrument   InstrumentKey
	TargetPrice  Money
	CurrentPrice Money
	Direction    string // "above", "below", "drop_pct", "rise_pct"
	Timestamp    time.Time
}

func (e AlertTriggeredEvent) EventType() string    { return "alert.triggered" }
func (e AlertTriggeredEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskLimitBreachedEvent is emitted when riskguard blocks an order.
type RiskLimitBreachedEvent struct {
	Email    string
	Reason   string // matches riskguard.RejectionReason values
	Message  string
	ToolName string
	Timestamp time.Time
}

func (e RiskLimitBreachedEvent) EventType() string    { return "risk.limit_breached" }
func (e RiskLimitBreachedEvent) OccurredAt() time.Time { return e.Timestamp }

// SessionCreatedEvent is emitted when a new MCP session is established.
type SessionCreatedEvent struct {
	Email     string
	SessionID string
	Broker    string // "zerodha", "angelone", etc.
	Timestamp time.Time
}

func (e SessionCreatedEvent) EventType() string    { return "session.created" }
func (e SessionCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

// UserFrozenEvent is emitted when a user's trading is frozen (manual or auto).
type UserFrozenEvent struct {
	Email    string
	FrozenBy string // "admin", "riskguard:circuit-breaker"
	Reason   string
	Timestamp time.Time
}

func (e UserFrozenEvent) EventType() string    { return "user.frozen" }
func (e UserFrozenEvent) OccurredAt() time.Time { return e.Timestamp }

// UserSuspendedEvent is emitted when an admin suspends a user account.
type UserSuspendedEvent struct {
	Email    string
	By       string // admin email
	Reason   string
	Timestamp time.Time
}

func (e UserSuspendedEvent) EventType() string    { return "user.suspended" }
func (e UserSuspendedEvent) OccurredAt() time.Time { return e.Timestamp }

// GlobalFreezeEvent is emitted when an admin activates the server-wide trading freeze.
type GlobalFreezeEvent struct {
	By     string // admin email
	Reason string
	Timestamp time.Time
}

func (e GlobalFreezeEvent) EventType() string    { return "global.freeze" }
func (e GlobalFreezeEvent) OccurredAt() time.Time { return e.Timestamp }

// FamilyInvitedEvent is emitted when an admin invites a family member.
type FamilyInvitedEvent struct {
	AdminEmail   string
	InvitedEmail string
	Timestamp    time.Time
}

func (e FamilyInvitedEvent) EventType() string    { return "family.invited" }
func (e FamilyInvitedEvent) OccurredAt() time.Time { return e.Timestamp }

// --- Event dispatcher ---

// EventDispatcher is a simple in-process pub/sub for domain events.
// Handlers are called synchronously in the order they were registered.
// Use goroutines inside handlers if async processing is needed.
type EventDispatcher struct {
	mu       sync.RWMutex
	handlers map[string][]func(Event)
}

// NewEventDispatcher creates a ready-to-use dispatcher.
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		handlers: make(map[string][]func(Event)),
	}
}

// Subscribe registers a handler for the given event type.
// The handler will be called every time an event of that type is dispatched.
func (d *EventDispatcher) Subscribe(eventType string, handler func(Event)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[eventType] = append(d.handlers[eventType], handler)
}

// Dispatch sends an event to all registered handlers for its type.
// Handlers are called synchronously under a read lock, so Subscribe
// calls from within a handler will deadlock — use a goroutine if needed.
func (d *EventDispatcher) Dispatch(event Event) {
	d.mu.RLock()
	handlers := d.handlers[event.EventType()]
	d.mu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}
