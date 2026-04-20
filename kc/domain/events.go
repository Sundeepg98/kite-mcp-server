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

// OrderFilledEvent is emitted after an order is filled by the exchange.
type OrderFilledEvent struct {
	Email      string
	OrderID    string
	FilledQty  Quantity
	FilledPrice Money
	Timestamp  time.Time
}

func (e OrderFilledEvent) EventType() string    { return "order.filled" }
func (e OrderFilledEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionOpenedEvent is emitted when a new position is opened.
//
// Aggregate-ID rule: positions do not have a broker-assigned unique ID —
// Kite's Position struct doesn't expose an "opening order" field — so we
// can't reliably join open and close events by ID. Instead, we key
// position events by the natural tuple (email, exchange, symbol, product)
// via PositionAggregateID() below. A single user-instrument-product
// aggregate may contain multiple open→close lifecycles across time;
// walking the event stream makes lifecycle boundaries visible.
//
// Product is required for the aggregate ID. PositionID is kept for
// tracing — it equals the opening order ID from place_order — but is
// no longer the aggregate key.
type PositionOpenedEvent struct {
	Email           string
	PositionID      string // opening order ID (historical trace only)
	Instrument      InstrumentKey
	Product         string // MIS, CNC, NRML — part of aggregate key
	Qty             Quantity
	AvgPrice        Money
	TransactionType string // "BUY" or "SELL"
	Timestamp       time.Time
}

func (e PositionOpenedEvent) EventType() string    { return "position.opened" }
func (e PositionOpenedEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionClosedEvent is emitted after a position is closed via close_position.
// OrderID is the closing order (fresh from Kite), not the opening one —
// use PositionAggregateID() to join with the corresponding open event.
type PositionClosedEvent struct {
	Email           string
	OrderID         string // the closing order's ID
	Instrument      InstrumentKey
	Product         string // MIS, CNC, NRML — part of aggregate key
	Qty             Quantity
	TransactionType string // opposite direction used to close
	Timestamp       time.Time
}

func (e PositionClosedEvent) EventType() string    { return "position.closed" }
func (e PositionClosedEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionAggregateID returns the natural aggregate key for position events.
// Format: "email:exchange:tradingsymbol:product". Both PositionOpenedEvent
// and PositionClosedEvent for the same (user, instrument, product) triple
// land under the same aggregate ID, allowing event-store replay to
// reconstruct the full position history.
func PositionAggregateID(email string, instrument InstrumentKey, product string) string {
	return email + ":" + instrument.Exchange + ":" + instrument.Tradingsymbol + ":" + product
}

// AlertCreatedEvent is emitted when a new price alert is created.
type AlertCreatedEvent struct {
	Email       string
	AlertID     string
	Instrument  InstrumentKey
	TargetPrice Money
	Direction   string // "above", "below", "drop_pct", "rise_pct"
	Timestamp   time.Time
}

func (e AlertCreatedEvent) EventType() string    { return "alert.created" }
func (e AlertCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

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

// AlertDeletedEvent is emitted when a price alert is deleted.
type AlertDeletedEvent struct {
	Email   string
	AlertID string
	Timestamp time.Time
}

func (e AlertDeletedEvent) EventType() string    { return "alert.deleted" }
func (e AlertDeletedEvent) OccurredAt() time.Time { return e.Timestamp }

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

// SessionClearedEvent is emitted when the Kite session data attached to an
// MCP session is cleared (without terminating the session itself). Phase C
// ES: append-only audit record of the clear, keyed by session ID.
type SessionClearedEvent struct {
	SessionID string
	Reason    string // "post_credential_register" / "profile_check_failed" / "admin_action"
	Timestamp time.Time
}

func (e SessionClearedEvent) EventType() string    { return "session.cleared" }
func (e SessionClearedEvent) OccurredAt() time.Time { return e.Timestamp }

// SessionInvalidatedEvent is emitted when an MCP session is ended (the
// SessionRegistry entry is evicted, cleanup hooks run). Distinct from
// SessionClearedEvent which keeps the session alive without broker data.
type SessionInvalidatedEvent struct {
	SessionID string
	Reason    string // "expired" / "admin_action" / "logout"
	Timestamp time.Time
}

func (e SessionInvalidatedEvent) EventType() string    { return "session.invalidated" }
func (e SessionInvalidatedEvent) OccurredAt() time.Time { return e.Timestamp }

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

// FamilyMemberRemovedEvent is emitted when an admin unlinks a family member
// from their billing plan.
type FamilyMemberRemovedEvent struct {
	AdminEmail   string
	RemovedEmail string
	Timestamp    time.Time
}

func (e FamilyMemberRemovedEvent) EventType() string    { return "family.member_removed" }
func (e FamilyMemberRemovedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistCreatedEvent is emitted when a new watchlist is created.
type WatchlistCreatedEvent struct {
	Email       string
	WatchlistID string
	Name        string
	Timestamp   time.Time
}

func (e WatchlistCreatedEvent) EventType() string    { return "watchlist.created" }
func (e WatchlistCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistDeletedEvent is emitted when a watchlist is deleted.
type WatchlistDeletedEvent struct {
	Email       string
	WatchlistID string
	Name        string // captured before deletion for audit trail
	ItemCount   int    // captured before deletion so auditors see the scope
	Timestamp   time.Time
}

func (e WatchlistDeletedEvent) EventType() string    { return "watchlist.deleted" }
func (e WatchlistDeletedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistItemAddedEvent is emitted when an instrument is added to a watchlist.
type WatchlistItemAddedEvent struct {
	Email       string
	WatchlistID string
	Instrument  InstrumentKey
	Timestamp   time.Time
}

func (e WatchlistItemAddedEvent) EventType() string    { return "watchlist.item_added" }
func (e WatchlistItemAddedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistItemRemovedEvent is emitted when an instrument is removed from a watchlist.
type WatchlistItemRemovedEvent struct {
	Email       string
	WatchlistID string
	ItemID      string
	Timestamp   time.Time
}

func (e WatchlistItemRemovedEvent) EventType() string    { return "watchlist.item_removed" }
func (e WatchlistItemRemovedEvent) OccurredAt() time.Time { return e.Timestamp }

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
