package domain

import (
	"strings"

	"github.com/zerodha/kite-mcp-server/broker"
)

// --- Order status constants (broker-agnostic, uppercased) ---
//
// These mirror the string values that Kite's API returns in the Status field
// of an order. Keeping them as domain-level constants avoids sprinkling
// magic strings across riskguard, analytics, ops, and paper-trading code.
//
// See also: kc/eventsourcing/order_aggregate.go which uses a different
// set of internal lifecycle states (NEW/PLACED/MODIFIED/FILLED/CANCELLED)
// for the event-sourced aggregate. The constants below model the *broker*'s
// view of the order (what Kite reports), not the aggregate's internal state.

const (
	// OrderStatusOpen means the order is accepted by the exchange and sitting
	// in the book awaiting fill. Cancellable.
	OrderStatusOpen = "OPEN"
	// OrderStatusTriggerPending means a stop-loss / SL-M order's trigger
	// price has not yet been crossed. Cancellable.
	OrderStatusTriggerPending = "TRIGGER PENDING"
	// OrderStatusValidationPending is a transient state while Kite validates
	// the order. Not cancellable (will transition to OPEN or REJECTED).
	OrderStatusValidationPending = "VALIDATION PENDING"
	// OrderStatusAMOReqReceived is the overnight-order accepted state.
	// Pending but not yet open in the book.
	OrderStatusAMOReqReceived = "AMO REQ RECEIVED"
	// OrderStatusComplete is the terminal filled state.
	OrderStatusComplete = "COMPLETE"
	// OrderStatusCancelled is the terminal user/system-cancelled state.
	OrderStatusCancelled = "CANCELLED"
	// OrderStatusRejected is the terminal risk-rejected state.
	OrderStatusRejected = "REJECTED"
)

// Order is the rich domain entity for a broker order. It wraps a broker.Order
// DTO (no duplicate field storage) and exposes lifecycle methods that
// encapsulate the business rules of an order's state transitions.
//
// Consumers previously duplicated these checks inline (e.g.
// `if o.Status == "OPEN" || o.Status == "TRIGGER PENDING"`). The Order
// entity centralises them so that a change in status semantics (e.g. Kite
// adding a new intermediate state) requires a single edit here.
//
// The wrapped DTO stays the source of truth — see DTO() for passthrough to
// existing broker / persistence code.
type Order struct {
	dto broker.Order
}

// NewOrderFromBroker lifts a broker.Order DTO into the rich domain entity.
func NewOrderFromBroker(b broker.Order) Order {
	return Order{dto: b}
}

// ToDomainOrder is a converter alias — identical to NewOrderFromBroker,
// named for ergonomic use at adapter boundaries.
// Example: `d := domain.ToDomainOrder(brokerOrder)`.
func ToDomainOrder(b broker.Order) Order {
	return NewOrderFromBroker(b)
}

// DTO returns the underlying broker DTO for passthrough to code that still
// consumes broker.Order directly (persistence, broker adapters).
func (o Order) DTO() broker.Order {
	return o.dto
}

// ID returns the broker-assigned order identifier.
func (o Order) ID() string {
	return o.dto.OrderID
}

// Status returns the broker's current status string (as Kite reports it).
// Prefer IsTerminal / IsPending / CanCancel for state queries.
func (o Order) Status() string {
	return o.dto.Status
}

// normalizedStatus returns the uppercased, trimmed status for case-insensitive
// comparison. Kite typically returns uppercase but defensive callers have
// sometimes seen mixed case on edge transports.
func (o Order) normalizedStatus() string {
	return strings.ToUpper(strings.TrimSpace(o.dto.Status))
}

// CanCancel reports whether the order is in a cancellable state.
// An order is cancellable only while it is resting in the book awaiting
// fill (OPEN) or awaiting its stop-loss trigger (TRIGGER PENDING).
func (o Order) CanCancel() bool {
	s := o.normalizedStatus()
	return s == OrderStatusOpen || s == OrderStatusTriggerPending
}

// IsTerminal reports whether the order has reached a terminal state and will
// not transition further. Terminal states are COMPLETE / CANCELLED / REJECTED.
func (o Order) IsTerminal() bool {
	s := o.normalizedStatus()
	return s == OrderStatusComplete || s == OrderStatusCancelled || s == OrderStatusRejected
}

// IsPending reports whether the order is in any non-terminal, in-flight state.
// This is the complement of IsTerminal excluding the zero-value/empty status,
// which is treated as neither pending nor terminal (unknown).
func (o Order) IsPending() bool {
	s := o.normalizedStatus()
	return s == OrderStatusOpen ||
		s == OrderStatusTriggerPending ||
		s == OrderStatusValidationPending ||
		s == OrderStatusAMOReqReceived
}

// IsComplete reports whether the order reached the COMPLETE state.
// Case-insensitive — matches the broker's reported status regardless of
// casing variations observed on edge transports.
func (o Order) IsComplete() bool {
	return o.normalizedStatus() == OrderStatusComplete
}

// IsRejected reports whether the order reached the REJECTED state.
// Case-insensitive.
func (o Order) IsRejected() bool {
	return o.normalizedStatus() == OrderStatusRejected
}

// IsCancelled reports whether the order reached the CANCELLED state.
// Case-insensitive.
func (o Order) IsCancelled() bool {
	return o.normalizedStatus() == OrderStatusCancelled
}

// FillPercentage returns the percentage of the order quantity that has been
// filled, in the range [0, 100]. Returns 0 when Quantity is zero (avoids a
// divide-by-zero) and clamps to 100 when FilledQuantity > Quantity (which
// should not happen but has been observed on partial-then-modified orders).
func (o Order) FillPercentage() float64 {
	if o.dto.Quantity <= 0 {
		return 0
	}
	pct := float64(o.dto.FilledQuantity) / float64(o.dto.Quantity) * 100
	if pct > 100 {
		return 100
	}
	if pct < 0 {
		return 0
	}
	return pct
}
