package eventsourcing

import (
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// AggregateRoot is the interface that all event-sourced aggregates must satisfy.
// An aggregate reconstitutes its state by replaying events, and emits new events
// when commands mutate it.
//
// ARCHITECTURE NOTE: Aggregates are currently used as test infrastructure only.
// In production, order/position/alert state comes from broker APIs and CRUD stores,
// not from event replay. The aggregates model domain invariants and lifecycle
// transitions, which is valuable for testing correctness of event schemas and
// state machine logic. They may be wired into production use cases in the future
// if temporal queries or multi-broker replay become requirements.
type AggregateRoot interface {
	// AggregateID returns the unique identifier for this aggregate instance.
	AggregateID() string
	// AggregateType returns the type name (e.g., "Order", "Alert").
	AggregateType() string
	// Version returns the number of events applied to this aggregate.
	Version() int
	// Apply replays a single domain event to reconstitute state.
	Apply(event domain.Event)
	// PendingEvents returns the uncommitted events emitted by command methods.
	PendingEvents() []domain.Event
	// ClearPendingEvents removes all uncommitted events (called after persistence).
	ClearPendingEvents()
}

// BaseAggregate provides the common bookkeeping for all aggregates:
// ID tracking, version counter, and pending event accumulation.
type BaseAggregate struct {
	id      string
	version int
	pending []domain.Event
}

// AggregateID returns the aggregate's unique identifier.
func (b *BaseAggregate) AggregateID() string { return b.id }

// Version returns the number of events that have been applied.
func (b *BaseAggregate) Version() int { return b.version }

// PendingEvents returns all uncommitted events.
func (b *BaseAggregate) PendingEvents() []domain.Event { return b.pending }

// ClearPendingEvents removes all uncommitted events after they have been persisted.
func (b *BaseAggregate) ClearPendingEvents() { b.pending = nil }

// raise records a new event as pending. Does not increment version —
// that happens in Apply, which the aggregate's command methods must call.
func (b *BaseAggregate) raise(event domain.Event) {
	b.pending = append(b.pending, event)
}

// incrementVersion is called by Apply to track how many events have been
// processed (both during command execution and historical replay).
func (b *BaseAggregate) incrementVersion() {
	b.version++
}
