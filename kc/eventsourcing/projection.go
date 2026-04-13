package eventsourcing

import (
	"sort"
	"sync"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Projector is a read-side projection that maintains live OrderAggregate,
// AlertAggregate, and PositionAggregate snapshots by subscribing to the
// domain.EventDispatcher. Each incoming public domain event is replayed into
// the matching aggregate via Apply.
//
// This is how the three aggregates are kept wired into production: a use case
// dispatches (e.g.) domain.OrderPlacedEvent on the shared dispatcher, the
// projector Subscribe handler looks up (or constructs) the aggregate for the
// event's aggregate ID, and calls aggregate.Apply(event) to update state.
//
// The projection is in-process, synchronous, and cleared on restart. It is a
// read-side only: it does not persist events (that is done by the audit log
// subscribers in app/wire.go) and does not replay from history.
type Projector struct {
	mu        sync.RWMutex
	orders    map[string]*OrderAggregate    // key: OrderID
	alerts    map[string]*AlertAggregate    // key: AlertID
	positions map[string]*PositionAggregate // key: PositionID or synthetic key from OrderID+Instrument
}

// NewProjector constructs an empty Projector with initialized maps.
func NewProjector() *Projector {
	return &Projector{
		orders:    make(map[string]*OrderAggregate),
		alerts:    make(map[string]*AlertAggregate),
		positions: make(map[string]*PositionAggregate),
	}
}

// Subscribe registers handlers on the dispatcher for every order/alert/
// position event type. Safe to call once per projector.
func (p *Projector) Subscribe(d *domain.EventDispatcher) {
	if d == nil {
		return
	}
	d.Subscribe("order.placed", p.handleOrderEvent)
	d.Subscribe("order.modified", p.handleOrderEvent)
	d.Subscribe("order.cancelled", p.handleOrderEvent)
	d.Subscribe("order.filled", p.handleOrderEvent)

	d.Subscribe("alert.created", p.handleAlertEvent)
	d.Subscribe("alert.triggered", p.handleAlertEvent)
	d.Subscribe("alert.deleted", p.handleAlertEvent)

	d.Subscribe("position.opened", p.handlePositionEvent)
	d.Subscribe("position.closed", p.handlePositionEvent)
}

func (p *Projector) handleOrderEvent(event domain.Event) {
	var id string
	switch e := event.(type) {
	case domain.OrderPlacedEvent:
		id = e.OrderID
	case domain.OrderModifiedEvent:
		id = e.OrderID
	case domain.OrderCancelledEvent:
		id = e.OrderID
	case domain.OrderFilledEvent:
		id = e.OrderID
	default:
		return
	}
	if id == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	agg, ok := p.orders[id]
	if !ok {
		agg = NewOrderAggregate(id)
		p.orders[id] = agg
	}
	agg.Apply(event)
}

func (p *Projector) handleAlertEvent(event domain.Event) {
	var id string
	switch e := event.(type) {
	case domain.AlertCreatedEvent:
		id = e.AlertID
	case domain.AlertTriggeredEvent:
		id = e.AlertID
	case domain.AlertDeletedEvent:
		id = e.AlertID
	default:
		return
	}
	if id == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	agg, ok := p.alerts[id]
	if !ok {
		agg = NewAlertAggregate(id)
		p.alerts[id] = agg
	}
	agg.Apply(event)
}

func (p *Projector) handlePositionEvent(event domain.Event) {
	// Both PositionOpenedEvent and PositionClosedEvent use the natural
	// aggregate key — (email, exchange, symbol, product) — so open and
	// close events for the same position land under one aggregate in the
	// projector, matching how the event store persists them. See
	// domain.PositionAggregateID in kc/domain/events.go.
	var id string
	switch e := event.(type) {
	case domain.PositionOpenedEvent:
		id = domain.PositionAggregateID(e.Email, e.Instrument, e.Product)
	case domain.PositionClosedEvent:
		id = domain.PositionAggregateID(e.Email, e.Instrument, e.Product)
	default:
		return
	}
	if id == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	agg, ok := p.positions[id]
	if !ok {
		agg = NewPositionAggregate(id)
		p.positions[id] = agg
	}
	agg.Apply(event)
}

// --- Read API ---

// GetOrder returns a snapshot of the projected order aggregate with the given
// order ID. The bool result is false if the projector has never seen an event
// for that order.
func (p *Projector) GetOrder(id string) (*OrderAggregate, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	agg, ok := p.orders[id]
	return agg, ok
}

// GetAlert returns a snapshot of the projected alert aggregate with the given
// alert ID.
func (p *Projector) GetAlert(id string) (*AlertAggregate, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	agg, ok := p.alerts[id]
	return agg, ok
}

// GetPosition returns a snapshot of the projected position aggregate with the
// given ID (PositionID for opens, OrderID for closes).
func (p *Projector) GetPosition(id string) (*PositionAggregate, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	agg, ok := p.positions[id]
	return agg, ok
}

// ListActiveOrders returns all projected orders currently in PLACED or
// MODIFIED state, sorted by placed-at (oldest first).
func (p *Projector) ListActiveOrders() []*OrderAggregate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*OrderAggregate, 0, len(p.orders))
	for _, o := range p.orders {
		if o.Status == OrderStatusPlaced || o.Status == OrderStatusModified {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlacedAt.Before(out[j].PlacedAt) })
	return out
}

// ListOrdersForEmail returns all projected orders belonging to the given
// email regardless of status (PLACED, MODIFIED, FILLED, CANCELLED), sorted
// by placed-at (oldest first). Intended for the optimistic-fallback path
// in GetOrdersQuery when Kite is rate-limited or unavailable — callers
// get the full current-day lifecycle, not just active ones.
func (p *Projector) ListOrdersForEmail(email string) []*OrderAggregate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*OrderAggregate, 0, len(p.orders))
	for _, o := range p.orders {
		if o.Email == email {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlacedAt.Before(out[j].PlacedAt) })
	return out
}

// ListActiveAlerts returns all projected alerts currently in ACTIVE state,
// sorted by created-at (oldest first).
func (p *Projector) ListActiveAlerts() []*AlertAggregate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*AlertAggregate, 0, len(p.alerts))
	for _, a := range p.alerts {
		if a.Status == AlertStatusActive {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// OrderCount returns the total number of projected orders.
func (p *Projector) OrderCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.orders)
}

// AlertCount returns the total number of projected alerts.
func (p *Projector) AlertCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.alerts)
}

// PositionCount returns the total number of projected positions.
func (p *Projector) PositionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.positions)
}
