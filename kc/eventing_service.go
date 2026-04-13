package kc

import (
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// EventingService groups the domain event dispatcher and append-only event
// store. Both are optional infrastructure: Manager holds the concrete values
// and this service mediates access so use-case code can depend on a narrow
// surface rather than the whole Manager.
type EventingService struct {
	m *Manager
}

func newEventingService(m *Manager) *EventingService {
	return &EventingService{m: m}
}

// Dispatcher returns the domain event dispatcher, or nil if not configured.
func (e *EventingService) Dispatcher() *domain.EventDispatcher { return e.m.eventDispatcher }

// SetDispatcher sets the domain event dispatcher and subscribes the read-side
// projector so order/alert/position events flow into the live aggregate maps.
// Also wires the dispatcher into the session service so new MCP sessions
// emit SessionCreatedEvent.
func (e *EventingService) SetDispatcher(d *domain.EventDispatcher) {
	e.m.eventDispatcher = d
	if d != nil && e.m.projector != nil {
		e.m.projector.Subscribe(d)
	}
	if e.m.sessionSvc != nil {
		e.m.sessionSvc.SetEventDispatcher(d)
	}
}

// Store returns the domain audit log (append-only event store), or nil.
func (e *EventingService) Store() *eventsourcing.EventStore { return e.m.eventStore }

// SetStore sets the domain audit log.
func (e *EventingService) SetStore(s *eventsourcing.EventStore) { e.m.eventStore = s }

// ---------------------------------------------------------------------------
// Manager-level delegators (moved from manager.go).
// ---------------------------------------------------------------------------

// Eventing returns the eventing service.
func (m *Manager) Eventing() *EventingService { return m.eventing }

// EventDispatcher returns the domain event dispatcher, or nil if not configured.
func (m *Manager) EventDispatcher() *domain.EventDispatcher { return m.eventing.Dispatcher() }

// SetEventDispatcher sets the domain event dispatcher.
func (m *Manager) SetEventDispatcher(d *domain.EventDispatcher) { m.eventing.SetDispatcher(d) }

// EventStoreConcrete returns the domain audit log, or nil if not configured.
func (m *Manager) EventStoreConcrete() *eventsourcing.EventStore { return m.eventing.Store() }

// SetEventStore sets the domain audit log.
func (m *Manager) SetEventStore(s *eventsourcing.EventStore) { m.eventing.SetStore(s) }

// Projector returns the read-side projection of order/alert/position
// aggregates. Always non-nil after Manager construction; starts empty and
// populates as events flow through the dispatcher.
func (m *Manager) Projector() *eventsourcing.Projector { return m.projector }
