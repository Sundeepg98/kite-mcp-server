package kc

import "github.com/zerodha/kite-mcp-server/kc/usecases"

// manager_use_cases.go holds the startup-once construction of use case
// instances that the CommandBus / QueryBus handlers dispatch into.
//
// Wave D Phase 1 Slice D2 introduces this seam for the three order-
// write use cases (PlaceOrder / ModifyOrder / CancelOrder). Subsequent
// slices migrate the remaining 11 ctx-bound use cases per
// .research/wave-d-resolver-refactor-plan.md §6.
//
// Preconditions (load-bearing):
//   - sessionSvc must be non-nil → satisfied after initFocusedServices
//   - riskGuard MAY be nil → use cases are nil-safe per their docs
//   - eventing must be non-nil (the facade itself; its Dispatcher() is
//     also nil-safe because the use case wraps the dispatch path)
//   - Logger must be non-nil (validated up-front in NewWithOptions)
//   - Instruments MAY be nil at this point if the test fixture left it
//     out; the InstrumentLookup wiring uses InstrumentsManagerConcrete()
//     which is nil-safe at the call site.
//
// Mutations to riskGuard / eventStore / Instruments after this helper
// runs do NOT propagate to the constructed use cases. That's a behaviour
// shift from the prior per-request-construction pattern, but it matches
// the eventual Wire/fx end-state where use cases are graph-resolved
// once at startup. Tests that exercise "set X to nil mid-flight" must
// reconstruct the manager (the standing pattern outside Wave D scope)
// or use the deprecated SetX setters.

// initOrderUseCases constructs the order + GTT write use cases once and
// stores them on the Manager. registerOrderCommands / the GTT handler
// triple then dispatch into these instances rather than constructing
// fresh ones per request.
//
// Called from NewWithOptions after initFocusedServices (which builds
// sessionSvc) and BEFORE registerCQRSHandlers (which wires the
// CommandBus handlers that read these fields).
//
// EVENT-DISPATCHER NOTE (load-bearing):
//
// Production wiring (app/wire.go:384) calls
// kcManager.SetEventDispatcher(eventDispatcher) AFTER kc.NewWithOptions
// returns. At init-time below, m.eventing.Dispatcher() returns nil. We
// pass nil here; EventingService.SetDispatcher then propagates the real
// dispatcher into each use case via its SetEventDispatcher setter when
// app/wire.go finishes wiring. Without this two-phase dispatcher
// wiring, OrderPlaced / GTTPlaced / etc. events would silently drop
// because the use case captured a nil pointer at construction.
//
// Tests that don't call SetEventDispatcher get use cases with nil
// dispatchers — domain events are skipped, matching the prior
// per-request-construction behaviour where tests rarely wired one.
func (m *Manager) initOrderUseCases() {
	// PlaceOrder — full pipeline (instruments lookup, riskguard, broker,
	// event dispatch, optional event-store append).
	placeUC := usecases.NewPlaceOrderUseCase(
		m.sessionSvc,
		m.riskGuard,
		m.eventing.Dispatcher(), // nil at init-time; EventingService.SetDispatcher propagates later
		m.Logger,
	)
	if m.eventStore != nil {
		placeUC.SetEventStore(m.eventStore)
	}
	if im := m.InstrumentsManagerConcrete(); im != nil {
		placeUC.SetInstrumentLookup(&instrumentLookupAdapter{mgr: im})
	}
	m.placeOrderUC = placeUC

	// ModifyOrder — same pipeline minus the instruments lookup (modify
	// only changes price/qty, not instrument metadata).
	modifyUC := usecases.NewModifyOrderUseCase(
		m.sessionSvc,
		m.riskGuard,
		m.eventing.Dispatcher(),
		m.Logger,
	)
	if m.eventStore != nil {
		modifyUC.SetEventStore(m.eventStore)
	}
	m.modifyOrderUC = modifyUC

	// CancelOrder — no riskguard (cancel is always allowed; riskguard
	// only gates outbound state-creating actions). No instruments lookup.
	cancelUC := usecases.NewCancelOrderUseCase(
		m.sessionSvc,
		m.eventing.Dispatcher(),
		m.Logger,
	)
	if m.eventStore != nil {
		cancelUC.SetEventStore(m.eventStore)
	}
	m.cancelOrderUC = cancelUC

	// PlaceGTT / ModifyGTT / DeleteGTT — Slice D3. GTT use case
	// constructors take only (resolver, logger); event dispatcher and
	// event store are wired post-construction via SetX setters.
	placeGTT := usecases.NewPlaceGTTUseCase(m.sessionSvc, m.Logger)
	if m.eventStore != nil {
		placeGTT.SetEventStore(m.eventStore)
	}
	if d := m.eventing.Dispatcher(); d != nil {
		placeGTT.SetEventDispatcher(d)
	}
	m.placeGTTUC = placeGTT

	modifyGTT := usecases.NewModifyGTTUseCase(m.sessionSvc, m.Logger)
	if m.eventStore != nil {
		modifyGTT.SetEventStore(m.eventStore)
	}
	if d := m.eventing.Dispatcher(); d != nil {
		modifyGTT.SetEventDispatcher(d)
	}
	m.modifyGTTUC = modifyGTT

	deleteGTT := usecases.NewDeleteGTTUseCase(m.sessionSvc, m.Logger)
	if m.eventStore != nil {
		deleteGTT.SetEventStore(m.eventStore)
	}
	if d := m.eventing.Dispatcher(); d != nil {
		deleteGTT.SetEventDispatcher(d)
	}
	m.deleteGTTUC = deleteGTT

	// ClosePosition / CloseAllPositions — Slice D4. Both take
	// (resolver, guard, events, logger); event dispatcher comes via
	// the constructor (nil at init, propagated by SetDispatcher).
	closePos := usecases.NewClosePositionUseCase(
		m.sessionSvc,
		m.riskGuard,
		m.eventing.Dispatcher(),
		m.Logger,
	)
	m.closePositionUC = closePos

	closeAll := usecases.NewCloseAllPositionsUseCase(
		m.sessionSvc,
		m.riskGuard,
		m.eventing.Dispatcher(),
		m.Logger,
	)
	m.closeAllPositionsUC = closeAll
}
