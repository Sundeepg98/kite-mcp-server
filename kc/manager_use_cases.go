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

// initOrderUseCases constructs the place/modify/cancel order use cases
// once and stores them on the Manager. registerOrderCommands then
// dispatches into these instances rather than constructing fresh ones
// per request.
//
// Called from NewWithOptions after initFocusedServices (which builds
// sessionSvc) and BEFORE registerCQRSHandlers (which wires the
// CommandBus handlers that read these fields).
func (m *Manager) initOrderUseCases() {
	// PlaceOrder — full pipeline (instruments lookup, riskguard, broker,
	// event dispatch, optional event-store append).
	placeUC := usecases.NewPlaceOrderUseCase(
		m.sessionSvc,
		m.riskGuard,
		m.eventing.Dispatcher(),
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
}
