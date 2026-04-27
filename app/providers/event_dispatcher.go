package providers

import "github.com/zerodha/kite-mcp-server/kc/domain"

// event_dispatcher.go — Wave D Phase 2 Slice P2.4f. Wires the
// 36 always-on dispatcher → audit-log subscriptions as an Fx graph
// node.
//
// LEGACY BEHAVIOUR PRESERVED
//
// app/wire.go:438-539 imperatively chained 36 calls of the form:
//
//	eventDispatcher.Subscribe("order.filled", makeEventPersister(eventStore, "Order", logger))
//
// Each subscription routes a typed domain event through the
// persister to the domain_events SQL table. The full list is
// captured in CanonicalPersisterSubscriptions below — moving it from
// inline imperative code to a data-driven slice trims ~100 LOC at
// the composition site, makes the audit-log → SQL contract
// inspectable as a single value, and lets P2.4f tests assert on
// the count + ordering without re-running the production path.
//
// CONSTRUCTION OWNERSHIP
//
// The persister builder (closure capture of eventStore + logger)
// stays at the composition site (app/wire.go) because:
//   - app.makeEventPersister is package-private and depends on
//     deriveAggregateID + deriveEmailHash (also package-private,
//     non-trivial helpers).
//   - Moving them into providers/ would require either making them
//     all public on the app package or duplicating the logic.
//   - The composition site has the eventStore + logger in scope
//     trivially and can supply the closure as a graph input.
//
// This mirrors the P2.4b BriefingService / P2.4c riskguard auto-
// freeze split: composition keeps adapters; provider takes ports
// and closures.
//
// THE PERSISTER BUILDER PORT
//
// PersisterBuilderFunc is a closure that takes the aggregate type
// (e.g. "Order", "Position") and returns a domain.Event handler
// that routes the event through the configured event store. The
// composition site supplies:
//
//	func(aggType string) func(domain.Event) {
//	    return makeEventPersister(eventStore, aggType, logger)
//	}
//
// In tests, supply a no-op builder OR a recording builder that
// captures the (aggType, event) pairs for assertions.
//
// THE SUBSCRIBE PORT
//
// EventDispatcherDeps carries an OPTIONAL Subscribe override —
// when nil, the provider calls dispatcher.Subscribe directly
// (production behaviour). When non-nil, it routes through the
// caller-supplied function, which lets tests record subscription
// order without reflection on the dispatcher's private handler
// map. See event_dispatcher_test.go's recordingDispatcher pattern.

// EventStorePersister is one row in the canonical subscription list:
// "subscribe this event type, persist it under this aggregate type".
//
// EventType matches the string returned by the typed event's
// EventType() method (e.g. "order.filled", "position.opened").
// AggregateType is the SQL column value used to filter the audit
// stream by aggregate (e.g. "Order", "Position", "RiskguardCounters").
type EventStorePersister struct {
	EventType     string
	AggregateType string
}

// CanonicalPersisterSubscriptions is the full list of dispatcher →
// audit-log subscriptions wired by app/wire.go:438-539. Order MATTERS:
// subscriptions register in this order, and the dispatcher fires
// handlers in registration order on every Dispatch call. Reordering
// changes the order in which the audit row lands relative to other
// handlers (projector, persister) for the same event.
//
// The list is grouped by logical class (audit-trail core,
// riskguard counters, failure paths, success paths) for readability;
// the actual order is the order entries appear here.
var CanonicalPersisterSubscriptions = []EventStorePersister{
	// --- Audit-trail core (12 events) — production paths that
	//     persist via dispatcher only. order.placed / .modified /
	//     .cancelled use cases append directly to eventStore via
	//     eventStore.Append; subscribing the persister here would
	//     double-write. See app/wire.go:432-437 for the rationale.
	{"order.filled", "Order"},
	{"position.opened", "Position"},
	{"position.closed", "Position"},
	{"alert.triggered", "Alert"},
	{"user.frozen", "User"},
	{"user.suspended", "User"},
	{"global.freeze", "Global"},
	{"family.invited", "Family"},
	{"family.member_removed", "Family"},
	{"risk.limit_breached", "RiskGuard"},
	{"session.created", "Session"},
	{"billing.tier_changed", "Billing"},

	// --- Riskguard counters aggregate (3 events) — three event
	//     types share the "RiskguardCounters" aggregate type so
	//     projector queries can pull the full counters stream by
	//     aggregate_type without joining across event_type rows.
	{"riskguard.kill_switch_tripped", "RiskguardCounters"},
	{"riskguard.daily_counter_reset", "RiskguardCounters"},
	{"riskguard.rejection_recorded", "RiskguardCounters"},

	// --- Failure-path events (6 events) — order/MF/GTT/paper
	//     rejection events + position conversion + trailing-stop
	//     trigger. Failure paths land on the same aggregate stream
	//     as the success paths so projector queries see the full
	//     place→modify→reject→cancel timelines.
	{"order.rejected", "Order"},
	{"position.converted", "Position"},
	{"paper.order_rejected", "PaperOrder"},
	{"mf.order_rejected", "MFOrder"},
	{"gtt.rejected", "GTT"},
	{"trailing_stop.triggered", "TrailingStop"},

	// --- Success-path typed events (15 events) — post-aux-cleanup,
	//     persister now writes the audit row from these dispatches
	//     (with EmailHash for PII correlation).
	{"mf.order_placed", "MFOrder"},
	{"mf.order_cancelled", "MFOrder"},
	{"mf.sip_placed", "MFSIP"},
	{"mf.sip_cancelled", "MFSIP"},
	{"gtt.placed", "GTT"},
	{"gtt.modified", "GTT"},
	{"gtt.deleted", "GTT"},
	{"trailing_stop.set", "TrailingStop"},
	{"trailing_stop.cancelled", "TrailingStop"},
	{"native_alert.placed", "NativeAlert"},
	{"native_alert.modified", "NativeAlert"},
	{"native_alert.deleted", "NativeAlert"},
	{"paper.enabled", "PaperTrading"},
	{"paper.disabled", "PaperTrading"},
	{"paper.reset", "PaperTrading"},
}

// PersisterBuilderFunc is the closure type the composition site
// supplies. Given an aggregate type, returns a handler that
// persists each dispatched event of the corresponding type.
// Typical implementation: closes over an *eventsourcing.EventStore
// + *slog.Logger to call eventStore.Append.
type PersisterBuilderFunc func(aggregateType string) func(domain.Event)

// SubscribeFunc is the optional Subscribe override. nil = call
// dispatcher.Subscribe directly. Non-nil = route through the caller
// (used by tests to record order/count).
type SubscribeFunc func(eventType string, handler func(domain.Event))

// EventDispatcherDeps carries the inputs BuildEventSubscriptions
// consumes. Single-arg-struct convention.
type EventDispatcherDeps struct {
	// Dispatcher is the *domain.EventDispatcher to subscribe on.
	// Required for the provider to do any work; nil = no-op return.
	Dispatcher *domain.EventDispatcher

	// PersisterBuilder constructs the per-aggregate-type handler.
	// nil = no-op return (the eventStore failed to init, so no
	// handler can be built).
	PersisterBuilder PersisterBuilderFunc

	// Subscribe is the optional Subscribe override. nil = call
	// Dispatcher.Subscribe directly. Non-nil = route through the
	// caller (test seam).
	Subscribe SubscribeFunc
}

// InitializedEventDispatcher wraps the post-subscription dispatcher
// + the count of subscriptions wired. SubscriptionCount=36 in the
// happy path; 0 when the provider was a no-op (nil dispatcher OR
// nil builder).
//
// Per the wrapper-type convention from audit_init.go: gives the Fx
// type graph a distinct "post-init" type so future providers
// consuming "the wired dispatcher" depend on
// *InitializedEventDispatcher rather than *domain.EventDispatcher
// directly. (Today no Fx consumer reads the wrapper because all
// dispatcher consumers — paperEngine, billingStore, fillWatcher —
// stay at composition; the wrapper exists to preserve the option
// for future migration.)
type InitializedEventDispatcher struct {
	// Dispatcher is the same pointer supplied as input.
	Dispatcher *domain.EventDispatcher

	// SubscriptionCount is the number of Subscribe calls the
	// provider performed. Equal to len(CanonicalPersisterSubscriptions)
	// in the happy path; 0 when input was a no-op.
	SubscriptionCount int
}

// BuildEventSubscriptions wires every entry in
// CanonicalPersisterSubscriptions onto the supplied dispatcher.
// Returns the wrapper with the count of subscriptions wired.
//
// No-op contract:
//   - nil Dispatcher → wrapper with SubscriptionCount=0, no panics.
//   - nil PersisterBuilder → same.
//
// Pure function — no I/O beyond dispatcher.Subscribe (which is an
// in-memory map mutation). Subscriptions persist for the
// dispatcher's lifetime; there is no "unsubscribe" path because
// the dispatcher is recreated on every initializeServices call.
func BuildEventSubscriptions(deps EventDispatcherDeps) *InitializedEventDispatcher {
	if deps.Dispatcher == nil || deps.PersisterBuilder == nil {
		return &InitializedEventDispatcher{
			Dispatcher:        deps.Dispatcher,
			SubscriptionCount: 0,
		}
	}

	subscribe := deps.Subscribe
	if subscribe == nil {
		subscribe = deps.Dispatcher.Subscribe
	}

	for _, sub := range CanonicalPersisterSubscriptions {
		handler := deps.PersisterBuilder(sub.AggregateType)
		subscribe(sub.EventType, handler)
	}

	return &InitializedEventDispatcher{
		Dispatcher:        deps.Dispatcher,
		SubscriptionCount: len(CanonicalPersisterSubscriptions),
	}
}
