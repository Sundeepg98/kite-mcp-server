package eventsourcing

// ceil_test.go — coverage ceiling documentation for kc/eventsourcing.
// Current: 99.2%. Ceiling: 99.2%.
//
// Every uncovered line in this package is documented below with the exact
// line number and the reason it cannot be reached in tests.
//
// ===========================================================================
// alert_aggregate.go
// ===========================================================================
//
// Line 283: `return nil, fmt.Errorf("eventsourcing: unknown event type %T", event)`
//   in ToAlertStoredEvents — default branch of the type switch. The only
//   callers produce events of known types (alertCreatedEvent, alertTriggeredEvent,
//   alertDeletedEvent). The PendingEvents() method only appends events created
//   by AlertAggregate methods (Create, Trigger, Delete), all of which produce
//   known types. Unreachable without adding a new event type and forgetting to
//   update the switch.
//
// Lines 285-286: `if err != nil { return nil, err }`
//   in ToAlertStoredEvents — MarshalPayload wraps json.Marshal on plain structs
//   (AlertCreatedPayload, AlertTriggeredPayload, AlertDeletedPayload). These
//   structs contain only string/float64/int fields, which json.Marshal cannot
//   fail on. Unreachable.
//
// ===========================================================================
// order_aggregate.go
// ===========================================================================
//
// Line 436: `return nil, fmt.Errorf("eventsourcing: unknown event type %T", event)`
//   in ToStoredEvents — same reasoning as alert_aggregate.go:283. PendingEvents
//   only contains orderPlacedEvent, orderModifiedEvent, orderCancelledEvent,
//   orderFilledEvent. Unreachable.
//
// Lines 438-439: `if err != nil { return nil, err }`
//   in ToStoredEvents — same as alert_aggregate.go:285-286. All payload structs
//   are plain value types. json.Marshal always succeeds. Unreachable.
//
// ===========================================================================
// position_aggregate.go
// ===========================================================================
//
// Line 254: `return nil, fmt.Errorf("eventsourcing: unknown event type %T", event)`
//   in ToPositionStoredEvents — same reasoning. Only positionOpenedEvent and
//   positionClosedEvent are appended by PositionAggregate methods. Unreachable.
//
// Lines 256-257: `if err != nil { return nil, err }`
//   in ToPositionStoredEvents — same as above. Plain struct payloads.
//   json.Marshal always succeeds. Unreachable.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// All uncovered lines (6 total across 3 files) are defensive error paths in
// ToXxxStoredEvents functions:
//   1. Default branches in type switches — the only way to reach them is to
//      introduce a new event type without updating the switch (compile-time
//      oversight, not a runtime scenario).
//   2. MarshalPayload error checks — json.Marshal on plain structs with
//      string/float64/int fields cannot fail.
//
// Ceiling: 99.2% (6 unreachable lines out of ~750 statements).
