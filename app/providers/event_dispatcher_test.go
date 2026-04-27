package providers

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// event_dispatcher_test.go covers BuildEventSubscriptions. Wave D
// Phase 2 Slice P2.4f.
//
// The provider takes a dispatcher + a persister-builder function +
// a static list of (event-type, aggregate-type) pairs and wires
// every entry as a Subscribe call. Returns wrapper with subscription
// count for testability.

// recordingDispatcher wraps a *domain.EventDispatcher and records
// the (eventType, handler) pairs registered via Subscribe. We use
// this to verify the provider wires every entry in the canonical
// list exactly once.
//
// A real *domain.EventDispatcher works too (it's a concrete type
// the provider takes) — we just don't have a way to inspect its
// internal handler map without exporting it. Recording-via-wrapper
// is cleaner than reflection-poking the dispatcher's private
// handlers field.
type recordingDispatcher struct {
	dispatcher *domain.EventDispatcher
	mu         sync.Mutex
	calls      []string // event types in registration order
}

func newRecordingDispatcher() *recordingDispatcher {
	return &recordingDispatcher{
		dispatcher: domain.NewEventDispatcher(),
	}
}

func (r *recordingDispatcher) Subscribe(eventType string, handler func(domain.Event)) {
	r.mu.Lock()
	r.calls = append(r.calls, eventType)
	r.mu.Unlock()
	r.dispatcher.Subscribe(eventType, handler)
}

// TestCanonicalPersisterSubscriptions_HasExpectedCount pins the
// "36 subscriptions" expectation from wire.go:438-539. If the list
// changes (additions / deletions), this test fails so we surface
// the spec change in code review.
func TestCanonicalPersisterSubscriptions_HasExpectedCount(t *testing.T) {
	t.Parallel()

	const expected = 36
	got := len(CanonicalPersisterSubscriptions)
	if got != expected {
		t.Errorf("expected %d canonical subscriptions; got %d", expected, got)
	}
}

// TestCanonicalPersisterSubscriptions_AllEventTypesUnique verifies
// no event type appears twice in the canonical list. wire.go's
// legacy code uses Subscribe (which appends), so duplicates would
// silently double-write to the audit log. The list MUST be unique.
func TestCanonicalPersisterSubscriptions_AllEventTypesUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, len(CanonicalPersisterSubscriptions))
	for _, sub := range CanonicalPersisterSubscriptions {
		if _, dup := seen[sub.EventType]; dup {
			t.Errorf("duplicate event type in canonical list: %q", sub.EventType)
		}
		seen[sub.EventType] = struct{}{}
	}
}

// TestCanonicalPersisterSubscriptions_AggregateTypeNonEmpty verifies
// every entry has a non-empty AggregateType. The persister uses
// AggregateType as the SQL column value; an empty string would
// pollute the domain_events table with rows that can't be filtered
// by aggregate.
func TestCanonicalPersisterSubscriptions_AggregateTypeNonEmpty(t *testing.T) {
	t.Parallel()

	for _, sub := range CanonicalPersisterSubscriptions {
		if sub.AggregateType == "" {
			t.Errorf("empty AggregateType for event %q", sub.EventType)
		}
	}
}

// TestBuildEventSubscriptions_NilDispatcher_ReturnsNilWrapper
// verifies the provider's "no work needed" path: if the dispatcher
// input is nil, the wrapper has SubscriptionCount=0 and no panics.
// (This shouldn't happen in normal Fx wiring — wire.go always
// constructs a dispatcher — but the provider defends against it.)
func TestBuildEventSubscriptions_NilDispatcher_ReturnsNilWrapper(t *testing.T) {
	t.Parallel()

	deps := EventDispatcherDeps{
		Dispatcher:        nil,
		PersisterBuilder:  func(_ string) func(domain.Event) { return func(_ domain.Event) {} },
	}
	got := BuildEventSubscriptions(deps)
	if got == nil {
		t.Fatal("expected non-nil wrapper even with nil dispatcher")
	}
	if got.SubscriptionCount != 0 {
		t.Errorf("expected 0 subscriptions for nil dispatcher; got %d", got.SubscriptionCount)
	}
}

// TestBuildEventSubscriptions_NilBuilder_ReturnsNilWrapper verifies
// that a nil persister-builder is also a "no work needed" signal
// (the eventStore failed to init, so no persister can be built).
// SubscriptionCount=0 → composition site sees the dispatcher has no
// audit-trail wiring.
func TestBuildEventSubscriptions_NilBuilder_ReturnsNilWrapper(t *testing.T) {
	t.Parallel()

	deps := EventDispatcherDeps{
		Dispatcher:       domain.NewEventDispatcher(),
		PersisterBuilder: nil,
	}
	got := BuildEventSubscriptions(deps)
	if got == nil {
		t.Fatal("expected non-nil wrapper even with nil builder")
	}
	if got.SubscriptionCount != 0 {
		t.Errorf("expected 0 subscriptions for nil builder; got %d", got.SubscriptionCount)
	}
}

// TestBuildEventSubscriptions_AllPresent_Wires36 verifies the happy
// path: with a real dispatcher + a persister builder, the provider
// wires every canonical subscription. We verify via a custom
// dispatcher wrapper that records each Subscribe call.
func TestBuildEventSubscriptions_AllPresent_Wires36(t *testing.T) {
	t.Parallel()

	// Use a real *domain.EventDispatcher; provide a builder that
	// returns a no-op handler. The provider should call Subscribe
	// 36 times.
	dispatcher := domain.NewEventDispatcher()
	builderCalls := atomic.Int32{}
	builder := func(_ string) func(domain.Event) {
		builderCalls.Add(1)
		return func(_ domain.Event) {}
	}
	deps := EventDispatcherDeps{
		Dispatcher:       dispatcher,
		PersisterBuilder: builder,
	}
	got := BuildEventSubscriptions(deps)
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if got.SubscriptionCount != 36 {
		t.Errorf("expected 36 subscriptions; got %d", got.SubscriptionCount)
	}
	// The builder is called once per canonical entry (36 times).
	if got := builderCalls.Load(); got != 36 {
		t.Errorf("expected builder called 36 times; got %d", got)
	}
}

// TestBuildEventSubscriptions_OrderingPreservesCanonicalList
// verifies that subscriptions are wired in the order they appear in
// CanonicalPersisterSubscriptions. Order matters for log-tailing
// and projector consumers — a swap would change the
// order in which handlers run for the same event type (Subscribe
// appends to a slice).
//
// We verify this via a recording dispatcher that captures each
// Subscribe call's eventType.
func TestBuildEventSubscriptions_OrderingPreservesCanonicalList(t *testing.T) {
	t.Parallel()

	rec := newRecordingDispatcher()
	builder := func(_ string) func(domain.Event) {
		return func(_ domain.Event) {}
	}
	// We use a SubscribeFunc adapter so the provider wires through
	// our recorder. (See file-level doc for the design.)
	deps := EventDispatcherDeps{
		Dispatcher:       rec.dispatcher,
		Subscribe:        rec.Subscribe,
		PersisterBuilder: builder,
	}
	got := BuildEventSubscriptions(deps)
	if got.SubscriptionCount != 36 {
		t.Fatalf("expected 36; got %d", got.SubscriptionCount)
	}
	// Verify the ordering matches.
	if len(rec.calls) != len(CanonicalPersisterSubscriptions) {
		t.Fatalf("recorder saw %d Subscribe calls; expected %d", len(rec.calls), len(CanonicalPersisterSubscriptions))
	}
	for i, sub := range CanonicalPersisterSubscriptions {
		if rec.calls[i] != sub.EventType {
			t.Errorf("subscription[%d]: got %q, want %q", i, rec.calls[i], sub.EventType)
		}
	}
}
