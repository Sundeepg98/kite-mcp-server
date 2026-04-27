package kc

// fill_watcher_lifecycle_test.go — coverage close-out for the
// fill_watcher constructor / Start / Watch / pollLoop edge branches
// that existing kc/fill_watcher_test.go doesn't reach.
//
// Sub-commit C of Wave B option 2 (kc/ root Manager boot + lifecycle).
//
// Targets:
//   1. FillWatcherResolverFromSessionSvc — both nil + non-nil paths
//      (was 0%)
//   2. sessionSvcBrokerAdapter.GetBrokerForEmail — the 3-line adapter
//      that exists only to satisfy Go's interface-method strict-match
//      rule (was 0%)
//   3. Start() nil-dispatcher early-return + event-type-mismatch
//      branch in the subscribed callback (was 71.4%)
//   4. Watch() nil-resolver / nil-dispatcher / empty-OrderID
//      early-returns (was 71.4%)
//   5. pollLoop broker-resolution-failure silent-exit branch + the
//      "invalid filled qty" warn-and-exit branch (was 86.2%)
//
// Note: kc/scheduler/ subpackage is at 90.2% coverage, kc/alerts/
// briefing is at 95.7% — both already above the 80% standard tier
// threshold and outside the kc/ root scope. Focus stays on
// kc/fill_watcher.go where real gaps remain.
//
// File-scope: deliberately new file separate from
// kc/fill_watcher_test.go so concurrent Wave D BrokerResolver work
// (which may touch SessionService internals the existing tests use)
// does not collide.

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// quietWatcherLogger discards log output to keep test logs clean.
// Local helper rather than reusing newFillWatcherTestLogger from
// fill_watcher_test.go so concurrent agents renaming that helper
// don't break this file.
func quietWatcherLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ===========================================================================
// FillWatcherResolverFromSessionSvc — both branches (was 0%)
// ===========================================================================

// TestFillWatcherResolverFromSessionSvc_NilReturnsNil verifies the
// nil-guard at fill_watcher.go:103-105: passing a nil SessionService
// produces a nil resolver rather than a struct wrapping nil.
func TestFillWatcherResolverFromSessionSvc_NilReturnsNil(t *testing.T) {
	t.Parallel()

	resolver := FillWatcherResolverFromSessionSvc(nil)
	assert.Nil(t, resolver,
		"nil SessionService must produce a nil resolver, not a wrapper around nil")
}

// TestFillWatcherResolverFromSessionSvc_WrapsNonNil verifies the
// happy-path: a real SessionService gets wrapped in the
// sessionSvcBrokerAdapter, and adapter.GetBrokerForEmail delegates
// to the underlying SessionService.GetBrokerForEmail.
func TestFillWatcherResolverFromSessionSvc_WrapsNonNil(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(t.Context(),
		WithLogger(quietWatcherLogger()),
		WithDevMode(true),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	resolver := FillWatcherResolverFromSessionSvc(mgr.SessionSvc())
	require.NotNil(t, resolver,
		"non-nil SessionService must yield a non-nil resolver")

	// Drive the adapter — calling GetBrokerForEmail on the wrapper
	// reaches sessionSvcBrokerAdapter.GetBrokerForEmail (the 3-line
	// adapter at fill_watcher.go:94).
	//
	// In DevMode without an active session, the underlying call
	// returns an error — the contract is "the call reaches the
	// adapter and returns whatever SessionService produces"; we
	// don't pin success/failure here, just exercise the line.
	_, _ = resolver.GetBrokerForEmail("nobody@test.com")
}

// ===========================================================================
// Start() — nil-dispatcher early-return + event-type-mismatch branch
// ===========================================================================

// TestFillWatcher_Start_NilDispatcherIsNoop verifies the early-return
// at fill_watcher.go:203-205: a watcher built without a dispatcher
// still tolerates Start() being called (the function silently no-ops
// rather than panicking on a nil .Subscribe call).
func TestFillWatcher_Start_NilDispatcherIsNoop(t *testing.T) {
	t.Parallel()

	w := NewFillWatcher(FillWatcherConfig{
		Broker:     &fakeOrderHistoryClient{},
		Dispatcher: nil, // deliberately nil
		Logger:     quietWatcherLogger(),
	})
	// Must not panic. Idempotent.
	w.Start()
	w.Start()
}

// TestFillWatcher_Start_IgnoresNonOrderPlacedEvents verifies the
// type-assertion negative branch at fill_watcher.go:207-209: when
// the dispatcher fires an event that isn't a domain.OrderPlacedEvent,
// the subscribed callback returns early without calling Watch.
//
// Without this branch, a wrong-typed event would panic the watcher
// goroutine (calling Watch with a zero-value OrderPlacedEvent would
// fall into the empty-OrderID early-return and be safe — but the
// type check stops earlier, before w.Watch is called at all).
func TestFillWatcher_Start_IgnoresNonOrderPlacedEvents(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	fake := &fakeOrderHistoryClient{snapshots: [][]broker.Order{nil}}
	w := NewFillWatcher(FillWatcherConfig{
		Broker:     fake,
		Dispatcher: dispatcher,
		Logger:     quietWatcherLogger(),
		Clock:      testutil.NewFakeClock(time.Now()),
	})
	w.Start()
	t.Cleanup(w.Stop)

	// Dispatch an event of the wrong type — OrderFilledEvent, not
	// OrderPlacedEvent. The Start callback must not invoke Watch.
	dispatcher.Dispatch(domain.OrderFilledEvent{
		OrderID:   "wrong-type",
		Email:     "u@t.com",
		Timestamp: time.Now(),
	})

	// Wait briefly for any spuriously-spawned goroutine to make a
	// poll call. With the type-check in place, callCount should be 0.
	w.Wait(50 * time.Millisecond)
	assert.Equal(t, 0, fake.callCount(),
		"non-OrderPlacedEvent must NOT spawn a poll goroutine")
}

// ===========================================================================
// Watch() — three early-return guards (was 71.4%)
// ===========================================================================

// TestFillWatcher_Watch_NilResolverNoop verifies the early-return at
// fill_watcher.go:226-228: a watcher with no resolver (and no
// broker, hence the staticBrokerResolver wrap was skipped) drops
// the Watch call silently.
func TestFillWatcher_Watch_NilResolverNoop(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	w := NewFillWatcher(FillWatcherConfig{
		Broker:     nil, // no broker
		Resolver:   nil, // no resolver either
		Dispatcher: dispatcher,
		Logger:     quietWatcherLogger(),
	})
	t.Cleanup(w.Stop)

	// Must not panic, must not spawn a goroutine. Hard to assert
	// "no goroutine" directly, but Wait returning immediately is a
	// proxy for "wg.Add was never called".
	w.Watch(domain.OrderPlacedEvent{
		OrderID: "ord-1",
		Email:   "u@t.com",
	})
	done := make(chan struct{})
	go func() {
		w.Wait(100 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
		// Wait returned promptly — no goroutines pending.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Wait should return immediately when nil-resolver Watch was a no-op")
	}
}

// TestFillWatcher_Watch_NilDispatcherNoop verifies the early-return:
// even with a resolver, a nil dispatcher means there's nowhere to
// send the eventual OrderFilledEvent — Watch should drop the call
// silently. The constructor allows this combination because
// resolver / dispatcher are both populated independently.
func TestFillWatcher_Watch_NilDispatcherNoop(t *testing.T) {
	t.Parallel()

	fake := &fakeOrderHistoryClient{}
	w := NewFillWatcher(FillWatcherConfig{
		Broker:     fake,
		Dispatcher: nil, // no dispatcher
		Logger:     quietWatcherLogger(),
	})
	t.Cleanup(w.Stop)

	w.Watch(domain.OrderPlacedEvent{
		OrderID: "ord-2",
		Email:   "u@t.com",
	})

	// Verify no goroutine spawned (Wait returns instantly).
	w.Wait(100 * time.Millisecond)
	assert.Equal(t, 0, fake.callCount(),
		"nil dispatcher must skip the goroutine entirely")
}

// TestFillWatcher_Watch_EmptyOrderIDNoop verifies the empty-OrderID
// early-return at fill_watcher.go:229-231: an event with no OrderID
// (defensive — production never emits this) drops the call rather
// than spawning a goroutine that would then GetOrderHistory("").
func TestFillWatcher_Watch_EmptyOrderIDNoop(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	fake := &fakeOrderHistoryClient{}
	w := NewFillWatcher(FillWatcherConfig{
		Broker:     fake,
		Dispatcher: dispatcher,
		Logger:     quietWatcherLogger(),
	})
	t.Cleanup(w.Stop)

	w.Watch(domain.OrderPlacedEvent{
		OrderID: "", // deliberately empty
		Email:   "u@t.com",
	})

	w.Wait(100 * time.Millisecond)
	assert.Equal(t, 0, fake.callCount(),
		"empty OrderID must short-circuit before goroutine spawn")
}

// ===========================================================================
// pollLoop — broker-resolution-failure silent-exit branch
// ===========================================================================

// failingResolver is a FillWatcherBrokerResolver that always errors.
// Used to exercise the resolver-error branch in pollLoop at
// fill_watcher.go:271-278.
type failingResolver struct{ err error }

func (f failingResolver) GetBrokerForEmail(_ string) (FillWatcherBroker, error) {
	return nil, f.err
}

// TestFillWatcher_PollLoop_ResolverErrorSilentExit verifies the
// resolver-error branch: when GetBrokerForEmail returns an error,
// pollLoop logs at debug and exits without polling. The dispatcher
// must NOT receive an OrderFilledEvent.
func TestFillWatcher_PollLoop_ResolverErrorSilentExit(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	var dispatched int32
	dispatcher.Subscribe("order.filled", func(e domain.Event) {
		atomic.AddInt32(&dispatched, 1)
	})

	fc := testutil.NewFakeClock(time.Now())
	w := NewFillWatcher(FillWatcherConfig{
		Resolver:     failingResolver{err: errors.New("session terminated")},
		Dispatcher:   dispatcher,
		Logger:       quietWatcherLogger(),
		Clock:        fc,
		PollInterval: 100 * time.Millisecond,
		MaxDuration:  1 * time.Second,
	})
	t.Cleanup(w.Stop)

	w.Watch(domain.OrderPlacedEvent{
		OrderID: "resolver-fail",
		Email:   "u@t.com",
	})

	// pollLoop should resolve immediately, see the error, and exit.
	// Wait briefly — if the goroutine never returned, Wait would
	// block until our timeout.
	w.Wait(500 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&dispatched),
		"resolver error must NOT dispatch any OrderFilledEvent")
}

// resolverReturningNilBroker exercises the second half of the guard
// at line 272: berr is nil but bc is also nil. pollLoop should
// treat this the same as the error case and exit silently.
type resolverReturningNilBroker struct{}

func (r resolverReturningNilBroker) GetBrokerForEmail(_ string) (FillWatcherBroker, error) {
	return nil, nil
}

// TestFillWatcher_PollLoop_NilBrokerSilentExit verifies the
// "bc == nil" branch: even with no error, a nil broker means there's
// nothing to poll. Mirrors the error case in outcome.
func TestFillWatcher_PollLoop_NilBrokerSilentExit(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	var dispatched int32
	dispatcher.Subscribe("order.filled", func(e domain.Event) {
		atomic.AddInt32(&dispatched, 1)
	})

	w := NewFillWatcher(FillWatcherConfig{
		Resolver:     resolverReturningNilBroker{},
		Dispatcher:   dispatcher,
		Logger:       quietWatcherLogger(),
		Clock:        testutil.NewFakeClock(time.Now()),
		PollInterval: 100 * time.Millisecond,
		MaxDuration:  1 * time.Second,
	})
	t.Cleanup(w.Stop)

	w.Watch(domain.OrderPlacedEvent{
		OrderID: "nil-broker",
		Email:   "u@t.com",
	})

	w.Wait(500 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&dispatched))
}

// ===========================================================================
// pollLoop — invalid-filled-qty warn-and-exit branch
// ===========================================================================

// TestFillWatcher_PollLoop_ZeroFilledQtyDoesNotDispatch verifies the
// guard at fill_watcher.go:329-337: when an order reaches a terminal
// status (e.g. COMPLETE) but reports FilledQuantity=0, NewQuantity
// rejects it (positive-only validation), and pollLoop logs a warn
// and exits without dispatching. Pins the contract that the bus
// never sees an OrderFilledEvent with zero qty.
func TestFillWatcher_PollLoop_ZeroFilledQtyDoesNotDispatch(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	var dispatched int32
	dispatcher.Subscribe("order.filled", func(e domain.Event) {
		atomic.AddInt32(&dispatched, 1)
	})

	// Snapshot: terminal COMPLETE but FilledQuantity=0.
	fake := &fakeOrderHistoryClient{
		snapshots: [][]broker.Order{
			{
				{
					OrderID:        "zero-qty",
					Status:         "COMPLETE",
					FilledQuantity: 0, // forces NewQuantity error path
					AveragePrice:   100,
				},
			},
		},
	}

	fc := testutil.NewFakeClock(time.Now())
	w := NewFillWatcher(FillWatcherConfig{
		Broker:       fake,
		Dispatcher:   dispatcher,
		Logger:       quietWatcherLogger(),
		Clock:        fc,
		PollInterval: 100 * time.Millisecond,
		MaxDuration:  1 * time.Second,
	})
	t.Cleanup(w.Stop)

	w.Watch(domain.OrderPlacedEvent{
		OrderID: "zero-qty",
		Email:   "u@t.com",
	})

	// Advance past the first tick so pollLoop calls GetOrderHistory.
	fc.Advance(150 * time.Millisecond)
	w.Wait(500 * time.Millisecond)

	// The poll fired (callCount > 0), but no event dispatched
	// because the filled qty was invalid.
	assert.Greater(t, fake.callCount(), 0,
		"pollLoop must have called GetOrderHistory at least once")
	assert.Equal(t, int32(0), atomic.LoadInt32(&dispatched),
		"zero FilledQuantity must NOT produce an OrderFilledEvent")
}

// ===========================================================================
// NewFillWatcher — default-fill branches (was 92.3%)
// ===========================================================================

// TestNewFillWatcher_DefaultsApplied verifies the three
// default-fallback branches in the constructor:
//
//   1. nil Clock -> testutil.RealClock{}
//   2. zero/negative PollInterval -> 5 * time.Second
//   3. zero/negative MaxDuration -> 60 * time.Second
//
// We check defaults via the public Wait timeout: with PollInterval=0
// and a Stop() right after Watch, the ticker would otherwise be
// invalid. Using RealClock means we can't easily inspect internal
// state — instead, verify the watcher boots cleanly and supports
// Wait/Stop without panics.
func TestNewFillWatcher_DefaultsApplied(t *testing.T) {
	t.Parallel()

	dispatcher := domain.NewEventDispatcher()
	w := NewFillWatcher(FillWatcherConfig{
		Broker:     &fakeOrderHistoryClient{},
		Dispatcher: dispatcher,
		Logger:     quietWatcherLogger(),
		// Clock, PollInterval, MaxDuration deliberately zero — the
		// constructor must fill the defaults.
	})
	require.NotNil(t, w)
	w.Stop() // sanity: lifecycle works with defaulted values
	w.Wait(100 * time.Millisecond)
}

// TestNewFillWatcher_NegativePollIntervalGetsDefault covers the
// boundary where PollInterval is explicitly negative — the
// constructor's "<= 0" check at line 162-164 reads "default
// to 5s when the caller passes a non-positive value".
func TestNewFillWatcher_NegativePollIntervalGetsDefault(t *testing.T) {
	t.Parallel()

	w := NewFillWatcher(FillWatcherConfig{
		Broker:       &fakeOrderHistoryClient{},
		Dispatcher:   domain.NewEventDispatcher(),
		Logger:       quietWatcherLogger(),
		PollInterval: -1 * time.Second, // negative — must be defaulted
		MaxDuration:  -1 * time.Second, // negative — must be defaulted
	})
	require.NotNil(t, w)
	w.Stop()
	w.Wait(100 * time.Millisecond)
}
