package kc

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// fakeOrderHistoryClient is a hand-rolled test double for the narrow
// broker.OrderManager surface the fill-watcher depends on. Returns a
// scripted sequence of snapshots per call, preserving call-ordering
// assertions for poll-count testing.
type fakeOrderHistoryClient struct {
	mu         sync.Mutex
	snapshots  [][]broker.Order // one element = one response history
	callIdx    int32            // atomic: number of GetOrderHistory calls so far
	err        error            // if non-nil, return on every call
	onCallHook func(int32)      // optional hook invoked after each call, with 1-indexed call count
}

func (f *fakeOrderHistoryClient) GetOrders() ([]broker.Order, error)             { return nil, nil }
func (f *fakeOrderHistoryClient) GetOrderTrades(string) ([]broker.Trade, error)  { return nil, nil }
func (f *fakeOrderHistoryClient) PlaceOrder(broker.OrderParams) (broker.OrderResponse, error) {
	return broker.OrderResponse{}, nil
}
func (f *fakeOrderHistoryClient) ModifyOrder(string, broker.OrderParams) (broker.OrderResponse, error) {
	return broker.OrderResponse{}, nil
}
func (f *fakeOrderHistoryClient) CancelOrder(string, string) (broker.OrderResponse, error) {
	return broker.OrderResponse{}, nil
}

func (f *fakeOrderHistoryClient) GetOrderHistory(_ string) ([]broker.Order, error) {
	idx := atomic.AddInt32(&f.callIdx, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		if f.onCallHook != nil {
			f.onCallHook(idx)
		}
		return nil, f.err
	}
	// Return the snapshot for the (idx-1)th call; pad with the last snapshot
	// if the caller polls beyond the scripted length.
	i := int(idx - 1)
	if i >= len(f.snapshots) {
		i = len(f.snapshots) - 1
	}
	result := f.snapshots[i]
	if f.onCallHook != nil {
		f.onCallHook(idx)
	}
	return result, nil
}

func (f *fakeOrderHistoryClient) callCount() int { return int(atomic.LoadInt32(&f.callIdx)) }

func newFillWatcherTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestFillWatcher_FiresOnceOnComplete asserts that when the broker
// reports a terminal COMPLETE state after N polls, exactly one
// OrderFilledEvent is dispatched — even if the clock advances further
// and the broker keeps reporting COMPLETE.
func TestFillWatcher_FiresOnceOnComplete(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Now())
	dispatcher := domain.NewEventDispatcher()

	var firedEvents []domain.OrderFilledEvent
	var mu sync.Mutex
	dispatcher.Subscribe("order.filled", func(e domain.Event) {
		mu.Lock()
		defer mu.Unlock()
		firedEvents = append(firedEvents, e.(domain.OrderFilledEvent))
	})

	// Snapshot script: OPEN → OPEN → COMPLETE on the 3rd poll.
	fbc := &fakeOrderHistoryClient{
		snapshots: [][]broker.Order{
			{{OrderID: "ORD1", Status: "OPEN", FilledQuantity: 0}},
			{{OrderID: "ORD1", Status: "OPEN", FilledQuantity: 0}},
			{{OrderID: "ORD1", Status: "COMPLETE", FilledQuantity: 10, AveragePrice: 1500.0}},
			// Extra snapshots — if the watcher keeps polling after COMPLETE,
			// we want the event count to stay at 1.
			{{OrderID: "ORD1", Status: "COMPLETE", FilledQuantity: 10, AveragePrice: 1500.0}},
			{{OrderID: "ORD1", Status: "COMPLETE", FilledQuantity: 10, AveragePrice: 1500.0}},
		},
	}

	// Signal the test when each poll completes so Advance can fire the
	// next tick without racing with the watcher goroutine.
	pollCh := make(chan int32, 16)
	fbc.onCallHook = func(idx int32) { pollCh <- idx }

	w := NewFillWatcher(FillWatcherConfig{
		Broker:       fbc,
		Dispatcher:   dispatcher,
		Logger:       newFillWatcherTestLogger(),
		Clock:        clock,
		PollInterval: 5 * time.Second,
		MaxDuration:  60 * time.Second,
	})

	w.Watch(domain.OrderPlacedEvent{
		Email:           "u@t.com",
		OrderID:         "ORD1",
		TransactionType: "BUY",
		Timestamp:       clock.Now(),
	})

	// Drive the scheduler: 3 ticks brings us through the snapshot script
	// to the COMPLETE state. Wait for each poll to commit before advancing
	// so we do not race the clock past ticks the goroutine has not yet
	// consumed.
	for i := int32(1); i <= 3; i++ {
		clock.Advance(5 * time.Second)
		select {
		case got := <-pollCh:
			require.Equal(t, i, got, "expected poll %d, got %d", i, got)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for poll %d", i)
		}
	}

	// Give the goroutine a moment to dispatch + exit its loop.
	w.Wait(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, firedEvents, 1, "OrderFilledEvent should fire exactly once")
	assert.Equal(t, "ORD1", firedEvents[0].OrderID)
	assert.Equal(t, "u@t.com", firedEvents[0].Email)
	assert.Equal(t, 10, firedEvents[0].FilledQty.Int())
	assert.Equal(t, 1500.0, firedEvents[0].FilledPrice.Amount)
}

// TestFillWatcher_GivesUpAtBudget asserts that if the order never
// reaches COMPLETE, the watcher stops polling after MaxDuration and
// does not dispatch a fill event.
func TestFillWatcher_GivesUpAtBudget(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Now())
	dispatcher := domain.NewEventDispatcher()

	var eventCount int32
	dispatcher.Subscribe("order.filled", func(_ domain.Event) {
		atomic.AddInt32(&eventCount, 1)
	})

	// Always OPEN — never reaches terminal state.
	fbc := &fakeOrderHistoryClient{
		snapshots: [][]broker.Order{
			{{OrderID: "ORD_STALE", Status: "OPEN"}},
		},
	}
	pollCh := make(chan int32, 32)
	fbc.onCallHook = func(idx int32) { pollCh <- idx }

	w := NewFillWatcher(FillWatcherConfig{
		Broker:       fbc,
		Dispatcher:   dispatcher,
		Logger:       newFillWatcherTestLogger(),
		Clock:        clock,
		PollInterval: 5 * time.Second,
		MaxDuration:  60 * time.Second,
	})

	w.Watch(domain.OrderPlacedEvent{Email: "u@t.com", OrderID: "ORD_STALE", Timestamp: clock.Now()})

	// 12 polls (60s / 5s) should fully exhaust the budget. Advance and
	// drain each poll in lockstep.
	for i := int32(1); i <= 12; i++ {
		clock.Advance(5 * time.Second)
		select {
		case got := <-pollCh:
			require.Equal(t, i, got)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for poll %d", i)
		}
	}

	// One more advance — the budget-check must stop the loop before the
	// 13th poll fires. We use a short-timeout receive to prove no poll
	// arrives.
	clock.Advance(5 * time.Second)
	select {
	case got := <-pollCh:
		t.Fatalf("expected no further poll after budget exhausted, got poll %d", got)
	case <-time.After(200 * time.Millisecond):
		// expected — no further poll
	}

	w.Wait(2 * time.Second)

	assert.Equal(t, int32(0), atomic.LoadInt32(&eventCount), "no fill event should have fired")
	assert.Equal(t, 12, fbc.callCount(), "should have polled exactly 12 times")
}

// TestFillWatcher_BrokerErrorKeepsPolling asserts that a transient
// GetOrderHistory error does not abort the watcher — transient network
// blips are exactly what the poller exists to tolerate.
func TestFillWatcher_BrokerErrorKeepsPolling(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Now())
	dispatcher := domain.NewEventDispatcher()

	var eventCount int32
	dispatcher.Subscribe("order.filled", func(_ domain.Event) {
		atomic.AddInt32(&eventCount, 1)
	})

	// Snapshots are irrelevant while err is set; we'll flip the error
	// off before the 3rd poll and load a COMPLETE snapshot.
	// NOTE: the hook runs INSIDE GetOrderHistory while holding fbc.mu,
	// so it must never call fbc.mu.Lock() again (would deadlock).
	// Mutations happen via unlocked field writes; safe because the hook
	// runs under the mutex the lookup path uses too.
	fbc := &fakeOrderHistoryClient{
		err: errors.New("temporary kite outage"),
	}
	pollCh := make(chan int32, 32)
	fbc.onCallHook = func(idx int32) {
		// Flip to success on the 3rd poll. We're already inside the
		// mutex-locked GetOrderHistory body, so direct field writes
		// are safe.
		if idx == 3 {
			fbc.err = nil
			fbc.snapshots = [][]broker.Order{
				{{OrderID: "ORD_RETRY", Status: "COMPLETE", FilledQuantity: 5, AveragePrice: 100.0}},
			}
			// Reset callIdx so the next snapshot lookup returns index 0.
			atomic.StoreInt32(&fbc.callIdx, 0)
		}
		pollCh <- idx
	}

	w := NewFillWatcher(FillWatcherConfig{
		Broker:       fbc,
		Dispatcher:   dispatcher,
		Logger:       newFillWatcherTestLogger(),
		Clock:        clock,
		PollInterval: 5 * time.Second,
		MaxDuration:  60 * time.Second,
	})

	w.Watch(domain.OrderPlacedEvent{Email: "u@t.com", OrderID: "ORD_RETRY", Timestamp: clock.Now()})

	// 3 error polls, then one successful poll that returns COMPLETE.
	for i := int32(1); i <= 4; i++ {
		clock.Advance(5 * time.Second)
		select {
		case <-pollCh:
			// ok
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for poll %d", i)
		}
	}

	w.Wait(2 * time.Second)

	assert.Equal(t, int32(1), atomic.LoadInt32(&eventCount), "fill event fires once the broker recovers")
}

// TestFillWatcher_SubscribesToOrderPlacedEvent asserts that Start
// hooks the dispatcher so every OrderPlacedEvent launches a watcher
// automatically — the "bridge" wiring expected by app/wire.go.
func TestFillWatcher_SubscribesToOrderPlacedEvent(t *testing.T) {
	t.Parallel()

	clock := testutil.NewFakeClock(time.Now())
	dispatcher := domain.NewEventDispatcher()

	var filledCount int32
	dispatcher.Subscribe("order.filled", func(_ domain.Event) {
		atomic.AddInt32(&filledCount, 1)
	})

	fbc := &fakeOrderHistoryClient{
		snapshots: [][]broker.Order{
			{{OrderID: "AUTO1", Status: "COMPLETE", FilledQuantity: 1, AveragePrice: 10}},
		},
	}
	pollCh := make(chan int32, 4)
	fbc.onCallHook = func(idx int32) { pollCh <- idx }

	w := NewFillWatcher(FillWatcherConfig{
		Broker:       fbc,
		Dispatcher:   dispatcher,
		Logger:       newFillWatcherTestLogger(),
		Clock:        clock,
		PollInterval: 5 * time.Second,
		MaxDuration:  60 * time.Second,
	})
	w.Start() // subscribes to OrderPlacedEvent on dispatcher

	// Dispatch the event synchronously — the Subscribe handler launches
	// a goroutine, so we drive the clock after the dispatch returns.
	dispatcher.Dispatch(domain.OrderPlacedEvent{
		Email:     "u@t.com",
		OrderID:   "AUTO1",
		Timestamp: clock.Now(),
	})

	clock.Advance(5 * time.Second)
	select {
	case <-pollCh:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not poll after OrderPlacedEvent dispatch")
	}

	w.Wait(2 * time.Second)

	assert.Equal(t, int32(1), atomic.LoadInt32(&filledCount))
}
