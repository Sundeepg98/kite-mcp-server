package eventsourcing

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// newTestStore creates a temporary SQLite DB and initializes the event store.
func newTestStore(t *testing.T) *EventStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_events.db")
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
	})

	store := NewEventStore(db)
	require.NoError(t, store.InitTable())
	return store
}

// --- EventStore tests ---

func TestAppendAndLoadEvents(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	events := []StoredEvent{
		{
			AggregateID:   "order-1",
			AggregateType: "Order",
			EventType:     "OrderPlaced",
			Payload:       []byte(`{"email":"test@example.com","exchange":"NSE","tradingsymbol":"RELIANCE","transaction_type":"BUY","quantity":10,"price":2500.0}`),
			OccurredAt:    now,
			Sequence:      1,
		},
		{
			AggregateID:   "order-1",
			AggregateType: "Order",
			EventType:     "OrderFilled",
			Payload:       []byte(`{"filled_price":2501.5,"filled_quantity":10}`),
			OccurredAt:    now.Add(time.Second),
			Sequence:      2,
		},
	}

	err := store.Append(events...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("order-1")
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "OrderPlaced", loaded[0].EventType)
	assert.Equal(t, "OrderFilled", loaded[1].EventType)
	assert.Equal(t, int64(1), loaded[0].Sequence)
	assert.Equal(t, int64(2), loaded[1].Sequence)
	assert.NotEmpty(t, loaded[0].ID)
	assert.NotEmpty(t, loaded[1].ID)
}

func TestLoadByAggregateIDFilters(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Append events for two different aggregates.
	err := store.Append(
		StoredEvent{
			AggregateID:   "order-A",
			AggregateType: "Order",
			EventType:     "OrderPlaced",
			Payload:       []byte(`{}`),
			OccurredAt:    now,
			Sequence:      1,
		},
		StoredEvent{
			AggregateID:   "order-B",
			AggregateType: "Order",
			EventType:     "OrderPlaced",
			Payload:       []byte(`{}`),
			OccurredAt:    now,
			Sequence:      1,
		},
		StoredEvent{
			AggregateID:   "order-A",
			AggregateType: "Order",
			EventType:     "OrderCancelled",
			Payload:       []byte(`{}`),
			OccurredAt:    now.Add(time.Second),
			Sequence:      2,
		},
	)
	require.NoError(t, err)

	eventsA, err := store.LoadEvents("order-A")
	require.NoError(t, err)
	assert.Len(t, eventsA, 2)

	eventsB, err := store.LoadEvents("order-B")
	require.NoError(t, err)
	assert.Len(t, eventsB, 1)

	eventsNone, err := store.LoadEvents("order-C")
	require.NoError(t, err)
	assert.Len(t, eventsNone, 0)
}

func TestNextSequenceAutoIncrements(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()

	// Empty aggregate starts at sequence 1.
	seq, err := store.NextSequence("order-X")
	require.NoError(t, err)
	assert.Equal(t, int64(1), seq)

	// After appending one event, next is 2.
	err = store.Append(StoredEvent{
		AggregateID:   "order-X",
		AggregateType: "Order",
		EventType:     "OrderPlaced",
		Payload:       []byte(`{}`),
		OccurredAt:    now,
		Sequence:      1,
	})
	require.NoError(t, err)

	seq, err = store.NextSequence("order-X")
	require.NoError(t, err)
	assert.Equal(t, int64(2), seq)
}

func TestLoadEventsSinceFilters(t *testing.T) {
	store := newTestStore(t)
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	t2 := t0.Add(2 * time.Hour)

	err := store.Append(
		StoredEvent{
			AggregateID:   "order-1",
			AggregateType: "Order",
			EventType:     "OrderPlaced",
			Payload:       []byte(`{}`),
			OccurredAt:    t0,
			Sequence:      1,
		},
		StoredEvent{
			AggregateID:   "order-1",
			AggregateType: "Order",
			EventType:     "OrderFilled",
			Payload:       []byte(`{}`),
			OccurredAt:    t2,
			Sequence:      2,
		},
	)
	require.NoError(t, err)

	// Events since t1 should only return the t2 event.
	events, err := store.LoadEventsSince(t1)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "OrderFilled", events[0].EventType)
}

// --- OrderAggregate tests ---

func TestOrderAggregate_PlaceCancelLifecycle(t *testing.T) {
	agg := NewOrderAggregate("order-1")
	assert.Equal(t, OrderStatusNew, agg.Status)
	assert.Equal(t, 0, agg.Version())

	err := agg.Place(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           2500.0,
	}, "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusPlaced, agg.Status)
	assert.Equal(t, "user@example.com", agg.Email)
	assert.Equal(t, "RELIANCE", agg.Tradingsymbol)
	assert.Equal(t, "NSE", agg.Exchange)
	assert.Equal(t, "BUY", agg.TransactionType)
	assert.Equal(t, 10, agg.Quantity)
	assert.Equal(t, 2500.0, agg.Price)
	assert.Equal(t, 1, agg.Version())
	assert.Len(t, agg.PendingEvents(), 1)

	err = agg.Cancel()
	require.NoError(t, err)
	assert.Equal(t, OrderStatusCancelled, agg.Status)
	assert.False(t, agg.CancelledAt.IsZero())
	assert.Equal(t, 2, agg.Version())
	assert.Len(t, agg.PendingEvents(), 2)
}

func TestOrderAggregate_PlaceFillLifecycle(t *testing.T) {
	agg := NewOrderAggregate("order-2")

	err := agg.Place(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "SELL",
		OrderType:       "MARKET",
		Product:         "MIS",
		Quantity:        50,
	}, "trader@example.com")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusPlaced, agg.Status)

	err = agg.Fill(1800.50, 50)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusFilled, agg.Status)
	assert.Equal(t, 1800.50, agg.FilledPrice)
	assert.Equal(t, 50, agg.FilledQuantity)
	assert.False(t, agg.FilledAt.IsZero())
	assert.Equal(t, 2, agg.Version())
}

func TestOrderAggregate_InvalidTransitions(t *testing.T) {
	// Cannot cancel a NEW order.
	agg := NewOrderAggregate("order-3")
	err := agg.Cancel()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel order in NEW state")

	// Cannot fill a NEW order.
	err = agg.Fill(100, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot fill order in NEW state")

	// Cannot place a PLACED order again.
	err = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "TCS", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 5, Price: 3000,
	}, "test@test.com")
	require.NoError(t, err)

	err = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "TCS", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 5, Price: 3000,
	}, "test@test.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot place order in PLACED state")

	// Cannot cancel a FILLED order.
	agg2 := NewOrderAggregate("order-4")
	_ = agg2.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "TCS", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 5, Price: 3000,
	}, "test@test.com")
	_ = agg2.Fill(3001, 5)
	err = agg2.Cancel()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel order in FILLED state")
}

func TestOrderAggregate_PlaceValidation(t *testing.T) {
	agg := NewOrderAggregate("order-v")

	// Zero quantity.
	err := agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 0,
	}, "user@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantity must be positive")

	// Empty tradingsymbol.
	err = agg.Place(broker.OrderParams{
		Exchange: "NSE", TransactionType: "BUY", Quantity: 10,
	}, "user@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tradingsymbol is required")

	// Empty email.
	err = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		Quantity: 10,
	}, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestOrderAggregate_FillValidation(t *testing.T) {
	agg := NewOrderAggregate("order-fv")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")

	err := agg.Fill(0, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fill price must be positive")

	err = agg.Fill(2500, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fill quantity must be positive")
}

func TestReconstitutFromEvents(t *testing.T) {
	store := newTestStore(t)

	// Create and persist an aggregate.
	agg := NewOrderAggregate("order-recon")
	err := agg.Place(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "HDFCBANK",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        20,
		Price:           1700.0,
	}, "recon@example.com")
	require.NoError(t, err)

	err = agg.Fill(1698.50, 20)
	require.NoError(t, err)

	// Convert to stored events and persist.
	storedEvents, err := ToStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 2)

	err = store.Append(storedEvents...)
	require.NoError(t, err)

	// Reconstitute from stored events.
	loaded, err := store.LoadEvents("order-recon")
	require.NoError(t, err)

	reconstituted, err := LoadOrderFromEvents(loaded)
	require.NoError(t, err)

	// Verify state matches.
	assert.Equal(t, agg.AggregateID(), reconstituted.AggregateID())
	assert.Equal(t, OrderStatusFilled, reconstituted.Status)
	assert.Equal(t, "recon@example.com", reconstituted.Email)
	assert.Equal(t, "HDFCBANK", reconstituted.Tradingsymbol)
	assert.Equal(t, "NSE", reconstituted.Exchange)
	assert.Equal(t, "BUY", reconstituted.TransactionType)
	assert.Equal(t, 20, reconstituted.Quantity)
	assert.Equal(t, 1700.0, reconstituted.Price)
	assert.Equal(t, 1698.50, reconstituted.FilledPrice)
	assert.Equal(t, 20, reconstituted.FilledQuantity)
	assert.Equal(t, 2, reconstituted.Version())
	assert.Empty(t, reconstituted.PendingEvents(), "reconstituted aggregate should have no pending events")
}

func TestReconstitutePlaceCancelFromEvents(t *testing.T) {
	store := newTestStore(t)

	agg := NewOrderAggregate("order-cancel-recon")
	err := agg.Place(broker.OrderParams{
		Exchange: "BSE", Tradingsymbol: "WIPRO", TransactionType: "SELL",
		OrderType: "MARKET", Product: "MIS", Quantity: 100,
	}, "cancel@example.com")
	require.NoError(t, err)

	err = agg.Cancel()
	require.NoError(t, err)

	storedEvents, err := ToStoredEvents(agg, 1)
	require.NoError(t, err)
	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("order-cancel-recon")
	require.NoError(t, err)
	reconstituted, err := LoadOrderFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, OrderStatusCancelled, reconstituted.Status)
	assert.Equal(t, "cancel@example.com", reconstituted.Email)
	assert.Equal(t, "WIPRO", reconstituted.Tradingsymbol)
	assert.False(t, reconstituted.CancelledAt.IsZero())
}

func TestLoadOrderFromEventsEmpty(t *testing.T) {
	_, err := LoadOrderFromEvents(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no events to load order from")
}

func TestConcurrentAppendSafety(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := store.Append(StoredEvent{
				AggregateID:   "concurrent-order",
				AggregateType: "Order",
				EventType:     "OrderPlaced",
				Payload:       []byte(`{}`),
				OccurredAt:    now.Add(time.Duration(i) * time.Millisecond),
				Sequence:      int64(i + 1),
			})
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent append error: %v", err)
	}

	events, err := store.LoadEvents("concurrent-order")
	require.NoError(t, err)
	assert.Len(t, events, 20)
}

func TestMarshalPayload(t *testing.T) {
	p := OrderPlacedPayload{
		Email:         "test@test.com",
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Quantity:      5,
		Price:         1500,
	}
	b, err := MarshalPayload(p)
	require.NoError(t, err)

	var decoded OrderPlacedPayload
	err = json.Unmarshal(b, &decoded)
	require.NoError(t, err)
	assert.Equal(t, p, decoded)
}

func TestClearPendingEvents(t *testing.T) {
	agg := NewOrderAggregate("order-clear")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "TCS", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 1, Price: 100,
	}, "test@test.com")
	assert.Len(t, agg.PendingEvents(), 1)

	agg.ClearPendingEvents()
	assert.Empty(t, agg.PendingEvents())
}

func TestAggregateType(t *testing.T) {
	agg := NewOrderAggregate("order-type-test")
	assert.Equal(t, "Order", agg.AggregateType())
	assert.Equal(t, "order-type-test", agg.AggregateID())
}
