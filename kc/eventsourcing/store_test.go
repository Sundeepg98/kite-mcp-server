package eventsourcing

// Coverage ceiling: 99.2% — 6 unreachable lines across 3 aggregate files.
// All are defensive error paths: type-switch default branches (unknown event types)
// and MarshalPayload error checks (json.Marshal on plain structs never fails).

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	assert.Equal(t, "RELIANCE", agg.Instrument.Tradingsymbol)
	assert.Equal(t, "NSE", agg.Instrument.Exchange)
	assert.Equal(t, "BUY", agg.TransactionType)
	assert.Equal(t, 10, agg.Quantity.Int())
	assert.Equal(t, 2500.0, agg.Price.Amount)
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
	t.Parallel()
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
	assert.Equal(t, 1800.50, agg.FilledPrice.Amount)
	assert.Equal(t, 50, agg.FilledQuantity.Int())
	assert.False(t, agg.FilledAt.IsZero())
	assert.Equal(t, 2, agg.Version())
}

func TestOrderAggregate_InvalidTransitions(t *testing.T) {
	t.Parallel()
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
	assert.Contains(t, err.Error(), "cannot cancel filled order")
}

func TestOrderAggregate_PlaceValidation(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	assert.Contains(t, err.Error(), "quantity must be positive")
}

func TestReconstitutFromEvents(t *testing.T) {
	t.Parallel()
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
	assert.Equal(t, "HDFCBANK", reconstituted.Instrument.Tradingsymbol)
	assert.Equal(t, "NSE", reconstituted.Instrument.Exchange)
	assert.Equal(t, "BUY", reconstituted.TransactionType)
	assert.Equal(t, 20, reconstituted.Quantity.Int())
	assert.Equal(t, 1700.0, reconstituted.Price.Amount)
	assert.Equal(t, 1698.50, reconstituted.FilledPrice.Amount)
	assert.Equal(t, 20, reconstituted.FilledQuantity.Int())
	assert.Equal(t, 2, reconstituted.Version())
	assert.Empty(t, reconstituted.PendingEvents(), "reconstituted aggregate should have no pending events")
}

func TestReconstitutePlaceCancelFromEvents(t *testing.T) {
	t.Parallel()
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
	assert.Equal(t, "WIPRO", reconstituted.Instrument.Tradingsymbol)
	assert.False(t, reconstituted.CancelledAt.IsZero())
}

func TestLoadOrderFromEventsEmpty(t *testing.T) {
	t.Parallel()
	_, err := LoadOrderFromEvents(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no events to load order from")
}

func TestConcurrentAppendSafety(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	now := time.Now().UTC()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := range 20 {
		wg.Go(func() {
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
		})
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	agg := NewOrderAggregate("order-type-test")
	assert.Equal(t, "Order", agg.AggregateType())
	assert.Equal(t, "order-type-test", agg.AggregateID())
}

// --- OrderModified tests ---

func TestOrderAggregate_PlaceModifyFillLifecycle(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("order-modify-1")

	err := agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Product: "CNC", Quantity: 10, Price: 2500.0,
	}, "user@example.com")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusPlaced, agg.Status)

	// Modify price and quantity.
	err = agg.Modify(20, 2600.0, "")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusModified, agg.Status)
	assert.Equal(t, 20, agg.Quantity.Int())
	assert.Equal(t, 2600.0, agg.Price.Amount)
	assert.Equal(t, "LIMIT", agg.OrderType) // unchanged since we passed ""
	assert.Equal(t, 1, agg.ModifyCount)
	assert.False(t, agg.ModifiedAt.IsZero())
	assert.Equal(t, 2, agg.Version())

	// Fill the modified order.
	err = agg.Fill(2598.0, 20)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusFilled, agg.Status)
	assert.Equal(t, 3, agg.Version())
}

func TestOrderAggregate_ModifyMultipleTimes(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("order-multi-mod")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "INFY", TransactionType: "BUY",
		OrderType: "LIMIT", Product: "CNC", Quantity: 10, Price: 1500,
	}, "user@example.com")

	// First modification.
	err := agg.Modify(15, 1550, "")
	require.NoError(t, err)
	assert.Equal(t, 1, agg.ModifyCount)

	// Second modification — modify a MODIFIED order.
	err = agg.Modify(20, 1600, "MARKET")
	require.NoError(t, err)
	assert.Equal(t, 2, agg.ModifyCount)
	assert.Equal(t, "MARKET", agg.OrderType)
	assert.Equal(t, 20, agg.Quantity.Int())
	assert.Equal(t, 1600.0, agg.Price.Amount)
}

func TestOrderAggregate_ModifyCancelLifecycle(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("order-mod-cancel")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "TCS", TransactionType: "SELL",
		OrderType: "LIMIT", Product: "CNC", Quantity: 5, Price: 3000,
	}, "user@example.com")

	err := agg.Modify(10, 3100, "")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusModified, agg.Status)

	// Cancel a modified order — should succeed.
	err = agg.Cancel()
	require.NoError(t, err)
	assert.Equal(t, OrderStatusCancelled, agg.Status)
}

func TestOrderAggregate_ModifyInvalidTransitions(t *testing.T) {
	t.Parallel()
	// Cannot modify a NEW order.
	agg := NewOrderAggregate("order-mod-inv-1")
	err := agg.Modify(10, 100, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot modify order in NEW state")

	// Cannot modify a CANCELLED order.
	agg2 := NewOrderAggregate("order-mod-inv-2")
	_ = agg2.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")
	_ = agg2.Cancel()
	err = agg2.Modify(20, 2600, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot modify cancelled order")

	// Cannot modify a FILLED order.
	agg3 := NewOrderAggregate("order-mod-inv-3")
	_ = agg3.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")
	_ = agg3.Fill(2501, 10)
	err = agg3.Modify(20, 2600, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot modify filled order")
}

func TestOrderAggregate_ModifyValidation(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("order-mod-val")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")

	// Zero quantity.
	err := agg.Modify(0, 2600, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantity must be positive")

	// No changes.
	err = agg.Modify(10, 2500, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "modify must change at least one field")

	// Same quantity and price but new order type — should succeed.
	err = agg.Modify(10, 2500, "MARKET")
	require.NoError(t, err)
}

// --- Invariant query method tests ---

func TestCanModifyInvariant(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("inv-modify")
	assert.Error(t, agg.CanModify(), "NEW should not be modifiable")

	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")
	assert.NoError(t, agg.CanModify(), "PLACED should be modifiable")
}

func TestCanCancelInvariant(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("inv-cancel")
	assert.Error(t, agg.CanCancel(), "NEW should not be cancellable")

	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")
	assert.NoError(t, agg.CanCancel(), "PLACED should be cancellable")

	_ = agg.Cancel()
	assert.Error(t, agg.CanCancel(), "CANCELLED should not be cancellable again")
}

func TestCanFillInvariant(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("inv-fill")
	assert.Error(t, agg.CanFill(), "NEW should not be fillable")

	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "user@example.com")
	assert.NoError(t, agg.CanFill(), "PLACED should be fillable")

	_ = agg.Fill(2501, 10)
	assert.Error(t, agg.CanFill(), "FILLED should not be fillable again")
}

// --- Modify event reconstitution tests ---

func TestReconstitutePlaceModifyFillFromEvents(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	agg := NewOrderAggregate("order-mod-recon")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Product: "CNC", Quantity: 10, Price: 2500,
	}, "mod@example.com")
	_ = agg.Modify(20, 2600, "")
	_ = agg.Fill(2598, 20)

	storedEvents, err := ToStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 3)
	assert.Equal(t, "OrderPlaced", storedEvents[0].EventType)
	assert.Equal(t, "OrderModified", storedEvents[1].EventType)
	assert.Equal(t, "OrderFilled", storedEvents[2].EventType)

	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("order-mod-recon")
	require.NoError(t, err)

	reconstituted, err := LoadOrderFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, OrderStatusFilled, reconstituted.Status)
	assert.Equal(t, 20, reconstituted.Quantity.Int())
	assert.Equal(t, 2600.0, reconstituted.Price.Amount)
	assert.Equal(t, 2598.0, reconstituted.FilledPrice.Amount)
	assert.Equal(t, 1, reconstituted.ModifyCount)
	assert.Equal(t, 3, reconstituted.Version())
	assert.Empty(t, reconstituted.PendingEvents())
}
