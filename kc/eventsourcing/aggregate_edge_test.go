package eventsourcing

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// =============================================================================
// Deserialization error paths — bad JSON payloads
// =============================================================================

func TestDeserializeAlertEvent_BadJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		eventType string
		payload   string
	}{
		{"AlertCreated bad json", "AlertCreated", `{bad json`},
		{"AlertTriggered bad json", "AlertTriggered", `{bad json`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := StoredEvent{
				AggregateID: "a1",
				EventType:   tc.eventType,
				Payload:     []byte(tc.payload),
				OccurredAt:  time.Now(),
			}
			_, err := deserializeAlertEvent(stored)
			assert.Error(t, err)
		})
	}
}

func TestDeserializeAlertEvent_UnknownType(t *testing.T) {
	t.Parallel()
	stored := StoredEvent{
		AggregateID: "a1",
		EventType:   "AlertUnknown",
		Payload:     []byte(`{}`),
		OccurredAt:  time.Now(),
	}
	_, err := deserializeAlertEvent(stored)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown alert event type")
}

func TestDeserializeOrderEvent_BadJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		eventType string
		payload   string
	}{
		{"OrderPlaced bad json", "OrderPlaced", `{bad`},
		{"OrderModified bad json", "OrderModified", `{bad`},
		{"OrderFilled bad json", "OrderFilled", `{bad`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := StoredEvent{
				AggregateID: "o1",
				EventType:   tc.eventType,
				Payload:     []byte(tc.payload),
				OccurredAt:  time.Now(),
			}
			_, err := deserializeOrderEvent(stored)
			assert.Error(t, err)
		})
	}
}

func TestDeserializeOrderEvent_UnknownType(t *testing.T) {
	t.Parallel()
	stored := StoredEvent{
		AggregateID: "o1",
		EventType:   "OrderBogus",
		Payload:     []byte(`{}`),
		OccurredAt:  time.Now(),
	}
	_, err := deserializeOrderEvent(stored)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown order event type")
}

func TestDeserializePositionEvent_BadJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		eventType string
		payload   string
	}{
		{"PositionOpened bad json", "PositionOpened", `{bad`},
		{"PositionClosed bad json", "PositionClosed", `{bad`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := StoredEvent{
				AggregateID: "p1",
				EventType:   tc.eventType,
				Payload:     []byte(tc.payload),
				OccurredAt:  time.Now(),
			}
			_, err := deserializePositionEvent(stored)
			assert.Error(t, err)
		})
	}
}

func TestDeserializePositionEvent_UnknownType(t *testing.T) {
	t.Parallel()
	stored := StoredEvent{
		AggregateID: "p1",
		EventType:   "PositionBogus",
		Payload:     []byte(`{}`),
		OccurredAt:  time.Now(),
	}
	_, err := deserializePositionEvent(stored)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown position event type")
}

// =============================================================================
// LoadXFromEvents — deserialization error propagation
// =============================================================================

func TestLoadAlertFromEvents_DeserializationError(t *testing.T) {
	t.Parallel()
	events := []StoredEvent{
		{
			AggregateID: "a1",
			EventType:   "AlertBogus",
			Payload:     []byte(`{}`),
			OccurredAt:  time.Now(),
			Sequence:    1,
		},
	}
	_, err := LoadAlertFromEvents(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize event")
}

func TestLoadOrderFromEvents_DeserializationError(t *testing.T) {
	t.Parallel()
	events := []StoredEvent{
		{
			AggregateID: "o1",
			EventType:   "OrderBogus",
			Payload:     []byte(`{}`),
			OccurredAt:  time.Now(),
			Sequence:    1,
		},
	}
	_, err := LoadOrderFromEvents(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize event")
}

func TestLoadPositionFromEvents_DeserializationError(t *testing.T) {
	t.Parallel()
	events := []StoredEvent{
		{
			AggregateID: "p1",
			EventType:   "PositionBogus",
			Payload:     []byte(`{}`),
			OccurredAt:  time.Now(),
			Sequence:    1,
		},
	}
	_, err := LoadPositionFromEvents(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize event")
}

// =============================================================================
// ToXStoredEvents — unknown event type (default branch)
// =============================================================================

// fakeEvent implements domain.Event but doesn't match any known case.
type fakeEvent struct{ ts time.Time }

func (f *fakeEvent) EventType() string    { return "FakeEvent" }
func (f *fakeEvent) OccurredAt() time.Time { return f.ts }

func TestToAlertStoredEvents_UnknownEventType(t *testing.T) {
	t.Parallel()
	agg := NewAlertAggregate("a-unknown")
	// Manually inject a fake pending event that won't match any switch case.
	agg.pending = append(agg.pending, &fakeEvent{ts: time.Now()})

	_, err := ToAlertStoredEvents(agg, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestToStoredEvents_UnknownEventType(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("o-unknown")
	agg.pending = append(agg.pending, &fakeEvent{ts: time.Now()})

	_, err := ToStoredEvents(agg, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestToPositionStoredEvents_UnknownEventType(t *testing.T) {
	t.Parallel()
	agg := NewPositionAggregate("p-unknown")
	agg.pending = append(agg.pending, &fakeEvent{ts: time.Now()})

	_, err := ToPositionStoredEvents(agg, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

// =============================================================================
// CanFill — cancelled state (covers the missing branch)
// =============================================================================

func TestCanFill_CancelledState(t *testing.T) {
	t.Parallel()
	agg := NewOrderAggregate("o-can-fill-cancel")
	_ = agg.Place(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY",
		OrderType: "LIMIT", Quantity: 10, Price: 2500,
	}, "u@test.com")
	_ = agg.Cancel()

	err := agg.CanFill()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot fill cancelled order")
}

// =============================================================================
// CanClose — verify both branches
// =============================================================================

func TestCanClose_BothBranches(t *testing.T) {
	t.Parallel()
	agg := NewPositionAggregate("p-canclose-both")
	_ = agg.Open("u@test.com", "RELIANCE", "NSE", "BUY", 10, 2500)

	// Open => can close
	assert.NoError(t, agg.CanClose())

	// Close it
	_ = agg.Close("order-1", "SELL")

	// Closed => already closed
	err := agg.CanClose()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "position already closed")
}

// TestCanClose_UnknownState covers the "not in OPEN state" branch that differs from "already closed".
// This requires forcing an invalid state that shouldn't occur in normal usage.
func TestCanClose_UnknownState(t *testing.T) {
	t.Parallel()
	agg := NewPositionAggregate("p-canclose-unknown")
	// Manually set an invalid status
	agg.Status = "UNKNOWN"

	err := agg.CanClose()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "position not in OPEN state, got UNKNOWN")
}

// =============================================================================
// scanEvents error paths (using mock rows)
// =============================================================================

// mockRows implements the interface expected by scanEvents.
type mockRows struct {
	data    [][]interface{}
	idx     int
	scanErr error
	iterErr error
}

func (m *mockRows) Next() bool {
	return m.idx < len(m.data)
}

func (m *mockRows) Scan(dest ...any) error {
	if m.scanErr != nil {
		return m.scanErr
	}
	row := m.data[m.idx]
	m.idx++
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = row[i].(string)
		case *int64:
			*p = row[i].(int64)
		}
	}
	return nil
}

func (m *mockRows) Err() error {
	return m.iterErr
}

func TestScanEvents_ScanError(t *testing.T) {
	t.Parallel()
	rows := &mockRows{
		data:    [][]interface{}{{"id", "agg", "aggtype", "evtype", "{}", "2026-01-01T00:00:00Z", int64(1)}},
		scanErr: fmt.Errorf("scan failed"),
	}
	_, err := scanEvents(rows)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan event")
}

func TestScanEvents_BadTimestamp(t *testing.T) {
	t.Parallel()
	rows := &mockRows{
		data: [][]interface{}{{"id", "agg", "aggtype", "evtype", "{}", "not-a-time", int64(1)}},
	}
	_, err := scanEvents(rows)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse occurred_at")
}

func TestScanEvents_RowsErr(t *testing.T) {
	t.Parallel()
	rows := &mockRows{
		data:    [][]interface{}{}, // no data, but Err returns error
		iterErr: fmt.Errorf("iteration failed"),
	}
	_, err := scanEvents(rows)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "iterate events")
}

func TestScanEvents_Success(t *testing.T) {
	t.Parallel()
	rows := &mockRows{
		data: [][]interface{}{
			{"id1", "agg1", "Order", "OrderPlaced", `{"email":"u@test.com"}`, "2026-01-01T10:00:00Z", int64(1)},
			{"id2", "agg1", "Order", "OrderFilled", `{"filled_price":100}`, "2026-01-01T10:01:00Z", int64(2)},
		},
	}
	events, err := scanEvents(rows)
	require.NoError(t, err)
	assert.Len(t, events, 2)
	assert.Equal(t, "id1", events[0].ID)
	assert.Equal(t, "OrderPlaced", events[0].EventType)
}

// =============================================================================
// MarshalPayload — error path (unmarshalable value)
// =============================================================================

func TestMarshalPayload_Error(t *testing.T) {
	t.Parallel()
	// channels cannot be JSON marshaled
	_, err := MarshalPayload(make(chan int))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "marshal payload")
}

// =============================================================================
// Full round-trip: deserialization of all valid event types
// =============================================================================

func TestDeserializeOrderEvent_AllValidTypes(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name      string
		eventType string
		payload   interface{}
	}{
		{"OrderPlaced", "OrderPlaced", OrderPlacedPayload{
			Email: "u@test.com", Exchange: "NSE", Tradingsymbol: "INFY",
			TransactionType: "BUY", OrderType: "LIMIT", Product: "CNC",
			Quantity: 10, Price: 1500,
		}},
		{"OrderModified", "OrderModified", OrderModifiedPayload{
			NewQuantity: 20, NewPrice: 2000, NewOrderType: "MARKET",
		}},
		{"OrderCancelled", "OrderCancelled", OrderCancelledPayload{}},
		{"OrderFilled", "OrderFilled", OrderFilledPayload{
			FilledPrice: 1500, FilledQuantity: 10,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			stored := StoredEvent{
				AggregateID: "o1",
				EventType:   tc.eventType,
				Payload:     payload,
				OccurredAt:  now,
				Sequence:    1,
			}
			event, err := deserializeOrderEvent(stored)
			require.NoError(t, err)
			assert.Equal(t, tc.eventType, event.EventType())
			assert.Equal(t, now, event.OccurredAt())
		})
	}
}

func TestDeserializeAlertEvent_AllValidTypes(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name      string
		eventType string
		payload   interface{}
	}{
		{"AlertCreated", "AlertCreated", AlertCreatedPayload{
			Email: "u@test.com", Symbol: "INFY", Exchange: "NSE",
			TargetPrice: 1500, Direction: "above",
		}},
		{"AlertTriggered", "AlertTriggered", AlertTriggeredPayload{CurrentPrice: 1505}},
		{"AlertDeleted", "AlertDeleted", AlertDeletedPayload{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			stored := StoredEvent{
				AggregateID: "a1",
				EventType:   tc.eventType,
				Payload:     payload,
				OccurredAt:  now,
				Sequence:    1,
			}
			event, err := deserializeAlertEvent(stored)
			require.NoError(t, err)
			assert.Equal(t, tc.eventType, event.EventType())
			assert.Equal(t, now, event.OccurredAt())
		})
	}
}

func TestDeserializePositionEvent_AllValidTypes(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name      string
		eventType string
		payload   interface{}
	}{
		{"PositionOpened", "PositionOpened", PositionOpenedPayload{
			Email: "u@test.com", Symbol: "INFY", Exchange: "NSE",
			TransactionType: "BUY", Quantity: 10, AvgPrice: 1500,
		}},
		{"PositionClosed", "PositionClosed", PositionClosedPayload{
			CloseOrderID: "order-1", TransactionType: "SELL",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.payload)
			require.NoError(t, err)
			stored := StoredEvent{
				AggregateID: "p1",
				EventType:   tc.eventType,
				Payload:     payload,
				OccurredAt:  now,
				Sequence:    1,
			}
			event, err := deserializePositionEvent(stored)
			require.NoError(t, err)
			assert.Equal(t, tc.eventType, event.EventType())
			assert.Equal(t, now, event.OccurredAt())
		})
	}
}

// =============================================================================
// Event type methods on internal event types
// =============================================================================

func TestInternalEventTypes_OccurredAt(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name  string
		event domain.Event
	}{
		{"alertCreated", &alertCreatedEvent{timestamp: now}},
		{"alertTriggered", &alertTriggeredEvent{timestamp: now}},
		{"alertDeleted", &alertDeletedEvent{timestamp: now}},
		{"orderPlaced", &orderPlacedEvent{timestamp: now}},
		{"orderModified", &orderModifiedEvent{timestamp: now}},
		{"orderCancelled", &orderCancelledEvent{timestamp: now}},
		{"orderFilled", &orderFilledEvent{timestamp: now}},
		{"positionOpened", &positionOpenedEvent{timestamp: now}},
		{"positionClosed", &positionClosedEvent{timestamp: now}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, now, tc.event.OccurredAt())
			assert.NotEmpty(t, tc.event.EventType())
		})
	}
}

// =============================================================================
// Store: Append with pre-set ID (covers the ID-empty check skip)
// =============================================================================

func TestAppend_WithPresetID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)

	customID := "custom-event-id-12345"
	err := store.Append(StoredEvent{
		ID:            customID,
		AggregateID:   "order-preset",
		AggregateType: "Order",
		EventType:     "OrderPlaced",
		Payload:       []byte(`{}`),
		OccurredAt:    now,
		Sequence:      1,
	})
	require.NoError(t, err)

	loaded, err := store.LoadEvents("order-preset")
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, customID, loaded[0].ID)
}

// =============================================================================
// Full reconstitution: Alert Create -> Trigger -> Delete
// =============================================================================

// =============================================================================
// Store: error paths (closed DB)
// =============================================================================

func TestAppend_DBError(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Get underlying DB and close it
	// We can force an error by corrupting state: drop the table
	store.db.ExecDDL("DROP TABLE domain_events")

	err := store.Append(StoredEvent{
		AggregateID:   "err-order",
		AggregateType: "Order",
		EventType:     "OrderPlaced",
		Payload:       []byte(`{}`),
		OccurredAt:    time.Now(),
		Sequence:      1,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "append event")
}

func TestLoadEvents_DBError(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Drop the table to force query error
	store.db.ExecDDL("DROP TABLE domain_events")

	_, err := store.LoadEvents("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load events")
}

func TestLoadEventsSince_DBError(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Drop the table to force query error
	store.db.ExecDDL("DROP TABLE domain_events")

	_, err := store.LoadEventsSince(time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load events since")
}

func TestNextSequence_DBError(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	// Drop the table to force query error
	store.db.ExecDDL("DROP TABLE domain_events")

	_, err := store.NextSequence("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "next sequence")
}

func TestAlertAggregate_FullLifecycleReconstitution(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	agg := NewAlertAggregate("alert-full")
	_ = agg.Create("full@test.com", "TCS", "NSE", 3000, "above")
	_ = agg.Trigger(3005)
	_ = agg.Delete()

	storedEvents, err := ToAlertStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 3)

	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("alert-full")
	require.NoError(t, err)

	reconstituted, err := LoadAlertFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, AlertStatusDeleted, reconstituted.Status)
	assert.Equal(t, "full@test.com", reconstituted.Email)
	assert.Equal(t, 3, reconstituted.Version())
}
