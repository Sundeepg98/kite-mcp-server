package eventsourcing

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// testStore opens a fresh in-memory DB and an EventStore on top, with both
// domain_events and event_outbox tables initialized. Caller is responsible
// for any pump lifecycle.
func testStore(t *testing.T) (*EventStore, *alerts.DB) {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store := NewEventStore(db)
	require.NoError(t, store.InitTable())
	require.NoError(t, store.InitOutboxTable())
	return store, db
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func sampleEvent(aggregateID string, seq int64) StoredEvent {
	return StoredEvent{
		AggregateID:   aggregateID,
		AggregateType: "Order",
		EventType:     "order.placed",
		Payload:       []byte(`{"qty":1}`),
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
}

func TestAppendToOutbox_WritesPendingRow(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	require.NoError(t, store.AppendToOutbox(sampleEvent("O1", 1)))

	// Drain manually — the pump-less test path. Should pick up the row.
	n, err := store.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "Drain must consume the pending row")

	events, err := store.LoadEvents("O1")
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "order.placed", events[0].EventType)
}

func TestDrain_IsIdempotent(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	require.NoError(t, store.AppendToOutbox(sampleEvent("O2", 1)))

	n1, err := store.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n1)

	// Second drain should report 0 — the row is already processed.
	n2, err := store.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n2, "second drain on the same row must be a no-op")
}

func TestDrain_OrdersByInsertion(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	for i := int64(1); i <= 5; i++ {
		require.NoError(t, store.AppendToOutbox(sampleEvent("O3", i)))
		// Stagger inserted_at so timestamps differ.
		time.Sleep(2 * time.Millisecond)
	}

	n, err := store.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 5, n)

	events, err := store.LoadEvents("O3")
	require.NoError(t, err)
	require.Len(t, events, 5)
	for i, e := range events {
		assert.Equal(t, int64(i+1), e.Sequence, "drain must preserve sequence order")
	}
}

func TestOutboxPump_StartupRecoversLeftover(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	// Simulate a previous-process crash: row in outbox, not yet drained.
	require.NoError(t, store.AppendToOutbox(sampleEvent("O4", 1)))

	pump := NewOutboxPump(store, newDiscardLogger())
	t.Cleanup(pump.Stop)

	// Wait briefly for the startup-drain tick (immediate Drain in run()).
	require.Eventually(t, func() bool {
		events, err := store.LoadEvents("O4")
		return err == nil && len(events) == 1
	}, 1*time.Second, 20*time.Millisecond)
}

func TestOutboxPump_DrainsContinuously(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	pump := NewOutboxPump(store, newDiscardLogger())
	t.Cleanup(pump.Stop)

	// After pump is running, write some new outbox entries; they should
	// flow through within a tick or two.
	for i := int64(1); i <= 3; i++ {
		require.NoError(t, store.AppendToOutbox(sampleEvent("O5", i)))
	}
	require.Eventually(t, func() bool {
		events, err := store.LoadEvents("O5")
		return err == nil && len(events) == 3
	}, 1*time.Second, 20*time.Millisecond)
}

func TestOutboxPump_StopIsIdempotent(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	pump := NewOutboxPump(store, newDiscardLogger())
	pump.Stop()
	pump.Stop() // second call must not panic
}

func TestDrain_ContextCancel(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	for i := int64(1); i <= 5; i++ {
		require.NoError(t, store.AppendToOutbox(sampleEvent("O6", i)))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel
	// The drain may process zero or some rows depending on whether
	// ctx.Err() is checked at the loop boundary; the contract is that
	// it doesn't error on its own besides ctx.Err() and stops cleanly.
	n, err := store.Drain(ctx)
	if err != nil {
		assert.ErrorIs(t, err, context.Canceled)
	}
	assert.LessOrEqual(t, n, 5)
}
