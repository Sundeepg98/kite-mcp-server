package eventsourcing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PositionAggregate tests ---

func TestPositionAggregate_OpenCloseLifecycle(t *testing.T) {
	agg := NewPositionAggregate("pos-1")
	assert.Equal(t, PositionStatusOpen, agg.Status)
	assert.Equal(t, 0, agg.Version())
	assert.Equal(t, "Position", agg.AggregateType())

	err := agg.Open("user@example.com", "RELIANCE", "NSE", "BUY", 10, 2500.0)
	require.NoError(t, err)
	assert.Equal(t, PositionStatusOpen, agg.Status)
	assert.Equal(t, "user@example.com", agg.Email)
	assert.Equal(t, "RELIANCE", agg.Symbol)
	assert.Equal(t, "NSE", agg.Exchange)
	assert.Equal(t, "BUY", agg.TransactionType)
	assert.Equal(t, 10, agg.Quantity)
	assert.Equal(t, 2500.0, agg.AvgPrice)
	assert.Equal(t, 1, agg.Version())
	assert.Len(t, agg.PendingEvents(), 1)
	assert.False(t, agg.OpenedAt.IsZero())

	err = agg.Close("order-close-1", "SELL")
	require.NoError(t, err)
	assert.Equal(t, PositionStatusClosed, agg.Status)
	assert.Equal(t, 0, agg.Quantity)
	assert.False(t, agg.ClosedAt.IsZero())
	assert.Equal(t, 2, agg.Version())
	assert.Len(t, agg.PendingEvents(), 2)
}

func TestPositionAggregate_CannotCloseAlreadyClosed(t *testing.T) {
	agg := NewPositionAggregate("pos-2")
	_ = agg.Open("user@example.com", "INFY", "NSE", "SELL", 50, 1800.0)
	_ = agg.Close("order-c", "BUY")

	err := agg.Close("order-c2", "BUY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "position already closed")
}

func TestPositionAggregate_CannotOpenTwice(t *testing.T) {
	agg := NewPositionAggregate("pos-3")
	err := agg.Open("user@example.com", "TCS", "NSE", "BUY", 5, 3000.0)
	require.NoError(t, err)

	err = agg.Open("user@example.com", "TCS", "NSE", "BUY", 5, 3000.0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "position already opened")
}

func TestPositionAggregate_OpenValidation(t *testing.T) {
	agg := NewPositionAggregate("pos-v")

	err := agg.Open("", "RELIANCE", "NSE", "BUY", 10, 2500)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	err = agg.Open("user@example.com", "", "NSE", "BUY", 10, 2500)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symbol is required")

	err = agg.Open("user@example.com", "RELIANCE", "NSE", "BUY", 0, 2500)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantity must be positive")
}

func TestPositionAggregate_CanCloseInvariant(t *testing.T) {
	agg := NewPositionAggregate("pos-inv")

	// Open position can be closed.
	_ = agg.Open("user@example.com", "RELIANCE", "NSE", "BUY", 10, 2500)
	assert.NoError(t, agg.CanClose())

	// Closed position cannot be closed again.
	_ = agg.Close("order-c", "SELL")
	assert.Error(t, agg.CanClose())
	assert.Contains(t, agg.CanClose().Error(), "position already closed")
}

func TestPositionAggregate_ReconstitutionFromEvents(t *testing.T) {
	store := newTestStore(t)

	agg := NewPositionAggregate("pos-recon")
	_ = agg.Open("recon@example.com", "HDFCBANK", "NSE", "BUY", 20, 1700.0)
	_ = agg.Close("order-close-recon", "SELL")

	storedEvents, err := ToPositionStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 2)
	assert.Equal(t, "PositionOpened", storedEvents[0].EventType)
	assert.Equal(t, "PositionClosed", storedEvents[1].EventType)

	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("pos-recon")
	require.NoError(t, err)

	reconstituted, err := LoadPositionFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, "pos-recon", reconstituted.AggregateID())
	assert.Equal(t, PositionStatusClosed, reconstituted.Status)
	assert.Equal(t, "recon@example.com", reconstituted.Email)
	assert.Equal(t, "HDFCBANK", reconstituted.Symbol)
	assert.Equal(t, 0, reconstituted.Quantity)
	assert.Equal(t, 2, reconstituted.Version())
	assert.Empty(t, reconstituted.PendingEvents())
}

func TestPositionAggregate_LoadFromEventsEmpty(t *testing.T) {
	_, err := LoadPositionFromEvents(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no events to load position from")
}
