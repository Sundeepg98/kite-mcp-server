package eventsourcing

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- AlertAggregate tests ---

func TestAlertAggregate_CreateTriggerLifecycle(t *testing.T) {
	agg := NewAlertAggregate("alert-1")
	assert.Equal(t, AlertStatusActive, agg.Status)
	assert.Equal(t, 0, agg.Version())
	assert.Equal(t, "Alert", agg.AggregateType())

	err := agg.Create("user@example.com", "RELIANCE", "NSE", 2600.0, "above")
	require.NoError(t, err)
	assert.Equal(t, AlertStatusActive, agg.Status)
	assert.Equal(t, "user@example.com", agg.Email)
	assert.Equal(t, "RELIANCE", agg.Symbol)
	assert.Equal(t, "NSE", agg.Exchange)
	assert.Equal(t, 2600.0, agg.TargetPrice)
	assert.Equal(t, "above", agg.Direction)
	assert.Equal(t, 1, agg.Version())
	assert.Len(t, agg.PendingEvents(), 1)
	assert.False(t, agg.CreatedAt.IsZero())

	err = agg.Trigger(2605.50)
	require.NoError(t, err)
	assert.Equal(t, AlertStatusTriggered, agg.Status)
	assert.False(t, agg.TriggeredAt.IsZero())
	assert.Equal(t, 2, agg.Version())
	assert.Len(t, agg.PendingEvents(), 2)
}

func TestAlertAggregate_CreateDeleteLifecycle(t *testing.T) {
	agg := NewAlertAggregate("alert-2")
	_ = agg.Create("user@example.com", "INFY", "NSE", 1500.0, "below")

	err := agg.Delete()
	require.NoError(t, err)
	assert.Equal(t, AlertStatusDeleted, agg.Status)
	assert.False(t, agg.DeletedAt.IsZero())
	assert.Equal(t, 2, agg.Version())
}

func TestAlertAggregate_CannotTriggerTriggered(t *testing.T) {
	agg := NewAlertAggregate("alert-3")
	_ = agg.Create("user@example.com", "TCS", "NSE", 3000.0, "above")
	_ = agg.Trigger(3001.0)

	err := agg.Trigger(3002.0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alert not active")
}

func TestAlertAggregate_CannotTriggerDeleted(t *testing.T) {
	agg := NewAlertAggregate("alert-4")
	_ = agg.Create("user@example.com", "TCS", "NSE", 3000.0, "above")
	_ = agg.Delete()

	err := agg.Trigger(3001.0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alert not active")
}

func TestAlertAggregate_CannotDeleteAlreadyDeleted(t *testing.T) {
	agg := NewAlertAggregate("alert-5")
	_ = agg.Create("user@example.com", "INFY", "NSE", 1500.0, "below")
	_ = agg.Delete()

	err := agg.Delete()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alert already deleted")
}

func TestAlertAggregate_CanDeleteTriggered(t *testing.T) {
	// Triggered alerts can still be cleaned up via delete.
	agg := NewAlertAggregate("alert-6")
	_ = agg.Create("user@example.com", "RELIANCE", "NSE", 2600.0, "above")
	_ = agg.Trigger(2605.0)

	err := agg.Delete()
	require.NoError(t, err)
	assert.Equal(t, AlertStatusDeleted, agg.Status)
}

func TestAlertAggregate_CannotCreateTwice(t *testing.T) {
	agg := NewAlertAggregate("alert-7")
	_ = agg.Create("user@example.com", "TCS", "NSE", 3000.0, "above")

	err := agg.Create("user@example.com", "TCS", "NSE", 3000.0, "above")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alert already created")
}

func TestAlertAggregate_CreateValidation(t *testing.T) {
	agg := NewAlertAggregate("alert-v")

	err := agg.Create("", "RELIANCE", "NSE", 2600, "above")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	err = agg.Create("user@example.com", "", "NSE", 2600, "above")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symbol is required")

	err = agg.Create("user@example.com", "RELIANCE", "NSE", 0, "above")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target price must be positive")
}

func TestAlertAggregate_InvariantMethods(t *testing.T) {
	agg := NewAlertAggregate("alert-inv")
	_ = agg.Create("user@example.com", "RELIANCE", "NSE", 2600, "above")

	assert.NoError(t, agg.CanTrigger())
	assert.NoError(t, agg.CanDelete())

	_ = agg.Trigger(2605)
	assert.Error(t, agg.CanTrigger())
	assert.NoError(t, agg.CanDelete()) // triggered can still be deleted
}

func TestAlertAggregate_ReconstitutionFromEvents(t *testing.T) {
	store := newTestStore(t)

	agg := NewAlertAggregate("alert-recon")
	_ = agg.Create("recon@example.com", "HDFCBANK", "NSE", 1700.0, "below")
	_ = agg.Trigger(1695.50)

	storedEvents, err := ToAlertStoredEvents(agg, 1)
	require.NoError(t, err)
	require.Len(t, storedEvents, 2)
	assert.Equal(t, "AlertCreated", storedEvents[0].EventType)
	assert.Equal(t, "AlertTriggered", storedEvents[1].EventType)

	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("alert-recon")
	require.NoError(t, err)

	reconstituted, err := LoadAlertFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, "alert-recon", reconstituted.AggregateID())
	assert.Equal(t, AlertStatusTriggered, reconstituted.Status)
	assert.Equal(t, "recon@example.com", reconstituted.Email)
	assert.Equal(t, "HDFCBANK", reconstituted.Symbol)
	assert.Equal(t, "NSE", reconstituted.Exchange)
	assert.Equal(t, 1700.0, reconstituted.TargetPrice)
	assert.Equal(t, "below", reconstituted.Direction)
	assert.Equal(t, 2, reconstituted.Version())
	assert.Empty(t, reconstituted.PendingEvents())
}

func TestAlertAggregate_ReconstitutionCreateDeleteFromEvents(t *testing.T) {
	store := newTestStore(t)

	agg := NewAlertAggregate("alert-del-recon")
	_ = agg.Create("del@example.com", "WIPRO", "BSE", 500.0, "above")
	_ = agg.Delete()

	storedEvents, err := ToAlertStoredEvents(agg, 1)
	require.NoError(t, err)
	err = store.Append(storedEvents...)
	require.NoError(t, err)

	loaded, err := store.LoadEvents("alert-del-recon")
	require.NoError(t, err)
	reconstituted, err := LoadAlertFromEvents(loaded)
	require.NoError(t, err)

	assert.Equal(t, AlertStatusDeleted, reconstituted.Status)
	assert.False(t, reconstituted.DeletedAt.IsZero())
}

func TestAlertAggregate_LoadFromEventsEmpty(t *testing.T) {
	_, err := LoadAlertFromEvents(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no events to load alert from")
}
