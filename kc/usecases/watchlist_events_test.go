package usecases

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// watchlist_events_test.go — Event-source pilot tests for the watchlist
// aggregate. Verifies that every successful mutation through the four
// CQRS use cases dispatches a typed domain.Watchlist*Event via the
// shared EventDispatcher. The audit-log persistence path
// (appendWatchlistEvent → eventStore.Append) is covered separately in
// usecases_edge_test.go — these tests focus on the dispatcher contract:
// runtime subscribers (projector, future consumers) MUST observe a
// typed event for every mutation that succeeds at the store layer.
//
// Pattern mirrors kc/billing/billing_store_test.go's TierChanged tests
// (commit 562f623) — the canonical template for "lift store mutations
// to typed domain events" inside this codebase.

// TestCreateWatchlist_DispatchesTypedEvent verifies a successful create
// fires a domain.WatchlistCreatedEvent with the expected fields.
func TestCreateWatchlist_DispatchesTypedEvent(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createID: "wl-1"}
	dispatcher := domain.NewEventDispatcher()

	var captured domain.WatchlistCreatedEvent
	seen := false
	dispatcher.Subscribe("watchlist.created", func(e domain.Event) {
		captured = e.(domain.WatchlistCreatedEvent)
		seen = true
	})

	uc := NewCreateWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	got, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "alice@example.com",
		Name:  "TechStocks",
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, seen, "WatchlistCreatedEvent should be dispatched on success")
	assert.Equal(t, "alice@example.com", captured.Email)
	assert.Equal(t, "wl-1", captured.WatchlistID)
	assert.Equal(t, "TechStocks", captured.Name)
	assert.WithinDuration(t, time.Now(), captured.Timestamp, 2*time.Second)
}

// TestCreateWatchlist_NoDispatchOnStoreFailure verifies that when the
// underlying store rejects the create (e.g. quota exceeded), no event
// is dispatched — the dispatcher contract is "real state changes only,
// silent on failure" (matches the TierChangedEvent contract).
func TestCreateWatchlist_NoDispatchOnStoreFailure(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createErr: assert.AnError}
	dispatcher := domain.NewEventDispatcher()

	count := 0
	dispatcher.Subscribe("watchlist.created", func(e domain.Event) { count++ })

	uc := NewCreateWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "alice@example.com",
		Name:  "TechStocks",
	})
	require.Error(t, err)
	assert.Equal(t, 0, count, "no event should be dispatched when store rejects the create")
}

// TestCreateWatchlist_NilDispatcherIsSafe verifies the use case still
// works without a dispatcher attached (the legacy path / older callers).
func TestCreateWatchlist_NilDispatcherIsSafe(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createID: "wl-x"}
	uc := NewCreateWatchlistUseCase(store, testLogger()) // no SetEventDispatcher

	got, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "alice@example.com",
		Name:  "Safe",
	})
	require.NoError(t, err)
	assert.Equal(t, "wl-x", got.ID)
}

// TestDeleteWatchlist_DispatchesTypedEvent verifies the delete path
// fires a domain.WatchlistDeletedEvent with the pre-delete name and
// item count captured for audit scope.
func TestDeleteWatchlist_DispatchesTypedEvent(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		watchlists: []*watchlist.Watchlist{{ID: "wl-9", Name: "LargeCaps"}},
		itemCounts: map[string]int{"wl-9": 7},
	}
	dispatcher := domain.NewEventDispatcher()

	var captured domain.WatchlistDeletedEvent
	seen := false
	dispatcher.Subscribe("watchlist.deleted", func(e domain.Event) {
		captured = e.(domain.WatchlistDeletedEvent)
		seen = true
	})

	uc := NewDeleteWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	_, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{
		Email:       "bob@example.com",
		WatchlistID: "wl-9",
	})
	require.NoError(t, err)
	require.True(t, seen)
	assert.Equal(t, "bob@example.com", captured.Email)
	assert.Equal(t, "wl-9", captured.WatchlistID)
	assert.Equal(t, "LargeCaps", captured.Name, "pre-delete name should be captured for audit")
	assert.Equal(t, 7, captured.ItemCount, "pre-delete item count should be captured")
}

// TestDeleteWatchlist_NoDispatchOnStoreFailure: a delete that fails at
// the store layer should not emit an event (consistency with create).
func TestDeleteWatchlist_NoDispatchOnStoreFailure(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{deleteErr: assert.AnError}
	dispatcher := domain.NewEventDispatcher()

	count := 0
	dispatcher.Subscribe("watchlist.deleted", func(e domain.Event) { count++ })

	uc := NewDeleteWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	_, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{
		Email:       "bob@example.com",
		WatchlistID: "wl-9",
	})
	require.Error(t, err)
	assert.Equal(t, 0, count)
}

// TestAddToWatchlist_DispatchesTypedEvent verifies an add fires a
// domain.WatchlistItemAddedEvent with the InstrumentKey populated.
func TestAddToWatchlist_DispatchesTypedEvent(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{}
	dispatcher := domain.NewEventDispatcher()

	var captured domain.WatchlistItemAddedEvent
	seen := false
	dispatcher.Subscribe("watchlist.item_added", func(e domain.Event) {
		captured = e.(domain.WatchlistItemAddedEvent)
		seen = true
	})

	uc := NewAddToWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email:           "carol@example.com",
		WatchlistID:     "wl-2",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		InstrumentToken: 12345,
	})
	require.NoError(t, err)
	require.True(t, seen)
	assert.Equal(t, "carol@example.com", captured.Email)
	assert.Equal(t, "wl-2", captured.WatchlistID)
	assert.Equal(t, "NSE", captured.Instrument.Exchange)
	assert.Equal(t, "RELIANCE", captured.Instrument.Tradingsymbol)
}

// TestAddToWatchlist_NoDispatchOnStoreFailure: an add that fails (e.g.
// duplicate, max items) should not emit an event.
func TestAddToWatchlist_NoDispatchOnStoreFailure(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{addItemErr: assert.AnError}
	dispatcher := domain.NewEventDispatcher()

	count := 0
	dispatcher.Subscribe("watchlist.item_added", func(e domain.Event) { count++ })

	uc := NewAddToWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.AddToWatchlistCommand{
		Email:         "carol@example.com",
		WatchlistID:   "wl-2",
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	require.Error(t, err)
	assert.Equal(t, 0, count)
}

// TestRemoveFromWatchlist_DispatchesTypedEvent verifies the remove path
// fires a domain.WatchlistItemRemovedEvent.
func TestRemoveFromWatchlist_DispatchesTypedEvent(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{}
	dispatcher := domain.NewEventDispatcher()

	var captured domain.WatchlistItemRemovedEvent
	seen := false
	dispatcher.Subscribe("watchlist.item_removed", func(e domain.Event) {
		captured = e.(domain.WatchlistItemRemovedEvent)
		seen = true
	})

	uc := NewRemoveFromWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{
		Email:       "dave@example.com",
		WatchlistID: "wl-3",
		ItemID:      "item-5",
	})
	require.NoError(t, err)
	require.True(t, seen)
	assert.Equal(t, "dave@example.com", captured.Email)
	assert.Equal(t, "wl-3", captured.WatchlistID)
	assert.Equal(t, "item-5", captured.ItemID)
}

// TestRemoveFromWatchlist_NoDispatchOnStoreFailure: idempotency on
// failure path.
func TestRemoveFromWatchlist_NoDispatchOnStoreFailure(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{removeItemErr: assert.AnError}
	dispatcher := domain.NewEventDispatcher()

	count := 0
	dispatcher.Subscribe("watchlist.item_removed", func(e domain.Event) { count++ })

	uc := NewRemoveFromWatchlistUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{
		Email:       "dave@example.com",
		WatchlistID: "wl-3",
		ItemID:      "item-5",
	})
	require.Error(t, err)
	assert.Equal(t, 0, count)
}

// TestWatchlist_DispatchAndAuditCoexist verifies that when BOTH
// SetEventStore AND SetEventDispatcher are wired (production wiring),
// the create succeeds and BOTH paths fire — the audit log gets an
// entry AND the dispatcher gets a typed event. They are independent;
// neither blocks the other.
func TestWatchlist_DispatchAndAuditCoexist(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createID: "wl-coexist"}
	events := &mockEventAppender{}
	dispatcher := domain.NewEventDispatcher()

	dispatched := 0
	dispatcher.Subscribe("watchlist.created", func(e domain.Event) { dispatched++ })

	uc := NewCreateWatchlistUseCase(store, testLogger())
	uc.SetEventStore(events)
	uc.SetEventDispatcher(dispatcher)

	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "alice@example.com",
		Name:  "Coexist",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, dispatched, "dispatcher should fire exactly once")
	assert.Len(t, events.appended, 1, "audit log should have exactly one entry")
}

// TestWatchlist_AllFourMutationsDispatch is the integration-flavoured
// test that exercises every mutation against a single dispatcher,
// asserting the order and event-types match a realistic user lifecycle:
// create → add → remove → delete. Catches accidental dispatcher-field
// misnaming (e.g. set on Add but not Remove) by enforcing the full
// sequence.
func TestWatchlist_AllFourMutationsDispatch(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		createID:   "wl-flow",
		watchlists: []*watchlist.Watchlist{{ID: "wl-flow", Name: "Flow"}},
		itemCounts: map[string]int{"wl-flow": 1},
	}
	dispatcher := domain.NewEventDispatcher()

	var seq []string
	for _, et := range []string{"watchlist.created", "watchlist.item_added", "watchlist.item_removed", "watchlist.deleted"} {
		t := et
		dispatcher.Subscribe(t, func(e domain.Event) { seq = append(seq, e.EventType()) })
	}

	createUC := NewCreateWatchlistUseCase(store, testLogger())
	createUC.SetEventDispatcher(dispatcher)
	addUC := NewAddToWatchlistUseCase(store, testLogger())
	addUC.SetEventDispatcher(dispatcher)
	removeUC := NewRemoveFromWatchlistUseCase(store, testLogger())
	removeUC.SetEventDispatcher(dispatcher)
	deleteUC := NewDeleteWatchlistUseCase(store, testLogger())
	deleteUC.SetEventDispatcher(dispatcher)

	ctx := context.Background()
	_, err := createUC.Execute(ctx, cqrs.CreateWatchlistCommand{Email: "u@t.com", Name: "Flow"})
	require.NoError(t, err)
	err = addUC.Execute(ctx, cqrs.AddToWatchlistCommand{Email: "u@t.com", WatchlistID: "wl-flow", Exchange: "NSE", Tradingsymbol: "INFY"})
	require.NoError(t, err)
	err = removeUC.Execute(ctx, cqrs.RemoveFromWatchlistCommand{Email: "u@t.com", WatchlistID: "wl-flow", ItemID: "item-1"})
	require.NoError(t, err)
	_, err = deleteUC.Execute(ctx, cqrs.DeleteWatchlistCommand{Email: "u@t.com", WatchlistID: "wl-flow"})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"watchlist.created",
		"watchlist.item_added",
		"watchlist.item_removed",
		"watchlist.deleted",
	}, seq, "all four mutations should dispatch typed events in order")
}
