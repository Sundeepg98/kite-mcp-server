package usecases

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// telegram_events_test.go — Event-source contract tests for the
// Telegram subscription aggregate. Verifies that every successful
// SetupTelegramCommand mutation dispatches the correct typed
// domain.Telegram*Event via the shared EventDispatcher:
//
//   - First-time bind (no prior chat ID for this email) → TelegramSubscribedEvent
//   - Re-bind to a different chat ID                    → TelegramChatBoundEvent
//   - Same chat ID re-submitted (no-op)                 → SILENT
//   - Validation failure / store rejection              → SILENT
//
// Pattern mirrors kc/usecases/watchlist_events_test.go (commit aeb3e8c)
// — the canonical "lift store mutations to typed domain events"
// template inside this codebase. Audit persistence is owned by the
// command-bus LoggingMiddleware; these tests focus purely on the
// dispatcher contract.

// stubTelegramStore is a controllable fake of TelegramStore for the
// dispatch contract tests. Distinct from the canonical mockTelegramStore
// in usecases_edge_test.go because we need (a) configurable seed values
// for "had prior" cases and (b) settable error path on Set — neither of
// which the existing mock provides without disturbing other tests.
type stubTelegramStore struct {
	chatID   int64
	hasEntry bool
	setCalls int
	lastSet  int64
}

func (s *stubTelegramStore) SetTelegramChatID(email string, chatID int64) {
	s.setCalls++
	s.lastSet = chatID
	s.chatID = chatID
	s.hasEntry = true
}

func (s *stubTelegramStore) GetTelegramChatID(email string) (int64, bool) {
	if !s.hasEntry {
		return 0, false
	}
	return s.chatID, true
}

// TestSetupTelegram_DispatchesSubscribedOnFirstBind verifies the
// first-time onboarding path — no prior chat ID for this email —
// fires a typed TelegramSubscribedEvent with the expected fields.
func TestSetupTelegram_DispatchesSubscribedOnFirstBind(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{} // no prior entry
	dispatcher := domain.NewEventDispatcher()

	var captured domain.TelegramSubscribedEvent
	seen := false
	dispatcher.Subscribe("telegram.subscribed", func(e domain.Event) {
		captured = e.(domain.TelegramSubscribedEvent)
		seen = true
	})
	otherCount := 0
	dispatcher.Subscribe("telegram.chat_bound", func(e domain.Event) { otherCount++ })

	uc := NewSetupTelegramUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{
		Email:  "alice@example.com",
		ChatID: 12345,
	})
	require.NoError(t, err)
	require.True(t, seen, "TelegramSubscribedEvent should fire on first bind")
	assert.Equal(t, "alice@example.com", captured.UserEmail)
	assert.Equal(t, int64(12345), captured.ChatID)
	assert.WithinDuration(t, time.Now(), captured.Timestamp, 2*time.Second)
	assert.Equal(t, 0, otherCount, "no chat_bound on first bind")
	assert.Equal(t, int64(12345), store.lastSet)
}

// TestSetupTelegram_DispatchesChatBoundOnRebind verifies that re-binding
// an existing subscriber to a different chat ID emits the rotation
// event with both old and new chat IDs captured.
func TestSetupTelegram_DispatchesChatBoundOnRebind(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{chatID: 11111, hasEntry: true} // prior subscriber
	dispatcher := domain.NewEventDispatcher()

	var captured domain.TelegramChatBoundEvent
	seen := false
	dispatcher.Subscribe("telegram.chat_bound", func(e domain.Event) {
		captured = e.(domain.TelegramChatBoundEvent)
		seen = true
	})
	subCount := 0
	dispatcher.Subscribe("telegram.subscribed", func(e domain.Event) { subCount++ })

	uc := NewSetupTelegramUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{
		Email:  "bob@example.com",
		ChatID: 22222,
	})
	require.NoError(t, err)
	require.True(t, seen, "TelegramChatBoundEvent should fire on rebind")
	assert.Equal(t, "bob@example.com", captured.UserEmail)
	assert.Equal(t, int64(11111), captured.OldChatID, "old chat ID captured pre-mutation")
	assert.Equal(t, int64(22222), captured.NewChatID, "new chat ID captured")
	assert.WithinDuration(t, time.Now(), captured.Timestamp, 2*time.Second)
	assert.Equal(t, 0, subCount, "no subscribed event on rebind")
}

// TestSetupTelegram_NoDispatchOnSameChatID verifies the "real
// transitions only" contract — re-submitting the same chat ID is a
// no-op writes that MUST NOT emit an event. Mirrors TierChangedEvent's
// silent-on-no-op semantics.
func TestSetupTelegram_NoDispatchOnSameChatID(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{chatID: 99999, hasEntry: true}
	dispatcher := domain.NewEventDispatcher()

	subCount := 0
	bindCount := 0
	dispatcher.Subscribe("telegram.subscribed", func(e domain.Event) { subCount++ })
	dispatcher.Subscribe("telegram.chat_bound", func(e domain.Event) { bindCount++ })

	uc := NewSetupTelegramUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{
		Email:  "carol@example.com",
		ChatID: 99999, // same as prior
	})
	require.NoError(t, err)
	assert.Equal(t, 0, subCount, "no subscribed on no-op write")
	assert.Equal(t, 0, bindCount, "no chat_bound on no-op write")
}

// TestSetupTelegram_NoDispatchOnValidationFailure verifies that a
// validation failure (empty email, zero chat ID) short-circuits before
// reaching the store, and crucially, does not emit any event.
func TestSetupTelegram_NoDispatchOnValidationFailure(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{}
	dispatcher := domain.NewEventDispatcher()

	total := 0
	dispatcher.Subscribe("telegram.subscribed", func(e domain.Event) { total++ })
	dispatcher.Subscribe("telegram.chat_bound", func(e domain.Event) { total++ })

	uc := NewSetupTelegramUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	// Empty email
	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{ChatID: 555})
	require.Error(t, err)
	assert.Equal(t, 0, total, "no event on empty email")
	assert.Equal(t, 0, store.setCalls, "store mutation must not be attempted")

	// Zero chat ID
	err = uc.Execute(context.Background(), cqrs.SetupTelegramCommand{Email: "x@y.com"})
	require.Error(t, err)
	assert.Equal(t, 0, total, "no event on zero chat ID")
	assert.Equal(t, 0, store.setCalls)
}

// TestSetupTelegram_NilDispatcherIsSafe verifies the use case still
// works with no dispatcher wired (the legacy path / older callers).
// Pattern mirrors CreateWatchlistUseCase's nil-dispatcher safety test.
func TestSetupTelegram_NilDispatcherIsSafe(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{}
	uc := NewSetupTelegramUseCase(store, testLogger()) // no SetEventDispatcher

	err := uc.Execute(context.Background(), cqrs.SetupTelegramCommand{
		Email:  "noevents@example.com",
		ChatID: 7777,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(7777), store.lastSet, "store mutation should still happen")
}

// TestSetupTelegram_AggregateIDDerivation verifies that the helper
// returns the "telegram:<email>" form so the natural aggregate key is
// stable across the subscription lifecycle (subscribe + multiple
// rebinds all key under one stream).
func TestSetupTelegram_AggregateIDDerivation(t *testing.T) {
	t.Parallel()
	got := domain.TelegramSubscriptionAggregateID("user@example.com")
	assert.Equal(t, "telegram:user@example.com", got)

	// Empty-email defence in depth — still produces a usable key so
	// the event-store NOT NULL constraint never fires.
	gotEmpty := domain.TelegramSubscriptionAggregateID("")
	assert.Equal(t, "telegram:unknown", gotEmpty)
}

// TestSetupTelegram_FullLifecycleSequence is the integration-flavoured
// test that exercises subscribe → rebind → no-op → rebind against a
// single dispatcher, asserting the full sequence of typed events lands
// in the right order. Catches accidental field misnaming or
// branch-misordering in the use-case switch.
func TestSetupTelegram_FullLifecycleSequence(t *testing.T) {
	t.Parallel()
	store := &stubTelegramStore{}
	dispatcher := domain.NewEventDispatcher()

	var seq []string
	dispatcher.Subscribe("telegram.subscribed", func(e domain.Event) { seq = append(seq, e.EventType()) })
	dispatcher.Subscribe("telegram.chat_bound", func(e domain.Event) { seq = append(seq, e.EventType()) })

	uc := NewSetupTelegramUseCase(store, testLogger())
	uc.SetEventDispatcher(dispatcher)

	ctx := context.Background()

	// 1) First-time subscribe → telegram.subscribed
	require.NoError(t, uc.Execute(ctx, cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 100}))
	// 2) Rebind to new chat → telegram.chat_bound
	require.NoError(t, uc.Execute(ctx, cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 200}))
	// 3) Same chat (no-op) → silent
	require.NoError(t, uc.Execute(ctx, cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 200}))
	// 4) Rebind again → telegram.chat_bound
	require.NoError(t, uc.Execute(ctx, cqrs.SetupTelegramCommand{Email: "u@t.com", ChatID: 300}))

	assert.Equal(t, []string{
		"telegram.subscribed",
		"telegram.chat_bound",
		// (no-op skipped)
		"telegram.chat_bound",
	}, seq)
}

