package eventsourcing

// coverage_close_test.go — closes the residual eventsourcing coverage
// gaps to lift the package from 88.2% toward 100%. Targets the
// dot-format ("public domain event") deserialize branches in each
// aggregate's deserialize* function — these were silently uncovered
// because the existing TestDeserialize*_AllValidTypes tests in
// aggregate_edge_test.go only exercise the legacy PascalCase
// ("OrderPlaced" / "AlertCreated" / "PositionOpened") forms. Production
// today persists in the dot-format via makeEventPersister, so reaching
// these branches is the load-bearing replay path.
//
// Also covers store.LoadEventsByEmailHash (was 0%), the EventStore
// logger() helper, and InitTable migration idempotency.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// ---------------------------------------------------------------------------
// Order: dot-format deserialize branches
// ---------------------------------------------------------------------------

// TestDeserializeOrderEvent_DotFormatTypes covers the four
// "order.placed" / "order.modified" / "order.cancelled" / "order.filled"
// branches (lines 426-449 of order_aggregate.go) that production
// makeEventPersister writes. These were uncovered because
// aggregate_edge_test.go only tested the legacy PascalCase forms.
//
// Round-trip: marshal the typed domain.Event struct as JSON (mirrors
// makeEventPersister), feed through deserializeOrderEvent, assert the
// returned event is the same domain type with the right fields.
func TestDeserializeOrderEvent_DotFormatTypes(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(10)

	t.Run("order.placed", func(t *testing.T) {
		t.Parallel()
		original := domain.OrderPlacedEvent{
			Email:           "trader@test.com",
			OrderID:         "ORD-1",
			Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
			Qty:             qty,
			Price:           domain.NewINR(2500),
			TransactionType: "BUY",
			Timestamp:       now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ORD-1", EventType: "order.placed",
			Payload: payload, OccurredAt: now, Sequence: 1,
		}
		ev, err := deserializeOrderEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.OrderPlacedEvent)
		require.True(t, ok, "want domain.OrderPlacedEvent, got %T", ev)
		assert.Equal(t, "ORD-1", got.OrderID)
		assert.Equal(t, "trader@test.com", got.Email)
		assert.Equal(t, "BUY", got.TransactionType)
		assert.Equal(t, "order.placed", got.EventType())
	})

	t.Run("order.modified", func(t *testing.T) {
		t.Parallel()
		original := domain.OrderModifiedEvent{
			Email: "trader@test.com", OrderID: "ORD-2", Timestamp: now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ORD-2", EventType: "order.modified",
			Payload: payload, OccurredAt: now, Sequence: 2,
		}
		ev, err := deserializeOrderEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.OrderModifiedEvent)
		require.True(t, ok)
		assert.Equal(t, "ORD-2", got.OrderID)
		assert.Equal(t, "order.modified", got.EventType())
	})

	t.Run("order.cancelled", func(t *testing.T) {
		t.Parallel()
		original := domain.OrderCancelledEvent{
			Email: "trader@test.com", OrderID: "ORD-3", Timestamp: now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ORD-3", EventType: "order.cancelled",
			Payload: payload, OccurredAt: now, Sequence: 1,
		}
		ev, err := deserializeOrderEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.OrderCancelledEvent)
		require.True(t, ok)
		assert.Equal(t, "ORD-3", got.OrderID)
		assert.Equal(t, "order.cancelled", got.EventType())
	})

	t.Run("order.filled", func(t *testing.T) {
		t.Parallel()
		filledQty, _ := domain.NewQuantity(10)
		original := domain.OrderFilledEvent{
			Email:       "trader@test.com",
			OrderID:     "ORD-4",
			FilledQty:   filledQty,
			FilledPrice: domain.NewINR(2510),
			Status:      "COMPLETE",
			Timestamp:   now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ORD-4", EventType: "order.filled",
			Payload: payload, OccurredAt: now, Sequence: 1,
		}
		ev, err := deserializeOrderEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.OrderFilledEvent)
		require.True(t, ok)
		assert.Equal(t, "ORD-4", got.OrderID)
		assert.Equal(t, "COMPLETE", got.Status)
		assert.Equal(t, "order.filled", got.EventType())
	})
}

// TestDeserialize_DotFormatBadJSON covers the json.Unmarshal err paths
// in every dot-format branch across order/alert/position
// deserializers. Each branch routes through json.Unmarshal — feeding
// malformed JSON exercises the err return for all 9 cases at once.
func TestDeserialize_DotFormatBadJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eventType string
		fn        func(StoredEvent) (domain.Event, error)
	}{
		{"order.placed", deserializeOrderEvent},
		{"order.modified", deserializeOrderEvent},
		{"order.cancelled", deserializeOrderEvent},
		{"order.filled", deserializeOrderEvent},
		{"alert.created", deserializeAlertEvent},
		{"alert.triggered", deserializeAlertEvent},
		{"alert.deleted", deserializeAlertEvent},
		{"position.opened", deserializePositionEvent},
		{"position.closed", deserializePositionEvent},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.eventType, func(t *testing.T) {
			t.Parallel()
			stored := StoredEvent{
				AggregateID: "X", EventType: tc.eventType,
				Payload: []byte(`{malformed`), OccurredAt: time.Now(),
			}
			_, err := tc.fn(stored)
			require.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Alert: dot-format deserialize branches
// ---------------------------------------------------------------------------

// TestDeserializeAlertEvent_DotFormatTypes covers
// "alert.created" / "alert.triggered" / "alert.deleted" branches in
// deserializeAlertEvent.
func TestDeserializeAlertEvent_DotFormatTypes(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	t.Run("alert.created", func(t *testing.T) {
		t.Parallel()
		original := domain.AlertCreatedEvent{
			Email:       "trader@test.com",
			AlertID:     "ALERT-1",
			Instrument:  domain.NewInstrumentKey("NSE", "RELIANCE"),
			TargetPrice: domain.NewINR(2500),
			Direction:   "above",
			Timestamp:   now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ALERT-1", EventType: "alert.created",
			Payload: payload, OccurredAt: now, Sequence: 1,
		}
		ev, err := deserializeAlertEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.AlertCreatedEvent)
		require.True(t, ok)
		assert.Equal(t, "ALERT-1", got.AlertID)
		assert.Equal(t, "above", got.Direction)
		assert.Equal(t, "alert.created", got.EventType())
	})

	t.Run("alert.triggered", func(t *testing.T) {
		t.Parallel()
		original := domain.AlertTriggeredEvent{
			Email:        "trader@test.com",
			AlertID:      "ALERT-2",
			Instrument:   domain.NewInstrumentKey("NSE", "INFY"),
			TargetPrice:  domain.NewINR(1500),
			CurrentPrice: domain.NewINR(1505),
			Direction:    "above",
			Timestamp:    now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ALERT-2", EventType: "alert.triggered",
			Payload: payload, OccurredAt: now, Sequence: 2,
		}
		ev, err := deserializeAlertEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.AlertTriggeredEvent)
		require.True(t, ok)
		assert.Equal(t, "ALERT-2", got.AlertID)
		assert.InDelta(t, 1505.0, got.CurrentPrice.Float64(), 0.001)
		assert.Equal(t, "alert.triggered", got.EventType())
	})

	t.Run("alert.deleted", func(t *testing.T) {
		t.Parallel()
		original := domain.AlertDeletedEvent{
			Email:     "trader@test.com",
			AlertID:   "ALERT-3",
			Timestamp: now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "ALERT-3", EventType: "alert.deleted",
			Payload: payload, OccurredAt: now, Sequence: 3,
		}
		ev, err := deserializeAlertEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.AlertDeletedEvent)
		require.True(t, ok)
		assert.Equal(t, "ALERT-3", got.AlertID)
		assert.Equal(t, "alert.deleted", got.EventType())
	})
}

// ---------------------------------------------------------------------------
// Position: dot-format deserialize branches
// ---------------------------------------------------------------------------

// TestDeserializePositionEvent_DotFormatTypes covers position.opened
// and position.closed dot-format branches in deserializePositionEvent.
func TestDeserializePositionEvent_DotFormatTypes(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	qty, _ := domain.NewQuantity(10)

	t.Run("position.opened", func(t *testing.T) {
		t.Parallel()
		original := domain.PositionOpenedEvent{
			Email:           "trader@test.com",
			PositionID:      "POS-1",
			Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
			Product:         "CNC",
			Qty:             qty,
			AvgPrice:        domain.NewINR(2500),
			TransactionType: "BUY",
			Timestamp:       now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "POS-1", EventType: "position.opened",
			Payload: payload, OccurredAt: now, Sequence: 1,
		}
		ev, err := deserializePositionEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.PositionOpenedEvent)
		require.True(t, ok)
		assert.Equal(t, "POS-1", got.PositionID)
		assert.Equal(t, "CNC", got.Product)
		assert.Equal(t, "position.opened", got.EventType())
	})

	t.Run("position.closed", func(t *testing.T) {
		t.Parallel()
		original := domain.PositionClosedEvent{
			Email:           "trader@test.com",
			OrderID:         "ORD-CLOSE",
			Instrument:      domain.NewInstrumentKey("NSE", "RELIANCE"),
			Product:         "CNC",
			Qty:             qty,
			TransactionType: "SELL",
			Timestamp:       now,
		}
		payload, err := json.Marshal(original)
		require.NoError(t, err)
		stored := StoredEvent{
			AggregateID: "POS-2", EventType: "position.closed",
			Payload: payload, OccurredAt: now, Sequence: 2,
		}
		ev, err := deserializePositionEvent(stored)
		require.NoError(t, err)
		got, ok := ev.(domain.PositionClosedEvent)
		require.True(t, ok)
		assert.Equal(t, "ORD-CLOSE", got.OrderID)
		assert.Equal(t, "SELL", got.TransactionType)
		assert.Equal(t, "position.closed", got.EventType())
	})
}

// ---------------------------------------------------------------------------
// Session: deserialize branches (was 70.6%)
// ---------------------------------------------------------------------------

// TestDeserializeSessionEvent_CreatedDomainStruct covers the path where
// makeEventPersister wrote the full domain.SessionCreatedEvent struct
// (the "try domain form first; fall back" branch at lines 126-129).
func TestDeserializeSessionEvent_CreatedDomainStruct(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	original := domain.SessionCreatedEvent{
		Email:     "trader@test.com",
		SessionID: "sess-1",
		Broker:    "zerodha",
		Timestamp: now,
	}
	payload, err := json.Marshal(original)
	require.NoError(t, err)
	stored := StoredEvent{
		AggregateID: "sess-1", EventType: "session.created",
		Payload: payload, OccurredAt: now, Sequence: 1,
	}
	ev, err := deserializeSessionEvent(stored)
	require.NoError(t, err)
	got, ok := ev.(domain.SessionCreatedEvent)
	require.True(t, ok)
	assert.Equal(t, "sess-1", got.SessionID)
	assert.Equal(t, "zerodha", got.Broker)
}

// TestDeserializeSessionEvent_CreatedNarrowPayload covers the use-case
// path: the use case persists the narrower SessionCreatedPayload (no
// Timestamp field), and deserializeSessionEvent's fallback path
// reconstructs the domain event using stored.OccurredAt. This branch
// fires when the unmarshal-as-domain attempt sees an empty SessionID
// (the SessionCreatedEvent JSON form requires it).
func TestDeserializeSessionEvent_CreatedNarrowPayload(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	// Construct via the narrow payload (use-case write path).
	payload, err := MarshalPayload(SessionCreatedPayload{
		Email:     "narrow@test.com",
		SessionID: "sess-narrow",
		Broker:    "zerodha",
	})
	require.NoError(t, err)
	// Now strip the SessionID from the JSON object after marshalling,
	// then re-add it under "session_id" only — the SessionCreatedPayload
	// struct already uses snake_case json tags, but the
	// domain.SessionCreatedEvent struct uses PascalCase fields
	// (no json tags), so the unmarshal-as-domain attempt won't populate
	// SessionID and will return success-but-empty, triggering the
	// fallback path.
	stored := StoredEvent{
		AggregateID: "sess-narrow", EventType: "session.created",
		Payload: payload, OccurredAt: now, Sequence: 1,
	}
	ev, err := deserializeSessionEvent(stored)
	require.NoError(t, err)
	got, ok := ev.(domain.SessionCreatedEvent)
	require.True(t, ok)
	assert.Equal(t, "sess-narrow", got.SessionID)
	assert.Equal(t, "zerodha", got.Broker)
	// Timestamp comes from stored.OccurredAt, not the payload.
	assert.True(t, got.Timestamp.Equal(now))
}

// TestDeserializeSessionEvent_Cleared covers the session.cleared branch.
func TestDeserializeSessionEvent_Cleared(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	payload, err := MarshalPayload(SessionClearedPayload{
		SessionID: "sess-cleared",
		Reason:    "post_credential_register",
	})
	require.NoError(t, err)
	stored := StoredEvent{
		AggregateID: "sess-cleared", EventType: "session.cleared",
		Payload: payload, OccurredAt: now, Sequence: 1,
	}
	ev, err := deserializeSessionEvent(stored)
	require.NoError(t, err)
	got, ok := ev.(domain.SessionClearedEvent)
	require.True(t, ok)
	assert.Equal(t, "sess-cleared", got.SessionID)
	assert.Equal(t, "post_credential_register", got.Reason)
}

// TestDeserializeSessionEvent_Invalidated covers the session.invalidated
// branch (was uncovered — SessionAggregate's Apply doesn't currently
// dispatch invalidation, so this branch is reached only via direct
// deserialize calls in tests).
func TestDeserializeSessionEvent_Invalidated(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	payload, err := MarshalPayload(SessionInvalidatedPayload{
		SessionID: "sess-inv",
		Reason:    "expired",
	})
	require.NoError(t, err)
	stored := StoredEvent{
		AggregateID: "sess-inv", EventType: "session.invalidated",
		Payload: payload, OccurredAt: now, Sequence: 1,
	}
	ev, err := deserializeSessionEvent(stored)
	require.NoError(t, err)
	got, ok := ev.(domain.SessionInvalidatedEvent)
	require.True(t, ok)
	assert.Equal(t, "sess-inv", got.SessionID)
	assert.Equal(t, "expired", got.Reason)
}

// TestDeserializeSessionEvent_BadJSON covers the json.Unmarshal err
// paths in cleared/invalidated branches plus the narrow-payload
// fallback path on session.created.
func TestDeserializeSessionEvent_BadJSON(t *testing.T) {
	t.Parallel()
	for _, et := range []string{"session.created", "session.cleared", "session.invalidated"} {
		et := et
		t.Run(et, func(t *testing.T) {
			t.Parallel()
			stored := StoredEvent{
				AggregateID: "sess-x", EventType: et,
				Payload: []byte(`{nope`), OccurredAt: time.Now(),
			}
			_, err := deserializeSessionEvent(stored)
			require.Error(t, err)
		})
	}
}

// TestDeserializeSessionEvent_UnknownType covers the default error
// branch (was uncovered — only the three known types had tests).
func TestDeserializeSessionEvent_UnknownType(t *testing.T) {
	t.Parallel()
	stored := StoredEvent{
		AggregateID: "sess-x", EventType: "session.weird_thing",
		Payload: []byte(`{}`), OccurredAt: time.Now(),
	}
	_, err := deserializeSessionEvent(stored)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown session event type")
	assert.Contains(t, err.Error(), "session.weird_thing")
}

// ---------------------------------------------------------------------------
// store.LoadEventsByEmailHash (was 0%)
// ---------------------------------------------------------------------------

// hashEmail mirrors audit.HashEmail without taking the import: SHA-256
// hex of the lowercased email. Used only inside this test file.
func hashEmail(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(h[:])
}

// TestLoadEventsByEmailHash_EmptyHashReturnsNil covers the
// empty-string fast-path: empty emailHash short-circuits to nil
// without hitting the DB. This is the defence against accidentally
// matching every system event row (which has email_hash="").
func TestLoadEventsByEmailHash_EmptyHashReturnsNil(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)

	// Append a system-event row with empty email_hash.
	require.NoError(t, store.Append(StoredEvent{
		AggregateID:   "global",
		AggregateType: "Global",
		EventType:     "global.freeze",
		Payload:       []byte(`{}`),
		OccurredAt:    time.Now().UTC(),
		Sequence:      1,
		EmailHash:     "", // system event
	}))

	events, err := store.LoadEventsByEmailHash("", time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	assert.Nil(t, events, "empty hash must return nil, never match the system-event empty default")
}

// TestLoadEventsByEmailHash_MatchesUserEvents covers the happy path:
// the per-user data-portability export queries by hash + since-time.
func TestLoadEventsByEmailHash_MatchesUserEvents(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)

	aliceHash := hashEmail("alice@test.com")
	bobHash := hashEmail("bob@test.com")
	now := time.Now().UTC()

	// Two events for alice, one for bob — verify per-hash filter.
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "ORD-A1", AggregateType: "Order", EventType: "order.placed",
		Payload: []byte(`{}`), OccurredAt: now.Add(-10 * time.Minute), Sequence: 1,
		EmailHash: aliceHash,
	}))
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "ORD-A2", AggregateType: "Order", EventType: "order.cancelled",
		Payload: []byte(`{}`), OccurredAt: now.Add(-5 * time.Minute), Sequence: 1,
		EmailHash: aliceHash,
	}))
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "ORD-B1", AggregateType: "Order", EventType: "order.placed",
		Payload: []byte(`{}`), OccurredAt: now.Add(-7 * time.Minute), Sequence: 1,
		EmailHash: bobHash,
	}))

	// Load alice's events from before now — should get both.
	aliceEvents, err := store.LoadEventsByEmailHash(aliceHash, now.Add(-1*time.Hour))
	require.NoError(t, err)
	require.Len(t, aliceEvents, 2)
	// Sorted by occurred_at ASC.
	assert.Equal(t, "ORD-A1", aliceEvents[0].AggregateID, "oldest first")
	assert.Equal(t, "ORD-A2", aliceEvents[1].AggregateID)

	// Bob's hash returns only his event.
	bobEvents, err := store.LoadEventsByEmailHash(bobHash, now.Add(-1*time.Hour))
	require.NoError(t, err)
	require.Len(t, bobEvents, 1)
	assert.Equal(t, "ORD-B1", bobEvents[0].AggregateID)
}

// TestLoadEventsByEmailHash_SinceTimeFilters covers the since-time
// filter: events older than `since` are excluded.
func TestLoadEventsByEmailHash_SinceTimeFilters(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)

	hash := hashEmail("trader@test.com")
	now := time.Now().UTC()

	// Old event (1 day ago) and recent event (5 min ago).
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "OLD", AggregateType: "Order", EventType: "order.placed",
		Payload: []byte(`{}`), OccurredAt: now.Add(-24 * time.Hour), Sequence: 1,
		EmailHash: hash,
	}))
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "NEW", AggregateType: "Order", EventType: "order.placed",
		Payload: []byte(`{}`), OccurredAt: now.Add(-5 * time.Minute), Sequence: 1,
		EmailHash: hash,
	}))

	// Filter from 1 hour ago — only the recent event qualifies.
	since := now.Add(-1 * time.Hour)
	events, err := store.LoadEventsByEmailHash(hash, since)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "NEW", events[0].AggregateID)
}

// TestLoadEventsByEmailHash_NoMatch covers the empty-result path: a
// valid hash that nothing in the store matches.
func TestLoadEventsByEmailHash_NoMatch(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)

	// Append for a different user.
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "ORD-1", AggregateType: "Order", EventType: "order.placed",
		Payload: []byte(`{}`), OccurredAt: time.Now().UTC(), Sequence: 1,
		EmailHash: hashEmail("other@test.com"),
	}))

	// Query with a hash that has no rows.
	events, err := store.LoadEventsByEmailHash(hashEmail("nobody@test.com"), time.Time{})
	require.NoError(t, err)
	assert.Empty(t, events)
}

// ---------------------------------------------------------------------------
// store.logger() helper (was 0%)
// ---------------------------------------------------------------------------

// TestEventStoreLogger_ReturnsNonNil covers the helper at line 244 of
// outbox.go. The helper exists so the inline drain path can log
// warnings without a nil-deref; it returns slog.Default() unconditionally.
func TestEventStoreLogger_ReturnsNonNil(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	got := store.logger()
	require.NotNil(t, got, "store.logger() must always return a non-nil logger (slog.Default fallback)")
}

// ---------------------------------------------------------------------------
// InitTable migration idempotency (was 80%)
// ---------------------------------------------------------------------------

// TestInitTable_IsIdempotent covers the second-call path: the
// CREATE TABLE IF NOT EXISTS plus the ALTER TABLE migration must
// tolerate re-invocation cleanly. This pins the production guarantee
// that startup can call InitTable twice without error (e.g. graceful
// restart with shared DB).
func TestInitTable_IsIdempotent(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t) // first InitTable already ran in helper
	// Second call must succeed too.
	require.NoError(t, store.InitTable())
	// And a third, just to be paranoid.
	require.NoError(t, store.InitTable())

	// Functional invariant: the table is still usable after re-init.
	require.NoError(t, store.Append(StoredEvent{
		AggregateID: "post-init", AggregateType: "Test", EventType: "test.event",
		Payload: []byte(`{}`), OccurredAt: time.Now().UTC(), Sequence: 1,
	}))
	events, err := store.LoadEvents("post-init")
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

// TestInitOutboxTable_IsIdempotent covers the same idempotency
// guarantee for the outbox table. Helps lift InitOutboxTable from 80%
// to higher coverage.
func TestInitOutboxTable_IsIdempotent(t *testing.T) {
	t.Parallel()
	store, _ := testStore(t)
	require.NoError(t, store.InitOutboxTable())
	require.NoError(t, store.InitOutboxTable())

	// Functional check: outbox is still writable post-re-init.
	require.NoError(t, store.AppendToOutbox(sampleEvent("post-outbox-init", 1)))
	n, err := store.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}
