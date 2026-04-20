package eventsourcing

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionAggregate_Apply walks the aggregate through created → cleared →
// invalidated and verifies each state transition. Covers the Apply branches.
func TestSessionAggregate_Apply(t *testing.T) {
	t.Parallel()

	agg := NewSessionAggregate("sess-1")
	assert.Equal(t, "", agg.Status, "fresh aggregate has no status")

	agg.Apply(domain.SessionCreatedEvent{
		Email:     "alice@example.com",
		SessionID: "sess-1",
		Broker:    "zerodha",
		Timestamp: time.Date(2026, 4, 20, 9, 0, 0, 0, time.UTC),
	})
	assert.Equal(t, SessionStatusActive, agg.Status)
	assert.Equal(t, "alice@example.com", agg.Email)
	assert.Equal(t, 1, agg.Version())

	agg.Apply(domain.SessionClearedEvent{
		SessionID: "sess-1",
		Reason:    "post_credential_register",
		Timestamp: time.Date(2026, 4, 20, 9, 5, 0, 0, time.UTC),
	})
	assert.Equal(t, SessionStatusCleared, agg.Status)
	assert.Equal(t, "post_credential_register", agg.LastClearReason)
	assert.Equal(t, 2, agg.Version())

	agg.Apply(domain.SessionInvalidatedEvent{
		SessionID: "sess-1",
		Reason:    "expired",
		Timestamp: time.Date(2026, 4, 20, 18, 0, 0, 0, time.UTC),
	})
	assert.Equal(t, SessionStatusInvalidated, agg.Status)
	assert.Equal(t, "expired", agg.InvalidationReason)
	assert.Equal(t, 3, agg.Version())
}

// TestLoadSessionFromEvents_RoundTrip persists a session.cleared event via
// the use-case payload format and verifies LoadSessionFromEvents replays it
// correctly into a SessionAggregate.
func TestLoadSessionFromEvents_RoundTrip(t *testing.T) {
	t.Parallel()

	clearedPayload, err := MarshalPayload(SessionClearedPayload{
		SessionID: "sess-42",
		Reason:    "profile_check_failed",
	})
	require.NoError(t, err)

	createdPayload, err := MarshalPayload(SessionCreatedPayload{
		Email:     "bob@example.com",
		SessionID: "sess-42",
		Broker:    "zerodha",
	})
	require.NoError(t, err)

	events := []StoredEvent{
		{
			AggregateID:   "sess-42",
			AggregateType: "Session",
			EventType:     "session.created",
			Payload:       createdPayload,
			OccurredAt:    time.Date(2026, 4, 20, 9, 0, 0, 0, time.UTC),
			Sequence:      1,
		},
		{
			AggregateID:   "sess-42",
			AggregateType: "Session",
			EventType:     "session.cleared",
			Payload:       clearedPayload,
			OccurredAt:    time.Date(2026, 4, 20, 9, 30, 0, 0, time.UTC),
			Sequence:      2,
		},
	}

	agg, err := LoadSessionFromEvents(events)
	require.NoError(t, err)
	assert.Equal(t, "sess-42", agg.AggregateID())
	assert.Equal(t, "bob@example.com", agg.Email)
	assert.Equal(t, SessionStatusCleared, agg.Status)
	assert.Equal(t, "profile_check_failed", agg.LastClearReason)
	assert.Equal(t, 2, agg.Version())
}

// TestLoadSessionFromEvents_EmptyStream returns an error rather than an
// empty aggregate — the caller should treat empty as "not found".
func TestLoadSessionFromEvents_EmptyStream(t *testing.T) {
	t.Parallel()
	_, err := LoadSessionFromEvents(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no events")
}

// TestLoadSessionFromEvents_UnknownEventType surfaces corruption as an
// explicit error rather than silently ignoring the unknown row.
func TestLoadSessionFromEvents_UnknownEventType(t *testing.T) {
	t.Parallel()
	_, err := LoadSessionFromEvents([]StoredEvent{
		{
			AggregateID:   "sess-x",
			AggregateType: "Session",
			EventType:     "session.teleported",
			Payload:       []byte(`{}`),
			OccurredAt:    time.Now().UTC(),
			Sequence:      1,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown session event type")
}

// TestLoadSessionFromEvents_CreatedDomainForm verifies that a session.created
// row written by makeEventPersister (full domain.SessionCreatedEvent struct,
// not the narrow SessionCreatedPayload) round-trips correctly.
func TestLoadSessionFromEvents_CreatedDomainForm(t *testing.T) {
	t.Parallel()
	full := domain.SessionCreatedEvent{
		Email:     "carol@example.com",
		SessionID: "sess-full",
		Broker:    "zerodha",
		Timestamp: time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
	}
	payload, err := json.Marshal(full)
	require.NoError(t, err)

	agg, err := LoadSessionFromEvents([]StoredEvent{
		{
			AggregateID:   "sess-full",
			AggregateType: "Session",
			EventType:     "session.created",
			Payload:       payload,
			OccurredAt:    full.Timestamp,
			Sequence:      1,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "carol@example.com", agg.Email)
	assert.Equal(t, SessionStatusActive, agg.Status)
}

// TestLoadSessionFromEvents_MalformedPayload surfaces JSON errors as
// wrapped deserialize errors.
func TestLoadSessionFromEvents_MalformedPayload(t *testing.T) {
	t.Parallel()
	_, err := LoadSessionFromEvents([]StoredEvent{
		{
			AggregateID:   "sess-bad",
			AggregateType: "Session",
			EventType:     "session.cleared",
			Payload:       []byte(`{not json`),
			OccurredAt:    time.Now().UTC(),
			Sequence:      1,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize")
}
