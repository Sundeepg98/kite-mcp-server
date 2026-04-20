package eventsourcing

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Session status constants — the small set of lifecycle states a session
// moves through over its lifetime. Active is the default starting state
// after a session.created event lands. Cleared means the broker attachment
// was torn down but the session record lives on. Invalidated is terminal.
const (
	SessionStatusActive      = "ACTIVE"
	SessionStatusCleared     = "CLEARED"
	SessionStatusInvalidated = "INVALIDATED"
)

// SessionAggregate models the lifecycle of an MCP session through events.
// State is only mutated via Apply, which processes domain events.
//
// NOTE: Not instantiated in production — session state lives in
// SessionRegistry (in-memory) with SQLite restore. The aggregate exists
// for testing event replay correctness and for compliance queries that
// walk session.created / session.cleared / session.invalidated streams.
type SessionAggregate struct {
	BaseAggregate
	Email          string
	Broker         string
	Status         string // ACTIVE, CLEARED, INVALIDATED
	CreatedAt      time.Time
	LastClearedAt  time.Time // reset each time session.cleared lands
	InvalidatedAt  time.Time
	LastClearReason string
	InvalidationReason string
}

// NewSessionAggregate creates a new session aggregate keyed by sessionID.
func NewSessionAggregate(sessionID string) *SessionAggregate {
	return &SessionAggregate{
		BaseAggregate: BaseAggregate{id: sessionID},
	}
}

// AggregateType returns "Session".
func (a *SessionAggregate) AggregateType() string { return "Session" }

// --- Payload types (for dual-format round-trip: see alert_aggregate.go) ---

// SessionCreatedPayload is the JSON payload for a session.created event
// when persisted by the use case path (not makeEventPersister).
type SessionCreatedPayload struct {
	Email     string `json:"email"`
	SessionID string `json:"session_id"`
	Broker    string `json:"broker"`
}

// SessionClearedPayload is the JSON payload for a session.cleared event.
type SessionClearedPayload struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// SessionInvalidatedPayload is the JSON payload for a session.invalidated event.
type SessionInvalidatedPayload struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason"`
}

// --- Apply (state reconstitution) ---

// Apply processes a domain event and updates aggregate state.
// Both the public domain.Session*Event types (dispatched on the bus and
// persisted via makeEventPersister) and any internal event types are handled.
func (a *SessionAggregate) Apply(event domain.Event) {
	switch e := event.(type) {
	case domain.SessionCreatedEvent:
		a.Email = e.Email
		a.Broker = e.Broker
		a.Status = SessionStatusActive
		a.CreatedAt = e.Timestamp
	case domain.SessionClearedEvent:
		// session.cleared keeps the session alive — it only tears down the
		// broker attachment. Remain CLEARED until a future session.created
		// or session.invalidated lands.
		a.Status = SessionStatusCleared
		a.LastClearedAt = e.Timestamp
		a.LastClearReason = e.Reason
	case domain.SessionInvalidatedEvent:
		a.Status = SessionStatusInvalidated
		a.InvalidatedAt = e.Timestamp
		a.InvalidationReason = e.Reason
	}
	a.incrementVersion()
}

// --- Reconstitution from stored events ---

// LoadSessionFromEvents replays a sequence of stored events to reconstitute
// a SessionAggregate. Returns an error if the stream is empty or an event
// type is unknown — the caller can treat that as a corrupted audit log.
func LoadSessionFromEvents(events []StoredEvent) (*SessionAggregate, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("eventsourcing: no events to load session from")
	}
	agg := NewSessionAggregate(events[0].AggregateID)
	for _, stored := range events {
		domainEvent, err := deserializeSessionEvent(stored)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: deserialize event %s: %w", stored.EventType, err)
		}
		agg.Apply(domainEvent)
	}
	agg.ClearPendingEvents()
	return agg, nil
}

func deserializeSessionEvent(stored StoredEvent) (domain.Event, error) {
	switch stored.EventType {
	case "session.created":
		// makeEventPersister writes the full domain.SessionCreatedEvent struct
		// as JSON; the use-case path writes the narrower SessionCreatedPayload.
		// Try the domain form first; fall back to the narrow payload on mismatch.
		var full domain.SessionCreatedEvent
		if err := json.Unmarshal(stored.Payload, &full); err == nil && full.SessionID != "" {
			return full, nil
		}
		var p SessionCreatedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return domain.SessionCreatedEvent{
			Email:     p.Email,
			SessionID: p.SessionID,
			Broker:    p.Broker,
			Timestamp: stored.OccurredAt,
		}, nil

	case "session.cleared":
		var p SessionClearedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return domain.SessionClearedEvent{
			SessionID: p.SessionID,
			Reason:    p.Reason,
			Timestamp: stored.OccurredAt,
		}, nil

	case "session.invalidated":
		var p SessionInvalidatedPayload
		if err := json.Unmarshal(stored.Payload, &p); err != nil {
			return nil, err
		}
		return domain.SessionInvalidatedEvent{
			SessionID: p.SessionID,
			Reason:    p.Reason,
			Timestamp: stored.OccurredAt,
		}, nil

	default:
		return nil, fmt.Errorf("unknown session event type: %s", stored.EventType)
	}
}
