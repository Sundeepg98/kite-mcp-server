// Package eventsourcing provides an append-only domain audit log backed by SQLite
// and aggregate patterns for modeling domain state transitions.
//
// ARCHITECTURE NOTE: In production, the EventStore functions as a **domain audit log**,
// not a true event-sourced system. Domain events are appended by makeEventPersister
// (in app/app.go) whenever use cases dispatch events, but they are never read back
// to reconstitute state. Reads go to broker APIs (orders, positions) or CRUD stores
// (alerts, users). The aggregate types (OrderAggregate, PositionAggregate, AlertAggregate)
// and their Load*FromEvents functions exist as test infrastructure for verifying
// event replay correctness — they are not instantiated in production code paths.
//
// Events are immutable once appended — no UPDATE or DELETE is ever issued.
// The domain_events table serves as a compliance/debugging audit trail.
package eventsourcing

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// StoredEvent is the persistent representation of a domain event.
// All events are stored in a single table, keyed by aggregate ID and type.
//
// EmailHash is the SHA-256 hex digest of the lowercased email associated
// with the event (PR-D Item 2). Empty for events with no user-association
// (system events, alert.triggered without recipient context). The audit
// log uses email_hash as the canonical user identifier so the
// domain_events table never carries plaintext PII — DPDP minimisation
// principle.
type StoredEvent struct {
	ID            string    `json:"id"`
	AggregateID   string    `json:"aggregate_id"`   // e.g., order ID
	AggregateType string    `json:"aggregate_type"`  // "Order", "Alert", etc.
	EventType     string    `json:"event_type"`      // "OrderPlaced", "OrderCancelled", etc.
	Payload       []byte    `json:"payload"`         // JSON-serialized event data
	OccurredAt    time.Time `json:"occurred_at"`
	Sequence      int64     `json:"sequence"`        // auto-incremented per aggregate
	EmailHash     string    `json:"email_hash,omitempty"` // SHA-256 hex of lowercased email; empty for system events
}

// EventStore provides append-only persistence for domain events backed by SQLite.
// In production, this acts as a domain audit log — events are appended but not
// read back for state reconstitution. LoadEvents and LoadEventsSince are available
// for debugging, compliance queries, and test infrastructure.
// It reuses the existing alerts.DB handle for database access.
type EventStore struct {
	db *alerts.DB
	mu sync.RWMutex
}

// NewEventStore creates an EventStore using the given database handle.
func NewEventStore(db *alerts.DB) *EventStore {
	return &EventStore{db: db}
}

// InitTable creates the domain_events table and indexes if they do not exist.
func (s *EventStore) InitTable() error {
	ddl := `
CREATE TABLE IF NOT EXISTS domain_events (
    id              TEXT PRIMARY KEY,
    aggregate_id    TEXT NOT NULL,
    aggregate_type  TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,
    sequence        INTEGER NOT NULL,
    email_hash      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_de_aggregate ON domain_events(aggregate_id, sequence ASC);
CREATE INDEX IF NOT EXISTS idx_de_type ON domain_events(aggregate_type, occurred_at ASC);
CREATE INDEX IF NOT EXISTS idx_de_occurred ON domain_events(occurred_at ASC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_de_aggregate_seq ON domain_events(aggregate_id, sequence);
CREATE INDEX IF NOT EXISTS idx_de_email_hash ON domain_events(email_hash, occurred_at ASC) WHERE email_hash != '';`
	if err := s.db.ExecDDL(ddl); err != nil {
		return err
	}
	// PR-D Item 2 migration: pre-existing tables get the email_hash column
	// added (SQLite ignores duplicate-column errors via the err discard).
	_ = s.db.ExecDDL(`ALTER TABLE domain_events ADD COLUMN email_hash TEXT NOT NULL DEFAULT ''`)
	return nil
}

// Append persists one or more events atomically. Each event is assigned a UUID
// if its ID is empty. The Sequence field must be set by the caller (typically
// derived from the aggregate version).
func (s *EventStore) Append(events ...StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range events {
		if e.ID == "" {
			e.ID = uuid.New().String()
		}
		err := s.db.ExecInsert(
			`INSERT INTO domain_events (id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID,
			e.AggregateID,
			e.AggregateType,
			e.EventType,
			string(e.Payload),
			e.OccurredAt.Format(time.RFC3339Nano),
			e.Sequence,
			e.EmailHash,
		)
		if err != nil {
			return fmt.Errorf("eventsourcing: append event %s: %w", e.EventType, err)
		}
	}
	return nil
}

// LoadEvents retrieves all events for a given aggregate, ordered by sequence.
func (s *EventStore) LoadEvents(aggregateID string) ([]StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.RawQuery(
		`SELECT id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash
		 FROM domain_events
		 WHERE aggregate_id = ?
		 ORDER BY sequence ASC`,
		aggregateID,
	)
	if err != nil {
		return nil, fmt.Errorf("eventsourcing: load events for %s: %w", aggregateID, err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// LoadEventsSince retrieves all events that occurred after the given time,
// ordered by occurred_at. Useful for building projections and read models.
func (s *EventStore) LoadEventsSince(since time.Time) ([]StoredEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.RawQuery(
		`SELECT id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash
		 FROM domain_events
		 WHERE occurred_at > ?
		 ORDER BY occurred_at ASC`,
		since.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("eventsourcing: load events since %s: %w", since.Format(time.RFC3339), err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// LoadEventsByEmailHash retrieves all events associated with the given
// hashed email, ordered by occurred_at. Used by the data-portability
// export (PR-D Item 3) to find every domain event a Data Principal
// accumulated over the retention window.
//
// Empty emailHash returns no rows (defensive — never matches the
// empty-string default for system events).
func (s *EventStore) LoadEventsByEmailHash(emailHash string, since time.Time) ([]StoredEvent, error) {
	if emailHash == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.RawQuery(
		`SELECT id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash
		 FROM domain_events
		 WHERE email_hash = ? AND occurred_at >= ?
		 ORDER BY occurred_at ASC`,
		emailHash,
		since.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("eventsourcing: load events by email_hash: %w", err)
	}
	defer rows.Close()

	return scanEvents(rows)
}

// NextSequence returns the next sequence number for an aggregate.
func (s *EventStore) NextSequence(aggregateID string) (int64, error) {
	var maxSeq int64
	err := s.db.QueryRow(
		`SELECT COALESCE(MAX(sequence), 0) FROM domain_events WHERE aggregate_id = ?`,
		aggregateID,
	).Scan(&maxSeq)
	if err != nil {
		return 0, fmt.Errorf("eventsourcing: next sequence for %s: %w", aggregateID, err)
	}
	return maxSeq + 1, nil
}

// scanEvents scans rows from a domain_events query into a slice of StoredEvent.
// Expects 8 columns: (id, aggregate_id, aggregate_type, event_type, payload,
// occurred_at, sequence, email_hash). Callers using the legacy 7-column
// projection should migrate — every prod query path includes email_hash
// after PR-D Item 2.
func scanEvents(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]StoredEvent, error) {
	var events []StoredEvent
	for rows.Next() {
		var e StoredEvent
		var occurredAtStr string
		var payload string
		if err := rows.Scan(&e.ID, &e.AggregateID, &e.AggregateType, &e.EventType, &payload, &occurredAtStr, &e.Sequence, &e.EmailHash); err != nil {
			return nil, fmt.Errorf("eventsourcing: scan event: %w", err)
		}
		e.Payload = []byte(payload)
		t, err := time.Parse(time.RFC3339Nano, occurredAtStr)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: parse occurred_at: %w", err)
		}
		e.OccurredAt = t
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("eventsourcing: iterate events: %w", err)
	}
	return events, nil
}

// MarshalPayload is a convenience helper that JSON-encodes a value for event payloads.
func MarshalPayload(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("eventsourcing: marshal payload: %w", err)
	}
	return b, nil
}
