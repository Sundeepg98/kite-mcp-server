// Package eventsourcing — transactional event outbox for hot mutation paths.
//
// Problem
// =======
// The default Append() path writes domain events synchronously inside the
// use case. For hot mutation paths (place_order, modify_order,
// cancel_order, create_alert) the failure window between
//
//     broker.Place → events.Dispatch → eventStore.Append
//
// can lose audit if the process crashes after the broker call but before
// the SQLite write commits. The broker side-effect already happened
// (Kite has the order); the audit log doesn't see it. Compliance gap.
//
// Solution
// ========
// Two-step write with a small SQLite outbox table:
//
//  1. AppendToOutbox(evt) — single, fast SQLite INSERT into event_outbox.
//     Use cases call this immediately after the broker call returns.
//     Process crashes here = no broker side effect was committed yet
//     (Place either succeeded fully and we got past it, or it didn't
//     and we never reached AppendToOutbox).
//
//  2. Async pump — background goroutine polls event_outbox every 100ms,
//     appends each pending row to domain_events via Append, marks the
//     row processed. Crash here = the row stays unprocessed; the next
//     pump tick (or startup-drain) picks it up.
//
// Result: the audit-loss window shrinks from "Append() commit duration
// + I/O contention + buffer flush" to a single ~1ms INSERT. Not perfect
// (any system that survives broker call but doesn't survive one more
// SQLite write loses audit), but materially better.
//
// On startup, NewOutboxPump runs Drain() once to recover entries the
// previous process didn't get to.

package eventsourcing

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// outboxPumpInterval is how often the background pump scans for unprocessed
// outbox rows. 100ms gives near-immediate audit landing while keeping the
// per-tick overhead trivial. Tune via config later if needed.
const outboxPumpInterval = 100 * time.Millisecond

// OutboxPump asynchronously drains event_outbox into domain_events.
// One pump per EventStore. Stop() must be called at shutdown so the
// goroutine terminates cleanly.
type OutboxPump struct {
	store    *EventStore
	logger   *slog.Logger
	interval time.Duration

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// NewOutboxPump creates and starts a pump for the given store. The pump
// runs an immediate Drain() then enters a polling loop.
func NewOutboxPump(store *EventStore, logger *slog.Logger) *OutboxPump {
	p := &OutboxPump{
		store:    store,
		logger:   logger,
		interval: outboxPumpInterval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go p.run()
	return p
}

// Stop signals the pump to exit. Idempotent. Returns after the goroutine
// has confirmed shutdown so callers can rely on no further DB activity
// from this pump after Stop returns.
func (p *OutboxPump) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

// run is the goroutine body. Performs an immediate startup-drain so any
// rows left over from a previous process get processed before regular
// polling begins.
func (p *OutboxPump) run() {
	defer close(p.done)
	// Startup drain — recover from previous-process crash.
	if n, err := p.store.Drain(context.Background()); err != nil {
		p.logger.Warn("outbox pump: startup drain failed", "error", err)
	} else if n > 0 {
		p.logger.Info("outbox pump: recovered events from previous run", "count", n)
	}

	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			// One last drain so any in-flight events make it through.
			if _, err := p.store.Drain(context.Background()); err != nil {
				p.logger.Warn("outbox pump: shutdown drain failed", "error", err)
			}
			return
		case <-t.C:
			if _, err := p.store.Drain(context.Background()); err != nil {
				p.logger.Warn("outbox pump: drain failed", "error", err)
			}
		}
	}
}

// InitOutboxTable creates event_outbox if missing. Call once during startup
// alongside InitTable. Idempotent.
func (s *EventStore) InitOutboxTable() error {
	ddl := `
CREATE TABLE IF NOT EXISTS event_outbox (
    id              TEXT PRIMARY KEY,
    aggregate_id    TEXT NOT NULL,
    aggregate_type  TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    occurred_at     TEXT NOT NULL,
    sequence        INTEGER NOT NULL,
    inserted_at     TEXT NOT NULL,
    processed       INTEGER NOT NULL DEFAULT 0,
    email_hash      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_outbox_unprocessed ON event_outbox(processed, inserted_at ASC) WHERE processed = 0;`
	if err := s.db.ExecDDL(ddl); err != nil {
		return err
	}
	// Migration for pre-PR-D outbox tables.
	_ = s.db.ExecDDL(`ALTER TABLE event_outbox ADD COLUMN email_hash TEXT NOT NULL DEFAULT ''`)
	return nil
}

// AppendToOutbox inserts an event into the staging outbox. The row is
// processed asynchronously by OutboxPump.Drain into domain_events. Use
// this on hot mutation paths (place_order, modify_order, cancel_order,
// create_alert) where the audit-loss window must be minimised.
//
// Failure here = caller should treat the event as not durably recorded
// (same as Append failing). The use case currently logs and continues;
// outbox semantics are preserved.
func (s *EventStore) AppendToOutbox(evt StoredEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if evt.ID == "" {
		evt.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	err := s.db.ExecInsert(
		`INSERT INTO event_outbox
		    (id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, inserted_at, processed, email_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		evt.ID,
		evt.AggregateID,
		evt.AggregateType,
		evt.EventType,
		string(evt.Payload),
		evt.OccurredAt.Format(time.RFC3339Nano),
		evt.Sequence,
		now,
		evt.EmailHash,
	)
	if err != nil {
		return fmt.Errorf("eventsourcing: outbox insert: %w", err)
	}
	return nil
}

// Drain processes all pending outbox rows, appending them to domain_events
// and marking them processed. Returns the number of rows successfully
// drained. Errors short-circuit the loop — partial progress is the whole
// point of an outbox pattern (next tick picks up where this one stopped).
//
// ctx is honoured between rows so a long backlog doesn't tie up shutdown.
func (s *EventStore) Drain(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.RawQuery(
		`SELECT id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash
		   FROM event_outbox
		  WHERE processed = 0
		  ORDER BY inserted_at ASC
		  LIMIT 100`)
	if err != nil {
		return 0, fmt.Errorf("eventsourcing: outbox query: %w", err)
	}
	pending, err := scanEvents(rows)
	rows.Close()
	if err != nil {
		return 0, fmt.Errorf("eventsourcing: outbox scan: %w", err)
	}
	processed := 0
	for _, evt := range pending {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}
		// Reuse the regular Append's INSERT path. We're already holding
		// the mutex; Append re-locks. To avoid the deadlock, copy the
		// INSERT inline.
		insErr := s.db.ExecInsert(
			`INSERT INTO domain_events (id, aggregate_id, aggregate_type, event_type, payload, occurred_at, sequence, email_hash)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			evt.ID,
			evt.AggregateID,
			evt.AggregateType,
			evt.EventType,
			string(evt.Payload),
			evt.OccurredAt.Format(time.RFC3339Nano),
			evt.Sequence,
			evt.EmailHash,
		)
		if insErr != nil {
			// Row insertion into domain_events failed (e.g. UNIQUE
			// violation if a previous Drain succeeded but didn't
			// mark processed). Mark processed anyway — duplicate
			// is a soft idempotency guarantee.
			s.logger().Warn("outbox drain: domain_events insert failed; marking processed",
				"event_id", evt.ID, "error", insErr)
		}
		_, markErr := s.db.ExecResult(`UPDATE event_outbox SET processed = 1 WHERE id = ?`, evt.ID)
		if markErr != nil {
			return processed, fmt.Errorf("eventsourcing: outbox mark processed: %w", markErr)
		}
		processed++
	}
	return processed, nil
}

// logger returns the EventStore's logger or a discard fallback. The store
// itself doesn't carry a logger field today; the pump-side logger handles
// observability. This helper exists so the inline path can log warnings
// without a nil-deref.
func (s *EventStore) logger() *slog.Logger {
	return slog.Default()
}
