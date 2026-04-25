package usecases

// auxiliary_event_helper.go — generic event-store helper for mutation
// domains whose events don't (yet) have a typed kc/domain.Event
// counterpart. Used by gtt, mf, native_alert, paper_trading,
// trailing_stop, and convert_position use cases so every mutation in
// those domains lands in the domain_events table for audit/replay.
//
// The watchlist use cases use an analogous (but inlined) helper named
// appendWatchlistEvent. We keep this helper generic so future mutation
// domains can adopt it without copy-paste.

import (
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// appendAuxEvent persists a mutation event to the audit/event store with
// the given aggregate type + ID + event type + payload. Failures are
// logged and swallowed — the SQL/broker write is source of truth, and
// the audit-trail miss should not fail the user-visible operation.
//
// store==nil is a normal dev-mode condition (no SQLite wired) — the
// helper short-circuits silently to keep test setup lightweight.
//
// payload may be any JSON-marshalable value. Use map[string]any for ad
// hoc payloads or a typed struct for the same shape; eventsourcing.
// MarshalPayload accepts both.
func appendAuxEvent(
	store EventAppender,
	logger *slog.Logger,
	aggregateType, aggregateID, eventType string,
	payload any,
) {
	if store == nil {
		return
	}
	if aggregateID == "" {
		// Skip rather than emit with an empty key — the Append index
		// is (aggregate_id, sequence). An empty ID would collide
		// across users and corrupt the replay stream.
		if logger != nil {
			logger.Warn("appendAuxEvent: empty aggregate_id; skipping",
				"event_type", eventType, "aggregate_type", aggregateType)
		}
		return
	}
	seq, err := store.NextSequence(aggregateID)
	if err != nil {
		if logger != nil {
			logger.Warn("event store NextSequence failed",
				"event_type", eventType, "aggregate_type", aggregateType,
				"aggregate_id", aggregateID, "error", err)
		}
		return
	}
	raw, err := eventsourcing.MarshalPayload(payload)
	if err != nil {
		if logger != nil {
			logger.Warn("event store payload marshal failed",
				"event_type", eventType, "error", err)
		}
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   aggregateID,
		AggregateType: aggregateType,
		EventType:     eventType,
		Payload:       raw,
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
	if err := store.Append(evt); err != nil {
		if logger != nil {
			logger.Warn("event store Append failed",
				"event_type", eventType, "aggregate_id", aggregateID, "error", err)
		}
	}
}
