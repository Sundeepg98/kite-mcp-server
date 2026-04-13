package kc

import (
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// This file holds the serializers + reconstitution helpers for the
// event-sourced read side. Extracted from kc/manager.go to keep that file
// under 1000 LOC — manager.go was bloating past the threshold as the
// reconstitution path grew (Order in §10 step 16, Alert in step 26).
//
// All three functions are package-level and called directly from the bus
// handlers registered in manager.go:registerCQRSHandlers(). Nothing about
// the read-side path changes; this is pure file layout.

// orderAggregateToProjectionResult serializes an OrderAggregate into the
// OrderProjectionResult read model. Timestamps are RFC3339 when non-zero.
func orderAggregateToProjectionResult(agg *eventsourcing.OrderAggregate) cqrs.OrderProjectionResult {
	res := cqrs.OrderProjectionResult{
		OrderID:         agg.AggregateID(),
		Status:          agg.Status,
		Email:           agg.Email,
		Exchange:        agg.Instrument.Exchange,
		Tradingsymbol:   agg.Instrument.Tradingsymbol,
		TransactionType: agg.TransactionType,
		OrderType:       agg.OrderType,
		Product:         agg.Product,
		Quantity:        agg.Quantity.Int(),
		Price:           agg.Price.Amount,
		FilledPrice:     agg.FilledPrice.Amount,
		FilledQuantity:  agg.FilledQuantity.Int(),
		ModifyCount:     agg.ModifyCount,
		Version:         agg.Version(),
		Found:           true,
	}
	if !agg.PlacedAt.IsZero() {
		res.PlacedAt = agg.PlacedAt.UTC().Format(time.RFC3339)
	}
	if !agg.ModifiedAt.IsZero() {
		res.ModifiedAt = agg.ModifiedAt.UTC().Format(time.RFC3339)
	}
	if !agg.CancelledAt.IsZero() {
		res.CancelledAt = agg.CancelledAt.UTC().Format(time.RFC3339)
	}
	if !agg.FilledAt.IsZero() {
		res.FilledAt = agg.FilledAt.UTC().Format(time.RFC3339)
	}
	return res
}

// reconstituteOrderHistory replays a persisted event stream for a single order
// aggregate and returns one snapshot per event plus the final state. Replaying
// growing prefixes is O(N^2) in event count, which is fine because real order
// lifecycles top out at ~5 events (placed + optional modifies + fill/cancel).
//
// First production caller of eventsourcing.LoadOrderFromEvents — before this,
// the reconstitution path existed only in test code. Turns the event store
// from a write-only audit log into a read-side source of truth for order
// lifecycle queries.
func reconstituteOrderHistory(orderID string, events []eventsourcing.StoredEvent) (cqrs.OrderHistoryResult, error) {
	snapshots := make([]cqrs.OrderStateSnapshot, 0, len(events))
	for i := 1; i <= len(events); i++ {
		prefix := events[:i]
		agg, err := eventsourcing.LoadOrderFromEvents(prefix)
		if err != nil {
			return cqrs.OrderHistoryResult{}, fmt.Errorf("cqrs: replay prefix %d: %w", i, err)
		}
		last := prefix[len(prefix)-1]
		snapshots = append(snapshots, cqrs.OrderStateSnapshot{
			Sequence:       last.Sequence,
			EventType:      last.EventType,
			OccurredAt:     last.OccurredAt.UTC().Format(time.RFC3339Nano),
			Status:         agg.Status,
			Quantity:       agg.Quantity.Int(),
			Price:          agg.Price.Amount,
			FilledPrice:    agg.FilledPrice.Amount,
			FilledQuantity: agg.FilledQuantity.Int(),
			ModifyCount:    agg.ModifyCount,
		})
	}

	// Final full replay for the aggregate-level fields.
	finalAgg, err := eventsourcing.LoadOrderFromEvents(events)
	if err != nil {
		return cqrs.OrderHistoryResult{}, fmt.Errorf("cqrs: final replay: %w", err)
	}
	result := cqrs.OrderHistoryResult{
		OrderID:          orderID,
		Found:            true,
		EventCount:       len(events),
		FinalStatus:      finalAgg.Status,
		Email:            finalAgg.Email,
		Exchange:         finalAgg.Instrument.Exchange,
		Tradingsymbol:    finalAgg.Instrument.Tradingsymbol,
		TransactionType:  finalAgg.TransactionType,
		OrderType:        finalAgg.OrderType,
		Product:          finalAgg.Product,
		FinalQuantity:    finalAgg.Quantity.Int(),
		FinalPrice:       finalAgg.Price.Amount,
		FinalFilledPrice: finalAgg.FilledPrice.Amount,
		FinalFilledQty:   finalAgg.FilledQuantity.Int(),
		ModifyCount:      finalAgg.ModifyCount,
		Version:          finalAgg.Version(),
		States:           snapshots,
	}
	if !finalAgg.PlacedAt.IsZero() {
		result.PlacedAt = finalAgg.PlacedAt.UTC().Format(time.RFC3339)
	}
	return result, nil
}

// reconstituteAlertHistory replays a persisted event stream for a single
// alert aggregate. Same growing-prefix pattern as reconstituteOrderHistory —
// O(N^2) is fine because alert lifecycles are typically ≤3 events (create,
// trigger, delete). First production caller of LoadAlertFromEvents.
func reconstituteAlertHistory(alertID string, events []eventsourcing.StoredEvent) (cqrs.AlertHistoryResult, error) {
	snapshots := make([]cqrs.AlertStateSnapshot, 0, len(events))
	for i := 1; i <= len(events); i++ {
		prefix := events[:i]
		agg, err := eventsourcing.LoadAlertFromEvents(prefix)
		if err != nil {
			return cqrs.AlertHistoryResult{}, fmt.Errorf("cqrs: replay prefix %d: %w", i, err)
		}
		last := prefix[len(prefix)-1]
		snap := cqrs.AlertStateSnapshot{
			Sequence:    last.Sequence,
			EventType:   last.EventType,
			OccurredAt:  last.OccurredAt.UTC().Format(time.RFC3339Nano),
			Status:      agg.Status,
			TargetPrice: agg.TargetPrice.Amount,
		}
		snapshots = append(snapshots, snap)
	}

	finalAgg, err := eventsourcing.LoadAlertFromEvents(events)
	if err != nil {
		return cqrs.AlertHistoryResult{}, fmt.Errorf("cqrs: final replay: %w", err)
	}
	result := cqrs.AlertHistoryResult{
		AlertID:       alertID,
		Found:         true,
		EventCount:    len(events),
		FinalStatus:   finalAgg.Status,
		Email:         finalAgg.Email,
		Exchange:      finalAgg.Instrument.Exchange,
		Tradingsymbol: finalAgg.Instrument.Tradingsymbol,
		Direction:     finalAgg.Direction,
		TargetPrice:   finalAgg.TargetPrice.Amount,
		Version:       finalAgg.Version(),
		States:        snapshots,
	}
	if !finalAgg.CreatedAt.IsZero() {
		result.CreatedAt = finalAgg.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !finalAgg.TriggeredAt.IsZero() {
		result.TriggeredAt = finalAgg.TriggeredAt.UTC().Format(time.RFC3339)
	}
	if !finalAgg.DeletedAt.IsZero() {
		result.DeletedAt = finalAgg.DeletedAt.UTC().Format(time.RFC3339)
	}
	return result, nil
}
