package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// CancelOrderUseCase orchestrates order cancellation:
// broker API call -> domain event dispatch.
// Riskguard is not applied to cancels (cancelling reduces risk, not increases it).
type CancelOrderUseCase struct {
	brokerResolver BrokerResolver
	events         *domain.EventDispatcher
	eventStore     EventAppender
	logger         *slog.Logger
}

// NewCancelOrderUseCase creates a CancelOrderUseCase with all dependencies injected.
func NewCancelOrderUseCase(
	resolver BrokerResolver,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *CancelOrderUseCase {
	return &CancelOrderUseCase{
		brokerResolver: resolver,
		events:         events,
		logger:         logger,
	}
}

// SetEventStore wires the domain audit-log appender. Phase C ES.
func (uc *CancelOrderUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// Execute cancels the specified order and returns the broker response.
func (uc *CancelOrderUseCase) Execute(ctx context.Context, cmd cqrs.CancelOrderCommand) (broker.OrderResponse, error) {
	// 1. Validate basic inputs.
	if cmd.Email == "" {
		return broker.OrderResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.OrderID == "" {
		return broker.OrderResponse{}, fmt.Errorf("usecases: order_id is required")
	}

	variety := cmd.Variety
	if variety == "" {
		variety = "regular"
	}

	// 2. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.OrderResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 3. Cancel order via broker API.
	resp, err := client.CancelOrder(cmd.OrderID, variety)
	if err != nil {
		uc.logger.Error("Order cancellation failed",
			"email", cmd.Email,
			"order_id", cmd.OrderID,
			"error", err,
		)
		return broker.OrderResponse{}, fmt.Errorf("usecases: cancel order: %w", err)
	}

	// 4. Dispatch domain event.
	now := time.Now().UTC()
	if uc.events != nil {
		uc.events.Dispatch(domain.OrderCancelledEvent{
			Email:     cmd.Email,
			OrderID:   cmd.OrderID,
			Timestamp: now,
		})
	}
	uc.appendCancelledEvent(cmd.OrderID, now)

	uc.logger.Info("Order cancelled",
		"email", cmd.Email,
		"order_id", cmd.OrderID,
	)

	return resp, nil
}

// appendCancelledEvent writes an order.cancelled StoredEvent to the audit
// log. Best-effort — the broker has already cancelled the order.
func (uc *CancelOrderUseCase) appendCancelledEvent(orderID string, occurredAt time.Time) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(orderID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on order.cancelled", "order_id", orderID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(eventsourcing.OrderCancelledPayload{})
	if err != nil { // COVERAGE: unreachable
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   orderID,
		AggregateType: "Order",
		EventType:     "order.cancelled",
		Payload:       payload,
		OccurredAt:    occurredAt,
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		uc.logger.Warn("event store Append failed on order.cancelled", "order_id", orderID, "error", err)
	}
}
