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
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ModifyOrderUseCase orchestrates the order modification pipeline:
// riskguard check -> broker API call -> domain event dispatch.
type ModifyOrderUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	eventStore     EventAppender
	logger         *slog.Logger
}

// NewModifyOrderUseCase creates a ModifyOrderUseCase with all dependencies injected.
func NewModifyOrderUseCase(
	resolver BrokerResolver,
	guard *riskguard.Guard,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *ModifyOrderUseCase {
	return &ModifyOrderUseCase{
		brokerResolver: resolver,
		riskguard:      guard,
		events:         events,
		logger:         logger,
	}
}

// SetEventStore wires the domain audit-log appender. Phase C ES.
func (uc *ModifyOrderUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// Execute runs the ModifyOrder pipeline and returns the broker response.
func (uc *ModifyOrderUseCase) Execute(ctx context.Context, cmd cqrs.ModifyOrderCommand) (broker.OrderResponse, error) {
	// 1. Validate basic inputs.
	if cmd.Email == "" {
		return broker.OrderResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.OrderID == "" {
		return broker.OrderResponse{}, fmt.Errorf("usecases: order_id is required")
	}

	// Extract raw price from Money VO.
	price := cmd.Price.Amount

	// Use domain specs for quantity/price validation on modify.
	// Quantity of 0 means "don't change" — only validate when provided.
	if cmd.Quantity > 0 {
		qtySpec := domain.NewQuantitySpec(1, 0)
		if !qtySpec.IsSatisfiedBy(cmd.Quantity) {
			return broker.OrderResponse{}, fmt.Errorf("usecases: %s", qtySpec.Reason())
		}
	}
	// Price validation for non-MARKET modify orders when price is provided.
	if price > 0 && cmd.OrderType != "MARKET" && cmd.OrderType != "SL-M" {
		priceSpec := domain.NewPriceSpec(0)
		if !priceSpec.IsSatisfiedBy(price) {
			return broker.OrderResponse{}, fmt.Errorf("usecases: %s", priceSpec.Reason())
		}
	}

	// 2. Run riskguard checks (if configured).
	// Modify orders still need rate-limit and daily-count checks.
	// Confirmed is threaded through ModifyOrderCommand from the MCP handler.
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:     cmd.Email,
			ToolName:  "modify_order",
			OrderType: cmd.OrderType,
			Quantity:  cmd.Quantity,
			Price:     price,
			Confirmed: cmd.Confirmed,
		})
		if !result.Allowed {
			uc.logger.Warn("Modify order blocked by riskguard",
				"email", cmd.Email,
				"order_id", cmd.OrderID,
				"reason", result.Reason,
				"message", result.Message,
			)
			if uc.events != nil {
				uc.events.Dispatch(domain.RiskLimitBreachedEvent{
					Email:     cmd.Email,
					Reason:    string(result.Reason),
					Message:   result.Message,
					ToolName:  "modify_order",
					Timestamp: time.Now().UTC(),
				})
			}
			return broker.OrderResponse{}, fmt.Errorf("usecases: modify order blocked by riskguard: %s", result.Message)
		}
	}

	// 3. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.OrderResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 4. Modify order via broker API.
	params := broker.OrderParams{
		Quantity:         cmd.Quantity,
		Price:            price,
		TriggerPrice:     cmd.TriggerPrice,
		OrderType:        cmd.OrderType,
		Validity:         cmd.Validity,
		DisclosedQty:     cmd.DisclosedQty,
		MarketProtection: cmd.MarketProtection,
		Variety:          cmd.Variety,
	}

	resp, err := client.ModifyOrder(cmd.OrderID, params)
	if err != nil {
		uc.logger.Error("Order modification failed",
			"email", cmd.Email,
			"order_id", cmd.OrderID,
			"error", err,
		)
		return broker.OrderResponse{}, fmt.Errorf("usecases: modify order: %w", err)
	}

	// 5. Dispatch domain event.
	now := time.Now().UTC()
	if uc.events != nil {
		uc.events.Dispatch(domain.OrderModifiedEvent{
			Email:     cmd.Email,
			OrderID:   cmd.OrderID,
			Timestamp: now,
		})
	}
	uc.appendModifiedEvent(cmd, now)

	uc.logger.Info("Order modified",
		"email", cmd.Email,
		"order_id", cmd.OrderID,
	)

	return resp, nil
}

// appendModifiedEvent writes an order.modified StoredEvent to the audit log.
// Best-effort — the broker has already modified the order by the time this
// runs. Payload matches OrderModifiedPayload (kc/eventsourcing/order_aggregate.go).
func (uc *ModifyOrderUseCase) appendModifiedEvent(cmd cqrs.ModifyOrderCommand, occurredAt time.Time) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(cmd.OrderID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on order.modified", "order_id", cmd.OrderID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(eventsourcing.OrderModifiedPayload{
		NewQuantity:  cmd.Quantity,
		NewPrice:     cmd.Price.Amount,
		NewOrderType: cmd.OrderType,
	})
	if err != nil { // COVERAGE: unreachable
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   cmd.OrderID,
		AggregateType: "Order",
		EventType:     "order.modified",
		Payload:       payload,
		OccurredAt:    occurredAt,
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		uc.logger.Warn("event store Append failed on order.modified", "order_id", cmd.OrderID, "error", err)
	}
}
