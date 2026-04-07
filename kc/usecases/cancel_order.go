package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// CancelOrderUseCase orchestrates order cancellation:
// broker API call -> domain event dispatch.
// Riskguard is not applied to cancels (cancelling reduces risk, not increases it).
type CancelOrderUseCase struct {
	brokerResolver BrokerResolver
	events         *domain.EventDispatcher
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
	if uc.events != nil {
		uc.events.Dispatch(domain.OrderCancelledEvent{
			Email:     cmd.Email,
			OrderID:   cmd.OrderID,
			Timestamp: time.Now().UTC(),
		})
	}

	uc.logger.Info("Order cancelled",
		"email", cmd.Email,
		"order_id", cmd.OrderID,
	)

	return resp, nil
}
