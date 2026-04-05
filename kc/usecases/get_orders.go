package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetOrdersUseCase retrieves all orders for the current trading day.
type GetOrdersUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetOrdersUseCase creates a GetOrdersUseCase with all dependencies injected.
func NewGetOrdersUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrdersUseCase {
	return &GetOrdersUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// Execute retrieves the user's orders for the current trading day.
func (uc *GetOrdersUseCase) Execute(ctx context.Context, query cqrs.GetOrdersQuery) ([]broker.Order, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	orders, err := client.GetOrders()
	if err != nil {
		uc.logger.Error("Failed to get orders", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get orders: %w", err)
	}

	return orders, nil
}
