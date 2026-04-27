package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// GetOrdersUseCase retrieves all orders for the current trading day.
//
// Wave D Phase 3 Package 5 (Logger sweep): logger is the kc/logger.Logger
// port; constructor takes *slog.Logger and converts via logport.NewSlog.
type GetOrdersUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

// NewGetOrdersUseCase creates a GetOrdersUseCase with all dependencies injected.
func NewGetOrdersUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrdersUseCase {
	return &GetOrdersUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
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
		uc.logger.Error(ctx, "Failed to get orders", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get orders: %w", err)
	}

	return orders, nil
}
