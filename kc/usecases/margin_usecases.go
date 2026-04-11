package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetOrderMarginsUseCase calculates margin required for orders.
type GetOrderMarginsUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetOrderMarginsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderMarginsUseCase {
	return &GetOrderMarginsUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetOrderMarginsUseCase) Execute(ctx context.Context, query cqrs.GetOrderMarginsQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if len(query.Orders) == 0 {
		return nil, fmt.Errorf("usecases: at least one order is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	params := make([]broker.OrderMarginParam, len(query.Orders))
	for i, o := range query.Orders {
		params[i] = broker.OrderMarginParam{
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Variety:         o.Variety,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Quantity:        o.Quantity,
			Price:           o.Price,
			TriggerPrice:    o.TriggerPrice,
		}
	}

	result, err := client.GetOrderMargins(params)
	if err != nil {
		uc.logger.Error("Failed to get order margins", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get order margins: %w", err)
	}

	return result, nil
}

// GetBasketMarginsUseCase calculates combined margin for a basket of orders.
type GetBasketMarginsUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetBasketMarginsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetBasketMarginsUseCase {
	return &GetBasketMarginsUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetBasketMarginsUseCase) Execute(ctx context.Context, query cqrs.GetBasketMarginsQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if len(query.Orders) == 0 {
		return nil, fmt.Errorf("usecases: at least one order is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	params := make([]broker.OrderMarginParam, len(query.Orders))
	for i, o := range query.Orders {
		params[i] = broker.OrderMarginParam{
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Variety:         o.Variety,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Quantity:        o.Quantity,
			Price:           o.Price,
			TriggerPrice:    o.TriggerPrice,
		}
	}

	result, err := client.GetBasketMargins(params, query.ConsiderPositions)
	if err != nil {
		uc.logger.Error("Failed to get basket margins", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get basket margins: %w", err)
	}

	return result, nil
}

// GetOrderChargesUseCase calculates brokerage, taxes, and charges for orders.
type GetOrderChargesUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetOrderChargesUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderChargesUseCase {
	return &GetOrderChargesUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetOrderChargesUseCase) Execute(ctx context.Context, query cqrs.GetOrderChargesQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if len(query.Orders) == 0 {
		return nil, fmt.Errorf("usecases: at least one order is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	params := make([]broker.OrderChargesParam, len(query.Orders))
	for i, o := range query.Orders {
		params[i] = broker.OrderChargesParam{
			OrderID:         o.OrderID,
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Quantity:        o.Quantity,
			AveragePrice:    o.AveragePrice,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Variety:         o.Variety,
		}
	}

	result, err := client.GetOrderCharges(params)
	if err != nil {
		uc.logger.Error("Failed to get order charges", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get order charges: %w", err)
	}

	return result, nil
}
