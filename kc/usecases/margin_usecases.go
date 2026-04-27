package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Wave D Phase 3 Package 5 (Logger sweep): use cases in this file
// type their logger field as the kc/logger.Logger port; constructors
// retain *slog.Logger and convert via logport.NewSlog.

// GetOrderMarginsUseCase calculates margin required for orders.
type GetOrderMarginsUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

func NewGetOrderMarginsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderMarginsUseCase {
	return &GetOrderMarginsUseCase{brokerResolver: resolver, logger: logport.NewSlog(logger)}
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
		if _, qerr := domain.NewQuantity(int(o.Quantity)); qerr != nil {
			return nil, fmt.Errorf("usecases: order %d: %w", i, qerr)
		}
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
		uc.logger.Error(ctx, "Failed to get order margins", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get order margins: %w", err)
	}

	return result, nil
}

// GetBasketMarginsUseCase calculates combined margin for a basket of orders.
type GetBasketMarginsUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

func NewGetBasketMarginsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetBasketMarginsUseCase {
	return &GetBasketMarginsUseCase{brokerResolver: resolver, logger: logport.NewSlog(logger)}
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
		if _, qerr := domain.NewQuantity(int(o.Quantity)); qerr != nil {
			return nil, fmt.Errorf("usecases: basket order %d: %w", i, qerr)
		}
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
		uc.logger.Error(ctx, "Failed to get basket margins", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get basket margins: %w", err)
	}

	return result, nil
}

// GetOrderChargesUseCase calculates brokerage, taxes, and charges for orders.
type GetOrderChargesUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

func NewGetOrderChargesUseCase(resolver BrokerResolver, logger *slog.Logger) *GetOrderChargesUseCase {
	return &GetOrderChargesUseCase{brokerResolver: resolver, logger: logport.NewSlog(logger)}
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
		if _, qerr := domain.NewQuantity(int(o.Quantity)); qerr != nil {
			return nil, fmt.Errorf("usecases: charges order %d: %w", i, qerr)
		}
		if avg := domain.NewINR(o.AveragePrice); !avg.IsPositive() {
			return nil, fmt.Errorf("usecases: charges order %d: average price must be positive", i)
		}
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
		uc.logger.Error(ctx, "Failed to get order charges", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get order charges: %w", err)
	}

	return result, nil
}
