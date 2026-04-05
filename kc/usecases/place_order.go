// Package usecases contains application use cases that orchestrate domain
// logic, infrastructure services, and cross-cutting concerns (riskguard, events).
//
// Each use case is a single-purpose struct with an Execute method, following
// Clean Architecture principles. Use cases depend on interfaces, not concrete
// implementations, making them fully testable with mocks.
package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// BrokerResolver resolves a broker.Client for a given user email.
// This abstracts the session/credential lookup so use cases don't depend on
// the full SessionService.
type BrokerResolver interface {
	GetBrokerForEmail(email string) (broker.Client, error)
}

// PlaceOrderUseCase orchestrates the full order placement pipeline:
// riskguard check -> broker API call -> domain event dispatch.
type PlaceOrderUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

// NewPlaceOrderUseCase creates a PlaceOrderUseCase with all dependencies injected.
func NewPlaceOrderUseCase(
	resolver BrokerResolver,
	guard *riskguard.Guard,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *PlaceOrderUseCase {
	return &PlaceOrderUseCase{
		brokerResolver: resolver,
		riskguard:      guard,
		events:         events,
		logger:         logger,
	}
}

// Execute runs the PlaceOrder pipeline and returns the broker-assigned order ID.
func (uc *PlaceOrderUseCase) Execute(ctx context.Context, cmd cqrs.PlaceOrderCommand) (string, error) {
	// 1. Validate basic inputs.
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return "", fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.Quantity <= 0 {
		return "", fmt.Errorf("usecases: quantity must be positive, got %d", cmd.Quantity)
	}

	// 2. Run riskguard checks (if configured).
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           cmd.Email,
			ToolName:        "place_order",
			Exchange:        cmd.Exchange,
			Tradingsymbol:   cmd.Tradingsymbol,
			TransactionType: cmd.TransactionType,
			Quantity:        cmd.Quantity,
			Price:           cmd.Price,
			OrderType:       cmd.OrderType,
		})
		if !result.Allowed {
			uc.logger.Warn("Order blocked by riskguard",
				"email", cmd.Email,
				"reason", result.Reason,
				"message", result.Message,
			)
			if uc.events != nil {
				uc.events.Dispatch(domain.RiskLimitBreachedEvent{
					Email:     cmd.Email,
					Reason:    string(result.Reason),
					Message:   result.Message,
					ToolName:  "place_order",
					Timestamp: time.Now().UTC(),
				})
			}
			return "", fmt.Errorf("usecases: order blocked by riskguard: %s", result.Message)
		}
	}

	// 3. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return "", fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 4. Place order via broker API.
	params := broker.OrderParams{
		Exchange:        cmd.Exchange,
		Tradingsymbol:   cmd.Tradingsymbol,
		TransactionType: cmd.TransactionType,
		OrderType:       cmd.OrderType,
		Product:         cmd.Product,
		Quantity:        cmd.Quantity,
		Price:           cmd.Price,
		TriggerPrice:    cmd.TriggerPrice,
		Validity:        cmd.Validity,
		Variety:         cmd.Variety,
		Tag:             cmd.Tag,
	}

	resp, err := client.PlaceOrder(params)
	if err != nil {
		uc.logger.Error("Order placement failed",
			"email", cmd.Email,
			"tradingsymbol", cmd.Tradingsymbol,
			"error", err,
		)
		return "", fmt.Errorf("usecases: place order: %w", err)
	}

	// 5. Dispatch domain event.
	if uc.events != nil {
		qty, _ := domain.NewQuantity(cmd.Quantity)
		uc.events.Dispatch(domain.OrderPlacedEvent{
			Email:           cmd.Email,
			OrderID:         resp.OrderID,
			Instrument:      domain.NewInstrumentKey(cmd.Exchange, cmd.Tradingsymbol),
			Qty:             qty,
			Price:           domain.NewINR(cmd.Price),
			TransactionType: cmd.TransactionType,
			Timestamp:       time.Now().UTC(),
		})
	}

	uc.logger.Info("Order placed",
		"email", cmd.Email,
		"order_id", resp.OrderID,
		"tradingsymbol", cmd.Tradingsymbol,
		"transaction_type", cmd.TransactionType,
	)

	return resp.OrderID, nil
}

