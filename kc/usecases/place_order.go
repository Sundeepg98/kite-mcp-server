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

	// Extract raw values from VOs for downstream use.
	qty := cmd.Qty.Int()
	price := cmd.Price.Amount
	exchange := cmd.Instrument.Exchange
	symbol := cmd.Instrument.Tradingsymbol

	// Use OrderSpec (specification pattern) for domain-level order validation.
	orderSpec := domain.NewOrderSpec(
		domain.NewQuantitySpec(1, 0), // min 1, no max
		domain.NewPriceSpec(0),       // positive price, no ceiling
	)
	candidate := domain.OrderCandidate{
		Quantity:        qty,
		Price:           price,
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		TransactionType: cmd.TransactionType,
		OrderType:       cmd.OrderType,
	}
	if !orderSpec.IsSatisfiedBy(candidate) {
		return "", fmt.Errorf("usecases: %s", orderSpec.Reason())
	}

	// 2. Run riskguard checks (if configured).
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           cmd.Email,
			ToolName:        "place_order",
			Exchange:        exchange,
			Tradingsymbol:   symbol,
			TransactionType: cmd.TransactionType,
			Quantity:        qty,
			Price:           price,
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
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		TransactionType: cmd.TransactionType,
		OrderType:       cmd.OrderType,
		Product:         cmd.Product,
		Quantity:        qty,
		Price:           price,
		TriggerPrice:    cmd.TriggerPrice,
		Validity:        cmd.Validity,
		Variety:         cmd.Variety,
		Tag:             cmd.Tag,
	}

	resp, err := client.PlaceOrder(params)
	if err != nil {
		uc.logger.Error("Order placement failed",
			"email", cmd.Email,
			"tradingsymbol", symbol,
			"error", err,
		)
		return "", fmt.Errorf("usecases: place order: %w", err)
	}

	// 5. Dispatch domain events.
	// OrderPlacedEvent drives the audit log and the order projection.
	// PositionOpenedEvent activates the position projection: each new order
	// is treated as opening a position candidate keyed by the order ID. Once
	// close_position / close_all_positions dispatches PositionClosedEvent
	// with the same-or-related order ID, the projection reflects the full
	// open → close lifecycle. Position ID is the broker order ID because
	// that's the only stable identifier available at placement time.
	if uc.events != nil {
		now := time.Now().UTC()
		uc.events.Dispatch(domain.OrderPlacedEvent{
			Email:           cmd.Email,
			OrderID:         resp.OrderID,
			Instrument:      cmd.Instrument,
			Qty:             cmd.Qty,
			Price:           cmd.Price,
			TransactionType: cmd.TransactionType,
			Timestamp:       now,
		})
		uc.events.Dispatch(domain.PositionOpenedEvent{
			Email:           cmd.Email,
			PositionID:      resp.OrderID,
			Instrument:      cmd.Instrument,
			Qty:             cmd.Qty,
			AvgPrice:        cmd.Price,
			TransactionType: cmd.TransactionType,
			Timestamp:       now,
		})
	}

	uc.logger.Info("Order placed",
		"email", cmd.Email,
		"order_id", resp.OrderID,
		"tradingsymbol", symbol,
		"transaction_type", cmd.TransactionType,
	)

	return resp.OrderID, nil
}

