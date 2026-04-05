package kc

import (
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
)

// OrderService owns order placement, modification, and cancellation.
// It resolves a broker.Client per user and delegates to the broker interface.
// Extracted from Manager as part of Clean Architecture / SOLID refactoring.
type OrderService struct {
	sessionSvc *SessionService
	logger     *slog.Logger
}

// NewOrderService creates a new OrderService.
func NewOrderService(sessionSvc *SessionService, logger *slog.Logger) *OrderService {
	return &OrderService{
		sessionSvc: sessionSvc,
		logger:     logger,
	}
}

// getBroker resolves a broker.Client for the given email.
func (os *OrderService) getBroker(email string) (broker.Client, error) {
	b, err := os.sessionSvc.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("order: %w", err)
	}
	return b, nil
}

// PlaceOrder places a new order for the user.
func (os *OrderService) PlaceOrder(email string, params broker.OrderParams) (broker.OrderResponse, error) {
	b, err := os.getBroker(email)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	resp, err := b.PlaceOrder(params)
	if err != nil {
		os.logger.Error("Failed to place order", "email", email, "error", err)
		return broker.OrderResponse{}, fmt.Errorf("failed to place order: %w", err)
	}
	return resp, nil
}

// ModifyOrder modifies an existing pending order.
func (os *OrderService) ModifyOrder(email, orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	b, err := os.getBroker(email)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	resp, err := b.ModifyOrder(orderID, params)
	if err != nil {
		os.logger.Error("Failed to modify order", "email", email, "order_id", orderID, "error", err)
		return broker.OrderResponse{}, fmt.Errorf("failed to modify order: %w", err)
	}
	return resp, nil
}

// CancelOrder cancels an existing pending order.
func (os *OrderService) CancelOrder(email, orderID string) (broker.OrderResponse, error) {
	b, err := os.getBroker(email)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	resp, err := b.CancelOrder(orderID)
	if err != nil {
		os.logger.Error("Failed to cancel order", "email", email, "order_id", orderID, "error", err)
		return broker.OrderResponse{}, fmt.Errorf("failed to cancel order: %w", err)
	}
	return resp, nil
}

// GetOrders returns all orders for the user's current trading day.
func (os *OrderService) GetOrders(email string) ([]broker.Order, error) {
	b, err := os.getBroker(email)
	if err != nil {
		return nil, err
	}
	orders, err := b.GetOrders()
	if err != nil {
		os.logger.Error("Failed to get orders", "email", email, "error", err)
		return nil, fmt.Errorf("failed to get orders: %w", err)
	}
	return orders, nil
}

// GetTrades returns all executed trades for the user's current trading day.
func (os *OrderService) GetTrades(email string) ([]broker.Trade, error) {
	b, err := os.getBroker(email)
	if err != nil {
		return nil, err
	}
	trades, err := b.GetTrades()
	if err != nil {
		os.logger.Error("Failed to get trades", "email", email, "error", err)
		return nil, fmt.Errorf("failed to get trades: %w", err)
	}
	return trades, nil
}
