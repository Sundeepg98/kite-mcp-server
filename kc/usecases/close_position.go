package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ClosePositionUseCase closes a single position by placing an opposite MARKET order.
// Pipeline: find position -> riskguard check -> place opposite order -> domain event.
type ClosePositionUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

// NewClosePositionUseCase creates a ClosePositionUseCase with all dependencies injected.
func NewClosePositionUseCase(
	resolver BrokerResolver,
	guard *riskguard.Guard,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *ClosePositionUseCase {
	return &ClosePositionUseCase{
		brokerResolver: resolver,
		riskguard:      guard,
		events:         events,
		logger:         logger,
	}
}

// ClosePositionResult contains the outcome of closing a position.
type ClosePositionResult struct {
	OrderID     string  `json:"order_id"`
	Instrument  string  `json:"instrument"`
	Quantity    int     `json:"quantity"`
	Direction   string  `json:"direction"`
	Product     string  `json:"product"`
	PositionPnL float64 `json:"position_pnl"`
}

// Execute finds the matching position and places an opposite MARKET order to close it.
func (uc *ClosePositionUseCase) Execute(ctx context.Context, email, exchange, symbol, productFilter string) (*ClosePositionResult, error) {
	// 1. Validate basic inputs.
	if email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if exchange == "" || symbol == "" {
		return nil, fmt.Errorf("usecases: exchange and symbol are required")
	}

	// 2. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 3. Fetch positions and find the matching one.
	positions, err := client.GetPositions()
	if err != nil {
		return nil, fmt.Errorf("usecases: fetch positions: %w", err)
	}

	var matched *broker.Position
	for i, p := range positions.Net {
		if p.Quantity == 0 {
			continue
		}
		if strings.EqualFold(p.Exchange, exchange) && strings.EqualFold(p.Tradingsymbol, symbol) {
			if productFilter != "" && strings.ToUpper(p.Product) != strings.ToUpper(productFilter) {
				continue
			}
			matched = &positions.Net[i]
			break
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("usecases: no open position found for %s:%s", exchange, symbol)
	}

	// 4. Determine opposite direction and quantity.
	var txnType string
	qty := int(math.Abs(float64(matched.Quantity)))
	if matched.Quantity > 0 {
		txnType = "SELL"
	} else {
		txnType = "BUY"
	}

	// 5. Run riskguard checks (if configured).
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           email,
			ToolName:        "close_position",
			Exchange:        matched.Exchange,
			Tradingsymbol:   matched.Tradingsymbol,
			TransactionType: txnType,
			Quantity:        qty,
		})
		if !result.Allowed {
			uc.logger.Warn("Close position blocked by riskguard",
				"email", email,
				"symbol", symbol,
				"reason", result.Reason,
				"message", result.Message,
			)
			if uc.events != nil {
				uc.events.Dispatch(domain.RiskLimitBreachedEvent{
					Email:     email,
					Reason:    string(result.Reason),
					Message:   result.Message,
					ToolName:  "close_position",
					Timestamp: time.Now().UTC(),
				})
			}
			return nil, fmt.Errorf("usecases: close position blocked by riskguard: %s", result.Message)
		}
	}

	// 6. Place opposite MARKET order.
	orderParams := broker.OrderParams{
		Exchange:         matched.Exchange,
		Tradingsymbol:    matched.Tradingsymbol,
		TransactionType:  txnType,
		Quantity:         qty,
		Product:          matched.Product,
		OrderType:        "MARKET",
		Validity:         "DAY",
		MarketProtection: kiteconnect.MarketProtectionAuto,
		Variety:          "regular",
	}

	resp, err := client.PlaceOrder(orderParams)
	if err != nil {
		uc.logger.Error("Failed to close position",
			"email", email,
			"symbol", symbol,
			"error", err,
		)
		return nil, fmt.Errorf("usecases: close position: %w", err)
	}

	// 7. Dispatch domain event.
	if uc.events != nil {
		q, _ := domain.NewQuantity(qty)
		uc.events.Dispatch(domain.PositionClosedEvent{
			Email:           email,
			OrderID:         resp.OrderID,
			Instrument:      domain.NewInstrumentKey(matched.Exchange, matched.Tradingsymbol),
			Qty:             q,
			TransactionType: txnType,
			Timestamp:       time.Now().UTC(),
		})
	}

	uc.logger.Info("Position closed",
		"email", email,
		"order_id", resp.OrderID,
		"symbol", symbol,
		"direction", txnType,
		"quantity", qty,
	)

	return &ClosePositionResult{
		OrderID:     resp.OrderID,
		Instrument:  fmt.Sprintf("%s:%s", matched.Exchange, matched.Tradingsymbol),
		Quantity:    qty,
		Direction:   txnType,
		Product:     matched.Product,
		PositionPnL: matched.PnL,
	}, nil
}
