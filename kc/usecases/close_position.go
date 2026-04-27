package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ExecuteCommand is the CQRS-bus adapter: unpacks a ClosePositionCommand and
// delegates to Execute. Preserves Execute's raw-arg signature for the existing
// test corpus while giving the CommandBus a typed entry point.
func (uc *ClosePositionUseCase) ExecuteCommand(ctx context.Context, cmd cqrs.ClosePositionCommand) (*ClosePositionResult, error) {
	return uc.Execute(ctx, cmd.Email, cmd.Exchange, cmd.Symbol, cmd.ProductFilter)
}

// ClosePositionUseCase closes a single position by placing an opposite MARKET order.
// Pipeline: find position -> riskguard check -> place opposite order -> domain event.
//
// Wave D Phase 3 Package 5 (Logger sweep): logger is the kc/logger.Logger
// port; constructor takes *slog.Logger and converts via logport.NewSlog.
type ClosePositionUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	logger         logport.Logger
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
		logger:         logport.NewSlog(logger),
	}
}

// SetEventDispatcher updates the domain event dispatcher post-construction.
// See PlaceOrderUseCase.SetEventDispatcher for the rationale (production
// wiring sets the dispatcher after the use case has already been built;
// without this setter the PositionClosedEvent emission silently drops).
func (uc *ClosePositionUseCase) SetEventDispatcher(d *domain.EventDispatcher) {
	uc.events = d
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
	// close_position is an exit derived from a confirmed tool call (the user
	// invoked close_position with elicitation already gating the MCP
	// boundary), so the synthetic order is Confirmed by construction.
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           email,
			ToolName:        "close_position",
			Exchange:        matched.Exchange,
			Tradingsymbol:   matched.Tradingsymbol,
			TransactionType: txnType,
			Quantity:        qty,
			Confirmed:       true,
		})
		if !result.Allowed {
			uc.logger.Warn(ctx, "Close position blocked by riskguard",
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
		MarketProtection: broker.MarketProtectionAuto,
		Variety:          "regular",
	}

	resp, err := client.PlaceOrder(orderParams)
	if err != nil {
		uc.logger.Error(ctx, "Failed to close position", err,
			"email", email,
			"symbol", symbol,
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
			Product:         matched.Product,
			Qty:             q,
			TransactionType: txnType,
			Timestamp:       time.Now().UTC(),
		})
	}

	uc.logger.Info(ctx, "Position closed",
		"email", email,
		"order_id", resp.OrderID,
		"symbol", symbol,
		"direction", txnType,
		"quantity", qty,
	)

	// Slice 6: lift the matched broker.Position to domain.Position
	// so the closed position's PnL JSON-emit goes through the
	// currency-aware Money accessor; .Float64() at the wire
	// boundary preserves byte-identical output for Telegram
	// confirmations and dashboard consumers.
	matchedPos := domain.NewPositionFromBroker(*matched)
	return &ClosePositionResult{
		OrderID:     resp.OrderID,
		Instrument:  fmt.Sprintf("%s:%s", matched.Exchange, matched.Tradingsymbol),
		Quantity:    qty,
		Direction:   txnType,
		Product:     matched.Product,
		PositionPnL: matchedPos.PnL().Float64(),
	}, nil
}
