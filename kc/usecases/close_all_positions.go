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

// ExecuteCommand is the CQRS-bus adapter: unpacks a CloseAllPositionsCommand
// and delegates to Execute. Preserves Execute's raw-arg signature for the
// existing test corpus while giving the CommandBus a typed entry point.
func (uc *CloseAllPositionsUseCase) ExecuteCommand(ctx context.Context, cmd cqrs.CloseAllPositionsCommand) (*CloseAllResult, error) {
	return uc.Execute(ctx, cmd.Email, cmd.ProductFilter)
}

// CloseAllPositionsUseCase exits all open positions by placing opposite MARKET orders.
// Pipeline: fetch positions -> filter -> riskguard per-order -> place orders -> events.
//
// Wave D Phase 3 Package 5 (Logger sweep): logger is the kc/logger.Logger
// port; constructor takes *slog.Logger and converts via logport.NewSlog.
type CloseAllPositionsUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	logger         logport.Logger
}

// NewCloseAllPositionsUseCase creates a CloseAllPositionsUseCase with all dependencies injected.
func NewCloseAllPositionsUseCase(
	resolver BrokerResolver,
	guard *riskguard.Guard,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *CloseAllPositionsUseCase {
	return &CloseAllPositionsUseCase{
		brokerResolver: resolver,
		riskguard:      guard,
		events:         events,
		logger:         logport.NewSlog(logger),
	}
}

// SetEventDispatcher updates the domain event dispatcher post-construction.
// See PlaceOrderUseCase.SetEventDispatcher for the rationale.
func (uc *CloseAllPositionsUseCase) SetEventDispatcher(d *domain.EventDispatcher) {
	uc.events = d
}

// CloseAllResult contains the outcome of closing all positions.
type CloseAllResult struct {
	SuccessCount  int                `json:"success_count"`
	ErrorCount    int                `json:"error_count"`
	Total         int                `json:"total"`
	ProductFilter string             `json:"product_filter"`
	Results       []CloseEntryResult `json:"results"`
}

// CloseEntryResult holds the outcome for a single position close attempt.
type CloseEntryResult struct {
	Tradingsymbol string `json:"tradingsymbol"`
	Exchange      string `json:"exchange"`
	Quantity      int    `json:"quantity"`
	Direction     string `json:"direction"`
	OrderID       string `json:"order_id,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Execute closes all matching positions and returns the aggregate result.
func (uc *CloseAllPositionsUseCase) Execute(ctx context.Context, email, productFilter string) (*CloseAllResult, error) {
	// 1. Validate basic inputs.
	if email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	productFilter = strings.ToUpper(productFilter)
	if productFilter == "" {
		productFilter = "ALL"
	}

	// 2. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 3. Fetch positions.
	positions, err := client.GetPositions()
	if err != nil {
		return nil, fmt.Errorf("usecases: fetch positions: %w", err)
	}

	// 4. Filter to positions with non-zero quantity.
	var toClose []broker.Position
	for _, p := range positions.Net {
		if p.Quantity == 0 {
			continue
		}
		if productFilter != "ALL" && strings.ToUpper(p.Product) != productFilter {
			continue
		}
		toClose = append(toClose, p)
	}

	if len(toClose) == 0 {
		return &CloseAllResult{
			ProductFilter: productFilter,
		}, nil
	}

	// 5. Close each position.
	var results []CloseEntryResult
	successCount := 0
	errorCount := 0

	for _, p := range toClose {
		var txnType string
		qty := int(math.Abs(float64(p.Quantity)))
		if p.Quantity > 0 {
			txnType = "SELL"
		} else {
			txnType = "BUY"
		}

		entry := CloseEntryResult{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Quantity:      qty,
			Direction:     txnType,
		}

		// Riskguard check per order.
		// close_all_positions is an exit derived from a confirmed tool
		// call, so each synthetic order is Confirmed by construction.
		if uc.riskguard != nil {
			result := uc.riskguard.CheckOrderCtx(ctx, riskguard.OrderCheckRequest{
				Email:           email,
				ToolName:        "close_all_positions",
				Exchange:        p.Exchange,
				Tradingsymbol:   p.Tradingsymbol,
				TransactionType: txnType,
				Quantity:        qty,
				Confirmed:       true,
			})
			if !result.Allowed {
				entry.Error = fmt.Sprintf("blocked by riskguard: %s", result.Message)
				errorCount++
				uc.logger.Warn(ctx, "Close all: position blocked by riskguard",
					"email", email,
					"symbol", p.Tradingsymbol,
					"reason", result.Reason,
				)
				results = append(results, entry)
				continue
			}
		}

		orderParams := broker.OrderParams{
			Exchange:         p.Exchange,
			Tradingsymbol:    p.Tradingsymbol,
			TransactionType:  txnType,
			Quantity:         qty,
			Product:          p.Product,
			OrderType:        "MARKET",
			Validity:         "DAY",
			MarketProtection: broker.MarketProtectionAuto,
			Variety:          "regular",
		}

		resp, placeErr := client.PlaceOrder(orderParams)
		if placeErr != nil {
			entry.Error = placeErr.Error()
			errorCount++
			uc.logger.Error(ctx, "Failed to close position", placeErr,
				"email", email,
				"symbol", p.Tradingsymbol,
			)
		} else {
			entry.OrderID = resp.OrderID
			successCount++

			// Dispatch event per closed position.
			if uc.events != nil {
				q, _ := domain.NewQuantity(qty)
				uc.events.Dispatch(domain.PositionClosedEvent{
					Email:           email,
					OrderID:         resp.OrderID,
					Instrument:      domain.NewInstrumentKey(p.Exchange, p.Tradingsymbol),
					Product:         p.Product,
					Qty:             q,
					TransactionType: txnType,
					Timestamp:       time.Now().UTC(),
				})
			}
		}

		results = append(results, entry)
	}

	uc.logger.Info(ctx, "Close all positions completed",
		"email", email,
		"success", successCount,
		"errors", errorCount,
		"total", len(toClose),
	)

	return &CloseAllResult{
		SuccessCount:  successCount,
		ErrorCount:    errorCount,
		Total:         len(toClose),
		ProductFilter: productFilter,
		Results:       results,
	}, nil
}
