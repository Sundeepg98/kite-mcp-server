package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// --- Pre-Trade Check Tool ---

// PreTradeCheckTool performs all pre-trade validation in a single composite call.
// Replaces 5 separate tool calls (get_ltp + get_order_margins + get_margins +
// get_positions + portfolio_concentration) with one server-side call.
type PreTradeCheckTool struct{}

func (*PreTradeCheckTool) Tool() mcp.Tool {
	return mcp.NewTool("order_risk_report",
		mcp.WithDescription("Factual pre-submission review of a prospective order. Computes margin required vs available, portfolio concentration %, existing position in the symbol, current LTP, and mechanical stop-loss levels in a single call. Composite wrapper over get_ltp + get_order_margins + get_margins + get_positions + portfolio_concentration. Output includes warnings and a status field (PROCEED / PROCEED WITH CAUTION / BLOCKED) derived purely from margin sufficiency and concentration thresholds. Not investment advice."),
		mcp.WithTitleAnnotation("Order Risk Report"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("exchange",
			mcp.Description("Exchange"),
			mcp.Required(),
			mcp.DefaultString("NSE"),
			mcp.Enum("NSE", "BSE", "NFO", "BFO", "MCX"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("BUY or SELL"),
			mcp.Required(),
			mcp.DefaultString("BUY"),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity"),
			mcp.Required(),
		),
		mcp.WithString("product",
			mcp.Description("Product type"),
			mcp.Required(),
			mcp.DefaultString("CNC"),
			mcp.Enum("CNC", "NRML", "MIS", "MTF"),
		),
		mcp.WithString("order_type",
			mcp.Description("Order type"),
			mcp.Required(),
			mcp.DefaultString("MARKET"),
			mcp.Enum("MARKET", "LIMIT", "SL", "SL-M"),
		),
		mcp.WithNumber("price",
			mcp.Description("Price for LIMIT orders"),
		),
	)
}

// preTradeResponse is the structured response returned by order_risk_report.
type preTradeResponse struct {
	Symbol          string                `json:"symbol"`
	Exchange        string                `json:"exchange"`
	Side            string                `json:"side"`
	Quantity        int                   `json:"quantity"`
	CurrentPrice    float64               `json:"current_price"`
	OrderValue      float64               `json:"order_value"`
	Margin          preTradeMargin        `json:"margin"`
	PortfolioImpact preTradePortfolio     `json:"portfolio_impact"`
	ExistingPos     *preTradeExistingPos  `json:"existing_position"`
	StopLoss        preTradeStopLoss      `json:"stop_loss_suggestion"`
	Warnings        []string              `json:"warnings"`
	Recommendation  string                `json:"recommendation"`
	Errors          map[string]string     `json:"errors,omitempty"`
}

type preTradeMargin struct {
	Required         float64 `json:"required"`
	Available        float64 `json:"available"`
	UtilizationAfter float64 `json:"utilization_after_pct"`
}

type preTradePortfolio struct {
	OrderAsPctOfPortfolio float64 `json:"order_as_pct_of_portfolio"`
	ConcentrationAfter    string  `json:"concentration_after"`
}

type preTradeExistingPos struct {
	Quantity     int     `json:"quantity"`
	Product      string  `json:"product"`
	AveragePrice float64 `json:"average_price"`
	PnL          float64 `json:"pnl"`
}

type preTradeStopLoss struct {
	CNC2Pct float64 `json:"cnc_2pct"`
	MIS1Pct float64 `json:"mis_1pct"`
}

func (*PreTradeCheckTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "order_risk_report")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		exchange := p.String("exchange", "NSE")
		tradingsymbol := p.String("tradingsymbol", "")
		transactionType := p.String("transaction_type", "BUY")
		quantity := p.Float("quantity", 0)
		product := p.String("product", "CNC")
		orderType := p.String("order_type", "MARKET")
		price := p.Float("price", 0)

		if quantity <= 0 {
			return mcp.NewToolResultError("quantity must be greater than 0"), nil
		}

		// Validate price for LIMIT orders
		if orderType == "LIMIT" && price <= 0 {
			return mcp.NewToolResultError("price must be greater than 0 for LIMIT orders"), nil
		}

		return handler.WithSession(ctx, "order_risk_report", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Route data gathering through CQRS query bus.
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.PreTradeCheckQuery{
				Email:           session.Email,
				Exchange:        exchange,
				Tradingsymbol:   tradingsymbol,
				TransactionType: transactionType,
				Quantity:        quantity,
				Product:         product,
				OrderType:       orderType,
				Price:           price,
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			ucResult, terr := BusResult[*usecases.PreTradeData](raw)
			if terr != nil {
				handler.manager.Logger.Error("order_risk_report bus result type mismatch", "error", terr)
				return mcp.NewToolResultError(terr.Error()), nil
			}

			resp := buildPreTradeResponse(
				exchange, tradingsymbol, transactionType,
				int(quantity), product, price,
				ucResult,
			)

			return handler.MarshalResponse(resp, "order_risk_report")
		})
	}
}

// buildPreTradeResponse processes parallel API results into a pre-trade check response.
// Consumes the typed *usecases.PreTradeData directly rather than a map[string]any
// so the broker-typed fields (LTP, Margins, Positions, Holdings) flow end-to-end
// without type assertions or reboxing at the tool layer.
func buildPreTradeResponse(
	exchange, tradingsymbol, transactionType string,
	quantity int, product string, limitPrice float64,
	data *usecases.PreTradeData,
) *preTradeResponse {
	resp := &preTradeResponse{
		Symbol:         tradingsymbol,
		Exchange:       exchange,
		Side:           transactionType,
		Quantity:       quantity,
		Warnings:       make([]string, 0),
		Recommendation: "PROCEED",
	}

	if data == nil {
		return resp
	}

	apiErrors := data.Errors
	if len(apiErrors) > 0 {
		resp.Errors = apiErrors
	}

	// --- Current price from LTP ---
	var currentPrice float64
	instrumentKey := exchange + ":" + tradingsymbol
	if data.LTP != nil {
		if ltpData, ok := data.LTP[instrumentKey]; ok {
			currentPrice = ltpData.LastPrice
		}
	}
	resp.CurrentPrice = roundTo2(currentPrice)

	// Use limit price for order value if provided, otherwise use current price
	priceForCalc := currentPrice
	if limitPrice > 0 {
		priceForCalc = limitPrice
	}
	orderValue := priceForCalc * float64(quantity)
	resp.OrderValue = roundTo2(orderValue)

	// --- Margin from GetOrderMargins (exact) ---
	var marginRequired float64
	if data.OrderMargins != nil {
		// GetOrderMargins returns any at the broker port — extract total.
		marginRequired = extractMarginTotal(data.OrderMargins, orderValue)
	} else {
		// Fallback estimate if GetOrderMargins failed
		marginRequired = orderValue
	}

	// --- Available margin from GetMargins (broker-agnostic) ---
	var marginAvailable float64
	if data.Margins != nil {
		marginAvailable = data.Margins.Equity.Available
	}

	utilizationAfter := 0.0
	if marginAvailable > 0 {
		utilizationAfter = marginRequired / marginAvailable * 100
	}

	resp.Margin = preTradeMargin{
		Required:         roundTo2(marginRequired),
		Available:        roundTo2(marginAvailable),
		UtilizationAfter: roundTo2(utilizationAfter),
	}

	// --- Portfolio concentration from holdings ---
	var totalPortfolioValue float64
	for _, h := range data.Holdings {
		totalPortfolioValue += h.LastPrice * float64(h.Quantity)
	}

	orderAsPct := 0.0
	totalAfter := totalPortfolioValue + orderValue
	if totalAfter > 0 {
		orderAsPct = orderValue / totalAfter * 100
	}

	concentrationAfter := "low"
	if orderAsPct >= 25 {
		concentrationAfter = "high"
	} else if orderAsPct >= 15 {
		concentrationAfter = "moderate"
	}

	resp.PortfolioImpact = preTradePortfolio{
		OrderAsPctOfPortfolio: roundTo2(orderAsPct),
		ConcentrationAfter:    concentrationAfter,
	}

	// --- Existing position check ---
	if data.Positions != nil {
		for _, p := range data.Positions.Net {
			if strings.EqualFold(p.Tradingsymbol, tradingsymbol) &&
				strings.EqualFold(p.Exchange, exchange) &&
				p.Quantity != 0 {
				resp.ExistingPos = &preTradeExistingPos{
					Quantity:     p.Quantity,
					Product:      p.Product,
					AveragePrice: roundTo2(p.AveragePrice),
					PnL:          roundTo2(p.PnL),
				}
				break
			}
		}
	}

	// --- Stop-loss suggestions ---
	if transactionType == "BUY" && priceForCalc > 0 {
		resp.StopLoss = preTradeStopLoss{
			CNC2Pct: roundTo2(priceForCalc * 0.98),
			MIS1Pct: roundTo2(priceForCalc * 0.99),
		}
	} else if transactionType == "SELL" && priceForCalc > 0 {
		// For SELL, stop-loss is above the price
		resp.StopLoss = preTradeStopLoss{
			CNC2Pct: roundTo2(priceForCalc * 1.02),
			MIS1Pct: roundTo2(priceForCalc * 1.01),
		}
	}

	// --- Warnings and recommendation ---
	if marginRequired > marginAvailable && marginAvailable > 0 {
		resp.Warnings = append(resp.Warnings,
			fmt.Sprintf("Insufficient margin: need %.2f, have %.2f", marginRequired, marginAvailable))
		resp.Recommendation = "BLOCKED"
	}

	if utilizationAfter > 70 && resp.Recommendation != "BLOCKED" {
		resp.Warnings = append(resp.Warnings,
			fmt.Sprintf("High margin utilization (%.0f%%) after this trade", utilizationAfter))
		if resp.Recommendation == "PROCEED" {
			resp.Recommendation = "PROCEED WITH CAUTION"
		}
	}

	if orderAsPct > 15 {
		resp.Warnings = append(resp.Warnings,
			fmt.Sprintf("Over-concentration: this order is %.1f%% of portfolio", orderAsPct))
		if resp.Recommendation == "PROCEED" {
			resp.Recommendation = "PROCEED WITH CAUTION"
		}
	}

	if resp.ExistingPos != nil {
		resp.Warnings = append(resp.Warnings,
			fmt.Sprintf("Existing position in %s: qty=%d, P&L=%.2f",
				tradingsymbol, resp.ExistingPos.Quantity, resp.ExistingPos.PnL))
	}

	// If LTP call failed, warn but don't block
	if _, ok := apiErrors["ltp"]; ok {
		resp.Warnings = append(resp.Warnings, "Could not fetch current price — order value may be inaccurate")
	}

	return resp
}

// extractMarginTotal attempts to extract a margin total from the raw GetOrderMargins response.
// GetOrderMargins returns any — the underlying structure varies by broker.
// Falls back to the provided fallback value if extraction fails.
func extractMarginTotal(raw any, fallback float64) float64 {
	// Try map with "total" key (mock broker and some raw returns)
	if m, ok := raw.(map[string]any); ok {
		if total, ok := m["total"].(float64); ok {
			return total
		}
	}
	// Try slice of maps (Zerodha returns []OrderMargins via broker adapter as any)
	if slice, ok := raw.([]any); ok && len(slice) > 0 {
		if m, ok := slice[0].(map[string]any); ok {
			if total, ok := m["total"].(float64); ok {
				return total
			}
		}
	}
	return fallback
}
