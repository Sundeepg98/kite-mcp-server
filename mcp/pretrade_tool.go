package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

// --- Pre-Trade Check Tool ---

// PreTradeCheckTool performs all pre-trade validation in a single composite call.
// Replaces 5 separate tool calls (get_ltp + get_order_margins + get_margins +
// get_positions + portfolio_concentration) with one server-side call.
type PreTradeCheckTool struct{}

func (*PreTradeCheckTool) Tool() mcp.Tool {
	return mcp.NewTool("pre_trade_check",
		mcp.WithDescription("Pre-trade validation -- checks margin, concentration, existing positions, and current price in ONE call. Use before placing any order. Much faster than calling get_ltp + get_order_margins + get_margins + get_positions + portfolio_concentration separately."),
		mcp.WithTitleAnnotation("Pre-Trade Check"),
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

// preTradeResponse is the structured response returned by pre_trade_check.
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
		handler.trackToolCall(ctx, "pre_trade_check")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		exchange := SafeAssertString(args["exchange"], "NSE")
		tradingsymbol := SafeAssertString(args["tradingsymbol"], "")
		transactionType := SafeAssertString(args["transaction_type"], "BUY")
		quantity := SafeAssertFloat64(args["quantity"], 0)
		product := SafeAssertString(args["product"], "CNC")
		orderType := SafeAssertString(args["order_type"], "MARKET")
		price := SafeAssertFloat64(args["price"], 0)

		if quantity <= 0 {
			return mcp.NewToolResultError("quantity must be greater than 0"), nil
		}

		// Validate price for LIMIT orders
		if orderType == "LIMIT" && price <= 0 {
			return mcp.NewToolResultError("price must be greater than 0 for LIMIT orders"), nil
		}

		instrumentKey := exchange + ":" + tradingsymbol

		return handler.WithSession(ctx, "pre_trade_check", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			client := session.Kite.Client

			// 5 parallel API calls
			ch := make(chan apiResult, 5)
			var wg sync.WaitGroup
			wg.Add(5)

			// 1. GetLTP
			go func() {
				defer wg.Done()
				ltp, err := client.GetLTP(instrumentKey)
				ch <- apiResult{"ltp", ltp, err}
			}()

			// 2. GetUserMargins
			go func() {
				defer wg.Done()
				margins, err := client.GetUserMargins()
				ch <- apiResult{"margins", margins, err}
			}()

			// 3. GetPositions
			go func() {
				defer wg.Done()
				positions, err := client.GetPositions()
				ch <- apiResult{"positions", positions, err}
			}()

			// 4. GetHoldings
			go func() {
				defer wg.Done()
				holdings, err := client.GetHoldings()
				ch <- apiResult{"holdings", holdings, err}
			}()

			// 5. GetOrderMargins
			go func() {
				defer wg.Done()
				orderMarginPrice := price
				// For MARKET orders, price is 0 — the API handles it
				resp, err := client.GetOrderMargins(kiteconnect.GetMarginParams{
					OrderParams: []kiteconnect.OrderMarginParam{{
						Exchange:        exchange,
						Tradingsymbol:   tradingsymbol,
						TransactionType: transactionType,
						Variety:         "regular",
						Product:         product,
						OrderType:       orderType,
						Quantity:        quantity,
						Price:           orderMarginPrice,
					}},
				})
				ch <- apiResult{"order_margins", resp, err}
			}()

			go func() {
				wg.Wait()
				close(ch)
			}()

			// Collect results
			data := make(map[string]any)
			errs := make(map[string]string)
			for r := range ch {
				if r.err != nil {
					errs[r.key] = r.err.Error()
				} else {
					data[r.key] = r.val
				}
			}

			resp := buildPreTradeResponse(
				exchange, tradingsymbol, transactionType,
				int(quantity), product, price,
				data, errs,
			)

			return handler.MarshalResponse(resp, "pre_trade_check")
		})
	}
}

// buildPreTradeResponse processes parallel API results into a pre-trade check response.
func buildPreTradeResponse(
	exchange, tradingsymbol, transactionType string,
	quantity int, product string, limitPrice float64,
	data map[string]any, apiErrors map[string]string,
) *preTradeResponse {
	resp := &preTradeResponse{
		Symbol:         tradingsymbol,
		Exchange:       exchange,
		Side:           transactionType,
		Quantity:       quantity,
		Warnings:       make([]string, 0),
		Recommendation: "PROCEED",
	}

	if len(apiErrors) > 0 {
		resp.Errors = apiErrors
	}

	// --- Current price from LTP ---
	var currentPrice float64
	instrumentKey := exchange + ":" + tradingsymbol
	if ltpRaw, ok := data["ltp"]; ok {
		ltpMap := ltpRaw.(kiteconnect.QuoteLTP)
		if ltpData, ok := ltpMap[instrumentKey]; ok {
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
	if omRaw, ok := data["order_margins"]; ok {
		orderMargins := omRaw.([]kiteconnect.OrderMargins)
		if len(orderMargins) > 0 {
			marginRequired = orderMargins[0].Total
		}
	} else {
		// Fallback estimate if GetOrderMargins failed
		marginRequired = orderValue
	}

	// --- Available margin from GetUserMargins ---
	var marginAvailable float64
	if marginsRaw, ok := data["margins"]; ok {
		margins := marginsRaw.(kiteconnect.AllMargins)
		marginAvailable = margins.Equity.Net
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
	if holdingsRaw, ok := data["holdings"]; ok {
		holdings := holdingsRaw.(kiteconnect.Holdings)
		for _, h := range holdings {
			totalPortfolioValue += h.LastPrice * float64(h.Quantity)
		}
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
	if positionsRaw, ok := data["positions"]; ok {
		positions := positionsRaw.(kiteconnect.Positions)
		for _, p := range positions.Net {
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
