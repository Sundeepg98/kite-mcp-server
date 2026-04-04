package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// --- Portfolio Rebalance Tool ---

type PortfolioRebalanceTool struct{}

func (*PortfolioRebalanceTool) Tool() mcp.Tool {
	return mcp.NewTool("portfolio_rebalance",
		mcp.WithDescription("Analyze portfolio against target allocations and suggest rebalancing trades. Provide target allocations as JSON (e.g., {\"RELIANCE\": 20, \"INFY\": 15, \"TCS\": 10} for percentage targets, or {\"RELIANCE\": 200000, \"INFY\": 150000} for value targets in INR). Returns drift analysis and suggested trades."),
		mcp.WithTitleAnnotation("Portfolio Rebalance"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("targets", mcp.Description("Target allocations as JSON. Keys are tradingsymbols. Values are either percentages (must sum to ~100) or absolute INR amounts."), mcp.Required()),
		mcp.WithString("mode", mcp.Description("Allocation mode: 'percentage' (default) or 'value'"), mcp.DefaultString("percentage")),
		mcp.WithNumber("threshold", mcp.Description("Minimum drift percentage to suggest a trade (default: 2.0). Trades below this threshold are skipped.")),
	)
}

// rebalanceAllocation represents drift analysis for a single symbol.
type rebalanceAllocation struct {
	Symbol         string  `json:"symbol"`
	Exchange       string  `json:"exchange"`
	CurrentValue   float64 `json:"current_value"`
	CurrentPct     float64 `json:"current_pct"`
	TargetPct      float64 `json:"target_pct"`
	TargetValue    float64 `json:"target_value"`
	DriftPct       float64 `json:"drift_pct"`
	Action         string  `json:"action"`
	Quantity       int     `json:"quantity"`
	EstimatedValue float64 `json:"estimated_value"`
}

// rebalanceTrade represents a single suggested trade.
type rebalanceTrade struct {
	Action    string  `json:"action"`
	Symbol    string  `json:"symbol"`
	Quantity  int     `json:"quantity"`
	Estimated float64 `json:"estimated_cost_or_proceeds"`
}

// rebalanceSummary holds aggregate trade summary.
type rebalanceSummary struct {
	TradesNeeded   int     `json:"trades_needed"`
	TotalBuyValue  float64 `json:"total_buy_value"`
	TotalSellValue float64 `json:"total_sell_value"`
	NetCashNeeded  float64 `json:"net_cash_needed"`
}

// rebalanceResponse is the full response payload.
type rebalanceResponse struct {
	TotalPortfolioValue float64               `json:"total_portfolio_value"`
	Mode                string                `json:"mode"`
	Threshold           float64               `json:"threshold"`
	Allocations         []rebalanceAllocation `json:"allocations"`
	SuggestedTrades     []rebalanceTrade      `json:"suggested_trades"`
	Summary             rebalanceSummary      `json:"summary"`
}

func (*PortfolioRebalanceTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "portfolio_rebalance")

		args := request.GetArguments()

		// Parse targets JSON string
		targetsStr := SafeAssertString(args["targets"], "")
		if targetsStr == "" {
			return mcp.NewToolResultError("Parameter 'targets' is required and must be a JSON object mapping symbols to allocation values."), nil
		}

		var targets map[string]float64
		if err := json.Unmarshal([]byte(targetsStr), &targets); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'targets' JSON: %s. Expected format: {\"RELIANCE\": 20, \"INFY\": 15}", err.Error())), nil
		}
		if len(targets) == 0 {
			return mcp.NewToolResultError("'targets' must contain at least one symbol allocation."), nil
		}

		// Parse mode
		mode := SafeAssertString(args["mode"], "percentage")
		if mode != "percentage" && mode != "value" {
			return mcp.NewToolResultError("Invalid 'mode': must be 'percentage' or 'value'."), nil
		}

		// Parse threshold (default 2.0)
		threshold := SafeAssertFloat64(args["threshold"], 2.0)
		if threshold < 0 {
			return mcp.NewToolResultError("'threshold' must be non-negative."), nil
		}

		// Validate percentage targets sum
		if mode == "percentage" {
			var totalPct float64
			for _, pct := range targets {
				if pct < 0 {
					return mcp.NewToolResultError("Target percentages must be non-negative."), nil
				}
				totalPct += pct
			}
			if totalPct > 105 {
				return mcp.NewToolResultError(fmt.Sprintf("Target percentages sum to %.1f%%, which exceeds 100%%. Reduce allocations so they sum to approximately 100%%.", totalPct)), nil
			}
		} else {
			for _, val := range targets {
				if val < 0 {
					return mcp.NewToolResultError("Target values must be non-negative."), nil
				}
			}
		}

		return handler.WithSession(ctx, "portfolio_rebalance", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Fetch current holdings
			holdings, err := session.Broker.GetHoldings()
			if err != nil {
				handler.trackToolError(ctx, "portfolio_rebalance", "api_error")
				return mcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}

			// Build a map of current holdings: symbol -> {exchange, quantity, lastPrice}
			type holdingInfo struct {
				Exchange  string
				Quantity  int
				LastPrice float64
			}
			holdingsMap := make(map[string]*holdingInfo, len(holdings))
			for _, h := range holdings {
				if h.Quantity <= 0 {
					continue
				}
				holdingsMap[h.Tradingsymbol] = &holdingInfo{
					Exchange:  h.Exchange,
					Quantity:  h.Quantity,
					LastPrice: h.LastPrice,
				}
			}

			// Collect all symbols that need LTP: target symbols not in holdings + all holdings
			// Holdings already have LastPrice from the API, but target symbols not currently
			// held need an LTP lookup.
			ltpNeeded := make([]string, 0)
			for symbol := range targets {
				if _, held := holdingsMap[symbol]; !held {
					ltpNeeded = append(ltpNeeded, "NSE:"+symbol)
				}
			}

			// Fetch LTP for symbols not in holdings
			ltpMap := make(map[string]float64) // symbol -> lastPrice
			if len(ltpNeeded) > 0 {
				ltpResp, ltpErr := session.Broker.GetLTP(ltpNeeded...)
				if ltpErr != nil {
					handler.trackToolError(ctx, "portfolio_rebalance", "ltp_error")
					return mcp.NewToolResultError("Failed to fetch LTP for target symbols: " + ltpErr.Error()), nil
				}
				for key, data := range ltpResp {
					// key is "NSE:SYMBOL", extract symbol
					parts := strings.SplitN(key, ":", 2)
					if len(parts) == 2 {
						ltpMap[parts[1]] = data.LastPrice
					}
				}
			}

			// Calculate total portfolio value from holdings
			var totalPortfolioValue float64
			for _, info := range holdingsMap {
				totalPortfolioValue += float64(info.Quantity) * info.LastPrice
			}

			// Handle empty portfolio — if mode=value, we can still suggest buys
			if totalPortfolioValue == 0 && mode == "percentage" {
				return mcp.NewToolResultError("Portfolio is empty (no holdings). Cannot calculate percentage-based rebalancing. Use mode='value' to suggest buy trades with absolute INR amounts."), nil
			}

			// Helper to get LTP for a symbol
			getLTP := func(symbol string) (float64, string) {
				if info, ok := holdingsMap[symbol]; ok {
					return info.LastPrice, info.Exchange
				}
				if price, ok := ltpMap[symbol]; ok {
					return price, "NSE"
				}
				return 0, "NSE"
			}

			// Build allocations and suggested trades
			allocations := make([]rebalanceAllocation, 0, len(targets)+len(holdingsMap))
			trades := make([]rebalanceTrade, 0)
			processedSymbols := make(map[string]bool)

			// Process target symbols
			for symbol, targetVal := range targets {
				processedSymbols[symbol] = true

				ltp, exchange := getLTP(symbol)
				if ltp <= 0 {
					// Can't compute rebalance without a price
					allocations = append(allocations, rebalanceAllocation{
						Symbol:   symbol,
						Exchange: exchange,
						Action:   "SKIP",
					})
					continue
				}

				// Current value
				var currentValue float64
				if info, ok := holdingsMap[symbol]; ok {
					currentValue = float64(info.Quantity) * info.LastPrice
				}

				// Current percentage
				currentPct := 0.0
				if totalPortfolioValue > 0 {
					currentPct = currentValue / totalPortfolioValue * 100
				}

				// Target value
				var targetValue float64
				var targetPct float64
				if mode == "percentage" {
					targetPct = targetVal
					targetValue = targetPct / 100 * totalPortfolioValue
				} else {
					targetValue = targetVal
					if totalPortfolioValue > 0 {
						targetPct = targetValue / totalPortfolioValue * 100
					}
				}

				// Drift
				driftPct := 0.0
				if targetValue > 0 {
					driftPct = (currentValue - targetValue) / targetValue * 100
				} else if currentValue > 0 {
					driftPct = 100.0 // fully over-allocated vs zero target
				}

				// Determine action and quantity
				action := "HOLD"
				var qty int
				var estimatedValue float64
				diff := currentValue - targetValue

				if math.Abs(driftPct) > threshold {
					if diff < 0 {
						// Need to buy
						action = "BUY"
						estimatedValue = math.Abs(diff)
						qty = int(math.Floor(estimatedValue / ltp))
						if qty > 0 {
							estimatedValue = float64(qty) * ltp
						} else {
							action = "HOLD" // not enough to buy even 1 share
						}
					} else {
						// Need to sell
						action = "SELL"
						estimatedValue = diff
						qty = int(math.Floor(estimatedValue / ltp))
						// Don't sell more than we hold
						if info, ok := holdingsMap[symbol]; ok && qty > info.Quantity {
							qty = info.Quantity
						}
						if qty > 0 {
							estimatedValue = float64(qty) * ltp
						} else {
							action = "HOLD"
						}
					}
				}

				alloc := rebalanceAllocation{
					Symbol:         symbol,
					Exchange:       exchange,
					CurrentValue:   roundTo2(currentValue),
					CurrentPct:     roundTo2(currentPct),
					TargetPct:      roundTo2(targetPct),
					TargetValue:    roundTo2(targetValue),
					DriftPct:       roundTo2(driftPct),
					Action:         action,
					Quantity:       qty,
					EstimatedValue: roundTo2(estimatedValue),
				}
				allocations = append(allocations, alloc)

				if action == "BUY" || action == "SELL" {
					trades = append(trades, rebalanceTrade{
						Action:    action,
						Symbol:    exchange + ":" + symbol,
						Quantity:  qty,
						Estimated: roundTo2(estimatedValue),
					})
				}
			}

			// Process holdings NOT in targets — suggest SELL ALL (over-allocated)
			for symbol, info := range holdingsMap {
				if processedSymbols[symbol] {
					continue
				}

				currentValue := float64(info.Quantity) * info.LastPrice
				currentPct := 0.0
				if totalPortfolioValue > 0 {
					currentPct = currentValue / totalPortfolioValue * 100
				}

				alloc := rebalanceAllocation{
					Symbol:         symbol,
					Exchange:       info.Exchange,
					CurrentValue:   roundTo2(currentValue),
					CurrentPct:     roundTo2(currentPct),
					TargetPct:      0,
					TargetValue:    0,
					DriftPct:       100,
					Action:         "SELL",
					Quantity:       info.Quantity,
					EstimatedValue: roundTo2(currentValue),
				}
				allocations = append(allocations, alloc)

				trades = append(trades, rebalanceTrade{
					Action:    "SELL",
					Symbol:    info.Exchange + ":" + symbol,
					Quantity:  info.Quantity,
					Estimated: roundTo2(currentValue),
				})
			}

			// Sort allocations by symbol for consistent output
			sort.Slice(allocations, func(i, j int) bool {
				return allocations[i].Symbol < allocations[j].Symbol
			})
			sort.Slice(trades, func(i, j int) bool {
				return trades[i].Symbol < trades[j].Symbol
			})

			// Compute summary
			var totalBuy, totalSell float64
			for _, t := range trades {
				if t.Action == "BUY" {
					totalBuy += t.Estimated
				} else if t.Action == "SELL" {
					totalSell += t.Estimated
				}
			}

			resp := &rebalanceResponse{
				TotalPortfolioValue: roundTo2(totalPortfolioValue),
				Mode:                mode,
				Threshold:           threshold,
				Allocations:         allocations,
				SuggestedTrades:     trades,
				Summary: rebalanceSummary{
					TradesNeeded:   len(trades),
					TotalBuyValue:  roundTo2(totalBuy),
					TotalSellValue: roundTo2(totalSell),
					NetCashNeeded:  roundTo2(totalBuy - totalSell),
				},
			}

			return handler.MarshalResponse(resp, "portfolio_rebalance")
		})
	}
}
