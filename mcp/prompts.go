package mcp

import (
	"context"
	"fmt"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// RegisterPrompts registers server-side MCP prompts for common trading workflows.
// These appear as /mcp__kite__morning_brief etc. in Claude Code.
func RegisterPrompts(srv *server.MCPServer, manager *kc.Manager) {
	srv.AddPrompt(
		gomcp.NewPrompt("morning_brief",
			gomcp.WithPromptDescription("Morning trading briefing — portfolio state, market indices, alerts, margin, warnings. Call this at the start of the trading day."),
		),
		morningBriefHandler(manager),
	)

	srv.AddPrompt(
		gomcp.NewPrompt("trade_check",
			gomcp.WithPromptDescription("Pre-flight check before placing a trade — margin, concentration, risk, stop-loss suggestion."),
			gomcp.WithArgument("symbol",
				gomcp.ArgumentDescription("Trading symbol (e.g. RELIANCE, NSE:INFY)"),
				gomcp.RequiredArgument(),
			),
			gomcp.WithArgument("action",
				gomcp.ArgumentDescription("BUY or SELL"),
				gomcp.RequiredArgument(),
			),
			gomcp.WithArgument("quantity",
				gomcp.ArgumentDescription("Number of shares/units"),
			),
		),
		tradeCheckHandler(manager),
	)

	srv.AddPrompt(
		gomcp.NewPrompt("eod_review",
			gomcp.WithPromptDescription("End-of-day trading review — P&L, positions, orders, alerts, action items for tomorrow."),
		),
		eodReviewHandler(manager),
	)

	manager.Logger.Info("MCP prompts registered", "count", 3)
}

func morningBriefHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		ist, _ := time.LoadLocation("Asia/Kolkata")
		now := time.Now().In(ist)

		instructions := fmt.Sprintf(`# Morning Trading Briefing — %s

You are a trading assistant preparing a morning briefing. Execute these steps in order:

## Step 1: Get Trading Context
Call the trading_context tool. This returns margin, positions, orders, holdings, alerts, and warnings in one shot.

## Step 2: Get Portfolio Summary
Call the portfolio_summary tool for total invested, current value, P&L, top gainers/losers.

## Step 3: Get Market Indices
Call get_ltp with instruments: ["NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX"]
Show index levels and direction vs previous close.

## Step 4: Check Alerts
Call list_alerts to show active alerts and any triggered overnight.

## Step 5: Check Watchlists
Call list_watchlists. If the user has watchlists, call get_watchlist for the most recent one.

## Step 6: Present the Briefing

Format as a structured report:

### Market Indices
- NIFTY 50, BANK NIFTY, SENSEX with price and change %%

### Account Status
- Token status, Margin available with utilization %%

### Portfolio Snapshot
- Holdings count, invested amount, current value, overall P&L, day P&L

### Positions
- Open positions count (MIS vs NRML), positions P&L

### Alerts
- Active count, triggered overnight with details

### Watchlist
- Items near targets (<5%% away) highlighted

### Top Movers (Holdings)
- Top 3 gainers and losers

### Warnings
- Any warnings from trading_context

### Action Items
- Actionable recommendations based on the data

## Market Context
- NSE/BSE hours: 9:15 AM — 3:30 PM IST
- Kite tokens expire ~6:00 AM IST daily
- Current time: %s IST
`, now.Format("2 Jan 2006"), now.Format("3:04 PM"))

		return &gomcp.GetPromptResult{
			Description: "Morning trading briefing",
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

func tradeCheckHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		symbol := request.Params.Arguments["symbol"]
		action := request.Params.Arguments["action"]
		quantity := request.Params.Arguments["quantity"]
		if quantity == "" {
			quantity = "not specified — ask the user"
		}
		if action == "" {
			action = "BUY"
		}

		instructions := fmt.Sprintf(`# Pre-Trade Check: %s %s %s

You are a trading assistant running a pre-flight check before placing an order. Follow these steps:

## Step 1: Use the Composite Pre-Trade Check
Call pre_trade_check with:
- tradingsymbol: %s
- transaction_type: %s
- quantity: %s
- exchange: NSE (unless symbol includes exchange prefix)
- product: CNC (ask user if unclear)
- order_type: MARKET (unless user specified a price)

This single tool returns: current price, margin check, portfolio impact, existing positions, stop-loss suggestion, warnings, and a recommendation.

## Step 2: Present the Pre-Flight Report

Format as:
### Current Price
- LTP, change %%, order value

### Margin Check
- Required vs available, utilization after trade, status (OK/WARNING/INSUFFICIENT)

### Portfolio Impact
- Trade as %% of portfolio, concentration after trade, existing position

### Risk Flags
- High margin utilization (>70%%)
- Over-concentration (>15%% in one stock)
- Trading against existing position
- Order value > 5%% of portfolio

### Stop-Loss Suggestion
- For CNC: SL at 2%% below buy price
- For MIS: SL at 1%% below buy price
- Offer to place GTT stop-loss alongside

### Recommendation
PROCEED / PROCEED WITH CAUTION / RECONSIDER

## Step 3: Confirm and Execute
Only place the order if the user explicitly confirms. Use place_order with market_protection: -1 (auto).

## Step 4: Stop-Loss Follow-Up
After order placement, ask about setting a stop-loss via place_gtt_order.
`, action, quantity, symbol, symbol, action, quantity)

		return &gomcp.GetPromptResult{
			Description: fmt.Sprintf("Pre-trade check for %s %s", action, symbol),
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

func eodReviewHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		ist, _ := time.LoadLocation("Asia/Kolkata")
		now := time.Now().In(ist)

		var timingNote string
		hour := now.Hour()
		min := now.Minute()
		if hour < 15 || (hour == 15 && min < 30) {
			timingNote = "NOTE: Market is still open. Positions and P&L may change."
		} else if hour == 15 && min < 45 {
			timingNote = "NOTE: Final settlement in progress."
		} else {
			timingNote = "Market is closed. Showing final settled positions."
		}

		instructions := fmt.Sprintf(`# End-of-Day Review — %s

%s

You are a trading assistant preparing an end-of-day review. Execute these steps:

## Step 1: Get Full Context
Call trading_context for the unified state snapshot.

## Step 2: Portfolio Performance
Call portfolio_summary for holdings P&L and top movers.

## Step 3: Position Analysis
Call position_analysis for detailed position breakdown.

## Step 4: Orders Review
Call get_orders to see all orders placed today.

## Step 5: Alert Status
Call list_alerts to check alert activity.

## Step 6: Present EOD Report

### Day Performance
- Holdings day P&L, positions day P&L, net day P&L

### Orders Today
- Placed, executed, rejected (with reasons), cancelled, pending AMO

### Open Positions
If MIS positions still open after 2:30 PM IST: WARNING about auto-square-off at 3:20 PM.
List all positions with P&L.

### Top Movers (Holdings)
- Top 3 gainers and losers with %% and amount

### Alerts
- Active count, triggered today, closest to trigger

### Action Items for Tomorrow
- Convert MIS to CNC if needed
- Set alerts for stocks that moved significantly
- Review rejected orders
- Rebalance if concentration changed

Current time: %s IST
`, now.Format("2 Jan 2006"), timingNote, now.Format("3:04 PM"))

		return &gomcp.GetPromptResult{
			Description: "End-of-day trading review",
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}
