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

	srv.AddPrompt(
		gomcp.NewPrompt("week_review",
			gomcp.WithPromptDescription("Weekly trading recap — P&L journal, trades, orders, best/worst day, most-traded symbol, commissions, discipline notes."),
		),
		weekReviewHandler(manager),
	)

	srv.AddPrompt(
		gomcp.NewPrompt("options_sanity_check",
			gomcp.WithPromptDescription("Pre-flight sanity checks for an options strategy — IV percentile, liquidity, max loss vs portfolio, breakevens."),
			gomcp.WithArgument("underlying",
				gomcp.ArgumentDescription("Underlying symbol (e.g. NIFTY, BANKNIFTY, RELIANCE)"),
				gomcp.RequiredArgument(),
			),
			gomcp.WithArgument("strategy_description",
				gomcp.ArgumentDescription("Free-text strategy description from the user (e.g. 'bull call spread 22000/22200 April expiry')"),
				gomcp.RequiredArgument(),
			),
		),
		optionsSanityCheckHandler(manager),
	)

	srv.AddPrompt(
		gomcp.NewPrompt("compliance_report",
			gomcp.WithPromptDescription("Compliance snapshot — SEBI algo status, IP whitelist, audit log completeness, risk guard status. Read-only factual dump."),
		),
		complianceReportHandler(manager),
	)

	srv.AddPrompt(
		gomcp.NewPrompt("setup_checklist",
			gomcp.WithPromptDescription("Walk through the setup checklist — credentials, IP whitelist, paper mode, Telegram, alerts, watchlist. Pass/fail per item."),
		),
		setupChecklistHandler(manager),
	)

	// Phase 3a Batch 5: route the registration log line through the
	// LoggerPort obtained via the standard ToolHandler factory rather
	// than the deprecated *kc.Manager.Logger slog field.
	NewToolHandler(manager).LoggerPort().Info(context.Background(), "MCP prompts registered", "count", 7)
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
Call order_risk_report with:
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

func weekReviewHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		ist, _ := time.LoadLocation("Asia/Kolkata")
		now := time.Now().In(ist)
		weekAgo := now.AddDate(0, 0, -7)

		instructions := fmt.Sprintf(`# Weekly Trading Review — %s to %s

You are a trading assistant summarising the user's trading activity for the past 7 days. Pull the data, then report factually. Do not advise.

## Step 1: Realised P&L Journal
Call get_pnl_journal with from_date=%s and to_date=%s (ISO dates). This returns closed round-trip trades per symbol with realised P&L, win/loss, and holding period.

## Step 2: Trades Executed
Call get_trades for the same window (if the tool supports from/to, use it; otherwise fetch the full list and filter client-side).

## Step 3: Order History
Call get_orders and also get_order_history_reconstituted (activity audit trail, 90-day retention). The reconstituted history works even if orders were placed from a different client, as long as they went through this server.

## Step 4: Activity Audit
Call open_dashboard with page="activity", days=7 to surface the audit timeline widget. Claude can summarise from the tool response or direct the user to the dashboard link.

## Step 5: Compose the Weekly Recap

Format as:

### Headline
- Net realised P&L for the week (+/- Rs X)
- Total trades: N (buys: A, sells: B)
- Total commissions paid: Rs X (from P&L journal breakdown)

### Best Day
- Date, net P&L, top contributor symbol

### Worst Day
- Date, net P&L, top detractor symbol

### Most-Traded Symbol
- Symbol, trade count, net P&L on that symbol

### Order Outcomes
- Placed: N
- Executed: N
- Rejected: N (list rejection reasons if any)
- Cancelled: N

### Notable Patterns (factual only, non-advisory)
If the data shows any of these, call them out as observations — NOT recommendations:
- Overtrading: >20 round-trips in the week
- Revenge-trading cluster: multiple losing trades on the same symbol within an hour
- Stopping at losses: consecutive losing days
- Heavy intraday turnover on a single symbol

Phrase these as "I observed X in the data" — not "you should stop doing Y".

### Missing Data Caveats
If get_pnl_journal is empty but trades exist, note that the journal only counts closed round-trips — open positions are not in the recap.

Window: %s to %s IST.
Current time: %s IST.

Not investment advice.
`, weekAgo.Format("2 Jan 2006"), now.Format("2 Jan 2006"),
			weekAgo.Format("2006-01-02"), now.Format("2006-01-02"),
			weekAgo.Format("2 Jan 2006 3:04 PM"), now.Format("2 Jan 2006 3:04 PM"),
			now.Format("3:04 PM"))

		_ = manager
		return &gomcp.GetPromptResult{
			Description: "Weekly trading review",
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

func optionsSanityCheckHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		underlying := request.Params.Arguments["underlying"]
		strategyDescription := request.Params.Arguments["strategy_description"]
		if underlying == "" {
			underlying = "(missing — ask the user for the underlying symbol)"
		}
		if strategyDescription == "" {
			strategyDescription = "(missing — ask the user to describe the strategy, e.g. 'bull call spread 22000/22200 April expiry')"
		}

		instructions := fmt.Sprintf(`# Options Sanity Check — %s

Strategy described by user: %s

You are a trading assistant running pre-flight sanity checks on an options strategy. Pull the data, surface facts, flag risks. Do not recommend for or against entering the trade.

## Step 1: Parse the Strategy
Extract from the user's description:
- Strategy type (long call, bull spread, iron condor, straddle, etc.)
- Legs: strike, CE/PE, expiry, buy/sell, quantity
If anything is ambiguous, ASK THE USER before continuing. Do not guess strikes.

## Step 2: Option Chain Snapshot
Call get_option_chain with underlying="%s" and strikes_around_atm=10.
This returns ATM +/- 10 strikes with CE/PE LTP, OI, volume, max pain, and PCR.

## Step 3: Implied Volatility Percentile
Call get_option_chain_greeks (or options_greeks) for each leg's strike+expiry.
Compute or surface the IV percentile vs the last 30-60 days for the underlying.
IV percentile answers: is current IV expensive (>75th) or cheap (<25th) historically?

If the tool doesn't expose historical IV, say so explicitly. Do not fabricate a percentile.

## Step 4: Liquidity Check at Chosen Strikes
For each leg:
- Open interest (OI) at that strike — rough proxy for depth
- Bid-ask spread width (if get_quotes returns depth) — narrow = liquid, wide = slippage risk
- Volume today
Flag any leg with OI < 10,000 lots or spread > 2%% of premium as "thin liquidity".

## Step 5: Max Loss vs Portfolio Size
Call portfolio_summary for total portfolio value (current_value).
Compute strategy max loss in rupees:
- Long options: max loss = premium paid * lot size * quantity
- Short naked options: max loss is theoretically unlimited — flag as UNDEFINED
- Spreads: max loss = (net debit) or (spread width - net credit) * lot size * quantity
Report max loss as absolute rupees AND as %% of portfolio.
Flag if max loss > 5%% of portfolio.

## Step 6: Breakevens
For each strategy type, compute breakeven prices:
- Long call: strike + premium
- Long put: strike - premium
- Bull call spread: long strike + net debit
- Iron condor: short put strike - net credit AND short call strike + net credit
- Straddle: strike +/- combined premium
Express as absolute prices and as %% move from current underlying LTP.

## Step 7: Present the Report

### Strategy
- Type, legs table (strike, CE/PE, expiry, action, qty)

### Current Market
- Underlying LTP, PCR, max pain

### IV Context
- Current IV per leg, 30-day percentile (or "historical IV unavailable — not computed")

### Liquidity
- OI, spread, volume per leg, with flags

### Risk
- Max loss (Rs and %% of portfolio)
- Margin required (call get_margins / order_margins if available)
- Breakevens (Rs and %% move needed)

### Flags
List every flag raised (thin liquidity, IV very high, max loss > 5%% portfolio, unlimited risk leg, etc.). Be specific and factual.

### Summary
One paragraph summary of the numbers. No recommendation to proceed or not.

Current time: %s IST. Market hours: 9:15 AM — 3:30 PM IST.

Not investment advice.
`, underlying, strategyDescription, underlying,
			time.Now().In(mustLoadIST()).Format("3:04 PM"))

		_ = manager
		return &gomcp.GetPromptResult{
			Description: fmt.Sprintf("Options sanity check for %s", underlying),
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

func complianceReportHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		ist, _ := time.LoadLocation("Asia/Kolkata")
		now := time.Now().In(ist)

		instructions := fmt.Sprintf(`# Compliance Snapshot — %s

You are generating a read-only compliance report for the user's personal records. Pull the data, report facts. No recommendations.

## Step 1: SEBI Algo Status
Call sebi_compliance_status. This returns:
- Algo-ID tagging (provided by Zerodha OMS, not by this server)
- Order Placement System (OPS) registration state
- Static egress IP and whitelist status
- Framework version / compliance claim

## Step 2: Static IP Whitelist Check
Call test_ip_whitelist. Report:
- Server's static egress IP (should be 209.71.68.157 for bom region)
- Whether the user's Kite developer console has it whitelisted
- Pass/fail status (SEBI April 2026 mandate)

## Step 3: Audit Log Completeness
Call server_metrics to get per-tool counters.
Then call open_dashboard with page="activity", days=30 to surface the audit trail.
Report:
- Total tool calls logged in the last 30 days
- Any dropped entries (check server_metrics for audit_buffer_drops counter)
- Audit retention window (default 90 days)
- Whether every order-placing call has a corresponding audit entry

If dropped entries > 0, state the count factually. Do not speculate on cause.

## Step 4: Risk Guard Status
Call admin_get_risk_status if the user is admin, otherwise infer from server_metrics.
Report:
- Kill switch state (armed / disarmed / firing)
- Order value cap (default Rs 5,00,000)
- Daily order count limit (default 200/day, used: N)
- Per-minute rate limit (default 10/min)
- Duplicate-order window (default 30s)
- Daily value cap (default Rs 10,00,000, used: Rs X)
- Auto-freeze circuit breaker status

## Step 5: Present the Report

Use this exact structure, filling in blanks with tool data:

### SEBI Algo
- Algo-ID tagging: [OMS-handled / not applicable]
- OPS registration: [status]
- Framework compliance: [version]

### Static IP Whitelist
- Egress IP: [ip]
- User whitelist status: [PASS / FAIL / UNKNOWN]

### Audit Trail
- Tool calls (last 30d): [count]
- Dropped entries: [count]
- Retention: [days]
- Order call coverage: [pct or "unable to compute"]

### Risk Guard
- Kill switch: [state]
- Order value cap: Rs [amount]
- Daily order count: [used]/[limit]
- Rate limit: [limit]/min
- Duplicate window: [seconds]
- Daily value: Rs [used]/[limit]
- Auto-freeze: [state]

### Summary
One paragraph, purely factual. No "you should" language. No advice.

Generated: %s IST.

Not investment advice.
`, now.Format("2 Jan 2006 3:04 PM"), now.Format("2 Jan 2006 3:04 PM"))

		_ = manager
		return &gomcp.GetPromptResult{
			Description: "Compliance snapshot",
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

func setupChecklistHandler(manager *kc.Manager) server.PromptHandlerFunc {
	return func(ctx context.Context, request gomcp.GetPromptRequest) (*gomcp.GetPromptResult, error) {
		instructions := `# Setup Checklist

You are walking the user through the setup checklist. For each item, call the relevant tool, report PASS / FAIL / NOT CONFIGURED with a one-line explanation.

## Step 1: Credentials Registered
Call get_profile.
- PASS if the tool returns a profile (email, user_id) without error.
- FAIL with reason if it returns auth_required or similar — direct the user to call login.

## Step 2: IP Whitelist
Call test_ip_whitelist.
- PASS if the server's static egress IP is whitelisted in the user's Kite developer console.
- FAIL with the exact IP to whitelist (default 209.71.68.157 for bom region).
- This is a SEBI April 2026 mandate — order placement will reject without it.

## Step 3: Paper Trading Mode
Call paper_trading_status.
- Report ENABLED (with virtual cash balance) or DISABLED.
- This is informational, not pass/fail — paper mode is user choice.

## Step 4: Telegram Configured
Check if Telegram notifier is configured. Call a telemetry-exposing tool or check server_metrics for telegram_enabled.
- PASS if chat ID is set and bot token configured.
- NOT CONFIGURED if missing — direct user to run setup_telegram with their chat ID from @userinfobot.

## Step 5: Alerts Active
Call list_alerts.
- PASS if at least one alert is configured (count > 0).
- NOT CONFIGURED if zero alerts. Not a failure — informational.

## Step 6: Watchlist Populated
Call list_watchlists.
- PASS if at least one watchlist exists and has items.
- NOT CONFIGURED if zero watchlists. Suggest create_watchlist + add_to_watchlist.

## Step 7: Compose the Checklist

Render as a table:

| # | Item | Status | Detail |
|---|------|--------|--------|
| 1 | Credentials | PASS/FAIL | email or reason |
| 2 | IP Whitelist | PASS/FAIL | IP or missing-reason |
| 3 | Paper Trading | ENABLED/DISABLED | virtual cash balance if enabled |
| 4 | Telegram | PASS/NOT CONFIGURED | chat_id or setup instructions |
| 5 | Alerts | PASS/NOT CONFIGURED | N alerts active |
| 6 | Watchlist | PASS/NOT CONFIGURED | N lists, M items |

### Next Steps
List only the items that are FAIL or NOT CONFIGURED, with the exact tool to call to fix each.

Not investment advice.
`

		_ = manager
		return &gomcp.GetPromptResult{
			Description: "Setup checklist walkthrough",
			Messages: []gomcp.PromptMessage{
				{Role: gomcp.RoleUser, Content: gomcp.TextContent{Type: "text", Text: instructions}},
			},
		}, nil
	}
}

// mustLoadIST returns the Asia/Kolkata location, falling back to UTC if the
// tzdata is unavailable. Prompt handlers use this for IST timestamps.
func mustLoadIST() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		return time.UTC
	}
	return loc
}
