---
name: morning-brief
description: Generate a daily pre-market briefing for an Indian retail trader using Zerodha Kite holdings, positions, indices, alerts, and margin. Use when the user asks for a "morning brief", "pre-market check", "what should I watch today", "pre-open check", or similar phrasing about Indian stock market start-of-day status.
---

# Morning Brief (Indian Markets)

When the user asks for a morning brief, pre-market check, or start-of-day state:

## 1. Gather state (one consolidated call, then fill gaps)

Prefer the composite tool — it's one MCP round-trip instead of five:

1. Call `trading_context` — returns margin, positions, orders, holdings, alerts, warnings.
2. Call `portfolio_summary` — returns invested, current value, P&L, top gainers/losers.
3. Call `get_ltp` with `["NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX"]` for index levels.
4. Call `list_alerts` for alert status (which triggered overnight, which are active).
5. Optionally call `list_watchlists` + `get_watchlist` to show distance-to-trigger on watched names.
6. Optionally call `get_fii_dii_flow` for yesterday's institutional activity.

If `trading_context` is unavailable in the user's tool list, fall back to `get_margins`,
`get_positions`, `get_holdings` individually.

## 2. Format the briefing

Use this shape — terse, scannable, IST timestamp at the top:

```
## Morning Brief — <Date> <Time> IST

### Market Indices
- NIFTY 50:   <price> (<change>%)
- BANK NIFTY: <price> (<change>%)
- SENSEX:     <price> (<change>%)

### Account Status
- Kite token: <Valid | Expired — re-auth before 9:15>
- Margin available: <amount> (<utilization>%)

### Portfolio Snapshot
- Holdings: <n> stocks, invested <amt>, current <amt>
- Overall P&L: <amt> (<pct>%)
- Day P&L: <amt>

### Positions
- Open: <n> (<MIS count> MIS, <NRML count> NRML)
- MIS auto-square at 3:20 PM IST — flag any MIS positions carried from yesterday

### Alerts
- Active: <count>
- Triggered overnight: <list with prices and times>

### Watchlist
- <name>: <count> items, closest to trigger: <symbol> at <pct>% away

### Institutional Flow (yesterday)
- FII: <net buy/sell amount>
- DII: <net buy/sell amount>

### Warnings
<List any warnings from trading_context — margin, rejected orders, expired token>
```

## 3. Indian market timing (use these as facts, not guesses)

- **Pre-open**: 9:00 — 9:07 IST (order entry for price discovery)
- **Pre-open match**: 9:07 — 9:15 IST
- **Regular trading**: 9:15 AM — 3:30 PM IST
- **Closing session**: 3:30 — 3:40 PM IST
- **AMO window**: 3:45 PM — 8:57 AM next trading day
- **Kite token refresh**: access tokens expire daily around 6:00 AM IST
- **Weekends and NSE holidays**: no trading

If the user runs this before 9:15 AM, frame everything as pre-market context. If after 3:30 PM,
note that you're showing post-close state and recommend running `eod-review` instead.

## 4. Guardrails (NEVER violate)

- Do NOT recommend specific buys or sells. This is situational awareness, not advice.
- Do NOT claim a stock or index "will" do anything. Use factual framing: "NIFTY closed -0.4%
  yesterday" not "NIFTY looks weak today".
- Do NOT invent levels the tools didn't return. If `get_ltp` failed for an index, say so.
- If the user explicitly asks for a trade as a follow-up, hand off to the `trade-check` skill.
- If margin utilization >70%, surface it as a warning but don't prescribe action — flag, don't
  recommend.
- If the Kite token is expired, tell the user to re-authenticate via the OAuth login flow; don't
  try to place orders against an expired token.
