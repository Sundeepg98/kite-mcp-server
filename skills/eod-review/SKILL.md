---
name: eod-review
description: End-of-day trading review for an Indian retail trader on Zerodha Kite — day P&L, positions still open, orders placed today, alert activity, MIS square-off warnings, and action items for tomorrow. Use when the user says "EOD review", "end of day summary", "how did today go", "close the books", "wrap up trading day", or asks for a post-market summary.
---

# End-of-Day Review

Run this after market close (3:30 PM IST) or as a running check anytime after lunch.

## 1. Gather state

Call in this order (many can be parallel):

1. `trading_context` — unified snapshot (margin, positions, orders, alerts, warnings).
2. `portfolio_summary` — holdings P&L, top gainers/losers, invested vs current.
3. `position_analysis` — detailed position breakdown (MIS vs NRML, avg price, net qty).
4. `get_orders` — all orders placed today (executed, rejected, cancelled, pending).
5. `list_alerts` — alert activity (triggered today, closest to trigger).
6. Optionally `get_pnl_journal` for a structured P&L entry.

## 2. Format the EOD report

```
## End-of-Day Review — <Date>

### Day Performance
- Holdings day P&L: <amt> (<pct>%)
- Positions day P&L: <amt>
- Net day P&L: <amt>

### Orders Today
- Placed: <n>
- Executed: <n>
- Rejected: <n> (reasons: <list>)
- Cancelled: <n>
- Pending AMO: <n>

### Open Positions

<If MIS positions still open AND time > 2:30 PM IST:>
WARNING: <n> MIS positions still open. Market closes 3:30 PM IST;
MIS auto-squares at 3:20 PM. Convert with `convert_position` if you
want to carry overnight.
- <symbol>: <qty>, avg <price>, P&L <amt>

<NRML / CNC positions:>
- <symbol>: <qty>, avg <price>, P&L <amt>

### Top Movers in Your Book
Gainers:
1. <symbol> +<pct>% (+<amt>)
2. ...
Losers:
1. <symbol> -<pct>% (-<amt>)
2. ...

### Alerts
- Active: <n>
- Triggered today: <list with prices>
- Closest to trigger (still armed): <symbol>, <pct>% away

### Tomorrow's Prep
- Pending AMO orders: <list> — will execute at 9:15 AM
- Convert MIS → CNC/NRML? (only if you want to carry)
- Set alerts on stocks that moved >3% today
- Review rejected orders and fix params if re-placing
```

## 3. Timing awareness

Adjust framing based on the current IST time:

- **Before 3:20 PM IST**: Label as "intraday check", not EOD. MIS positions can still be converted
  or squared manually.
- **3:20 — 3:30 PM IST**: Final hour. Flag auto-square-off loud and clear if any MIS remain.
- **3:30 — 3:40 PM IST**: Closing session. Positions are settling; numbers may still move.
- **After 3:40 PM IST**: True EOD. Numbers are final for the day.
- **After market close on weekends/holidays**: Show the most recent trading day's data but note it
  explicitly (e.g., "showing Friday's close — markets closed Sat/Sun").

## 4. MIS square-off — special handling

If any MIS positions are open AND the current time is after 2:30 PM IST, make this the loudest
section in the output. Options the user has:

- Let it auto-square at 3:20 PM (broker does this)
- Square manually now via `place_order` with opposite side
- Convert to CNC/NRML via `convert_position` if they have the margin and want to hold
- Do nothing (accept the square-off)

## 5. Guardrails

- Never make predictions about tomorrow ("will open gap up", "will continue rally"). Stick to:
  what happened today, what's open, what's queued.
- Never suggest fresh trades in the EOD — that's `trade-check` territory.
- Never omit the MIS warning when it applies. It's the single highest-impact action item.
- If Kite token expires overnight (it does, ~6 AM IST), remind the user to re-authenticate before
  placing orders tomorrow.
- If the user asks "did I make money today?", answer factually from `portfolio_summary` —
  don't editorialize.
