---
name: alert-playbook
description: Set up disciplined price/percentage/volume alerts on Zerodha Kite instruments — choose between server-managed (Telegram-notified) alerts, Kite native alerts (ATO), and GTT stop-losses based on the use case. Use when the user asks to "set an alert", "notify me when X hits Y", "alert me if NIFTY drops 2%", "watch this stock", "price alert on RELIANCE", or similar phrasing about triggers/notifications on Indian stocks.
---

# Alert Playbook

Three alert systems coexist in this MCP server. Pick the right one for the job.

## 1. Decide which alert type

| System | Trigger | Notification | Survives Kite token expiry? | Best for |
|---|---|---|---|---|
| **Server-managed alert** (`set_alert`) | Price above/below, % drop/rise with ref price | Telegram (if `setup_telegram` done), server log | Yes — server polls Kite; on token expiry it stops and notifies | Casual price watching, percentage-change triggers, portfolio-wide monitoring |
| **Kite native alert** (`place_native_alert`) | Price above/below, % change, LTP cross | Native Kite push/email (ATO) | Yes — lives inside Zerodha, independent of our server | Long-running alerts you want regardless of our server uptime |
| **GTT** (`place_gtt_order`) | Price trigger → order placed | Order placement (SMS/email from Kite) | Yes — Kite manages it | Stop-losses, target exits, buy-on-dip setups with a pre-decided action |

Rule of thumb: **if the alert should trigger an order, use GTT**. If it just needs to ping you,
use a server-managed or native alert.

## 2. Setting a server-managed alert

1. If Telegram isn't wired yet, walk the user through `setup_telegram` first (they need to DM
   the bot to get a chat_id).
2. Call `set_alert` with:
   - `instrument` — e.g., `NSE:RELIANCE`
   - `condition` — `above`, `below`, `drop_pct`, `rise_pct`
   - `value` — price for above/below, percent for drop/rise
   - `reference_price` — required for drop_pct / rise_pct (anchors the % change)
3. Confirm with `list_alerts`.

Example: "Alert me when RELIANCE drops 3% from 1400"
→ `condition: drop_pct, value: 3, reference_price: 1400`

## 3. Setting a Kite native alert

Use when the user wants Zerodha to own the alert (survives our server restarts, hosted outside
our infra):

1. Call `place_native_alert` with the instrument, trigger type, and trigger value.
2. Notifications go via Kite's own push/email channels — not Telegram.
3. Manage via `list_native_alerts` / `modify_native_alert` / `delete_native_alert`.

## 4. Setting a GTT (good-till-triggered order)

Use when the trigger should place an order, not just notify:

1. Call `place_gtt_order` with:
   - `trigger_type: "single"` (one price trigger) or `"two-leg"` (SL + target, for exits)
   - `exchange`, `tradingsymbol`
   - `trigger_values` — one price for single, two for two-leg
   - `orders` — the order params that fire when triggered (quantity, price, order_type,
     product, transaction_type)
2. GTTs expire after a year if not triggered. Confirm via `get_gtts`.

Classic pattern — **stop-loss + target on a fresh buy**:

- Just bought 100 RELIANCE at 1400 in CNC.
- `place_gtt_order` with two-leg: SL at 1372 (2% below), target at 1470 (5% above).
- If price hits 1372 first → SELL 100 at 1370 limit (slightly below trigger for slippage).
- If price hits 1470 first → SELL 100 at 1468 limit.

## 5. Alert-setting workflow

When the user asks to set an alert, follow this decision tree:

1. "What should happen when it triggers?"
   - Just notify me → server-managed or native alert
   - Place a trade → GTT

2. "Do you want Telegram notifications?" (only relevant for server-managed)
   - Yes + setup_telegram done → proceed
   - Yes + not wired → walk through `setup_telegram` first
   - No → native alert is better

3. Extract trigger: price? % change? both legs (GTT two-leg)?

4. Confirm the alert payload back to the user *before* calling the tool. Alerts that fire
   wrongly (or silently fail) are worse than no alert.

5. Call the tool, then show the alert ID and `list_alerts` / `get_gtts` entry back.

## 6. Alert hygiene

Periodically (the `morning-brief` and `eod-review` skills surface this):

- Clean up stale alerts that reference prices far from current LTP.
- Delete alerts on symbols you no longer hold or watch.
- Check that `setup_telegram` is still connected (chat_id can break if user leaves the group).

## 7. Guardrails

- Do NOT set alerts without user confirmation of the exact payload. "Alert me when NIFTY is
  high" is not specific enough — push back for a number.
- Do NOT conflate an alert with a stop-loss. An alert pings you; a GTT actually exits.
- Do NOT promise "instant" notification. Server polls Kite at a configured interval; native
  alerts depend on Kite's own schedule.
- If the user has more than ~50 active alerts, surface this and ask if they want to prune.
  Alert fatigue is real.
- Kite native alerts count against Zerodha's own platform limits (varies); if `place_native_alert`
  returns a limit error, explain and suggest server-managed instead.
