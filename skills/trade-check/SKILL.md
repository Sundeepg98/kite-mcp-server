---
name: trade-check
description: Run a pre-flight check before placing an equity order on Zerodha Kite — current price, margin required, portfolio concentration impact, existing exposure, and stop-loss suggestion. Use when the user says "should I buy X", "pre-trade check on Y", "can I afford Z quantity of ABC", "check before I place order", or asks to place an order without having run the check yet.
---

# Pre-Trade Check

Before any order lands on Kite, run a pre-flight. This skill is the gate between "I want to trade"
and `place_order`.

## 1. Parse intent

From the user's prompt, extract:

- **symbol** (required) — default exchange `NSE` if not prefixed
- **quantity** (required)
- **side** — BUY or SELL (default BUY)
- **order type** — MARKET or LIMIT with price (default MARKET)
- **product** — CNC (delivery) or MIS (intraday); ask if ambiguous

If any required field is missing, ask before calling tools. Don't guess quantity.

## 2. Prefer the composite tool

`order_risk_report` (also surfaced as `pre_trade_check` in some deployments) bundles the five
checks below into one MCP call. Use it first:

- It returns current price, margin check, portfolio impact, existing positions, stop-loss
  suggestions, warnings, and a recommendation (PROCEED / PROCEED WITH CAUTION / BLOCKED).
- If available, skip straight to step 4 (present the report) with the composite output.

## 3. Fall back to individual tools

If no composite is available, call in parallel where possible:

1. `get_ltp` — current price for the instrument.
2. `get_order_margins` — margin required for this specific order.
3. `get_margins` — available funds.
4. `get_positions` — existing exposure in this symbol.
5. `portfolio_concentration` — current HHI / top-position weights.

## 4. Present the pre-flight report

```
## Pre-Trade Check: <SIDE> <QTY> <SYMBOL>

### Current Price
- LTP: <price> (<today's change>%)
- Order Type: <MARKET | LIMIT @ price>
- Order Value: <qty x price>

### Margin Check
- Required: <amt>
- Available: <amt>
- Utilization after trade: <pct>%
- Status: OK | WARNING | INSUFFICIENT

### Portfolio Impact
- This trade as % of portfolio: <pct>%
- Top-5 concentration after trade: <pct>%
- Existing position in this symbol: none | <qty, avg price, unrealized P&L>

### Risk Flags
<List concerns — only include applicable ones:>
- Margin utilization >70% after trade
- Concentration in one stock >15% after trade
- Trading against existing position (SELL when you already have open SELL, etc.)
- Order value >5% of portfolio
- MARKET order in a thinly-traded symbol

### Stop-Loss Suggestion
- For CNC (delivery): SL ~2% below entry → <price>
- For MIS (intraday): SL ~1% below entry → <price>
- GTT two-leg: trigger at SL + target; ask user before placing

### Recommendation
PROCEED | PROCEED WITH CAUTION | RECONSIDER
```

## 5. Wait for explicit confirmation

- Never call `place_order` until the user says "yes" / "place it" / "go ahead" after seeing the
  report.
- If recommendation is RECONSIDER, ask the user to confirm they want to override before proceeding.
- If margin is INSUFFICIENT, stop. Don't place the order.

## 6. Place the order

When confirmed, call `place_order` with:

- `variety: "regular"`
- `exchange: NSE | BSE` (from symbol)
- `tradingsymbol`, `transaction_type`, `quantity`
- `order_type: MARKET | LIMIT`, `price` (if LIMIT)
- `product: CNC | MIS | NRML`
- `market_protection: -1` (auto) for MARKET orders — SEBI-compliant default

## 7. Follow up with stop-loss

After a BUY is filled (confirm via `get_order_history`):

- For CNC: offer `place_gtt_order` with two-leg trigger — SL ~2% below, target ~5% above (ask
  user to confirm percentages).
- For MIS: suggest placing an SL-M order via `place_order` instead (GTT doesn't apply to
  intraday).

## Guardrails

- NEVER place an order without the pre-flight report first, unless the user explicitly opts into
  fast mode ("skip checks, place now" or `--fast`).
- NEVER claim an entry "will work" or a target "will hit". Use factual framing around current
  price, margin, concentration.
- NEVER ignore an INSUFFICIENT margin result.
- If the user is trying to trade after 3:20 PM with MIS product, remind them auto-square-off is
  imminent.
- If Kite token is expired, stop and ask them to re-authenticate.
