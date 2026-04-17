---
name: options-sanity-check
description: Sanity check an Indian options trade before entry — IV, Greeks (delta/gamma/theta/vega), margin, liquidity, and payoff for single legs or multi-leg strategies on NIFTY/BANKNIFTY/stock options via Zerodha Kite. Use when the user asks about "options trade", "buy CE/PE", "sell PE/CE", "strategy builder", "spread", "iron condor", "straddle", "strangle", "IV check", "delta neutral", or anything involving F&O/derivatives on NSE.
---

# Options Sanity Check (NIFTY / BANKNIFTY / Stock F&O)

Options are high-gamma, high-theta instruments. This skill forces the user to look at Greeks,
liquidity, and margin before clicking. It is NOT a trade recommender.

## 1. Identify the leg(s)

From the user's prompt, extract each leg:

- **Underlying** (NIFTY, BANKNIFTY, RELIANCE, etc.)
- **Expiry** (weekly or monthly — ask if ambiguous)
- **Strike**
- **Option type** (CE = call, PE = put)
- **Side** (BUY or SELL)
- **Lots** (not shares — NIFTY lot size changes, confirm)

If the user says "sell 24500 PE expiring next Thursday", that's one leg. Multi-leg strategies
(straddle, strangle, spread, iron condor, butterfly) are 2-4 legs.

## 2. Pull the chain + Greeks

1. Call `get_option_chain` for the underlying + expiry — returns strikes, OI, IV.
2. Call `options_greeks` for the specific leg(s) — returns delta, gamma, theta, vega, IV using
   Black-Scholes.
3. For multi-leg strategies, call `options_payoff_builder` — returns payoff diagram points,
   max profit, max loss, breakevens.
4. Call `get_quotes` on each leg for bid/ask spread and volume (liquidity check).
5. Call `get_order_margins` (or `get_basket_margins` for multi-leg) — options margins differ
   wildly between buy and sell.

## 3. Present the sanity report

```
## Options Sanity Check: <strategy name or leg summary>

### Legs
1. <BUY|SELL> <lots> <underlying> <expiry> <strike> <CE|PE> @ <current premium>
2. ...

### Greeks (per leg, for 1 lot)
| Leg | Delta | Gamma | Theta | Vega | IV |
|---|---|---|---|---|---|
| 1 | <d> | <g> | <t>/day | <v> | <iv>% |

### Liquidity
- Bid-ask spread: <pct>% of premium — flag if >5%
- Today's volume: <n> contracts — flag if <100
- Open interest: <n>

### Payoff (multi-leg)
- Max profit: <amt> at <underlying price>
- Max loss: <amt> at <underlying price>
- Breakeven(s): <price1>, <price2>
- Net premium: debit <amt> | credit <amt>

### Margin
- Required (SPAN+Exposure): <amt>
- Available: <amt>
- Utilization after: <pct>%

### Risk Flags
<Only include applicable:>
- IV in top quintile — short-vol strategies face mean reversion risk
- IV in bottom quintile — long-vol strategies face decay without catalyst
- Theta > <X>% of premium/day — time decay is significant
- Undefined-risk leg (naked SELL without hedge) — margin locks up, tail risk is infinite
- Expiry within 7 days — gamma acceleration / pin risk
- Wide bid-ask — execution slippage likely
```

## 4. Ask before ordering

Options require EXTRA deliberation versus equity. Always ask:

- "Confirm the lot count — this is <n> lots = <n x lot_size> contracts."
- "Confirm expiry — <date>."
- "Is this a defined-risk trade or are you short naked? (We flag if naked.)"

Only call `place_order` (multiple times for multi-leg) after explicit "place it".

## 5. Indian options quirks

- **Lot sizes** change — NIFTY, BANKNIFTY, and stock options each have different lot sizes that
  SEBI revises periodically. Always use the lot size from `search_instruments` metadata,
  not memory.
- **Weekly expiries**: NIFTY and BANKNIFTY weeklies expire Thursday (NIFTY) / Wednesday
  (BANKNIFTY) — confirm with the chain data.
- **Cash-settled**: Indian index options are European-style and cash-settled. Stock options
  are physically settled — assignment risk at expiry.
- **Margin blocking**: SELL-side options block SPAN + Exposure margin; BUY-side only the
  premium.
- **Extrinsic decay accelerates** in the last week before expiry. Theta numbers from
  `options_greeks` should dominate the discussion for short-dated trades.

## 6. Guardrails

- NEVER recommend a direction ("buy CE, NIFTY will rally"). State Greeks and payoff; let the
  user decide direction.
- NEVER underplay undefined-risk legs. A naked SELL can blow through the account on a gap.
- NEVER claim IV is "cheap" or "expensive" without showing the IV rank or percentile context
  (if available from the chain data).
- If the user is a first-time options trader, point them at Zerodha Varsity / the Varsity
  options module before proceeding. Don't refuse to help, but flag the education gap.
