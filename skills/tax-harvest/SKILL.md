---
name: tax-harvest
description: Walk an Indian retail trader through tax-loss harvesting on their Zerodha equity holdings — identify STCG/LTCG positions with losses, estimate tax savings under Indian capital-gains rules, and plan the sell-and-rebuy sequence while avoiding wash-sale equivalents. Use when the user asks about "tax harvesting", "tax loss", "book losses to offset gains", "LTCG offset", "STCG reduction", "year-end tax", "harvest capital losses", or similar phrasing about Indian capital gains tax optimization.
---

# Tax-Loss Harvesting (India)

Indian equity capital gains tax is layered (STCG vs LTCG, different rates, ₹1.25L LTCG exemption
per financial year). This skill helps the user identify positions sitting on losses and plan
realizations without tripping over Indian-specific rules.

## 1. Pull the data

1. Call `tax_loss_analysis` — server-side analysis that buckets holdings into STCG/LTCG, flags
   loss candidates, and estimates potential tax savings at the current effective rates.
2. Call `get_holdings` to cross-check quantities and avg prices.
3. Call `get_trades` with a date range to see realized gains already booked this financial year
   (if the user has been trading). Needed to know how much tax shield is actually useful.
4. Call `get_ltp` on each candidate to price the exit.

## 2. Indian capital gains tax basics (use as facts)

- **Financial year**: April 1 to March 31. Harvesting must be settled before March 31 to count
  for the current FY.
- **STCG (Short-Term Capital Gains)**: Equity held ≤12 months → taxed at 20% flat (revised from
  15% — confirm current rate from `tax_loss_analysis` response, which reflects latest rules).
- **LTCG (Long-Term Capital Gains)**: Equity held >12 months → ₹1.25 lakh annual exemption per
  individual, then 12.5% on the excess (revised from 10%).
- **Losses**: STCL can offset STCG or LTCG. LTCL can only offset LTCG. Carried forward up to 8
  years if filed on time.
- **No wash-sale rule** in Indian tax law as of this writing — you can sell and re-buy the same
  day, and the loss is still recognized. BUT the re-buy resets the holding period to zero, so
  an LTCG position becomes STCG. Consider this carefully.
- **STT, brokerage, exchange charges** are deductible from capital gains (use `get_order_charges`
  to estimate these).

## 3. Format the harvest plan

```
## Tax-Loss Harvest Plan — FY <YYYY-YY>

### Current tax position
- Realized STCG this FY: <amt>
- Realized LTCG this FY: <amt> (₹1.25L exemption: <used | unused>)
- Realized STCL / LTCL this FY: <amt>
- Net taxable so far: <amt>

### Candidates for harvesting (unrealized losses)

| Symbol | Qty | Buy Date | Avg Cost | LTP | Unrealized Loss | Bucket |
|---|---|---|---|---|---|---|
| <sym> | <q> | <date> | <price> | <price> | <loss> | STCL | LTCL |

### Estimated tax shield
- STCL available to book: <amt> → offsets <amt> of STCG at 20% = ₹<tax savings>
- LTCL available to book: <amt> → offsets LTCG at 12.5% = ₹<tax savings>

### Proposed sequence
1. SELL <qty> <symbol> (books <loss amount> as <STCL|LTCL>)
2. ...

### Re-buy consideration
<If user wants to keep exposure:>
- You can re-buy the same symbol immediately (no wash-sale in India).
- IMPORTANT: Re-buying resets the holding period clock to zero.
  - If you sold a position held 14 months (LTCG), re-buying means the new lot is STCG until it
    crosses 12 months. This may cost more on future gains than the loss you're booking now.
- Alternative: buy a similar-exposure stock or sector ETF to preserve market exposure without
  resetting the clock on the sold name.

### Charges to factor in
- STT on sell: ~0.1% (delivery)
- Brokerage: <user's plan — check with `get_order_charges`>
- Exchange charges, stamp duty, GST: small but add up
- Net benefit after charges: <amt>
```

## 4. Walk through the sell sequence

Once the user approves the plan:

1. For each leg, route to `trade-check` (or run the pre-flight inline) to confirm margin and
   order params.
2. Use `place_order` with `variety: "regular"`, `transaction_type: "SELL"`, `product: "CNC"`.
3. Verify fills via `get_order_history`.
4. Update the user on realized P&L — note the bucket (STCL vs LTCL) so they track correctly.

If the user wants the re-buy as a paired transaction:

- Place SELL first, confirm fill.
- Then place BUY with fresh order.
- This will show as a new tax lot with today's date and cost basis.

## 5. Deadlines the user cares about

- **Last trading day of March**: All sells must execute on or before this day to count for the
  current FY. T+1 settlement means the trade settles the next day, but the tax event is the
  trade date.
- **September deadline for LTCG exemption**: LTCG from before Jan 31, 2018 had a grandfathered
  basis. Newer holdings don't — but if the user has very old lots, flag this.

## 6. Guardrails

- Do NOT quote tax rates from memory if they may have changed. Always source them from the
  `tax_loss_analysis` tool response, which reflects current server-side rates.
- Do NOT promise a specific tax savings number — it depends on the user's bracket, other income,
  and actual execution prices. Frame estimates as "~" and note assumptions.
- Do NOT execute sells without explicit user confirmation for each leg. This is a tax-sensitive
  operation.
- Remind the user: this is decision support, not tax advice. A CA should sign off on the actual
  filing.
- If the user's realized gains are already below the LTCG exemption, harvesting LTCL is wasted
  — flag that the shield has no value this FY.
- If the loss candidate is a position they'd buy back immediately at a higher price, factor
  slippage and STT — sometimes the "savings" are eaten by frictional costs.
