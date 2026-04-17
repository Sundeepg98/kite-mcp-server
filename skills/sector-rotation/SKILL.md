---
name: sector-rotation
description: Analyze sector exposure in an Indian equity portfolio — which sectors the user is overweight/underweight vs NIFTY benchmarks, how yesterday's FII/DII flows align with current holdings, and what the concentration numbers actually say. Use when the user asks about "sector exposure", "sector rotation", "am I too concentrated in IT", "banking exposure", "how diversified am I", "FII flow into my sectors", or similar phrasing about sector-level portfolio composition.
---

# Sector Rotation & Exposure Review

Indian markets have strong sector-level correlation (IT moves together on USD-INR, banks move
together on RBI policy, etc.). This skill surfaces the user's sector-level picture so they
decide rotation moves with facts instead of vibes.

## 1. Pull the data

1. Call `sector_exposure` — server maps the user's holdings across 150+ NSE stocks into 20+
   sectors (IT, Banking, Auto, Pharma, FMCG, Energy, Metals, Realty, Capital Goods, etc.) and
   returns weight per sector + HHI.
2. Call `portfolio_summary` — total invested, current value, day P&L per sector.
3. Call `portfolio_concentration` — HHI, top-5 weights, single-stock max.
4. Call `get_fii_dii_flow` — yesterday's net institutional buying/selling (often sector-tagged
   in the response).
5. Optionally call `get_ltp` on sector indices (`NSE:NIFTY IT`, `NSE:NIFTY BANK`, `NSE:NIFTY
   AUTO`, `NSE:NIFTY PHARMA`, `NSE:NIFTY FMCG`, `NSE:NIFTY ENERGY`, `NSE:NIFTY METAL`,
   `NSE:NIFTY REALTY`) for today's sector-level direction.

## 2. Format the exposure report

```
## Sector Exposure — <Date>

### Your Sector Mix (by value)
| Sector | Weight | Value | Day % | Top Holding |
|---|---|---|---|---|
| IT | <pct>% | <amt> | <pct>% | <symbol> |
| Banking | ... | ... | ... | ... |

### Concentration Signals
- HHI: <value> (0=fully diversified, 10000=single stock)
- Top-5 stocks: <pct>% of portfolio
- Single-stock max: <symbol> at <pct>%

### Benchmark Context
- Your IT weight vs NIFTY 50 IT weight: <user pct> vs <~13% benchmark> → overweight | underweight
- Your Banking weight vs NIFTY 50 Banking weight: <user pct> vs <~34% benchmark> → ...
(Note: benchmark weights rebalance quarterly — use them as orientation, not a target.)

### FII/DII Flow (yesterday)
- FII net: <buy | sell> <amt>, heaviest in <sector>
- DII net: <buy | sell> <amt>, heaviest in <sector>

### Today's Sector Indices
- NIFTY IT: <price> (<change>%)
- NIFTY BANK: ...
- NIFTY AUTO: ...

### Observations (factual only)
- You're <overweight|underweight> <sector> by <pct>% vs benchmark.
- Your heaviest single exposure is <symbol> at <pct>% — single-stock risk.
- FII net <direction> in <sector> does not automatically imply a move; note and move on.
```

## 3. Framing rules

- State facts: weights, HHI, flow direction. Do not prescribe rotation trades.
- Benchmark weights are orientation aids, not targets. A user's strategy might intentionally
  overweight IT or Pharma; don't assume deviation is wrong.
- FII/DII flow is one data point among many. Do not extrapolate next-day direction from it.

## 4. If the user asks "should I rotate out of X into Y?"

Do NOT answer directly with a trade recommendation. Instead:

1. Quantify: show current weight in X, current weight in Y.
2. Estimate the delta: what would the rebalance cost in taxes (link to `tax-harvest` skill) and
   transaction charges (`get_order_charges`)?
3. Highlight: is X a single-stock concentration problem or a sector concentration problem? The
   fix is different.
4. Hand off to `trade-check` if the user decides to actually place orders.

## 5. Sector definitions used by `sector_exposure`

The server uses NSE's sectoral classification as the source of truth. Common buckets:

- IT Services (TCS, INFY, WIPRO, HCLTECH, TECHM, LTIM, PERSISTENT)
- Private Banks (HDFCBANK, ICICIBANK, AXISBANK, KOTAKBANK, INDUSINDBK)
- PSU Banks (SBIN, PNB, BANKBARODA, CANBK)
- Auto (MARUTI, TATAMOTORS, M&M, BAJAJ-AUTO, EICHERMOT, HEROMOTOCO)
- Pharma (SUNPHARMA, DRREDDY, CIPLA, DIVISLAB, LUPIN)
- FMCG (HINDUNILVR, ITC, NESTLEIND, BRITANNIA, DABUR)
- Energy (RELIANCE, ONGC, IOC, BPCL, HPCL, NTPC, POWERGRID)
- Metals (TATASTEEL, JSWSTEEL, HINDALCO, VEDL, COALINDIA)
- Capital Goods (LT, SIEMENS, ABB, BEL, BHEL)
- Cement (ULTRACEMCO, SHREECEM, ACC, AMBUJACEM)
- Realty (DLF, GODREJPROP, OBEROIRLTY, PHOENIXLTD)

## 6. Guardrails

- Do NOT claim any sector "will outperform" or "is undervalued" — you don't know forward returns.
- Do NOT recommend specific rotation trades. State weights, let the user decide.
- Do NOT present HHI thresholds as hard rules. HHI >2500 is concentrated; HHI <1500 is spread;
  but these are heuristics, not policy.
- If the user's portfolio is already well-diversified, say so plainly and don't manufacture a
  rotation need.
