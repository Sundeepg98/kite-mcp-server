---
name: backtest-interpretation
description: Interpret backtest output from the historical_price_analyzer tool — four built-in strategies (SMA crossover, RSI reversal, breakout, mean reversion) over Indian stocks, with Sharpe, max drawdown, win rate, and avg trade. Use when the user asks about "backtest", "how would strategy X have performed", "test this on history", "Sharpe ratio", "max drawdown on this stock", or wants to evaluate a mechanical rule before committing capital.
---

# Backtest Interpretation

The server's `historical_price_analyzer` can run four pre-built strategies over any NSE/BSE
instrument with intraday or daily candles. This skill helps the user read the output without
falling into the classic backtesting traps (over-fitting, survivorship, look-ahead).

## 1. What the tool supports

Four built-in strategies (the server's code is the source of truth):

| Strategy | Entry | Exit | Notes |
|---|---|---|---|
| **SMA crossover** | Fast SMA crosses above slow SMA | Fast crosses below slow | Trend-following; chops in sideways markets |
| **RSI reversal** | RSI below 30 (oversold) → BUY; above 70 (overbought) → SELL | Fixed holding period or RSI mean-reverts | Range-bound setups; breaks in trending markets |
| **Breakout** | Price closes above N-day high | Stop-loss or target hit | Captures momentum; whipsaws at false breakouts |
| **Mean reversion** | Price deviates >k standard deviations from mean | Reverts to mean | Works in range-bound; breaks in regime shift |

## 2. Run the backtest

1. Get the user's strategy choice + parameters (periods, thresholds).
2. Call `historical_price_analyzer` with:
   - `exchange`, `tradingsymbol`
   - `strategy` (one of the four above)
   - `from_date`, `to_date`
   - `interval` (minute, day, etc.)
   - Strategy-specific parameters (e.g., SMA fast period, RSI period)
3. It returns trade-by-trade output plus summary stats.

## 3. Read the output like a skeptic

```
## Backtest: <strategy> on <symbol>, <from> to <to>

### Summary stats
- Total trades: <n>
- Win rate: <pct>%
- Avg P&L per trade: <amt> (<pct>%)
- Avg hold: <days>
- Sharpe ratio: <value>
- Max drawdown: <pct>%
- Final equity curve: <start> → <end> (<pct>%)

### Context needed to interpret
- Benchmark: what did buy-and-hold NIFTY 50 do over the same window? If the strategy made 15%
  and NIFTY made 20%, the strategy UNDERPERFORMED even if the number looks good.
- Time window bias: a bull-market window flatters trend-following; a choppy window flatters
  mean reversion.
- Number of trades: <10 trades means the Sharpe is unreliable (small sample).
- Costs: does the backtest include brokerage, STT, slippage? If not, real-world returns are
  lower. Typical cost drag for a delivery trade: 0.1-0.3% round-trip.

### Red flags to surface
- Sharpe >3 on daily bars is suspicious; double-check for look-ahead bias
- Max drawdown <5% on a multi-year test: could be a lucky window, not a robust strategy
- Win rate >70%: check that the avg loss isn't much bigger than avg win (classic tail risk)
- All trades in one direction: strategy hasn't been stress-tested in opposite regime
```

## 4. Common traps to call out explicitly

### Over-fitting
If the user tries many parameter combinations and picks the best, Sharpe is inflated. Rule of
thumb: if you tested >5 variants, discount the Sharpe by at least 30%.

### Look-ahead bias
Ensure the strategy uses only data available at decision time. If "close above 20-day high"
uses today's close to decide today's entry, you can't actually trade that. The server's built-in
strategies are coded to avoid this, but if the user asks for a custom twist, flag the risk.

### Survivorship
The stock you're backtesting is by definition still listed. Strategies that would have blown up
on delisted names won't show the damage here. Relevant for small-cap backtests.

### Regime shift
2015-2020 is different from 2020-2023 is different from 2023-2026. A strategy that worked in
one regime often fails in the next.

### No costs
If cost drag isn't in the backtest, subtract ~0.3-0.5% per round trip for realistic numbers.
The server's output may or may not include costs — check the response metadata.

## 5. Presenting to the user

Use this framing:

- State the numbers.
- Immediately pair them with the caveats above.
- If the user asks "should I trade this live?", the answer is never a direct yes. It's: run a
  walk-forward test, paper-trade it for 1-2 months (`paper_trading_toggle` enables this), then
  commit real capital with small size.

## 6. Offer next steps

After showing a backtest:

1. "Want to compare against buy-and-hold on the same window?" → Run `historical_price_analyzer`
   with no strategy (or compute buy-and-hold separately from `get_historical_data` output).
2. "Want to stress-test across multiple symbols?" → Run the same strategy on 5-10 stocks and
   compare.
3. "Want to paper-trade before going live?" → Hand off to paper-trading setup via
   `paper_trading_toggle`.
4. "Want to see this with different parameters?" → Grid-search, but remind the user that
   picking the best variant over-fits.

## 7. Guardrails

- NEVER present a backtest as a prediction. Past Sharpe is not future Sharpe.
- NEVER recommend going live on a backtest alone. Paper-trading is cheap; use it.
- NEVER suppress red flags (low trade count, missing costs, suspicious Sharpe). The point of
  this skill is to inject skepticism, not confirm the user's bias.
- If the user asks for a backtest over <6 months of data, note that the window is too short for
  meaningful statistical significance, but run it if they want the directional read.
- If the strategy's drawdown exceeds the user's stated risk tolerance, say so plainly.
