# Cookbook

This is how to get value out of kite-mcp-server in your first day. Each recipe is a conversation with Claude that actually runs end-to-end on our free hosted server at `kite-mcp-server.fly.dev` — no code required.

Before starting, connect your MCP client to `https://kite-mcp-server.fly.dev/mcp`, complete the OAuth handshake, and register your Kite developer app credentials via the `login` tool. Run `test_ip_whitelist` once to confirm your Kite console has the static egress IP `209.71.68.157` whitelisted (SEBI April 2026 mandate).

Every workflow below assumes those one-time setup steps are done. If a tool fails with `ip_not_whitelisted`, fix that before continuing.

---

## 1. Post-weekend review — "What did I do last week?"

**Setup**
- OAuth connected; credentials registered via `login`.
- No Kite session needed for the activity audit trail (it reads our internal SQLite audit store).

**Prompt to Claude**
```
What did I do last week on Kite? Show me the activity trail with any errors highlighted.
```

**Tool calls (in order)**
1. `open_dashboard` with `page="activity"`, `days=7`, `errors=true` — opens the activity timeline widget.
2. Optionally `get_pnl_journal` — pulls realised P&L per symbol for the window.
3. Optionally `get_order_history_reconstituted` for any specific order Claude wants to dig into.

**Expected output**
- Markdown link to `https://kite-mcp-server.fly.dev/dashboard/activity?days=7&errors=true` (or the activity widget inline if your client supports MCP Apps).
- Claude summarises the last 7 days: N orders placed, K rejections, and a P&L line. Everything is reconstituted from the server-side audit trail (90-day retention), so it works even if you changed clients.

**Common errors**
- *"No activity found"* — audit trail only records calls made through this server. If you traded directly on Kite Web, those trades show up in `get_trades` but not in the activity audit.
- *Empty P&L journal* — the journal is populated by closed trades only. If you're still holding, it shows zero realised.

---

## 2. Morning scan — "What's moving? futures + NIFTY options chain + unusual volume in my watchlist"

**Setup**
- At least one watchlist populated (`create_watchlist` + `add_to_watchlist` or via `/dashboard/watchlist`).
- Ticker not required — the scan uses REST LTP + option chain snapshots.

**Prompt to Claude**
```
Morning scan. Show me NIFTY futures, the NIFTY option chain around the ATM, and anything unusual in my default watchlist.
```

**Tool calls (in order)**
1. `get_quotes` with `instruments=["NFO:NIFTY24APRFUT"]` (or current month FUT) — front-month futures LTP + OI.
2. `get_option_chain` with `underlying="NIFTY"`, `strikes_around_atm=10` — ATM +/- 10 strikes with CE/PE LTP, OI, volume, max pain, PCR.
3. `list_watchlists` + `get_watchlist` for the user's default list — returns items enriched with LTP and `distance_entry_pct` / `near_target` flags.
4. `trading_context` — unified snapshot of positions, margins, pending orders, plus a market-status string.

**Expected output**
- Futures quote line, option-chain table (widget URI `ui://kite-mcp/options-chain` if supported), watchlist table with near-target items highlighted. Claude will typically call out max-pain drift and PCR extremes.

**Common errors**
- *"Instruments not loaded"* — the instrument master downloads on server startup; wait 30s and retry if the server just booted.
- *Empty option chain* — make sure `underlying` is an NSE index or a stock with F&O listings (NIFTY, BANKNIFTY, RELIANCE, etc.). Non-F&O tickers return an empty chain.

---

## 3. Backtest an idea — "Run RSI-reversal on RELIANCE for last 6 months"

**Setup**
- Credentials registered and session active (backtest pulls daily candles via `get_historical_data` under the hood).
- No watchlist prerequisite.

**Prompt to Claude**
```
Backtest an RSI-reversal strategy on RELIANCE for the last 180 days. Use default RSI parameters.
```

**Tool calls (in order)**
1. `historical_price_analyzer` with `strategy="rsi_reversal"`, `exchange="NSE"`, `tradingsymbol="RELIANCE"`, `days=180`.
   - The tool resolves the instrument token, fetches daily candles via the query bus, and runs the selected strategy.

**Expected output**
- A `BacktestResult` JSON blob Claude will render as: total return %, max drawdown %, Sharpe ratio, win rate, total trades, buy-and-hold comparison, and the last 50 round-trip trades in a trade log.

**What this tool actually supports**
Only 4 hardcoded strategies — `sma_crossover`, `rsi_reversal`, `breakout`, `mean_reversion`. Each exposes two tunable parameters (`param1`, `param2`) with sensible defaults. There is **no** custom strategy DSL, no Python hooks, no "bring your own signal". If you need something else, open an issue — or read `mcp/backtest_tool.go` and add a strategy.

**Common errors**
- *"Insufficient data: got N candles, need at least 50"* — increase `days` or pick a symbol with longer history.
- *"Unknown strategy 'foo'"* — must be one of the four names above, lowercase, underscore-separated.

---

## 4. Paper trade the idea — "Enable paper trading, place the signal as a buy order"

**Setup**
- Paper trading requires `ALERT_DB_PATH` on the server (the hosted Fly.io instance has it).
- OAuth authenticated.

**Prompt to Claude**
```
Enable paper trading with Rs 10 lakh virtual cash, then place a paper buy order
for 50 shares of RELIANCE at market.
```

**Tool calls (in order)**
1. `paper_trading_toggle` with `enable=true`, `initial_cash=1000000`.
2. `pre_trade_check` with the order params — composite check returning margins, charges, and LTP in one call; surfaced to Claude as a confirmation before the actual order.
3. `place_order` with `tradingsymbol="RELIANCE"`, `exchange="NSE"`, `transaction_type="BUY"`, `quantity=50`, `order_type="MARKET"`, `product="MIS"`.
   - The Paper Trading middleware intercepts the `place_order` call and routes it to the virtual portfolio. A real Kite order is **not** placed.
4. `paper_trading_status` — shows the new position in the virtual book.

**Expected output**
- Claude confirms "Paper mode ON", then surfaces the pre-trade check, then the elicitation (order confirmation) dialog fires if your client supports it. After confirmation, the paper order is filled at LTP and shows up in `paper_trading_status`.

**Common errors**
- *"Paper trading requires database configuration"* — paper mode is gated on `ALERT_DB_PATH`. Either use the hosted server or set the env var locally.
- Elicitation times out silently on older MCP clients — the order still goes through because elicit is fail-open.

---

## 5. EOD review + alert — "Show today's P&L and set an alert for NIFTY -0.5% tomorrow"

**Setup**
- Telegram configured for notifications (one-time `setup_telegram` with the chat ID from `@userinfobot`).
- Ticker running if you want the alert to fire live (otherwise it evaluates on the next LTP poll).

**Prompt to Claude**
```
Give me today's P&L summary, then set an alert to notify me if NIFTY drops 0.5% from current levels. Include sector breakdown.
```

**Tool calls (in order)**
1. `portfolio_summary` — today's unrealised + realised P&L across all holdings.
2. `sector_exposure` — 20+ sector buckets with concentration.
3. `portfolio_analysis` — rebalance suggestions if the user wants them (optional; Claude may skip).
4. `set_alert` with `instrument="NSE:NIFTY 50"`, `direction="drop_pct"`, `price=0.5` (percentage threshold). Omitting `reference_price` uses current LTP as the baseline.
5. `list_alerts` to confirm the alert was created.

**Expected output**
- Markdown P&L table, sector pie summary (via `ui://kite-mcp/portfolio` widget if supported), and an "Alert created: NIFTY 50 drop_pct 0.5% from Rs X" confirmation. When the alert fires, you get a Telegram DM.

**Common errors**
- *"Telegram notifier not configured"* — run `setup_telegram` with your chat ID first.
- *"Ticker not running, instrument not subscribed"* — alerts need the ticker subscribed to the instrument. Call `start_ticker` then `subscribe_instruments` with the instrument, or rely on the built-in alert scheduler that polls LTP.

---

## What's next

- **Verify your IP whitelist** via the setup widget at `https://kite-mcp-server.fly.dev/dashboard/setup` — the `test_ip_whitelist` tool drives the same check from the chat.
- **Your dashboard**: `https://kite-mcp-server.fly.dev/dashboard` — portfolio, activity, orders, alerts, and paper trading pages all render server-side.
- **Bug reports and feature requests**: open an issue at `https://github.com/zerodha/kite-mcp-server`.
