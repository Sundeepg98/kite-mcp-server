# Paper Trading / Simulation Mode Design

## Problem

Users can't test trading strategies without risking real money. Zerodha has no native paper trading. New users can't explore the server without a funded Kite account.

## Solution

A middleware that intercepts order and portfolio tools when paper mode is active, executing against a virtual portfolio (SQLite) with real market data. Same tool names, same parameters — the AI agent doesn't know the difference.

## Architecture

### Middleware Chain Position

```
Audit → Riskguard → PaperTrading → DashboardURL → Handler (Elicitation + Kite API)
```

- **After Audit**: Paper trades still logged (with paper flag)
- **After Riskguard**: Paper orders still go through safety checks (realism + AI loop protection)
- **Before Handlers**: Short-circuits before hitting real Kite API. Elicitation skipped (no value confirming fake orders).

### Tools Intercepted

**Write tools (execute against virtual portfolio):**
- place_order, modify_order, cancel_order
- close_position, close_all_positions
- place_gtt_order, modify_gtt_order, delete_gtt_order

**Read tools (return virtual data):**
- get_holdings, get_positions, get_orders, get_order_history, get_trades, get_margins

**Pass-through (real API, NOT intercepted):**
- get_ltp, get_quotes, get_ohlc, get_historical_data, search_instruments
- Ticker tools, alert tools, watchlist tools, analytics tools
- get_profile (real user info)

### New Package: `kc/papertrading/`

| File | Responsibility |
|------|---------------|
| `engine.go` | PaperEngine: place/modify/cancel virtual orders, update positions/holdings/cash |
| `store.go` | SQLite persistence: 4 tables (paper_accounts, paper_orders, paper_positions, paper_holdings) |
| `middleware.go` | MCP ToolHandlerMiddleware: intercept tools, route to engine |
| `monitor.go` | Background goroutine: poll LTP every 5s, fill OPEN limit orders |
| `engine_test.go` | Unit tests for engine logic |

### Database Schema (4 tables in existing SQLite)

```sql
CREATE TABLE paper_accounts (
    email          TEXT PRIMARY KEY,
    enabled        INTEGER NOT NULL DEFAULT 0,
    initial_cash   REAL NOT NULL DEFAULT 10000000,
    cash_balance   REAL NOT NULL,
    created_at     TEXT NOT NULL,
    reset_at       TEXT NOT NULL
);

CREATE TABLE paper_orders (
    order_id         TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    order_type       TEXT NOT NULL,
    product          TEXT NOT NULL,
    variety          TEXT NOT NULL DEFAULT 'regular',
    quantity         INTEGER NOT NULL,
    price            REAL DEFAULT 0,
    trigger_price    REAL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'OPEN',
    filled_quantity  INTEGER NOT NULL DEFAULT 0,
    average_price    REAL NOT NULL DEFAULT 0,
    placed_at        TEXT NOT NULL,
    filled_at        TEXT DEFAULT '',
    tag              TEXT DEFAULT 'paper'
);

CREATE TABLE paper_positions (
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    product          TEXT NOT NULL,
    quantity         INTEGER NOT NULL,
    average_price    REAL NOT NULL,
    last_price       REAL DEFAULT 0,
    pnl              REAL DEFAULT 0,
    PRIMARY KEY (email, exchange, tradingsymbol, product)
);

CREATE TABLE paper_holdings (
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    quantity         INTEGER NOT NULL,
    average_price    REAL NOT NULL,
    last_price       REAL DEFAULT 0,
    pnl              REAL DEFAULT 0,
    PRIMARY KEY (email, exchange, tradingsymbol)
);
```

### Order Fill Simulation

- **MARKET orders**: Fill immediately at real LTP (via Kite GetLTP API). Fill price = last traded price.
- **LIMIT orders**: Fill immediately if marketable (buy limit >= LTP for sell side). Otherwise store as OPEN. Background monitor polls LTP every 5s and fills when price crosses.
- **SL/SL-M orders**: Trigger when LTP crosses trigger_price, then fill as MARKET at LTP.
- **Cash accounting**: BUY deducts from cash_balance, SELL adds. Insufficient cash = order rejected.

### Riskguard Interaction

Paper orders go through riskguard checks but use a **separate tracker** (keyed by `paper:email`) so paper order counts/values don't consume real limits. Implemented via a context flag `papertrading.IsPaperMode(ctx)` that riskguard checks.

### New Management Tools (3)

1. **`paper_trading_toggle`** — Enable/disable paper mode. Params: `enable` (bool). When enabling, creates account with ₹1 crore default cash.
2. **`paper_trading_status`** — Returns: mode (paper/live), cash balance, total P&L, open orders count, positions count.
3. **`paper_trading_reset`** — Clears all virtual orders, positions, holdings. Resets cash to initial amount.

### Key Design Decisions

1. **Virtual-only reads** — When paper mode active, get_holdings/get_positions return ONLY virtual data, not merged with real. Clean separation, avoids confusion.
2. **₹1 crore default cash** — Enough for realistic multi-stock strategies. Configurable per user.
3. **Elicitation skipped** — Paper middleware sits before handlers, so elicitation (inside handlers) never fires. No value confirming fake orders.
4. **Corporate actions deferred** — Splits, dividends not tracked on virtual holdings. Paper sessions are typically short-lived.
5. **Audit logged** — All paper tool calls go through audit middleware with tool responses tagged `[PAPER]`.

### Files to Create/Modify

| File | Action |
|------|--------|
| `kc/papertrading/engine.go` | **New** — PaperEngine with PlaceOrder, ModifyOrder, CancelOrder, GetHoldings, GetPositions, GetOrders, GetMargins |
| `kc/papertrading/store.go` | **New** — SQLite persistence, InitTables, CRUD for all 4 tables |
| `kc/papertrading/middleware.go` | **New** — Middleware(), tool routing, response building |
| `kc/papertrading/monitor.go` | **New** — Background LIMIT order fill monitor |
| `kc/papertrading/engine_test.go` | **New** — Tests for engine logic |
| `mcp/paper_tools.go` | **New** — 3 management tools (toggle, status, reset) |
| `app/app.go` | Modify — Initialize PaperEngine, register middleware |
| `kc/manager.go` | Modify — Add paperEngine field + accessor |
| `mcp/mcp.go` | Modify — Register 3 new tools |
| `kc/riskguard/middleware.go` | Modify — Check paper mode context for separate tracking |

### Not in Scope

- Partial fills / slippage simulation (Phase 2)
- Corporate actions on virtual holdings (Phase 2)
- Paper trading widget (MCP App) (Phase 2)
- Paper mode via Telegram bot (Phase 2)
