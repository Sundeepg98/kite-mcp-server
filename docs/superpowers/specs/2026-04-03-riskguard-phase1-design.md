# Riskguard Phase 1: Core Financial Safety Controls

## Problem

The server places real orders on the Indian stock market with real money. Elicitation adds a human confirmation gate, but it doesn't protect against: confirmed-but-wrong orders (user clicks Accept on a hallucinated price), AI placing dozens of orders in a loop, or a compromised session placing unauthorized trades. There are zero server-side financial limits today.

## Solution

A middleware that intercepts order-placement tools and blocks orders that violate configurable safety limits. Runs before elicitation — obviously bad orders never reach the user for confirmation.

## The 4 Checks

### 1. Kill Switch (Trading Freeze)

Per-user boolean flag. When frozen, all order tools return an error immediately. Read-only tools still work (user can see positions, P&L, etc.).

- **Trigger**: Admin sets via ops dashboard API (`POST /admin/ops/api/risk/freeze`)
- **Reset**: Admin unfreezes via ops dashboard API (`POST /admin/ops/api/risk/unfreeze`)
- **Storage**: In-memory flag + `risk_limits.trading_frozen` column in SQLite
- **Message**: "ORDER BLOCKED [trading_frozen]: Trading is frozen for your account. Reason: {reason}. Contact admin."

### 2. Single Order Value Cap

Rejects any order where `quantity * price > MaxSingleOrderINR`. For MARKET orders, uses the tool's price argument or 0 (which means the check is skipped — MARKET orders don't have a known price at submission time, and the exchange's market protection handles price bands).

- **Default**: ₹5,00,000
- **Calculation**: `quantity * price` for LIMIT, `quantity * trigger_price` for SL/SL-M
- **MARKET orders**: Skipped (price unknown at submission; exchange market protection applies)
- **Message**: "ORDER BLOCKED [order_value_limit]: Order value ₹X exceeds limit ₹Y"

### 3. Quantity Limit (Exchange Freeze Quantity)

Rejects orders where quantity exceeds the exchange-mandated freeze quantity for the instrument. Uses the `FreezeQuantity` field already loaded in `instruments.Manager`.

- **Source**: `instruments.Manager.GetFreezeQuantity(exchange, tradingsymbol)`
- **Fallback**: If instrument not found or freeze quantity is 0, skip the check (fail open)
- **Message**: "ORDER BLOCKED [quantity_limit]: Quantity X exceeds freeze limit Y for {symbol}"

### 4. Daily Order Count

Tracks orders placed per user per day. Rejects when count exceeds the limit.

- **Default**: 200 orders/day
- **Counter**: In-memory per-user counter in `Guard.trackers`
- **Reset**: 9:15 AM IST (market open), not midnight. AMO orders placed before market open count toward the new day.
- **Incremented**: After successful order placement (post-middleware, on success)
- **Message**: "ORDER BLOCKED [daily_order_limit]: You have placed X orders today (limit: Y). Resets at next market open."

## Architecture

### Middleware Pattern

Same pattern as audit middleware (`kc/audit/middleware.go`). Wraps tool handlers:

```
Request → AuditMiddleware → RiskguardMiddleware → [Elicitation] → ToolHandler → KiteAPI
```

Only intercepts tools in the `orderTools` set (same 8 tools that have elicitation: place_order, modify_order, close_position, close_all_positions, place_gtt_order, modify_gtt_order, place_mf_order, place_mf_sip). All other tools pass through immediately.

### Guard Struct

```go
type Guard struct {
    mu       sync.RWMutex
    trackers map[string]*UserTracker // per-user state, keyed by email
    limits   map[string]*UserLimits  // per-user overrides from DB
    defaults UserLimits              // system defaults (env var overridable)
    instruments *instruments.Manager // for freeze quantity lookup
    db       *alerts.DB             // for persisting risk_limits
    logger   *slog.Logger
}
```

### UserTracker (in-memory per-user state)

```go
type UserTracker struct {
    DailyOrderCount int
    DayResetAt      time.Time // when counter was last reset
    Frozen          bool
    FrozenReason    string
}
```

### UserLimits (configurable per-user)

```go
type UserLimits struct {
    MaxSingleOrderINR float64 // default 500000
    MaxOrdersPerDay   int     // default 200
    TradingFrozen     bool
    FrozenBy          string
    FrozenReason      string
}
```

### Config Resolution

Three tiers, first match wins:
1. Per-user override from `risk_limits` SQLite table
2. Environment variable override (`RISK_MAX_ORDER_VALUE`, `RISK_MAX_ORDERS_PER_DAY`)
3. Hardcoded system defaults (₹5L, 200/day)

### CheckOrder Flow

```
1. Is user frozen? → BLOCK (kill switch)
2. Is order value > limit? → BLOCK (order value cap)
3. Is quantity > freeze qty? → BLOCK (quantity limit)
4. Is daily count ≥ limit? → BLOCK (daily order count)
5. All checks pass → ALLOW
```

### Rejection Logging

Every rejected order is logged to the existing audit trail via `slog`. Critical rejections (kill switch) also send a Telegram notification if the user has a Telegram chat ID registered.

### Admin Endpoints

Two new endpoints on the existing ops handler:

- `POST /admin/ops/api/risk/freeze` — body: `{"email": "...", "reason": "..."}`
- `POST /admin/ops/api/risk/unfreeze` — body: `{"email": "..."}`

These reuse the existing admin auth middleware.

## Database Schema

Add to existing SQLite database via `alerts.DB`:

```sql
CREATE TABLE IF NOT EXISTS risk_limits (
    email                TEXT PRIMARY KEY,
    max_single_order_inr REAL NOT NULL DEFAULT 500000,
    max_orders_per_day   INTEGER NOT NULL DEFAULT 200,
    trading_frozen       INTEGER NOT NULL DEFAULT 0,
    frozen_at            TEXT DEFAULT '',
    frozen_by            TEXT DEFAULT '',
    frozen_reason        TEXT DEFAULT '',
    updated_at           TEXT NOT NULL
);
```

## Files

| File | Action | Description |
|------|--------|-------------|
| `kc/riskguard/guard.go` | **New** | Guard struct, CheckOrder(), 4 check methods, UserTracker, UserLimits, NewGuard(), LoadLimits(), Freeze/Unfreeze |
| `kc/riskguard/guard_test.go` | **New** | Unit tests: each check individually, combined CheckOrder, freeze/unfreeze, daily reset, config resolution |
| `kc/manager.go` | Modify | Add `riskGuard *riskguard.Guard` field, `RiskGuard()` accessor, `SetRiskGuard()` |
| `app/app.go` | Modify | Initialize Guard after alert DB, register middleware, load limits from DB |
| `kc/alerts/db.go` | Modify | Add `risk_limits` table DDL to InitTables |
| `kc/ops/handler.go` | Modify | Add freeze/unfreeze admin endpoints |

## What's NOT in Phase 1

- Rate limiting per minute
- Duplicate order detection
- Daily loss limit with P&L tracking
- Circuit breaker (auto-freeze on rapid losses)
- Per-user configurable limits via admin UI (DB schema supports it, but no UI yet — admin uses raw API)
- MCP admin tools (freeze_trading, unfreeze_trading) — use ops dashboard HTTP API for now

## Testing Strategy

Unit tests for each check in isolation:
- `TestCheckKillSwitch` — frozen user blocked, unfrozen passes
- `TestCheckOrderValue` — over limit blocked, under passes, MARKET skipped
- `TestCheckQuantityLimit` — over freeze qty blocked, no instrument = pass
- `TestCheckDailyOrderCount` — at limit blocked, under passes, reset at 9:15 IST
- `TestCheckOrder` — combined flow, order of checks
- `TestFreeze/TestUnfreeze` — admin operations
- `TestConfigResolution` — per-user > env > default
