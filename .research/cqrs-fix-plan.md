# CQRS Fix Plan — Full Tool Mapping & Bus Design

## 1. Executive Summary

**Total tools in `mcp.go:GetAllTools()`**: 80 built-in tools (not 158 as originally estimated)
**Tools using CQRS (use case + command/query)**: 38 (47.5%)
**Tools bypassing CQRS**: 42 (52.5%)

The bypassing tools fall into these categories:
- **Kite-specific APIs not in `broker.Client`**: 17 tools (MF, margins, native alerts, convert position)
- **Local/infrastructure tools (no broker call)**: 16 tools (watchlist, paper trading, admin, setup, observability)
- **Broker-direct calls that should use CQRS**: 3 tools (get_order_trades, get_quotes, trading_context/pre_trade_check partially)
- **Composite/analytics tools using CQRS internally**: These already route through use cases

---

## 2. Complete Tool Mapping

### Legend
- **CQRS**: Uses `usecases.*UseCase` + `cqrs.*Command`/`cqrs.*Query`
- **BYPASS-broker**: Calls `session.Broker.*` directly (should be routed through use case)
- **BYPASS-kite**: Calls `session.Kite.Client.*` directly (Kite-specific, not in `broker.Client`)
- **BYPASS-manager**: Calls `manager.*Store()` directly (local data, no broker call)
- **BYPASS-infra**: Infrastructure/setup tool (login, dashboard, admin — no domain operation)

### A. Tools Using CQRS (38 tools)

| # | Tool Name | File:Line | Command/Query | Use Case |
|---|-----------|-----------|---------------|----------|
| 1 | `get_profile` | get_tools.go:28 | `GetProfileQuery` | `GetProfileUseCase` |
| 2 | `get_margins` | get_tools.go:47 | `GetMarginsQuery` | `GetMarginsUseCase` |
| 3 | `get_holdings` | get_tools.go:72 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 4 | `get_positions` | get_tools.go:112 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 5 | `get_trades` | get_tools.go:157 | `GetTradesQuery` | `GetTradesUseCase` |
| 6 | `get_orders` | get_tools.go:192 | `GetOrdersQuery` | `GetOrdersUseCase` |
| 7 | `get_gtts` | get_tools.go:227 | `GetGTTsQuery` | `GetGTTsUseCase` |
| 8 | `get_order_history` | get_tools.go:313 | `GetOrderHistoryQuery` | `GetOrderHistoryUseCase` |
| 9 | `get_historical_data` | market_tools.go:255 | `GetHistoricalDataQuery` | `GetHistoricalDataUseCase` |
| 10 | `get_ltp` | market_tools.go:315 | `GetLTPQuery` | `GetLTPUseCase` |
| 11 | `get_ohlc` | market_tools.go:366 | `GetOHLCQuery` | `GetOHLCUseCase` |
| 12 | `place_order` | post_tools.go:164 | `PlaceOrderCommand` | `PlaceOrderUseCase` |
| 13 | `modify_order` | post_tools.go:298 | `ModifyOrderCommand` | `ModifyOrderUseCase` |
| 14 | `cancel_order` | post_tools.go:366 | `CancelOrderCommand` | `CancelOrderUseCase` |
| 15 | `place_gtt_order` | post_tools.go:499 | `PlaceGTTCommand` | `PlaceGTTUseCase` |
| 16 | `modify_gtt_order` | post_tools.go:772 | `ModifyGTTCommand` | `ModifyGTTUseCase` |
| 17 | `delete_gtt_order` | post_tools.go:561 | `DeleteGTTCommand` | `DeleteGTTUseCase` |
| 18 | `close_position` | exit_tools.go:66 | (no cmd struct) | `ClosePositionUseCase` |
| 19 | `close_all_positions` | exit_tools.go:141 | (no cmd struct) | `CloseAllPositionsUseCase` |
| 20 | `set_alert` | alert_tools.go:185 | `CreateAlertCommand` | `CreateAlertUseCase` |
| 21 | `portfolio_summary` | analytics_tools.go:58 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 22 | `portfolio_concentration` | analytics_tools.go:220 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 23 | `position_analysis` | analytics_tools.go:376 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 24 | `sector_exposure` | sector_tool.go:65 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 25 | `tax_harvest_analysis` | tax_tools.go:121 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 26 | `dividend_calendar` | dividend_tool.go:139 | `GetPortfolioQuery` | `GetPortfolioUseCase` |
| 27 | `portfolio_rebalance` | rebalance_tool.go:130 | `GetPortfolioQuery` + `GetLTPQuery` | `GetPortfolioUseCase` + `GetLTPUseCase` |
| 28 | `backtest_strategy` | backtest_tool.go:158 | `GetHistoricalDataQuery` | `GetHistoricalDataUseCase` |
| 29 | `technical_indicators` | indicators_tool.go:70 | `GetHistoricalDataQuery` | `GetHistoricalDataUseCase` |
| 30 | `get_option_chain` | option_tools.go:172 | `GetLTPQuery` + `GetQuotesQuery` | `GetLTPUseCase` + `GetQuotesUseCase` |
| 31 | `options_greeks` | options_greeks_tool.go:279 | `GetLTPQuery` | `GetLTPUseCase` |
| 32 | `options_strategy` | options_greeks_tool.go:605 | `GetLTPQuery` | `GetLTPUseCase` |
| 33 | `sebi_compliance_status` | compliance_tool.go:77 | `GetProfileQuery` | `GetProfileUseCase` |

Note: Tools 21-33 are composite/analytics tools that internally use existing CQRS queries. They correctly route through use cases.

### B. Tools Bypassing CQRS — Broker Direct (3 tools, should fix)

| # | Tool Name | File:Line | Direct Call | Needed Command/Query |
|---|-----------|-----------|-------------|---------------------|
| 34 | `get_order_trades` | get_tools.go:273 | `session.Broker.GetOrderTrades(orderID)` | `GetOrderTradesQuery` → `GetOrderTradesUseCase` (exists!) |
| 35 | `get_quotes` | market_tools.go:59 | `session.Broker.GetQuotes(instruments...)` | `GetQuotesQuery` → `GetQuotesUseCase` (exists!) |
| 36 | `convert_position` | post_tools.go:646 | `session.Kite.Client.ConvertPosition(params)` | `ConvertPositionCommand` (new) → `ConvertPositionUseCase` (new) |

**Key finding**: `get_order_trades` and `get_quotes` have CQRS infrastructure already built (`GetOrderTradesUseCase`, `GetQuotesUseCase` in `kc/usecases/queries.go`) but the tool handlers bypass them! This is clearly a bug/oversight.

### C. Tools Bypassing CQRS — Kite-Specific APIs (17 tools)

These use `session.Kite.Client.*` for APIs not abstracted in `broker.Client`. Need `broker.Client` extension first (Task #2/#5).

| # | Tool Name | File:Line | Direct Call | Needed |
|---|-----------|-----------|-------------|--------|
| 37 | `get_mf_orders` | mf_tools.go:35 | `session.Kite.Client.GetMFOrders()` | `GetMFOrdersQuery` + use case |
| 38 | `get_mf_sips` | mf_tools.go:70 | `session.Kite.Client.GetMFSIPs()` | `GetMFSIPsQuery` + use case |
| 39 | `get_mf_holdings` | mf_tools.go:105 | `session.Kite.Client.GetMFHoldings()` | `GetMFHoldingsQuery` + use case |
| 40 | `place_mf_order` | mf_tools.go:195 | `session.Kite.Client.PlaceMFOrder(...)` | `PlaceMFOrderCommand` + use case |
| 41 | `cancel_mf_order` | mf_tools.go:236 | `session.Kite.Client.CancelMFOrder(...)` | `CancelMFOrderCommand` + use case |
| 42 | `place_mf_sip` | mf_tools.go:323 | `session.Kite.Client.PlaceMFSIP(...)` | `PlaceMFSIPCommand` + use case |
| 43 | `cancel_mf_sip` | mf_tools.go:364 | `session.Kite.Client.CancelMFSIP(...)` | `CancelMFSIPCommand` + use case |
| 44 | `get_order_margins` | margin_tools.go:106 | `session.Kite.Client.GetOrderMargins(...)` | `GetOrderMarginsQuery` + use case |
| 45 | `get_basket_margins` | margin_tools.go:178 | `session.Kite.Client.GetBasketMargins(...)` | `GetBasketMarginsQuery` + use case |
| 46 | `get_order_charges` | margin_tools.go:238 | `session.Kite.Client.GetOrderCharges(...)` | `GetOrderChargesQuery` + use case |
| 47 | `place_native_alert` | native_alert_tools.go:165 | `session.Kite.Client.CreateAlert(...)` | `PlaceNativeAlertCommand` + use case |
| 48 | `list_native_alerts` | native_alert_tools.go:211 | `session.Kite.Client.GetAlerts(...)` | `GetNativeAlertsQuery` + use case |
| 49 | `modify_native_alert` | native_alert_tools.go:373 | `session.Kite.Client.ModifyAlert(...)` | `ModifyNativeAlertCommand` + use case |
| 50 | `delete_native_alert` | native_alert_tools.go:427 | `session.Kite.Client.DeleteAlerts(...)` | `DeleteNativeAlertCommand` + use case |
| 51 | `get_native_alert_history` | native_alert_tools.go:475 | `session.Kite.Client.GetAlertHistory(...)` | `GetNativeAlertHistoryQuery` + use case |

### D. Tools Bypassing CQRS — Local/Infrastructure (16 tools, acceptable)

These tools operate on local data stores or infrastructure and don't make broker API calls. They interact with `manager.*Store()` methods. CQRS routing is **optional** for these — they could benefit from a CommandBus for audit/logging consistency but aren't urgent.

| # | Tool Name | File:Line | Category |
|---|-----------|-----------|----------|
| 52 | `login` | setup_tools.go:244 | Setup/infra |
| 53 | `open_dashboard` | setup_tools.go:433 | Setup/infra |
| 54 | `setup_telegram` | alert_tools.go:50 | Local store write |
| 55 | `list_alerts` | alert_tools.go:256 | Local store read |
| 56 | `delete_alert` | alert_tools.go:293 | Local store write |
| 57 | `create_watchlist` | watchlist_tools.go:33 | Local store write |
| 58 | `delete_watchlist` | watchlist_tools.go:85 | Local store write |
| 59 | `add_to_watchlist` | watchlist_tools.go:146 | Local store write |
| 60 | `remove_from_watchlist` | watchlist_tools.go:253 | Local store write |
| 61 | `get_watchlist` | watchlist_tools.go:346 | Local store read (+ LTP from Kite) |
| 62 | `list_watchlists` | watchlist_tools.go:488 | Local store read |
| 63 | `set_trailing_stop` | trailing_tools.go:65 | Local store write (+ broker reads for defaults) |
| 64 | `list_trailing_stops` | trailing_tools.go:234 | Local store read |
| 65 | `cancel_trailing_stop` | trailing_tools.go:275 | Local store write |
| 66 | `paper_trading_toggle` | paper_tools.go:27 | Paper engine |
| 67 | `paper_trading_status` | paper_tools.go:65 | Paper engine read |
| 68 | `paper_trading_reset` | paper_tools.go:98 | Paper engine |
| 69 | `get_pnl_journal` | pnl_tools.go:39 | P&L service read |
| 70 | `delete_my_account` | account_tools.go:31 | Account management |
| 71 | `update_my_credentials` | account_tools.go:107 | Account management |
| 72 | `server_metrics` | observability_tool.go:79 | Admin observability |

### E. Tools Bypassing CQRS — Admin Tools (14 tools, lower priority)

| # | Tool Name | File:Line |
|---|-----------|-----------|
| 73 | `admin_list_users` | admin_tools.go:54 |
| 74 | `admin_get_user` | admin_tools.go:144 |
| 75 | `admin_server_status` | admin_tools.go:234 |
| 76 | `admin_get_risk_status` | admin_tools.go:294 |
| 77 | `admin_suspend_user` | admin_tools.go:361 |
| 78 | `admin_activate_user` | admin_tools.go:461 |
| 79 | `admin_change_role` | admin_tools.go:505 |
| 80 | `admin_freeze_user` | admin_tools.go:585 |
| 81 | `admin_unfreeze_user` | admin_tools.go:662 |
| 82 | `admin_freeze_global` | admin_tools.go:705 |
| 83 | `admin_unfreeze_global` | admin_tools.go:787 |
| 84 | `admin_invite_family_member` | admin_tools.go:822 |
| 85 | `admin_list_family` | admin_tools.go:930 |
| 86 | `admin_remove_family_member` | admin_tools.go:1042 |

### F. Composite Tools (partially use CQRS, partially bypass)

| # | Tool Name | CQRS Part | Bypass Part |
|---|-----------|-----------|-------------|
| 87 | `trading_context` | context_tool.go | Calls multiple broker methods directly inside handler |
| 88 | `pre_trade_check` | pretrade_tool.go | Calls `session.Kite.Client.GetOrderMargins` + `session.Broker.*` directly |
| 89 | `search_instruments` | market_tools.go:95 | Uses `manager.Instruments.Filter()` (local, no broker call) |
| 90 | `start_ticker` | ticker_tools.go:27 | Uses `manager.TickerService()` (infrastructure) |
| 91 | `stop_ticker` | ticker_tools.go:72 | Uses `manager.TickerService()` (infrastructure) |
| 92 | `ticker_status` | ticker_tools.go:109 | Uses `manager.TickerService()` (infrastructure) |
| 93 | `subscribe_instruments` | ticker_tools.go:156 | Uses `manager.TickerService()` (infrastructure) |
| 94 | `unsubscribe_instruments` | ticker_tools.go:224 | Uses `manager.TickerService()` (infrastructure) |

---

## 3. CommandBus + QueryBus Design

### 3.1 Interfaces

```go
// kc/cqrs/bus.go

package cqrs

import "context"

// CommandBus dispatches commands to their registered handlers.
// All write operations flow through this single entry point.
type CommandBus interface {
    // Dispatch sends a command to its handler. Returns error if handler not found
    // or execution fails.
    Dispatch(ctx context.Context, cmd any) error

    // DispatchWithResult sends a command that returns a result (e.g., order ID).
    DispatchWithResult(ctx context.Context, cmd any) (any, error)
}

// QueryBus dispatches queries to their registered handlers.
// All read operations flow through this single entry point.
type QueryBus interface {
    // Dispatch sends a query to its handler and returns the result.
    Dispatch(ctx context.Context, query any) (any, error)
}

// Middleware wraps a handler with cross-cutting concerns.
type Middleware func(next HandlerFunc) HandlerFunc

// HandlerFunc is the generic signature for command/query handlers.
type HandlerFunc func(ctx context.Context, msg any) (any, error)
```

### 3.2 Concrete Implementation

```go
// kc/cqrs/inmemory_bus.go

package cqrs

import (
    "context"
    "fmt"
    "reflect"
    "sync"
)

// InMemoryBus is a simple, synchronous in-process bus.
// It routes commands/queries by Go type to registered handler functions.
type InMemoryBus struct {
    mu       sync.RWMutex
    handlers map[reflect.Type]HandlerFunc
    mw       []Middleware
}

func NewInMemoryBus(middlewares ...Middleware) *InMemoryBus {
    return &InMemoryBus{
        handlers: make(map[reflect.Type]HandlerFunc),
        mw:       middlewares,
    }
}

// Register associates a message type with a handler function.
// Panics on duplicate registration (programmer error).
func (b *InMemoryBus) Register(msgType reflect.Type, handler HandlerFunc) {
    b.mu.Lock()
    defer b.mu.Unlock()
    if _, exists := b.handlers[msgType]; exists {
        panic(fmt.Sprintf("cqrs: duplicate handler for %s", msgType))
    }
    b.handlers[msgType] = handler
}

// Dispatch routes a message to its handler, applying middleware.
func (b *InMemoryBus) Dispatch(ctx context.Context, msg any) error {
    _, err := b.DispatchWithResult(ctx, msg)
    return err
}

// DispatchWithResult routes and returns the handler's result.
func (b *InMemoryBus) DispatchWithResult(ctx context.Context, msg any) (any, error) {
    b.mu.RLock()
    msgType := reflect.TypeOf(msg)
    handler, ok := b.handlers[msgType]
    b.mu.RUnlock()

    if !ok {
        return nil, fmt.Errorf("cqrs: no handler registered for %s", msgType)
    }

    // Apply middleware chain (outermost first).
    final := handler
    for i := len(b.mw) - 1; i >= 0; i-- {
        final = b.mw[i](final)
    }

    return final(ctx, msg)
}
```

### 3.3 Built-in Middleware

```go
// Logging middleware
func LoggingMiddleware(logger *slog.Logger) Middleware {
    return func(next HandlerFunc) HandlerFunc {
        return func(ctx context.Context, msg any) (any, error) {
            msgType := reflect.TypeOf(msg).Name()
            start := time.Now()
            result, err := next(ctx, msg)
            duration := time.Since(start)
            if err != nil {
                logger.Error("Bus dispatch failed", "type", msgType, "duration_ms", duration.Milliseconds(), "error", err)
            } else {
                logger.Debug("Bus dispatch OK", "type", msgType, "duration_ms", duration.Milliseconds())
            }
            return result, err
        }
    }
}

// Audit middleware (integrates with existing audit.Store)
func AuditMiddleware(auditStore *audit.Store) Middleware { ... }
```

### 3.4 Commands Returning Data (Trading Server Pattern)

For a trading server, commands frequently return data (order ID, trigger ID, etc.). The existing `CommandHandlerWithResult[C, R]` interface handles this. The `InMemoryBus.DispatchWithResult()` returns `(any, error)`, and callers type-assert the result:

```go
// In tool handler:
result, err := commandBus.DispatchWithResult(ctx, cmd)
if err != nil { return err }
orderID := result.(string) // PlaceOrderCommand returns string
```

This is pragmatic for a trading server where:
- `PlaceOrderCommand` -> `string` (order ID)
- `ModifyOrderCommand` -> `broker.OrderResponse`
- `CancelOrderCommand` -> `broker.OrderResponse`
- `PlaceGTTCommand` -> `broker.GTTResponse`
- `CreateAlertCommand` -> `string` (alert ID)

The type assertion is safe because command types are statically known at each call site.

---

## 4. New Commands/Queries Needed

### 4.1 Immediate Fixes (no new infrastructure needed)

These 2 tools already have use cases built but the tool handlers bypass them:

| Tool | Fix |
|------|-----|
| `get_order_trades` | Replace `session.Broker.GetOrderTrades(orderID)` with `GetOrderTradesUseCase.Execute(ctx, GetOrderTradesQuery{...})` |
| `get_quotes` | Replace `session.Broker.GetQuotes(instruments...)` with `GetQuotesUseCase.Execute(ctx, email, GetQuotesQuery{...})` |

### 4.2 New Command/Query Structs (17 for Kite-specific APIs)

```go
// commands.go additions:
type ConvertPositionCommand struct { ... }  // convert_position
type PlaceMFOrderCommand struct { ... }     // place_mf_order
type CancelMFOrderCommand struct { ... }    // cancel_mf_order
type PlaceMFSIPCommand struct { ... }       // place_mf_sip
type CancelMFSIPCommand struct { ... }      // cancel_mf_sip
type PlaceNativeAlertCommand struct { ... } // place_native_alert
type ModifyNativeAlertCommand struct { ... }// modify_native_alert
type DeleteNativeAlertCommand struct { ... }// delete_native_alert

// queries.go additions:
type GetMFOrdersQuery struct { Email string }
type GetMFSIPsQuery struct { Email string }
type GetMFHoldingsQuery struct { Email string }
type GetOrderMarginsQuery struct { ... }
type GetBasketMarginsQuery struct { ... }
type GetOrderChargesQuery struct { ... }
type GetNativeAlertsQuery struct { ... }
type GetNativeAlertHistoryQuery struct { ... }
```

### 4.3 New Use Cases (17)

Each new command/query needs a corresponding use case. These are thin wrappers (validate + resolve broker + call API + log) following the existing pattern in `kc/usecases/`.

---

## 5. Totals

| Category | Count |
|----------|-------|
| **Existing CQRS commands** | 10 (PlaceOrder, ModifyOrder, CancelOrder, PlaceGTT, ModifyGTT, DeleteGTT, CreateAlert, DeleteAlert, FreezeUser, UnfreezeUser) + 2 watchlist |
| **Existing CQRS queries** | 14 (GetPortfolio, GetHoldings, GetPositions, GetOrders, GetOrderHistory, GetTrades, GetLTP, GetOHLC, GetQuotes, GetOrderTrades, GetHistoricalData, GetMargins, GetProfile, GetGTTs, GetAlerts, GetAuditTrail) |
| **Existing use cases** | 23 |
| **New commands needed** | 9 (ConvertPosition, PlaceMFOrder, CancelMFOrder, PlaceMFSIP, CancelMFSIP, PlaceNativeAlert, ModifyNativeAlert, DeleteNativeAlert, + local store commands if desired) |
| **New queries needed** | 8 (GetMFOrders, GetMFSIPs, GetMFHoldings, GetOrderMargins, GetBasketMargins, GetOrderCharges, GetNativeAlerts, GetNativeAlertHistory) |
| **New use cases needed** | 17 |
| **Bus middleware** | 2 (logging, audit) |

---

## 6. Priority Fix Order

### Phase 1: Quick wins (2 tool handler fixes, 0 new code)
1. Fix `get_order_trades` handler to use existing `GetOrderTradesUseCase`
2. Fix `get_quotes` handler to use existing `GetQuotesUseCase`

### Phase 2: Bus infrastructure + convert_position
3. Implement `CommandBus` + `QueryBus` in `kc/cqrs/bus.go`
4. Add `ConvertPositionCommand` + `ConvertPositionUseCase` (requires `broker.Client` extension)
5. Wire existing use cases through bus

### Phase 3: Kite-specific APIs (blocked by broker.Client extension — Task #5)
6. Extend `broker.Client` with MF, margin, native alert, convert position methods
7. Add 17 new command/query structs
8. Add 17 new use cases
9. Reroute all 17 bypassing tools through bus

### Phase 4: Local store tools (optional, for consistency)
10. Create commands for watchlist, alert, trailing stop, paper trading operations
11. Route through bus for unified audit logging

### Phase 5: Admin & composite tools (lowest priority)
12. Admin tools through bus
13. Decompose `trading_context` and `pre_trade_check` into bus dispatches
