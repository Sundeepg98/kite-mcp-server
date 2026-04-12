# Feature Inventory — Kite MCP Server

Verified from source on 2026-04-12. Counts reflect current `D:\kite-mcp-temp` tree, not prior agent claims.

---

## 1. MCP Tools (94 production tools)

Count (re-verified 2026-04-12): `NewTool("<name>"` in `mcp/*.go` excluding `*_test.go` → **94 occurrences, 94 unique tool names**, all in production files. `test_tool` exists ONLY in `tools_pure_test.go` and `ext_apps_test.go`, so it is not a production tool and was never part of the 94. Previous "93" figure subtracted test_tool by mistake.

### Market data / quotes (6)
| Tool | File |
|---|---|
| `get_quotes` | mcp/market_tools.go:23 |
| `search_instruments` | mcp/market_tools.go:73 |
| `get_historical_data` | mcp/market_tools.go:186 |
| `get_ltp` | mcp/market_tools.go:275 |
| `get_ohlc` | mcp/market_tools.go:331 |
| `get_option_chain` | mcp/option_tools.go:21 |

### Read tools / account (10)
`get_profile`, `get_margins`, `get_holdings`, `get_positions`, `get_trades`, `get_orders`, `get_gtts`, `get_order_trades`, `get_order_history`, `get_pnl_journal` (get_tools.go, pnl_tools.go)

### Order / GTT writes (7)
`place_order`, `modify_order`, `cancel_order`, `place_gtt_order`, `modify_gtt_order`, `delete_gtt_order`, `convert_position` (post_tools.go)

### Exit helpers (2)
`close_position`, `close_all_positions` (exit_tools.go)

### Trailing stops (3)
`set_trailing_stop`, `list_trailing_stops`, `cancel_trailing_stop` (trailing_tools.go)

### Pre-trade / margin / charges (4)
`pre_trade_check`, `get_order_margins`, `get_basket_margins`, `get_order_charges` (pretrade_tool.go, margin_tools.go)

### Mutual funds (7)
`get_mf_orders`, `get_mf_sips`, `get_mf_holdings`, `place_mf_order`, `cancel_mf_order`, `place_mf_sip`, `cancel_mf_sip` (mf_tools.go)

### Alerts — app-managed (4) + native Kite (5)
App: `setup_telegram`, `set_alert`, `list_alerts`, `delete_alert` (alert_tools.go)
Native: `place_native_alert`, `list_native_alerts`, `modify_native_alert`, `delete_native_alert`, `get_native_alert_history` (native_alert_tools.go)

### Watchlists (6)
`create_watchlist`, `delete_watchlist`, `add_to_watchlist`, `remove_from_watchlist`, `get_watchlist`, `list_watchlists` (watchlist_tools.go)

### Ticker (5)
`start_ticker`, `stop_ticker`, `ticker_status`, `subscribe_instruments`, `unsubscribe_instruments` (ticker_tools.go)

### Paper trading (3)
`paper_trading_toggle`, `paper_trading_status`, `paper_trading_reset` (paper_tools.go)

### Analytics / portfolio (6)
`portfolio_summary`, `portfolio_concentration`, `position_analysis` (analytics_tools.go), `portfolio_rebalance` (rebalance_tool.go), `sector_exposure` (sector_tool.go), `tax_harvest_analysis` (tax_tools.go)

### Technical / indicators / options / backtest (5)
`technical_indicators` (indicators_tool.go), `options_greeks`, `options_strategy` (options_greeks_tool.go), `backtest_strategy` (backtest_tool.go), `dividend_calendar` (dividend_tool.go)

### Admin — users (5)
`admin_list_users`, `admin_get_user`, `admin_suspend_user`, `admin_activate_user`, `admin_change_role` (admin_user_tools.go)

### Admin — risk (5)
`admin_get_risk_status`, `admin_freeze_user`, `admin_unfreeze_user`, `admin_freeze_global`, `admin_unfreeze_global` (admin_risk_tools.go)

### Admin — family (3)
`admin_invite_family_member`, `admin_list_family`, `admin_remove_family_member` (admin_family_tools.go)

### Admin — server / observability / compliance (3)
`admin_server_status` (admin_server_tools.go), `server_metrics` (observability_tool.go), `sebi_compliance_status` (compliance_tool.go)

### Setup / session / self-service (5)
`login`, `open_dashboard` (setup_tools.go), `trading_context` (context_tool.go), `delete_my_account`, `update_my_credentials` (account_tools.go)

**Total: 94 distinct production tools.** (6+10+7+2+3+4+7+4+5+6+5+3+6+5+5+5+3+3+5 = 94 across the 19 groups above.)

---

## 2. Middleware Chain

Registration order in `app/wire.go` (L181–263). Every tool call flows through this chain:

| # | Middleware | Source | Purpose |
|---|---|---|---|
| 1 | `CorrelationMiddleware` | mcp/correlation_middleware.go | UUID per call, injected into ctx |
| 2 | `TimeoutMiddleware(30s)` | mcp/timeout_middleware.go | Kills runaway tools |
| 3 | `audit.Middleware` | kc/audit | Async logging to `tool_calls` SQLite table |
| 4 | `HookMiddleware` | mcp/registry.go | Before/after plugin hooks |
| 5 | `CircuitBreaker(5,30s).Middleware` | mcp/circuitbreaker_middleware.go | 3-state broker-failure guard |
| 6 | `riskguard.Middleware` | kc/riskguard | 8 pre-trade safety checks |
| 7 | `ToolRateLimiter.Middleware` | mcp/ratelimit_middleware.go | Per-tool limits (place/modify/cancel 10/min) |
| 8 | `billing.Middleware` (opt) | kc/billing | Tier gating (when billingStore present) |
| 9 | `papertrading.Middleware` (opt) | kc/papertrading | Intercepts orders in paper mode |
| 10 | `DashboardURLMiddleware` | mcp/... | Appends dashboard deep-links to responses |

10 layers wired. `wire.go:181,183,185,188,191,193,202,222,259,263`.

---

## 3. HTTP Endpoints

### OAuth / auth (app/http.go)
- `/callback` (Kite + browser callbacks)
- `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`
- `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/email-lookup`
- `/auth/login`, `/auth/browser-login`, `/auth/admin-login`
- `/auth/google/login`, `/auth/google/callback`
- `/auth/accept-invite`

### MCP transports
- `/mcp` (streamable HTTP; rate-limited + RequireAuth)
- `/sse`, `/message` (SSE transport)

### Dashboard (kc/ops/dashboard.go RegisterRoutes)
Pages: `/dashboard`, `/dashboard/activity`, `/dashboard/orders`, `/dashboard/alerts`, `/dashboard/safety`, `/dashboard/paper`, `/dashboard/billing`
APIs: `/dashboard/api/activity`, `/activity/stream` (SSE), `/activity/export`, `/orders`, `/portfolio`, `/alerts`, `/alerts-enriched`, `/pnl-chart`, `/order-attribution`, `/status`, `/market-indices`, `/safety/status`, `/paper/status`, `/paper/holdings`, `/paper/positions`, `/paper/orders`, `/paper/reset`, `/portfolio-fragment`, `/safety-fragment`, `/paper-fragment`, `/sector-exposure`, `/tax-analysis`, `/account/delete`, `/account/credentials`

### Ops / admin
- `/admin/` (metrics admin handler)

### Webhooks
- `/webhooks/stripe` (billing, when enabled)
- Telegram webhook (path derived from bot token)

### Misc
- `/healthz`, `/favicon.ico`, `/robots.txt`
- `/pricing`, `/checkout/success`, `/billing/checkout`, `/stripe-portal`
- `/terms`, `/privacy`, `/` (landing)
- `/.well-known/security.txt`, `/.well-known/mcp/server-card.json`
- `/static/dashboard-base.css`
- `/debug/pprof/*` (when enabled)

---

## 4. Background Services

| Service | Started from | Notes |
|---|---|---|
| `sched.Start()` | app/wire.go:395 | kc/scheduler — morning brief, daily P&L, retention cleanup |
| `paperMonitor.Start()` | app/wire.go:297 | kc/papertrading — LIMIT fill monitor |
| Rate-limiter cleanup ticker | app/wire.go:244 (injected `cleanupInterval`) | Evicts stale per-IP limiters |
| Instruments refresh | kc/instruments (5-min ticker) | Dump refresh from api.kite.trade |
| Ticker service | kc/ticker (on-demand via start_ticker) | WebSocket stream |
| Briefing service | kc/alerts briefing package | Morning brief + EOD briefing (scheduler-driven) |
| Domain event persister | `makeEventPersister` subscriber (per ARCHITECTURE.md) | Drains domain events to `domain_events` table |

---

## 5. Domain Events

From `kc/domain/events.go` — **15 event types** (count verified by `grep -c "^type \w*Event struct"`):

OrderPlacedEvent, OrderModifiedEvent, OrderCancelledEvent, OrderFilledEvent, PositionOpenedEvent, PositionClosedEvent, AlertCreatedEvent, AlertTriggeredEvent, AlertDeletedEvent, RiskLimitBreachedEvent, SessionCreatedEvent, UserFrozenEvent, UserSuspendedEvent, GlobalFreezeEvent, FamilyInvitedEvent.

Dispatched via `kc/domain/events.go` typed dispatcher; persisted asynchronously via the event-persister subscriber wired in `app/wire.go` / `app/adapters.go`.

---

## 6. Per-Tool Architecture Coverage (qualitative, from arch-reaudit + final-arch-verification)

| Dimension | Status |
|---|---|
| Use-case routing | ALL write tools (place/modify/cancel/gtt/position/mf) go through `kc/usecases/*`. Read tools route through use cases except 4 `session.Broker.*` enrichment calls in `post_tools.go`, `trailing_tools.go`, `common.go`, and widget data functions in `ext_apps.go` (documented acceptable gaps). |
| SDK abstraction | All tool handlers consume `broker.Client`. Remaining `kiteconnect.New()` leaks in production: `kc/manager.go:393`, `kc/alerts/briefing.go:44`, `kc/telegram/bot.go:355`, `app/app.go:1737,1775` (exchanger). |
| Middleware coverage | Every registered tool receives all 10 middleware layers (chain is global, not per-tool). |
| Tests | Multiple test files per tool group: `post_tools_test.go`-style tests, `tools_mockkite_test.go`, `tools_edge_test.go`, `tools_session_test.go`, `tools_pure_test.go`, `tools_broker_test.go`, `tools_devmode_test.go`, `tools_validation_test.go`, `tools_middleware_test.go`, `tools_ext_apps_test.go`. Tool-level pass/fail per-tool matrix NOT constructed here (would require Phase 2c's deeper audit). |

---

## 7. Summary Numbers

- **MCP tools**: 94
- **Middleware layers**: 10
- **HTTP route families**: ~50 distinct paths across auth / MCP / dashboard / ops / billing / landing / pprof
- **Background services**: 7 long-running (scheduler, paper monitor, ratelimit cleanup, instruments refresh, ticker, briefing, event persister)
- **Domain events**: 15 types
- **Use case files**: 27 (per arch-reaudit)
- **Production packages**: see final-100-report (root, app, app/metrics, broker/mock, broker/zerodha, cmd/rotate-key, kc + 14 kc subpackages, mcp, oauth, plugins/example)

This inventory supersedes tool-count claims in earlier research docs (which cited "~60", "~80", "40 tools" at various points). The ground-truth count from source as of this scan is **94**.
