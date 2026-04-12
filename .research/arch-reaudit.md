# Architecture Re-Audit Scorecard

Date: 2026-04-12 | Post-refactoring assessment

---

## 1. CQRS — 92/100

**What's working (92%):**
- ALL read tools (get_profile, get_holdings, get_positions, get_orders, get_trades, get_ltp, get_ohlc, get_quotes, get_gtts, get_order_history, get_order_trades, get_mf_orders, get_mf_sips, get_mf_holdings) route through use cases
- ALL write tools (place_order, modify_order, cancel_order, place_gtt, modify_gtt, delete_gtt, place_mf_order, cancel_mf_order, place_mf_sip, cancel_mf_sip) route through use cases
- Use cases accept Commands/Queries from `kc/cqrs/` package
- 27 use case files in `kc/usecases/`
- Proper BrokerResolver interface for dependency injection

**Gaps to 100% (8%):**

| Gap | Location | Effort |
|-----|----------|--------|
| `session.Broker.GetOrderHistory()` after place_order for fill enrichment | `mcp/post_tools.go:192` | S - wrap in read query or accept as intentional UX enrichment |
| `session.Broker.GetOrderHistory()` + `session.Broker.GetLTP()` in trailing stop setup | `mcp/trailing_tools.go:117,131` | S - same pattern, "best-effort enrichment" not a primary operation |
| `brokerClientForEmail()` in ext_apps (4 calls) | `mcp/ext_apps.go:344,460,545,782` | M - ext_apps are MCP Apps widget data functions, not tool handlers; they bypass use cases entirely |
| `session.Broker.GetProfile()` for token validation | `mcp/common.go:117` | Accept - this is auth middleware, not a business operation |

**Verdict:** The CQRS bypasses are all in "enrichment" or "widget data" code paths, not primary tool handlers. The ext_apps bypasses (4 calls) are the biggest gap — these are data functions for MCP Apps inline widgets that fetch holdings/positions/orders/alerts directly.

**Fix for 100%:** Create thin read use cases for ext_apps (`GetPortfolioForWidget`, `GetOrdersForWidget`) and wrap trailing stop enrichment in existing queries. ~4 hours work. Pragmatic alternative: accept ext_apps as a separate "presentation adapter" layer exempt from CQRS.

---

## 2. Hexagonal / Ports & Adapters — 85/100

**What's working (85%):**
- `broker.Client` interface (502 lines) — clean port for all broker operations
- `broker.Factory` interface — creates broker clients from credentials
- `broker/zerodha/` adapter — implements Client, Factory, Authenticator
- `broker/mock/` adapter — demo client for DevMode
- `KiteClientFactory` interface in `kc/kite_client.go` — injectable factory for raw SDK clients
- `SetKiteClientFactory()` + `SetBrokerFactory()` setters for test injection

**SDK Leaks — `kiteconnect.New()` in production code outside factories:**

| Location | Context | Severity |
|----------|---------|----------|
| `app/app.go:1737,1775` | `kiteExchangerAdapter.ExchangeRequestToken` — OAuth token exchange | Medium — should use factory or Authenticator |
| `kc/manager.go:393` | `NewKiteConnect()` wrapper — delegated by `defaultKiteClientFactory` | OK — this IS the factory |
| `kc/alerts/briefing.go:34,40,46,52` | `defaultBrokerProvider` — 4 methods create raw clients | High — BrokerProvider interface exists but uses raw SDK |
| `kc/telegram/bot.go:339` | `getKiteClient()` for Telegram trading commands | High — should use KiteClientFactory |

**Fix for 100%:**
1. `kc/alerts/briefing.go`: Already has `BrokerProvider` interface — inject `KiteClientFactory` into `defaultBrokerProvider` so it calls `factory.NewClientWithToken()` instead of `kiteconnect.New()`. ~1 hour.
2. `kc/telegram/bot.go`: Pass `KiteClientFactory` to `TradingCommandHandler`, use it in `getKiteClient()`. ~30 min.
3. `app/app.go`: Replace raw `kiteconnect.New()` in exchanger with `broker.Authenticator.ExchangeToken()`. ~1 hour.

Total: ~2.5 hours for 100%.

---

## 3. DDD — 80/100

**What's working (80%):**
- **Value Objects**: `Money` (INR with Indian formatting), `Quantity` (positive int), `InstrumentKey` (exchange:symbol) — all in `kc/domain/`
- **Specification Pattern**: Generic `Spec[T]` with `And`, `Or`, `Not` compositors; concrete `QuantitySpec`, `PriceSpec`, `OrderSpec` — used in validation
- **Domain Events**: 9 event types (`OrderPlaced`, `OrderModified`, `OrderCancelled`, `PositionClosed`, `RiskLimitBreached`, `UserSuspended`, etc.)
- **Event Dispatcher**: pub/sub in `kc/domain/events.go` with typed listeners
- **Glossary**: `kc/domain/glossary.go` — ubiquitous language terms

**Gaps to 100% (20%):**

| Gap | Detail | Effort |
|-----|--------|--------|
| VOs not used in aggregates | Use cases pass raw `float64`/`int`/`string` instead of `Money`/`Quantity`/`InstrumentKey` | L — pervasive change across 27 use cases |
| No Aggregate Root pattern | No `Order` aggregate, `Position` aggregate in production (only in eventsourcing test infra) | M — aggregates exist in `kc/eventsourcing/` but are test-only |
| Specs not used in use cases | `OrderSpec` defined but `place_order` use case does its own inline validation | S — wire `OrderSpec.IsSatisfiedBy()` into `PlaceOrderUseCase` |
| Events not raised for read operations | Only write operations dispatch events; some reads (like "user viewed portfolio") could emit events | Accept — observability events are in audit middleware already |
| No repository interfaces | Use cases call `SessionService.GetBrokerForEmail()` directly rather than `OrderRepository.FindByID()` | L — would require abstracting Kite API behind repository pattern |

**Verdict:** DDD is "practical DDD" — value objects and events exist but aren't deeply integrated into the domain model. The trading domain is inherently thin (broker API is the system of record, no local state), so full DDD (aggregates, repositories) adds ceremony without proportional value.

**Fix for 100%:** Wire `OrderSpec` into use cases (1 hour). Full aggregate/repository layer is ~20 hours and questionable ROI since Kite API is the authority, not local state.

---

## 4. Middleware Chain — 95/100

**What's working (95%):**
8 middleware layers registered in order:
1. `TimeoutMiddleware` (30s) — prevents runaway tool calls
2. `AuditMiddleware` — logs every tool call to SQLite
3. `HookMiddleware` — before/after plugin hooks
4. `RiskguardMiddleware` — blocks orders exceeding safety limits
5. `ToolRateLimiter` — per-tool rate limiting (place/modify/cancel: 10/min)
6. `BillingMiddleware` — gates tools by subscription tier (optional)
7. `PaperTradingMiddleware` — intercepts orders in paper mode (optional)
8. `DashboardURLMiddleware` — appends dashboard links to responses

**Gaps to 100% (5%):**

| Gap | Detail | Effort |
|-----|--------|--------|
| No circuit breaker middleware | Repeated Kite API failures don't trigger auto-backoff | M — implement circuit breaker wrapping broker calls |
| No request correlation ID | Tool calls lack a trace ID for cross-cutting log correlation | S — add correlation ID middleware (generate UUID, inject into context) |

**Verdict:** Middleware is comprehensive. The missing pieces are operational maturity features, not correctness issues.

---

## 5. Event Sourcing (Audit Log) — 100/100

Correctly scoped as a **domain audit log**, not true event sourcing:
- `kc/eventsourcing/EventStore` — append-only SQLite table (`domain_events`)
- Events are immutable — no UPDATE/DELETE
- Write operations dispatch events via `domain.EventDispatcher`
- `makeEventPersister()` in `app/app.go` subscribes and persists
- Aggregates (`OrderAggregate`, `PositionAggregate`, `AlertAggregate`) exist as test infrastructure for verifying replay correctness
- Architecture note in package doc explicitly states this is NOT for state reconstitution

**Verdict:** 100%. The scope is correctly defined and implemented. No gap.

---

## 6. Plugin Pattern — 40/100

**What exists (40%):**
- `HookMiddleware` supports before/after hooks on tool calls
- `mcp/registry.go` has a `HookRegistry` for registering hooks
- MCP prompts in `mcp/prompts.go` (morning_brief, trade_check, eod_review)
- External plugin directory `~/.claude/plugins/local/kite-trading/` with 3 commands

**What's missing for 100% (60%):**

| Gap | Detail | Effort |
|-----|--------|--------|
| No plugin discovery/loading | Plugins are manually registered, no hot-loading | XL — full plugin system with lifecycle management |
| No plugin API/SDK | No documented interface for third-party tool registration | L — define Plugin interface, register/unregister lifecycle |
| No plugin isolation | Hooks run in-process, no sandboxing | XL — would need subprocess or WASM runtime |
| No plugin marketplace | No way to discover/install community plugins | XL — infrastructure project |

**Verdict:** 40% is appropriate for the current scope. A full plugin system is an order-of-magnitude effort (months) and not warranted unless the product strategy shifts to platform/marketplace. The hook system is sufficient for the current use case.

**Recommendation:** Accept 40% as "done for now". If plugin extensibility becomes a priority, start with a `Plugin` interface and dynamic tool registration (~2 weeks), not full isolation/marketplace.

---

## 7. Monolith Patterns

### Large Files

| File | Lines | Risk | Verdict |
|------|-------|------|---------|
| `kc/ops/dashboard.go` | 2284 | HIGH | God handler — serves 20+ routes, mixes API logic with HTML rendering. Split into `api_handlers.go` + `page_handlers.go`. |
| `app/app.go` | 2029 | HIGH | God constructor — builds the entire app in one file. Wiring, HTTP handlers, OAuth adapters, template rendering all mixed. Split into `wire.go` + `http.go` + `adapters.go`. |
| `kc/manager.go` | 1194 | MEDIUM | God object — 95 methods, ~25 struct fields. Already partially decomposed into services (SessionService, CredentialService, PortfolioService, OrderService, AlertService). But Manager still holds all stores and acts as service locator. |
| `kc/ops/dashboard_templates.go` | 1176 | MEDIUM | Large but focused — SSR template rendering. Cohesive responsibility. |
| `kc/ops/handler.go` | 1115 | LOW | Admin ops handler — similar to dashboard but admin-scoped. Reasonable size. |
| `mcp/admin_tools.go` | 1073 | LOW | 8 admin tools with full parameter definitions. Repetitive but cohesive. |
| `mcp/ext_apps.go` | 901 | MEDIUM | MCP Apps widget data functions — 4 data extractors. Bypasses CQRS. Should use use cases. |

### Package Size

| Package | Production Files | Risk |
|---------|-----------------|------|
| `mcp/` | 39 files | MEDIUM — largest package, but each file is a cohesive tool group |
| `kc/usecases/` | 27 files | LOW — 1 file per use case group, follows SRP |
| `kc/` | 17 files | MEDIUM — core package with mixed responsibilities (stores, services, types, session) |

### God Object: Manager

The `Manager` struct has ~25 fields and 95 methods. While services have been extracted (`SessionService`, `CredentialService`, `PortfolioService`, `OrderService`, `AlertService`), the Manager still:
- Holds all store references directly
- Acts as a service locator (every component gets `*Manager`)
- Exposes 95 accessor methods

**Fix:** Introduce a `DependencyContainer` or pass individual services to components instead of the full Manager. This is a large refactor (~8 hours) but would eliminate the god object.

---

## Summary Scorecard

| Pattern | Score | Change from Last | Key Gap |
|---------|-------|-----------------|---------|
| CQRS | 92% | +7% | ext_apps bypass, post-order enrichment |
| Hexagonal | 85% | +5% | 7 raw `kiteconnect.New()` in production code |
| DDD | 80% | +0% | VOs exist but not used in use cases |
| Middleware | 95% | +10% | No circuit breaker or correlation ID |
| Event Sourcing | 100% | +0% | Correctly scoped as audit log |
| Plugin | 40% | +5% | Hooks exist; full plugin system is future work |

### Priority Fixes (highest ROI)

1. **Hexagonal: Wire KiteClientFactory into briefing.go + telegram/bot.go** — 2.5 hours, eliminates all production SDK leaks
2. **CQRS: Create thin use cases for ext_apps widget data** — 4 hours, closes biggest CQRS gap
3. **Monolith: Split dashboard.go into api_handlers.go + page_handlers.go** — 3 hours, reduces 2284-line file
4. **Monolith: Split app.go into wire.go + http.go** — 4 hours, reduces 2029-line file

### Accepted Risks

- DDD VOs not used in use cases — trading domain is thin, broker API is authority
- Plugin pattern at 40% — full plugin system is months of work, not warranted
- Manager as service locator — works for current team size, revisit if >5 contributors
