# Architecture

This document describes the current, as-built architecture of `kite-mcp-server`.
It is reality-based: where a pattern is only partially adopted or has known
exceptions, that is called out explicitly. For aspirational targets see the
fix plans under `.research/`.

## 1. High-level picture

```
                        ┌───────────────────────────────────────┐
                        │             MCP Clients               │
                        │  (Claude Desktop, claude.ai, Cowork,  │
                        │   Claude Code, mcp-remote, etc.)      │
                        └───────────────┬───────────────────────┘
                                        │ HTTP / SSE / stdio
                                        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                              app/  (composition root)                    │
│                                                                          │
│  app.go        App struct + Config + NewApp + RunServer (lifecycle)      │
│  wire.go       initializeServices(): builds Manager, MCP server,         │
│                registers middleware chain, wires event persistence       │
│  http.go       HTTP server setup, TLS, graceful shutdown                 │
│  routes.go     HTTP route registration (extracted from http.go)          │
│  adapters.go   small adapter structs (paperLTPAdapter, instruments       │
│                freeze adapter, briefing token/credential adapters, etc.) │
│  ratelimit.go  per-IP rate limiter for HTTP endpoints                    │
│  legal.go      /privacy, /terms, /security HTML pages                    │
└──────────────────────────────────────────────────────────────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
┌──────────────────┐         ┌──────────────────┐          ┌──────────────────┐
│     mcp/         │         │       kc/        │          │      oauth/      │
│  (adapter)       │         │  (application +  │          │  (auth adapter)  │
│                  │         │   domain core)   │          │                  │
│  tool registry   │         │                  │          │  OAuth2 server   │
│  tool handlers   │         │  Manager         │          │  for mcp-remote  │
│  middleware      │         │  Services        │          │  dynamic client  │
│  prompts         │         │  Use Cases       │          │  registration    │
│  UI widgets      │         │  Domain VOs      │          │  JWT tokens      │
└────────┬─────────┘         │  Stores (SQLite) │          └──────────────────┘
         │                   │  Sub-packages    │
         │                   └────────┬─────────┘
         │                            │
         │ depends on both            ▼
         │                   ┌──────────────────┐
         └──────────────────▶│    broker/       │
                             │    (port)        │
                             │                  │
                             │  Client (ISP     │
                             │    composite)    │
                             │  Factory         │
                             │  Authenticator   │
                             └────────┬─────────┘
                                      │ implemented by
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
             ┌──────────────────┐          ┌──────────────────┐
             │ broker/zerodha/  │          │  broker/mock/    │
             │ (adapter)        │          │  (adapter)       │
             │                  │          │                  │
             │ wraps            │          │ in-memory        │
             │ gokiteconnect    │          │ DEV_MODE + tests │
             └──────────────────┘          └──────────────────┘
```

Everything outside `broker/` speaks to brokers exclusively through
`broker.Client` — with the known exceptions listed in §9.

## 2. Directory layout

### Top-level

| Path | Responsibility |
|------|---------------|
| `main.go` | Entry point; parses env config, calls `app.NewApp(...).RunServer()` |
| `app/` | Composition root: config, wiring, HTTP server, middleware registration, lifecycle |
| `broker/` | Port: `Client` interface + types; broker-agnostic DTOs |
| `broker/zerodha/` | Zerodha adapter wrapping `github.com/zerodha/gokiteconnect/v4` |
| `broker/mock/` | In-memory mock broker used in DEV_MODE and tests |
| `kc/` | Application core: Manager, services, use cases, domain, stores |
| `mcp/` | MCP adapter: tool registry, handlers, middleware, prompts, inline widgets |
| `oauth/` | OAuth2 server for mcp-remote (dynamic client registration, JWT) |
| `cmd/` | Small helper binaries (e.g. rotate-key) |
| `testutil/` | Shared test infrastructure (`MockKiteServer`, kcfixture) |
| `docs/` | Architectural and operational documentation |
| `scripts/` | Build and deploy scripts |
| `plugins/` | Optional external plugin directory (hook registration) |

### `kc/` sub-packages

| Path | Responsibility |
|------|---------------|
| `kc/domain/` | Value Objects (`Money`, `Quantity`, `InstrumentKey`), `Spec[T]` and concrete specs, domain events and dispatcher, glossary |
| `kc/cqrs/` | Command/Query types, in-memory bus with reflect-based routing, handler interfaces |
| `kc/usecases/` | 28 use-case files; every write and most reads go through a use case |
| `kc/eventsourcing/` | Append-only `domain_events` SQLite table; aggregates (`Order`, `Position`, `Alert`) kept as verification infrastructure — events are NOT replayed for state reconstitution |
| `kc/riskguard/` | 8-check financial safety engine + middleware (kill switch, order/qty/daily caps, rate limit, duplicate, circuit breaker) |
| `kc/papertrading/` | Virtual portfolio, order interception middleware, LIMIT fill monitor |
| `kc/audit/` | Tool-call audit log (SQLite), middleware, HMAC hash chain, encrypted email |
| `kc/alerts/` | Alert store, evaluator, briefing service, Telegram notifier, trailing stop manager, P&L snapshot |
| `kc/billing/` | Stripe subscription store, billing middleware |
| `kc/users/` | User store, family/invitation store |
| `kc/registry/` | `registered_clients` store (OAuth client registrations) |
| `kc/ops/` | Dashboard and admin HTTP handlers, SSR renderers (split by page) |
| `kc/instruments/` | Instrument master download and in-memory index |
| `kc/scheduler/` | Cron scheduler for briefings, P&L snapshot, audit cleanup |
| `kc/ticker/` | WebSocket ticker service (per-user) |
| `kc/telegram/` | Telegram bot handler, trading commands |
| `kc/watchlist/` | Per-user watchlists |
| `kc/isttz/` | IST timezone helper |
| `kc/templates/` | HTML templates for status and landing pages |

### `app/` file breakdown (post-split)

| File | Role |
|------|------|
| `app.go` (~416 lines) | `App` struct, `Config`, `NewApp`, `RunServer`, helper HTML pages |
| `wire.go` (~398 lines) | `initializeServices`: builds Manager, registers middleware chain, wires event persisters, starts scheduler |
| `http.go` | HTTP server, TLS, graceful shutdown |
| `routes.go` | Route registration |
| `adapters.go` (~436 lines) | Bridging adapters (paperLTPAdapter, briefingTokenAdapter, briefingCredAdapter, instrumentsFreezeAdapter, kiteExchangerAdapter, etc.) |
| `ratelimit.go` | Per-IP rate limiter |
| `legal.go` | Static legal pages |
| `metrics/` | `metrics.Manager` for Prometheus-style counters |

## 3. Hexagonal architecture (Ports and Adapters)

**Port**: `broker.Client` in `broker/broker.go` — the single abstraction over
all broker operations. After the ISP refactor it is a **composite interface
embedding 9 focused sub-interfaces** with 0 direct methods. Sum = 31 methods.

| Sub-interface | Methods | Purpose |
|---------------|---------|---------|
| `BrokerIdentity` | 1 | `BrokerName()` |
| `ProfileReader` | 2 | `GetProfile`, `GetMargins` |
| `PortfolioReader` | 3 | `GetHoldings`, `GetPositions`, `GetTrades` |
| `OrderManager` | 6 | Get/Place/Modify/Cancel/History/Trades |
| `MarketDataReader` | 4 | `GetLTP`, `GetOHLC`, `GetQuotes`, `GetHistoricalData` |
| `GTTManager` | 4 | Get/Place/Modify/Delete GTT |
| `PositionConverter` | 1 | `ConvertPosition` |
| `MutualFundClient` | 7 | All MF order + SIP + holdings |
| `MarginCalculator` | 3 | Order margins, basket margins, charges |

Callers are free to narrow their dependency to the minimum sub-interface they
need (e.g. an LTP enricher can take `broker.MarketDataReader`). That narrowing
is not yet rolled out across all call sites — the interfaces exist; callers
mostly still depend on the composite.

**Optional capability sub-interfaces** live alongside the core port:
- `broker.NativeAlertCapable` — only Zerodha implements server-side alerts.
  Tool handlers check via type assertion: `if nac, ok := client.(broker.NativeAlertCapable); ok`.

**Factory**: `broker.Factory` (in `broker/broker.go`) creates `Client` instances
from credentials. `broker.Authenticator` handles the OAuth exchange lifecycle
(login URL, token exchange, invalidation).

**Adapters**:
- `broker/zerodha/` — implements `Client`, `Factory`, and `Authenticator` by
  wrapping `gokiteconnect/v4`. Conversions between Zerodha SDK types and
  broker-agnostic DTOs live in `broker/zerodha/convert.go`.
- `broker/mock/` — in-memory implementation used by DEV_MODE and most tests.
  Supports error injection and per-method stubs.

**Known SDK leaks**: **ZERO in production code.** Every prior leak has been
routed through `broker.Factory`. The only remaining direct `kiteconnect.New()`
call sites are:

- `kc/manager.go` — the default `KiteClientFactory.NewClientWithToken`. This
  IS the factory implementation; by design it is the one place allowed to
  construct a raw SDK client.
- `kc/kite_client.go` — `DefaultKiteClientFactory`, co-located with the
  factory interface.

Briefing, Telegram fallback, and OAuth exchange — formerly listed as leaks —
now all go through `broker.Factory`. See `.research/resume-phase2-metrics.md`
for the authoritative breakdown.

## 4. CQRS

**Bus**: `kc/cqrs/bus.go` — `InMemoryBus` with reflect.Type-based routing and
middleware support. Commands and queries are plain structs:

```go
// kc/cqrs/commands.go
type PlaceOrderCommand struct {
    Email           string
    Key             domain.InstrumentKey  // VO
    Qty             domain.Quantity       // VO
    Price           domain.Money          // VO
    TransactionType string
    OrderType       string
    Product         string
    Validity        string
    // ...
}
```

**Use cases** (in `kc/usecases/`, 28 files) consume these command/query types
and orchestrate: input validation via specs → riskguard → broker call → domain
event dispatch. Example:

> **What CQRS means here**: the request-object pattern — typed `Command`/`Query`
> DTOs with domain VOs that use cases consume. `kc/cqrs/bus.go` and
> `kc/cqrs/query_dispatcher.go` exist but are **not instantiated** anywhere in
> production wiring; there is no reflect-routed bus in the hot path. The DTOs
> themselves are the real value — they give the handler layer a stable,
> typed contract to the use case layer.

```
PlaceOrderUseCase.Execute(ctx, cmd):
    1. validate email
    2. domain.OrderSpec.IsSatisfiedBy(cmd)     // QuantitySpec + PriceSpec
    3. broker := brokerResolver.GetBrokerForEmail(email)
    4. broker.PlaceOrder(...)
    5. events.Dispatch(domain.OrderPlacedEvent{...})
    6. return orderID
```

**Coverage**: All write tools (place/modify/cancel order, GTTs, MF orders and
SIPs, alerts, watchlists, paper trading, trailing stops, close position,
convert position, admin operations) and all read tools (profile, holdings,
positions, orders, trades, LTP, OHLC, quotes, order history, GTTs, MF data)
route through use cases.

**Accepted direct broker reads** (not routed through a query):
- `mcp/common.go` — `session.Broker.GetProfile()` as token-validity probe
- `mcp/post_tools.go` — `GetOrderHistory()` after place_order for fill enrichment
- `mcp/trailing_tools.go` — `GetOrderHistory()` + `GetLTP()` for trailing stop setup
- `mcp/native_alert_tools.go` — via `NativeAlertCapable` type assertion
- `mcp/ext_apps.go` — widget data functions (4 calls) — treated as a separate
  presentation-adapter layer intentionally exempt from CQRS

## 5. Domain-Driven Design

**Value Objects** (`kc/domain/`):
- `Money` — INR with Indian number formatting
- `Quantity` — positive int, JSON marshal/unmarshal
- `InstrumentKey` — `exchange:tradingsymbol`

VOs are used in `cqrs` command types and flow from the MCP handler layer down
into use cases. Use cases currently extract raw primitives from VOs before
calling `broker.Client` (the broker port speaks primitives because that is
what the Kite API speaks). This is "practical DDD", not full hexagonal DDD.

**Specification pattern** (`kc/domain/spec.go`):
- Generic `Spec[T]` with `And`, `Or`, `Not` compositors
- Concrete: `QuantitySpec`, `PriceSpec`, `OrderSpec`
- Wired into `PlaceOrderUseCase` and `ModifyOrderUseCase` for invariant checks

**Domain events** (`kc/domain/events.go`):
- 13+ event types: `OrderPlacedEvent`, `OrderModifiedEvent`, `OrderCancelledEvent`,
  `OrderFilledEvent`, `PositionClosedEvent`, `PositionOpenedEvent`,
  `AlertCreatedEvent`, `AlertTriggeredEvent`, `AlertDeletedEvent`,
  `RiskLimitBreachedEvent`, `UserSuspendedEvent`, `UserFrozenEvent`,
  `GlobalFreezeEvent`, `FamilyInvitedEvent`, `SessionCreatedEvent`
- `EventDispatcher` is a typed pub/sub with string-keyed subscriptions
- Events are dispatched from use cases only (not from read handlers)

**Aggregates** (`kc/eventsourcing/`):
- `OrderAggregate`, `PositionAggregate`, `AlertAggregate` — use VOs internally
- Exist as **verification infrastructure** for replay-correctness tests; the
  package doc explicitly notes this is NOT production state reconstitution

**Not implemented / accepted trade-offs**:
- No repository pattern over broker data — Kite API is the authoritative store
  of record. A local `OrderRepository` would be a fiction.
- No rich aggregate behaviour in the write path — use cases orchestrate
  directly against `broker.Client`.

## 6. Middleware chain

Registered in `app/wire.go:initializeServices` in **execution order** (the
first item runs first on an incoming request, the last item runs immediately
before the tool handler). `mcp-go`'s `WithToolHandlerMiddleware` applies
registrations in reverse: the first registered call wraps the handler last,
so it ends up outermost — i.e. executed first. Read the list below as
"outermost → innermost", which is the same as "request-time execution order":

1. `mcp.CorrelationMiddleware()` — generates a UUID per tool call, injects into
   `context`. Used for cross-log correlation.
2. `mcp.TimeoutMiddleware(30*time.Second)` — cancels tool handlers that exceed
   30 seconds.
3. `audit.Middleware(auditStore)` — logs every tool call to SQLite `tool_calls`
   (buffered async writer; PII redacted; 5-year retention).
4. `mcp.HookMiddleware()` — runs registered before/after plugin hooks.
5. `mcp.NewCircuitBreaker(5, 30*time.Second).Middleware()` — 3-state
   (Closed/Open/HalfOpen) circuit breaker for Kite API failures.
6. `riskguard.Middleware(riskGuard)` — blocks orders that violate the 8
   safety checks (kill switch, per-order cap ₹5L, qty cap, 200/day count
   cap, 10/min rate limit, 30s duplicate window, ₹10L daily value cap,
   auto-freeze circuit breaker).
7. `mcp.NewToolRateLimiter(...).Middleware()` — per-tool rate limits
   (`place_order` 10/min, `cancel_order` 20/min, `place_gtt_order` 5/min, etc.).
8. `billing.Middleware(billingStore, adminEmailFn)` — Stripe tier enforcement
   (opt-in via `STRIPE_SECRET_KEY`; skipped in DEV_MODE).
9. `papertrading.Middleware(paperEngine)` — intercepts order tools when the
   user has paper mode enabled (opt-in per user).
10. `mcp.DashboardURLMiddleware(kcManager)` — appends `dashboard_url` hints to
    responses for tools that have a relevant dashboard page.

Elicitation (`server.WithElicitation()`) is enabled at server level so tools
can request user confirmation before destructive operations. It fails open on
clients that don't support it.

## 7. Event Sourcing (audit log)

Scope is **domain audit log**, not true event sourcing:

- Events are dispatched from use cases via `domain.EventDispatcher`
- `app/wire.go` creates an `eventsourcing.EventStore` over the shared SQLite
  DB and subscribes `makeEventPersister()` to each event name
- Events land in the append-only `domain_events` table; there is no UPDATE
  or DELETE path
- Aggregates in `kc/eventsourcing/` can replay events in tests to verify
  correctness, but production code path NEVER reads events to reconstitute
  state — Kite API is the system of record

The package doc in `kc/eventsourcing/` explicitly states this constraint.

## 8. Testing patterns

### `testutil/` — shared, importable (not `_test.go`)

- `testutil/kiteserver.go` — `MockKiteServer` wraps an `httptest.Server` that
  simulates the Kite Connect REST API. Tests configure responses via `Set*`
  methods and point a `kiteconnect.Client` at `server.URL`. Handles the
  gokiteconnect routing quirk where `GetLTP`, `GetOHLC`, and `GetQuotes` all
  hit `/quote`.
- `testutil/logger.go` — `NewTestLogger(t)` returns a `slog.Logger` that
  routes to `t.Log`.
- `testutil/kcfixture/` — preconfigured `kc.Manager` factories for integration
  tests that need a full services graph.

### Per-package helpers

- `kc/helpers_test.go`, `mcp/helpers_test.go`, `app/helpers_test.go` — package-
  local fixture builders (private, as they depend on unexported types)
- `kc/mocks_test.go`, `kc/usecases/mocks_test.go` — hand-written test doubles
  for `broker.Client`, `BrokerResolver`, stores, etc.

### Mock factories (test injection)

Two factory interfaces exist specifically so tests can inject fake clients
without hitting the network:

- `kc.KiteClientFactory` — returns `*kiteconnect.Client`. Set via
  `Manager.BrokerServices().SetKiteClientFactory(...)`. Tests point it at a
  `MockKiteServer`.
- `broker.Factory` — returns `broker.Client`. Allows injecting `broker/mock`
  without touching the SDK.

### Test categories in `mcp/`

- `tools_pure_test.go` — parameter parsing, validation, no network
- `tools_mockkite_test.go` — end-to-end via `MockKiteServer`
- `tools_devmode_test.go` — full stack with `broker/mock`
- `tools_session_test.go` — session lifecycle
- `tools_middleware_test.go` — middleware chain assembly
- `middleware_chain_test.go` — per-middleware behaviour
- `*_edge_test.go` — error paths, boundary conditions
- `*_property_test.go` — property-based tests (options Greeks, indicators)

### Known Windows test issue

Smart App Control (SAC) blocks unsigned test binaries written to `%TEMP%` for
`kc/cqrs`, `kc/eventsourcing`, `kc/riskguard`, and `kc/billing`. These pass
on Linux/CI and on Windows with SAC disabled. Not a code issue.

## 9. Dependency injection points

Every non-trivial collaborator has an injection seam. These are the nine most
important ones — everything below is set via constructor or `Set*` accessor
and exercised by at least one test.

| # | Seam | Interface | Default | Set via | Purpose |
|---|------|-----------|---------|---------|---------|
| 1 | Kite SDK client | `kc.KiteClientFactory` | `defaultKiteClientFactory` | `BrokerServices().SetKiteClientFactory(f)` | Point raw SDK at `MockKiteServer` in tests |
| 2 | Broker client | `broker.Factory` | `zerodha.Factory{}` | Registered in `kc.New()` via `SetBrokerFactory` | Swap broker adapter; inject `broker/mock` in DEV_MODE |
| 3 | Broker resolver | `usecases.BrokerResolver` | `SessionService` | Constructor argument to every use case | Use cases never touch sessions directly |
| 4 | Domain events | `*domain.EventDispatcher` | `domain.NewEventDispatcher()` | `Manager.SetEventDispatcher(d)` | Subscribe event persisters and ad-hoc listeners |
| 5 | Event store | `*eventsourcing.EventStore` | `NewEventStore(alertDB)` | `Manager.SetEventStore(es)` | Append-only audit persistence |
| 6 | RiskGuard | `*riskguard.Guard` | `riskguard.NewGuard(logger)` | `Manager.SetRiskGuard(g)` | Order-placement safety middleware |
| 7 | Paper engine | `*papertrading.PaperEngine` | `papertrading.NewEngine(store, logger)` | `Manager.SetPaperEngine(e)` | Opt-in virtual trading interception |
| 8 | Billing store | `*billing.Store` | `billing.NewStore(alertDB, logger)` | `Manager.SetBillingStore(bs)` | Stripe tier gate (conditional) |
| 9 | Notification | `*alerts.TelegramNotifier` | created in `kc.New` if `TELEGRAM_BOT_TOKEN` set | constructor | Alert notifications + trading commands |

Supporting seams (wired similarly but less central): `AuditStore`,
`InvitationStore`, `FamilyService`, `PnLService`, `MCPServer`, `LTPProvider`
for paper trading, `FreezeQuantityLookup` for riskguard, `AutoFreezeNotifier`.

The 9 primary seams are all mockable and are exercised by tests under
`kc/usecases/`, `mcp/`, `app/`, and `testutil/kcfixture/`.

## 10. Manager as service locator (known wart)

`kc.Manager` still holds ~25 fields and exposes ~90 accessor methods. Services
have been extracted (`SessionService`, `CredentialService`, `PortfolioService`,
`OrderService`, `AlertService`, `FamilyService`, `BrokerServices`), but tool
handlers still receive `*kc.Manager` and call `manager.X()` to reach
collaborators.

`mcp/common.go` has `ToolHandlerDeps` as a first step toward narrower handler
dependencies, but most tool handlers still pull from `*Manager` directly.
Fully replacing this is tracked as "service locator reduction" in the phase
plans; it is a large refactor that is not blocking any feature work.

The `StoreAccessor` composite interface in `kc/manager_interfaces.go` has been
split into **20** single-method `*Provider` interfaces, so consumers **can**
depend on exactly the accessor they need. In practice only **4** of these
are actually consumed at call sites today:

- `SessionProvider`
- `CredentialResolver`
- `MetricsRecorder`
- `AppConfigProvider`

The other 16 are **defined but unused** — textbook Interface Segregation
theater: the split happened, nothing was migrated onto the narrowed types.
Treat the extras as a pool that new code can pull from, not as a finished
migration.

## 11. How to add a new MCP tool

1. **Define the tool struct** in the appropriate file under `mcp/`
   (e.g. `mcp/post_tools.go` for order mutations). Implement the `mcp.Tool`
   interface:

   ```go
   type MyNewTool struct{}

   func (*MyNewTool) Tool() gomcp.Tool {
       return gomcp.NewTool("my_new_tool",
           gomcp.WithDescription("..."),
           gomcp.WithString("param1", gomcp.Required()),
           // ... tool annotations (readOnlyHint, destructiveHint, etc.)
       )
   }

   func (*MyNewTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
       return func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
           // 1. Extract + validate params (see mcp/common.go helpers)
           // 2. Build a CQRS command/query struct with VOs
           // 3. Resolve the use case from manager (or from deps) and Execute()
           // 4. Marshal response via MarshalResponse (preserves structuredContent)
       }
   }
   ```

2. **Create a use case** in `kc/usecases/` if one does not already exist for
   the operation. Use cases depend on `BrokerResolver`, not on `Manager`.

3. **Add command/query type** in `kc/cqrs/commands.go` or `queries.go` using
   domain VOs (`domain.Money`, `domain.Quantity`, `domain.InstrumentKey`) where
   applicable.

4. **Register the tool** by adding `&MyNewTool{}` to the `builtIn` slice in
   `mcp/mcp.go:GetAllTools()`. Place it in the correct group (setup, read,
   write, market data, etc.) — the grouping is cosmetic but maintained.

5. **Add tool annotations**: set `Title`, `ReadOnlyHint`, `DestructiveHint`,
   `IdempotentHint`, `OpenWorldHint` on the `gomcp.Tool`. Required for all 60+
   existing tools.

6. **Elicitation** (if destructive): call `elicit.RequestConfirmation(ctx, ...)`
   in the handler before the broker call. Fails open on older clients.

7. **Write tests** in the same directory using one of:
   - `tools_pure_test.go` — param parsing/validation
   - `tools_mockkite_test.go` — end-to-end via `testutil.MockKiteServer`
   - `tools_devmode_test.go` — full stack via `broker/mock`

8. **Structured content**: `MarshalResponse` already emits `structuredContent`
   alongside the text — no extra work needed, just return a typed struct.

## 12. How to add a new broker

1. **Create the adapter package**: `broker/<name>/client.go`. Implement
   `broker.Client` — the compile-time check
   `var _ broker.Client = (*Client)(nil)` will tell you what's missing.

2. **Convert types** in `broker/<name>/convert.go`: every method that returns
   SDK-specific types must translate to the broker-agnostic DTOs in
   `broker/broker.go` (`Profile`, `Holding`, `Position`, `Order`, `Trade`,
   `Quote`, `OHLC`, `GTT`, MF types, margin types, etc.).

3. **Implement the factory and authenticator** in `broker/<name>/factory.go`:

   ```go
   type Factory struct{}

   func (Factory) Create(apiKey string) (broker.Client, error) { ... }
   func (Factory) CreateWithToken(apiKey, token string) (broker.Client, error) { ... }
   func (Factory) BrokerName() broker.Name { return broker.MyBroker }

   type Authenticator struct{}

   func (Authenticator) GetLoginURL(apiKey string) string { ... }
   func (Authenticator) ExchangeToken(apiKey, apiSecret, requestToken string) (broker.AuthResult, error) { ... }
   func (Authenticator) InvalidateToken(apiKey, accessToken string) error { ... }
   ```

4. **Add the broker Name constant** to `broker/broker.go`:
   `const MyBroker Name = "mybroker"`.

5. **Optional capabilities**: if the broker supports native alerts or any
   other optional feature, also implement the relevant sub-interface
   (`broker.NativeAlertCapable`, etc.). Tool handlers that use that feature
   type-assert and gracefully degrade when not supported.

6. **Wire it into `kc.New`**: register the factory and authenticator with the
   session service so credential-based client creation picks the right adapter.

7. **Tests**: `broker/<name>/client_test.go` should use `testutil.MockKiteServer`
   (or a broker-specific mock server) to exercise every method in the
   interface. Both `broker/zerodha/` and `broker/mock/` follow this pattern.

8. **Accept that Kite-specific plumbing still exists** in `kc/` (briefing
   service, Telegram bot fallback, OAuth exchanger adapter). See §3.
   Retrofitting those is a separate piece of work.

## 13. Not implemented / known gaps

Documented honestly so future work has a clean starting point:

- **Manager decomposition**: still a service locator with ~25 fields. 7
  sub-services extracted; rest remains. No ETA.
- **Plugin system**: only the hook middleware exists. No dynamic loading, no
  sandboxing, no marketplace. External plugins live in
  `~/.claude/plugins/local/kite-trading/` and are registered manually.
- **Multi-broker**: `broker.Factory` + `Authenticator` + 9 sub-interfaces make
  it feasible, but only `broker/zerodha/` and `broker/mock/` exist. No second
  real broker has been written.
- **Notification abstraction**: `alerts.TelegramNotifier` is still a concrete
  type. A `notification.Service` interface is proposed in
  `.research/hexagonal-fix-plan.md` but not yet implemented.
- **Full DDD repositories**: accepted as not valuable given Kite API is the
  authoritative store.
- **SDK leaks** listed in §3 still exist.
- **Remaining large files** (at the time of writing): `kc/ops/user_render.go`
  (158 lines — split complete), `mcp/ext_apps.go` (682 lines), `kc/manager.go`
  (728 lines). Tracked under phase 2/4 tasks.

## 13a. Known Production Issues

Surfaced by the error-handling audit in `.research/resume-error-audit.md`.
Three HIGH-severity issues were identified in `app/wire.go` + `kc/audit/`:

- **H1 — Audit store init failure starts the server silently unlogged.**
  `app/wire.go` logs the error from `auditStore.InitTable()` but leaves
  `auditMiddleware` nil, so every subsequent tool call proceeds without an
  audit trail. Compliance gap (SEBI/regulatory audit trail silently off).
- **H2 — Risk-limit load failure trades with defaults.**
  `app/wire.go` logs errors from `riskGuard.InitTable()` / `LoadLimits()` but
  continues. User-configured kill switches and daily caps are silently
  replaced by in-memory defaults.
- **H3 — Audit buffer fallback silently drops entries.**
  `kc/audit/store.go` `Enqueue` swallows the synchronous `Record` error when
  the worker hasn't started, and its buffer-full branch only `Warn`-logs a
  drop. Audit records are lost with no metric.

See `.research/resume-error-audit.md` for the full write-up and remediation
status (phase 2i task).

## 14. Further reading

The `.research/` directory contains the accumulated detail behind every
decision in this document:

- `resume-phase2-metrics.md` — **authoritative** current-state metrics
  (SDK leak count, use-case file count, Provider interface consumption,
  large-file line counts). Supersedes older scorecards.
- `final-arch-verification.md` — post-refactor scorecard (95.6% overall).
  **Stale**; kept for history. Prefer `resume-phase2-metrics.md`.
- `arch-reaudit.md` — full scorecard with per-pattern gap analysis
- `hexagonal-fix-plan.md` — complete migration plan, including Factory and
  Authenticator design
- `broker-isp.md` — 9 sub-interface split of `broker.Client`
- `store-accessor-split.md` — 18-provider split of `StoreAccessor`
- `cqrs-fix-plan.md` — CQRS bus and use case migration
- `ddd-es-fix-plan.md` — VO wiring and event sourcing scoping
- `integration-verification.md` — build, vet, and test status across packages
- `phase1-stabilize.md` through `phase2a-storeaccessor.md` — phase-by-phase
  work logs
