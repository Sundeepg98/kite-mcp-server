<!-- secret-scan-allow: research-doc-with-file-line-citations -->
---
title: Algo2Go Architectural Patterns — Canonical Decision Record
as-of: 2026-05-16
re-verify-by: 2026-08-16
master-head-at-write:
  kite-mcp-server: 03a3c35
  kite-mcp-bootstrap: 1d66075
  kite-mcp-kc: 3def64c
  kite-mcp-tools-common: 8e27bbe
scope: READ-ONLY codification; each pattern cited to a real precedent file:line. Refactor agents (Audit's Manager-decomp survey, Phase-3 tool-subgit agents, future Pattern-X agents) cite this doc instead of re-deriving.
budget-used: ~1.5h of 2-3h target
parallel-with: Audit's kc.Manager internal decomposition re-survey (reads-only on kc; both gits untouched)
---

# Algo2Go Architectural Patterns — Canonical Decision Record

## INPUTS — load-bearing facts probed `2026-05-16`

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | `algo2go/kite-mcp-decorators v0.1.0` (single-file 128 LOC) — generic typed decorator factory with `Decorator[Req, Resp any]` + `Compose` + `Apply` | `cat kite-mcp-decorators/decorators.go` | 2026-05-16 |
| 2 | `algo2go/kite-mcp-tools-common/plugin/tool_registry.go` defines `RegisterInternalTool(t common.Tool)` — panics on nil + duplicate name; `internalToolRegistry` slice append + `internalToolNames` dedup map under `sync.Mutex` | `grep -A 10 'func RegisterInternalTool' tools-common/plugin/tool_registry.go` | 2026-05-16 |
| 3 | `algo2go/kite-mcp-tools-common/middleware/middleware_chain.go` defines `MiddlewareBuilder` + `DefaultBuiltInOrder` (10 named slots: correlation, timeout, audit, hooks, circuitbreaker, riskguard, ratelimit, billing, papertrading, dashboardurl) — nil builders silently skipped | `head -40 tools-common/middleware/middleware_chain.go` | 2026-05-16 |
| 4 | `algo2go/kite-mcp-broker/broker.go` defines `broker.Client` interface as 9-interface composition (BrokerIdentity + ProfileReader + PortfolioReader + OrderManager + MarketDataReader + GTTManager + PositionConverter + MutualFundClient + MarginCalculator) at lines 554+ | `grep -A 12 '^type Client interface' broker/broker.go` | 2026-05-16 |
| 5 | `algo2go/kite-mcp-broker/conformance/conformance.go` ships a reusable adapter conformance harness with 4 buckets: PortContract + OptionalCapabilities + ErrorClassification + TickerLifecycle. Adapter authors run it in their own `_test.go` | `head -40 broker/conformance/conformance.go` | 2026-05-16 |
| 6 | `algo2go/kite-mcp-kc/ports/` has 7 Provider-interface files: alert.go, credential.go, instrument.go, order.go, session.go, audit_store_concrete.go (added today), session_registry.go (added today) — plus `assertions.go` with 7 compile-time `var _ X = (*kc.Manager)(nil)` checks | `ls kite-mcp-kc/ports/ && cat assertions.go` | 2026-05-16 |
| 7 | `algo2go/kite-mcp-kc/kite_client.go` declares `KiteClientFactory = zerodha.KiteClientFactory` type alias + `defaultKiteClientFactory` struct — pattern is "concrete factory delegated to broker SDK's NewKiteSDK so every client originates from the same seam" | `grep -A 8 'type KiteClientFactory' kite_client.go` | 2026-05-16 |
| 8 | `algo2go/kite-mcp-bootstrap/app/providers/` is the Fx-Provide module: lifecycle.go (FxLifecycleAdapter bridging fx.Lifecycle to legacy app.LifecycleManager), alert_svc.go (ProvideAlertSvc pure-function provider), 22 other adapter files | `ls bootstrap/app/providers/` | 2026-05-16 |
| 9 | `algo2go/kite-mcp-cqrs/bus.go` defines `CommandBus` + `QueryBus` + `InMemoryBus` (sync in-process, dispatch by Go-type reflection, optional middleware chain via `Middleware func(next HandlerFunc) HandlerFunc`) | `head -50 cqrs/bus.go` | 2026-05-16 |
| 10 | `algo2go/kite-mcp-eventsourcing/aggregate.go` defines `AggregateRoot` interface + `BaseAggregate` struct. **Architecture note in source**: "Aggregates are currently used as test infrastructure only. In production, state comes from broker APIs + CRUD stores, NOT event replay. May be wired into production use cases in the future if temporal queries or multi-broker replay become requirements." | `head -30 eventsourcing/aggregate.go` | 2026-05-16 |
| 11 | `algo2go/kite-mcp-bootstrap/mcp/aliases.go` (251 LOC) — Anchor 1 PR 1.1 Option B backward-compat shim. 15 type aliases (`type X = common.X`) preserve `mcp.X` callsites unchanged when packages move to `mcp/common` | `grep -nE 'type ' mcp/aliases.go + sed -n '39,61p'` | 2026-05-16 |
| 12 | **Provider-Interface Preservation Lesson** (memory `session_2026-05-16_decomposition-arc-complete.md`): "Provider interfaces require METHODS, not exported fields. Therefore 'drain accessor' refactors are structurally INCOMPATIBLE with Provider-interface satisfaction." | memory file lines 134-136 | 2026-05-16 |
| 13 | **Sprint 2-4 wall**: subpackage extraction blocked by unexported-field encapsulation (25 fields cross package boundary). File-split within same package is the only viable mechanical decomposition. | memory file lines 78-82 | 2026-05-16 |

> **Methodology**: every pattern below cites a real file in a real algo2go/* module at the HEAD verified above. No pattern is synthesized; each is recovered from production code.

---

## How to use this doc

Refactor agents facing a decomposition / extension / cross-cutting-concern decision should:

1. **Find the matching pattern below** (10 patterns numbered §1-§10).
2. **Read the "Use when" trigger** to confirm fit.
3. **Read the "Don't use when" anti-signal** to confirm not-fit.
4. **Follow the canonical precedent** — copy the shape, don't invent.
5. **Cite this doc** in commit message: `Pattern §N per architectural-patterns-record.md`.

If no pattern matches → §11 "When to introduce a NEW pattern" rules apply.
If two patterns conflict → §12 "Pattern-conflict resolution" rules apply.

---

## §1 — Provider Interface (god-object decoupling)

**Use when**: a consumer needs ONE method (or a narrow method group) from `*kc.Manager` (or any god-object) and currently reaches through the full struct.

**Don't use when**: the consumer needs >5 methods OR needs unexported fields. In that case the consumer IS a Manager-collaborator; let it depend on `*kc.Manager` directly.

**Canonical precedent**: `algo2go/kite-mcp-kc/ports/alert.go`, `credential.go`, `instrument.go`, `order.go`, `session.go`, `audit_store_concrete.go`, `session_registry.go` — each declares a single-method (or 2-3 method) interface that `*kc.Manager` satisfies. Compile-time assertions in `ports/assertions.go`:

```go
// algo2go/kite-mcp-kc/ports/assertions.go:12-20
var (
    _ SessionPort                = (*kc.Manager)(nil)
    _ CredentialPort             = (*kc.Manager)(nil)
    _ AlertPort                  = (*kc.Manager)(nil)
    _ OrderPort                  = (*kc.Manager)(nil)
    _ InstrumentPort             = (*kc.Manager)(nil)
    _ AuditStoreConcreteProvider = (*kc.Manager)(nil)
    _ SessionRegistryProvider    = (*kc.Manager)(nil)
)
```

**How to slot in**:
1. Create `algo2go/kite-mcp-kc/ports/<name>.go` declaring `type XProvider interface { X() *kc.Y }` (or narrower).
2. Add `_ XProvider = (*kc.Manager)(nil)` to `ports/assertions.go`.
3. If `*kc.Manager` doesn't already implement the method, add it to `manager_accessors.go` as a method-form accessor over an existing field (do NOT export a new field).
4. Migrate consumers from `manager.Y` (field access) or `manager.FullManagerHandle.Y` to `provider.X()`.
5. Run `go build ./...` in kc + kite-mcp-bootstrap to catch downstream breakage.

**Composition with other patterns**:
- §7 Fx-style DI: providers are constructor-injected via `ProvideXProvider(manager *kc.Manager) XProvider { return manager }`.
- §10 Aliases shim: NOT used here — ports do their own re-export.

**Alternatives considered + rejected**:
- **Export Manager field** (`m.tokenStore` → `m.TokenStore`): rejected because it breaks the Provider-Interface Preservation Lesson — exported fields are NOT interface-satisfying. Per Sprint 2-4 wall, this also forces 25+ field exports for a single sub-package extraction.
- **Type-alias to god-object**: rejected because `type CredentialPort = *kc.Manager` widens, not narrows.

**Empirical wall** (Sprint 2-4): if your refactor requires exporting Manager private fields, STOP — that's a wall, not a shortcut. See §1.5.

### §1.5 — Why "drain accessor" refactors don't compose with Provider Interface

Memory `session_2026-05-16_decomposition-arc-complete.md` line 134-136 records the empirical lesson:

> The Anchor 6 PR 6.4 work established narrow Provider interfaces as the canonical decoupling pattern between `*kc.Manager` and consumers. Provider interfaces require METHODS, not exported fields. Therefore "drain accessor" refactors are structurally INCOMPATIBLE with Provider-interface satisfaction.

**Concrete failure mode**: agent attempts to delete `Manager.SessionManager()` method and have consumers use `Manager.SessionManager` field directly. Result: `var _ SessionRegistryProvider = (*kc.Manager)(nil)` fails because the assertion expects a METHOD; field-access is not interface-satisfying. The Provider abstraction is BREAKING, not the refactor.

Of 11 "drainable" accessor candidates surveyed in B-series: 3 were truly redundant proxies (kept the rename); 5 were Provider-interface contracts (kept method-form intact); 3 were load-bearing setters (kept). **Net "drained": 3 of 11 candidates.** The other 8 are correctly architected as methods.

---

## §2 — Decorator Chain (generic typed cross-cutting)

**Use when**: callers want to compose audit + riskguard + elicitation + billing + paper-trading + ratelimit around a typed `func(ctx, Req) (Resp, error)` and care about type-safety + Go-generic ergonomics.

**Don't use when**: the wrapping target is an `mcp.CallToolRequest`/`*mcp.CallToolResult` MCP-wire-shape (use §3 Middleware instead — that's the MCP-specific surface).

**Canonical precedent**: `algo2go/kite-mcp-decorators/decorators.go` — entire 128 LOC module:

```go
// kite-mcp-decorators/decorators.go:68-78
type Handler[Req, Resp any] func(ctx context.Context, req Req) (Resp, error)
type Decorator[Req, Resp any] func(next Handler[Req, Resp]) Handler[Req, Resp]

func Compose[Req, Resp any](decorators ...Decorator[Req, Resp]) Decorator[Req, Resp]
func Apply[Req, Resp any](handler Handler[Req, Resp], decorators ...Decorator[Req, Resp]) Handler[Req, Resp]
```

**Composition contract** (verbatim from decorators.go:26-31):
> Compose(d1, d2, d3) returns a Decorator that wraps "outermost first": d1 wraps d2 wraps d3 wraps handler. Execution order matches gRPC's UnaryServerInterceptor + the existing mcp.HookMiddleware convention — the FIRST decorator listed is the OUTERMOST wrapper.

**Short-circuit semantics**: a decorator MAY return without calling next (riskguard short-circuit for blocked orders, billing tier-gating, paper-trading order interception).

**Nil safety**: Compose panics at composition time on nil decorator. Fail-fast at startup.

**How to slot in**:
1. Define your `Decorator[Req, Resp]` per the type signature.
2. Compose at wiring time: `placeOrder := decorators.Compose(AuditDec, RiskguardDec, BillingDec)(rawPlaceOrder)`.
3. Tests assert decorator order matters (TestCompose_Order in decorators_test.go).

**Composition with other patterns**:
- §3 Middleware: NOT interchangeable. Middleware operates on `server.ToolHandlerFunc` (MCP-wire); Decorator operates on your typed handler.
- §1 Provider Interface: each decorator can ACCEPT a Provider as a dependency — `RiskguardDec(rg riskguard.Guard) Decorator[OrderReq, OrderResp]`.

**Alternatives considered + rejected**:
- **Reflection-based decorator** (`func Apply(handler any, decorators ...any)`): rejected because type-erasure breaks compile-time guarantees and creates runtime-panic risk.
- **Codegen decorator** (per-Req-Resp generation): rejected (`.research/decorator-code-gen-evaluation.md`) — Go 1.21 generics deliver the same ergonomics at zero codegen cost.

---

## §3 — Middleware Chain (MCP/HTTP request lifecycle)

**Use when**: wrapping `server.ToolHandlerFunc` (MCP wire signature) with correlation, timeout, audit, riskguard, ratelimit, billing, papertrading, etc. Order-sensitive; layered before/after.

**Don't use when**: typed `Handler[Req, Resp]` (use §2 Decorator) OR pure synchronous data flow (use §2 Decorator).

**Canonical precedent**: `algo2go/kite-mcp-tools-common/middleware/middleware_chain.go`:

```go
// tools-common/middleware/middleware_chain.go:6-12
type MiddlewareBuilder func() server.ToolHandlerMiddleware
```

**`DefaultBuiltInOrder`** (verbatim from middleware_chain.go:21-37): 10 named slots in outer-to-inner order:

| Slot | Purpose | Order rationale |
|---|---|---|
| `correlation` | X-Request-ID injection | Outermost — every request traced |
| `timeout` | 30s default kill | Outside audit so timeouts logged |
| `audit` | tool_calls row write | BEFORE riskguard so blocked orders ARE logged |
| `hooks` | rolegate + telegramnotify plugins | Plugin extension point |
| `circuitbreaker` | Freeze all on error-rate spike | Outside ratelimit |
| `riskguard` | Pre-trade safety | Before ratelimit so blocks don't consume budget |
| `ratelimit` | Per-tool-per-user throttle | Per-user cost |
| `billing` | Tier-gating (Pro/Premium/Family) | After ratelimit so free-tier limits enforced |
| `papertrading` | Order-tool intercept (paper mode) | Closest to handler — last chance to swap |
| `dashboardurl` | Append dashboard_url hint | Response-shaping, innermost |

**Reordering is semantically load-bearing**: audit BEFORE riskguard means riskguard-blocked orders ARE logged; reversing drops them.

**How to slot in**:
1. Implement `func() server.ToolHandlerMiddleware` returning your middleware.
2. Register it in `DefaultBuiltInOrder` at the SEMANTICALLY-CORRECT slot.
3. Add a test asserting your middleware runs at the documented position (mirror existing tests in `middleware_chain_test.go`).
4. If middleware is optional (e.g. billing when STRIPE_SECRET_KEY unset), return `nil` from the builder — `BuildMiddlewareChain` silently skips.

**Composition with other patterns**:
- §1 Provider Interface: middleware constructors accept Providers (`func NewAuditMiddleware(audit AuditPort)`).
- §4 Plugin Registry: plugin around-hooks register via the same chain at the `hooks` slot.

**Alternatives considered + rejected**:
- **Decorator chain instead** (§2): rejected because MCP wire types are NOT typed — `gomcp.CallToolRequest` is a wire-format struct, not a per-handler-typed Req.

---

## §4 — Plugin Registry (extension point)

**Use when**: a new tool/handler must register itself at package-init time without editing a central GetAllTools() list. Goal: per-domain agents can add a tool by editing ONE file (their tool's `init()`), no central edit.

**Don't use when**: a one-off integration where a direct register call at startup is simpler.

**Canonical precedent**: `algo2go/kite-mcp-tools-common/plugin/tool_registry.go:42-54`:

```go
func RegisterInternalTool(t common.Tool) {
    if t == nil {
        panic("RegisterInternalTool: nil Tool")
    }
    name := t.Tool().Name
    internalToolRegistryMu.Lock()
    defer internalToolRegistryMu.Unlock()
    if _, exists := internalToolNames[name]; exists {
        panic(fmt.Sprintf("RegisterInternalTool: duplicate tool name %q", name))
    }
    internalToolNames[name] = struct{}{}
    internalToolRegistry = append(internalToolRegistry, t)
}
```

**Side-effect import pattern** in `bootstrap/mcp/plugin_aliases.go`:

```go
_ "github.com/algo2go/kite-mcp-bootstrap/mcp/admin"
_ "github.com/algo2go/kite-mcp-bootstrap/mcp/alerts"
// ...one per subdir
```

Each subdir's tool files contain `func init() { plugin.RegisterInternalTool(&MyTool{}) }`. The blank import in `plugin_aliases.go` makes the side-effect run at server startup.

**Two-tier registry rationale** (verbatim from tool_registry.go:10-21):
- `internalToolRegistry` — built-in tools registered by `<feature>_tools.go` init() calls
- `DefaultRegistry.toolPlugins` — external/3rd-party plugins via `RegisterPlugin`
- Splitting them lets per-domain agents edit ONLY their feature file without touching mcp.go (Investment J in `.research/agent-concurrency-decoupling-plan.md`)

**Wire-protocol invariant**: `GetInternalTools()` returns in registration order, then external plugins. SHA256-locked tool surface (`mcp/tool_surface_lock_test.go`) does not change as long as which-tools-register is preserved.

**How to slot in (new tool in existing subdir)**:
1. Create `mcp/<subdir>/<feature>_tool.go` (or wherever the tool's domain lives).
2. Declare `type MyTool struct{}` and implement `common.Tool` interface methods.
3. Add `func init() { plugin.RegisterInternalTool(&MyTool{}) }` at file bottom.
4. NO central edit required.

**How to slot in (new subdir entirely)**:
1. Steps 1-3 above.
2. Add `_ "github.com/algo2go/kite-mcp-bootstrap/mcp/<newsubdir>"` to `plugin_aliases.go`.
3. Verify tool count in `/healthz total_available` increments.

**Composition with other patterns**:
- §3 Middleware Chain: registered tools run through `DefaultBuiltInOrder`.
- §10 Aliases shim: aliases.go re-exports `Tool = common.Tool` so existing `mcp.Tool` references compile unchanged.

---

## §5 — Port + Adapter + Conformance (broker variation / strategy)

**Use when**: a vendor-variable surface (broker SDK, payment processor, identity provider) needs swap-ability. Multiple concrete implementations expected over the project lifetime.

**Don't use when**: only one implementation expected indefinitely. Premature abstraction.

**Canonical precedent**: `algo2go/kite-mcp-broker/` is the textbook port+adapter:

| Layer | File | Purpose |
|---|---|---|
| Port (interface) | `broker/broker.go:554` (`type Client interface`) | 9-sub-interface composition: BrokerIdentity, ProfileReader, PortfolioReader, OrderManager, MarketDataReader, GTTManager, PositionConverter, MutualFundClient, MarginCalculator |
| Adapter (real) | `broker/zerodha/` (10 files: factory.go, client.go, convert.go, ratelimit.go, etc.) | Zerodha-SDK-backed implementation |
| Adapter (mock) | `broker/mock/` (5 files: client.go, demo.go, etc.) | Test/in-memory adapter |
| Conformance harness | `broker/conformance/conformance.go` | 4 buckets: PortContract + OptionalCapabilities + ErrorClassification + TickerLifecycle |

**Conformance harness pattern** (verbatim shape from `conformance.go:24-37`):

```go
func TestUpstoxAdapter(t *testing.T) {
    factory := func(_ *testing.T) broker.Client { return upstox.NewMockedClient() }
    t.Run("PortContract", func(t *testing.T) { conformance.PortContract(t, factory) })
    t.Run("OptionalCapabilities", func(t *testing.T) { conformance.OptionalCapabilities(t, factory) })
    t.Run("ErrorClassification", func(t *testing.T) { conformance.ErrorClassification(t) })
    t.Run("TickerLifecycle", func(t *testing.T) { conformance.TickerLifecycle(t, ...) })
}
```

**How to slot in (new broker adapter)**:
1. Create new module `algo2go/kite-mcp-broker-<vendor>` OR new subdir `kite-mcp-broker/<vendor>/`.
2. Implement each sub-interface of `broker.Client`.
3. Write `<vendor>_test.go` that runs all 4 conformance buckets against your factory.
4. CI greens → adapter is "broker-Client-equivalent."

**Composition with other patterns**:
- §1 Provider Interface: broker.Client IS itself a Provider-shape (narrow interface, multiple consumers).
- §6 Factory: broker adapters expose a `factory.New<Vendor>(creds)` constructor.

**Alternatives considered + rejected**:
- **Big interface with all methods on one type**: rejected — 9 sub-interfaces allow consumers to ask for only what they need (`func f(p broker.PortfolioReader)`).
- **Per-vendor module replicating broker.Client**: rejected — single canonical port; conformance harness enforces shape.

---

## §6 — Factory (per-session resource construction)

**Use when**: a per-user-session resource (Kite SDK client, AlertEvaluator, Telegram bot session) needs construction at session-establish time with user-specific credentials/config.

**Don't use when**: a single global instance suffices (use plain construction in `main.go`).

**Canonical precedent**: `algo2go/kite-mcp-kc/kite_client.go`:

```go
// kite_client.go (excerpt)
type KiteClientFactory = zerodha.KiteClientFactory  // type alias to broker port

// defaultKiteClientFactory delegates to broker/zerodha.NewKiteSDK so
// every SDK client — MCP tool path and background-service path alike
// — originates from the same seam.
type defaultKiteClientFactory struct{}
```

**Pattern shape**:
- Factory is an INTERFACE (or type alias to broker's factory port).
- Factory has a method `New(credentials) Client` (or similar).
- Default implementation delegates to the broker SDK's constructor.
- Manager stores the factory (mockable in tests) and calls it at session-create time.

**How to slot in**:
1. Define `type XFactory interface { New(...) X }` if not already in the port.
2. Default implementation: `func NewDefaultXFactory() XFactory { return &defaultXFactory{} }`.
3. Manager accepts factory as constructor arg (or wires via §7 Fx-DI).
4. Tests can pass mock factory for isolation.

**Composition with other patterns**:
- §5 Port+Adapter: factory often returns a port-typed value (`broker.Client`).
- §7 Fx-style DI: factory is provided via `fx.Provide(NewDefaultXFactory)`.

---

## §7 — Fx-style DI (composition root)

**Use when**: wiring 30+ services at startup with explicit ordering, lifecycle hooks, and constructor-injected dependencies. Production composition root.

**Don't use when**: a small handful of services (<5). Plain `func wire()` in main.go is clearer.

**Canonical precedent**: `algo2go/kite-mcp-bootstrap/app/providers/` (Fx-Provide module) + `app/wire.go` (composition):

```go
// bootstrap/app/providers/alert_svc.go (excerpt)
func ProvideAlertSvc(initialized *InitializedManager) *kc.AlertService {
    if initialized == nil || initialized.Manager == nil {
        return nil
    }
    return initialized.Manager.AlertSvc
}
```

**Lifecycle bridge** (`providers/lifecycle.go` — Wave D Phase 2 Slice P2.3a):

> Fx's lifecycle model is symmetric (Hook{OnStart, OnStop}); our legacy app.LifecycleManager is asymmetric (Append-only). FxLifecycleAdapter is a hybrid: implements fx.Lifecycle so providers call lc.Append(Hook{...}) idiomatically, runs OnStart SYNCHRONOUSLY at Append time (preserving legacy "constructor returns means initialized"), bridges OnStop into the legacy LifecycleManager which runs stops in REVERSE registration order at app.Shutdown.

**How to slot in (new service)**:
1. Add `ProvideXService(deps...) *XService` to `app/providers/x_svc.go` matching the alert_svc.go shape.
2. Register in `app/wire.go`'s `fx.Provide(...)` call.
3. If service has lifecycle (background goroutine, DB connection), append OnStop to `lc fx.Lifecycle`.
4. Constructor-inject dependencies — Fx handles ordering.

**Composition with other patterns**:
- §1 Provider Interface: services typed as Providers in their declaration; `fx.Provide` returns concrete.
- §6 Factory: factories provided via Fx; consumed by services that need per-session construction.
- §3 Middleware Chain: middleware builders provided via Fx; composed in DefaultBuiltInOrder slot.

**Alternatives considered + rejected**:
- **Plain wire.go with manual ordering**: rejected at 30+ services — order-bugs become silent (forgot to construct X before Y references it).
- **Wire codegen** (Google's wire): rejected because runtime DI (Fx) gives same testability with no codegen step.

---

## §8 — CQRS Bus (command/query separation)

**Use when**: write operations need a single audit-point (every write goes through Dispatch) OR queries need a single read-side observability point.

**Don't use when**: simple direct-method-call semantics suffice. Bus indirection adds reflection cost.

**Canonical precedent**: `algo2go/kite-mcp-cqrs/bus.go`:

```go
// cqrs/bus.go:14-32
type CommandBus interface {
    Dispatch(ctx context.Context, cmd any) error
    DispatchWithResult(ctx context.Context, cmd any) (any, error)
}

type QueryBus interface {
    Dispatch(ctx context.Context, query any) (any, error)
}

type Middleware func(next HandlerFunc) HandlerFunc
type HandlerFunc func(ctx context.Context, msg any) (any, error)

type InMemoryBus struct {
    mu       sync.RWMutex
    handlers map[reflect.Type]HandlerFunc
    mw       []Middleware
}
```

**Dispatch routing**: by Go-type (`reflect.Type`) to registered handler. Synchronous in-process.

**Middleware**: bus-level middleware wraps every dispatch — used for logging, tracing, audit-context-injection.

**How to slot in (new command type)**:
1. Define struct in `algo2go/kite-mcp-cqrs/commands.go` or per-bounded-context commands file.
2. Implement handler: `func (m *Manager) HandleX(ctx, cmd XCommand) error`.
3. Register at startup: `bus.RegisterCommandHandler(XCommand{}, m.HandleX)`.
4. Producers call `bus.Dispatch(ctx, XCommand{...})`.

**Composition with other patterns**:
- §3 Middleware Chain: CQRS bus middleware ≠ MCP tool middleware. Different layers.
- §9 Event Sourcing: CQRS write side emits domain events to the event store.
- §7 Fx DI: bus is provided via `fx.Provide(cqrs.NewInMemoryBus)`.

---

## §9 — Event Sourcing (test infrastructure today; production gated)

**Use when**: testing domain-event correctness, aggregate state-machine invariants, or temporal-query feasibility.

**Don't use when (today)**: production state needs. Per `eventsourcing/aggregate.go:8-15`:

> Aggregates are currently used as test infrastructure only. In production, order/position/alert state comes from broker APIs and CRUD stores, NOT event replay. The aggregates model domain invariants and lifecycle transitions, which is valuable for testing correctness of event schemas and state machine logic. They may be wired into production use cases in the future if temporal queries or multi-broker replay become requirements.

**Canonical precedent**: `algo2go/kite-mcp-eventsourcing/aggregate.go`:

```go
type AggregateRoot interface {
    AggregateID() string
    AggregateType() string
    Version() int
    Apply(event domain.Event)
    PendingEvents() []domain.Event
    ClearPendingEvents()
}

type BaseAggregate struct {
    id      string
    version int
    pending []domain.Event
}
```

**4 production aggregates declared** (alert, order, position, session) all sourced from event-sourcing module but consumed test-side only.

**How to slot in (test fixture)**:
1. Compose `BaseAggregate` into your test aggregate.
2. Implement `Apply(event)` for each event type your aggregate cares about.
3. Replay events; assert state.

**When the production-gate opens** (criteria per aggregate.go comment): temporal queries OR multi-broker replay become requirements. At that point, this pattern promotes from "test infrastructure" to "production read-side."

**Composition with other patterns**:
- §8 CQRS: command-side emits events; ES aggregate replays them.
- §1 Provider Interface: future production wiring would expose `EventStore` as a Provider.

---

## §10 — Aliases-as-Compat-Shim (zero-cost type re-export)

**Use when**: a package's exported symbols MOVE to a new package, but you want existing callers (`foo.X`) to compile unchanged during the migration window.

**Don't use when**: the move is a complete deprecation and you WANT callers to break (force migration). Use deprecation comment instead.

**Canonical precedent**: `algo2go/kite-mcp-bootstrap/mcp/aliases.go` (251 LOC) — Anchor 1 PR 1.1 Option B:

```go
// mcp/aliases.go:39-61
type (
    ToolHandler          = common.ToolHandler
    ToolHandlerDeps      = common.ToolHandlerDeps
    ArgParser            = common.ArgParser
    ValidationError      = common.ValidationError
    ToolCache            = common.ToolCache
    PaginationParams     = common.PaginationParams
    PaginatedResponse    = common.PaginatedResponse
    MismatchKind         = common.MismatchKind
    Mismatch             = common.Mismatch
    ToolManifest         = common.ToolManifest
    SessionDepsFields    = common.SessionDepsFields
    AlertDepsFields      = common.AlertDepsFields
    OrderDepsFields      = common.OrderDepsFields
    AdminDepsFields      = common.AdminDepsFields
    ReadDepsFields       = common.ReadDepsFields

    TradingContext = paper.TradingContext  // cross-package alias
)
```

**Why it works**: `type X = Y` (with `=`) is a type ALIAS, NOT a new type. Struct-literal construction (`mcp.ToolHandler{...}`), method-set satisfaction (impl of `common.Tool` also satisfies `mcp.Tool`), and slice-element identity (`[]mcp.Tool` ≡ `[]common.Tool`) are interchangeable at every call site.

**Anti-pattern (DO NOT)**: `type X common.X` (without `=`) — creates a NEW type, breaks interchange, forces explicit conversions.

**How to slot in (during a package extraction)**:
1. Before the move: callers reference `oldpkg.X`.
2. Create `algo2go/<newpkg>/x.go` with the canonical declaration.
3. In `oldpkg`, add `aliases.go`: `type X = newpkg.X`.
4. Callers compile unchanged.
5. Migrate callers from `oldpkg.X` to `newpkg.X` at leisure (or never, if `oldpkg` is the orchestrator's natural import).

**Composition with other patterns**:
- §1 Provider Interface: ports are typically NOT aliased — they live in their own package and are imported directly by consumers.
- §4 Plugin Registry: `Tool = common.Tool` alias lets `init() { plugin.RegisterInternalTool(...) }` accept either the alias or the canonical type.

**Verified compatibility scope**: 15 type aliases in canonical precedent. ~50+ caller files reference via aliases without modification post-extraction. Zero runtime cost.

---

## §11 — When to introduce a NEW pattern

A new pattern is justified when:

1. **At least 2 production precedents exist** demonstrating the same shape. ONE instance is a coincidence; TWO is a pattern.
2. **The pattern reduces drift** vs. its alternatives (codify-once vs. re-derive-each-time).
3. **The pattern is empirically grounded** — recovered from working code, not invented from a design doc.
4. **The pattern complements existing 10 patterns** — does not overlap >50% with any §1-§10.

If only ONE precedent exists, document it as an ADR (or in §13 below as "candidate pattern") and wait for the second precedent.

**Anti-justifications** (do NOT introduce a pattern for):
- Theoretical elegance with no real precedent
- One-off needs that won't recur
- Patterns from other ecosystems (Hexagonal, Clean Architecture) without local empirical match
- Refactor-driven invention ("I wish this pattern existed so I could use it")

---

## §12 — Pattern-conflict resolution

When two patterns could apply to the same decision:

| Conflict | Winner | Reason |
|---|---|---|
| §2 Decorator vs §3 Middleware | §3 if MCP-wire types (`server.ToolHandlerFunc`); §2 if typed `Handler[Req, Resp]` | §3 is MCP-bound; §2 is type-system-bound |
| §1 Provider vs §10 Aliases | §1 (Provider Interface) | Aliases are syntactic; Providers are semantic. If you're decoupling, use Provider. Aliases is for migration windows only. |
| §5 Port+Adapter vs §1 Provider | §5 if multiple vendor implementations expected; §1 if single implementation hidden behind narrow interface | Vendor variation needs conformance harness (§5); single-impl decoupling needs Provider (§1) |
| §7 Fx-DI vs plain wire.go | §7 if 5+ services with cross-deps OR lifecycle hooks; plain wire.go if <5 services | DI overhead pays off at scale; below threshold it's ceremony |
| §8 CQRS Bus vs direct call | CQRS if write/read needs cross-cutting audit/observability; direct if simple method | Bus reflection cost only justified when middleware adds value |
| §9 ES vs §8 CQRS write-store | §8 (today) | ES is test-only today per its source documentation |
| §4 Plugin Registry vs explicit register | §4 if per-domain agents add tools concurrently; explicit if startup-only wire from main | Plugin registry decouples agents (Investment J); explicit is fine for single-agent wire |

**Last-resort rule**: if no resolution above applies, **the pattern with more existing call sites wins**. Don't fragment an established pattern across two competing implementations.

---

## §13 — Candidate patterns (ONE precedent, need a second)

These have ONE production precedent but haven't earned full pattern status yet. Document here so future agents can promote them with a second instance.

| Candidate | Single precedent | Promotion criterion |
|---|---|---|
| **Internal-package compat shim** | `algo2go/kite-mcp-kc/internal/util/` (added today at v0.1.1) — single-function utility hidden from external consumers via Go's internal-package rule | If 1 more internal/* sub-package lands in a different module, promote to full pattern |
| **Compile-time port assertion** | `algo2go/kite-mcp-kc/ports/assertions.go` (7 assertions for `*kc.Manager`) | Already widely used WITHIN ports/ but only one such file; if another module adopts the pattern for its own god-object, promote |
| **FxLifecycleAdapter bridge** | `algo2go/kite-mcp-bootstrap/app/providers/lifecycle.go` | If a second legacy-lifecycle bridge emerges (e.g. for a non-Fx external lib), promote to "Lifecycle bridge" pattern |
| **Side-effect import chain** | `algo2go/kite-mcp-bootstrap/mcp/plugin_aliases.go` (7 blank imports for tool subdirs) | One precedent; PROMOTE if Phase 3 sub-git extraction reuses the same shape (high probability per `bootstrap-decomp-empirical-mapping.md`) |
| **Conformance test harness as importable module** | `algo2go/kite-mcp-broker/conformance/` | Single instance; if another port (e.g. payment gateway, OAuth provider) ships a conformance package, promote to general "Port Conformance" pattern |

---

## §14 — Empirical surprises

1. **Provider Interface is the load-bearing decoupling primitive** — Sprint 2-4 wall (`session_2026-05-16_decomposition-arc-complete.md` lines 78-82) empirically rejected "drain accessor" as a decomposition technique. The lesson: methods (not fields) are interface-satisfying, so the Provider Interface pattern depends on Manager keeping its METHOD form. Field-exposure REGRESSES the architecture.

2. **Generic decorators landed at 80 LOC in pure Go** — `kite-mcp-decorators v0.1.0` proves Go 1.21 generics close the "typed cross-cutting" gap without codegen or reflection. The README cites `.research/decorator-code-gen-evaluation.md` as the formal rejection of codegen-based alternatives.

3. **Middleware ordering is documented but enforcement is implicit** — `DefaultBuiltInOrder` lists 10 slots; reordering breaks invariants (audit-before-riskguard so blocked orders are logged). The middleware_chain_test.go asserts the default. Operators who override take responsibility.

4. **Event Sourcing is intentionally test-only today** — the source comment is explicit. The 4 aggregates (alert, order, position, session) are correctness fixtures, not state-of-record. Production state comes from broker APIs + CRUD. Future promotion criteria are documented in the source.

5. **Type aliases solve ~50 caller migrations per extraction** — `bootstrap/mcp/aliases.go` (251 LOC, 15 type aliases) is the zero-runtime-cost compat shim for Anchor 1's per-package extractions. Worth reading once; replicate verbatim shape for future moves.

6. **9-sub-interface composition (broker.Client) is more granular than typical port design** — most Go ports are single interfaces with 5-15 methods. Broker's split into 9 sub-interfaces lets consumers depend on `broker.PortfolioReader` without seeing `OrderManager` — narrow consumer surface, narrow test surface. **Pattern recommendation: when a port grows past 10 methods, consider sub-interface composition.**

7. **Plugin registry's "two-tier" split** (internal vs external) is specifically motivated by `Investment J` in `.research/agent-concurrency-decoupling-plan.md` — eliminating central edit points so per-domain agents work concurrently without merge conflicts. This is an AGENT-CONCURRENCY pattern, not just a software-decoupling pattern.

8. **Fx-Lifecycle bridge is asymmetric-to-symmetric** — `FxLifecycleAdapter` (providers/lifecycle.go) runs OnStart synchronously at Append time (legacy compat) but defers OnStop to the legacy LifecycleManager (preserving REVERSE registration order). This is a one-off bridge with non-trivial semantics — read the source comment before touching.

9. **The Conformance harness pattern is the strongest "shape" insurance** — `broker/conformance/conformance.go` lets ANY future Upstox/Dhan/Angel One adapter prove its `broker.Client` conformance in ~10 LOC of `t.Run` blocks. If your port has multiple adapters expected, write the conformance harness BEFORE the second adapter, not after.

10. **No pattern requires reflection except CQRS bus** — Go's static type system + generics cover §1-§7, §10. CQRS bus uses `reflect.Type` for type-keyed dispatch (`map[reflect.Type]HandlerFunc`) because command types are open. Acceptable; alternative (sealed command enum) loses extensibility.

11. **Provider-Interface is incompatible with field-export AND with concrete-struct return** — a Provider returning `*kc.SessionRegistry` (the concrete) is documented in `session_registry.go` as a "leaf-stability deviation" with a path to future cleanup (relocate SessionRegistry to a leaf module). Concrete returns are an escape hatch, not the norm.

12. **All 10 patterns are EMPIRICALLY GROUNDED** — no synthesized "should-have" patterns. Each cites a real file:line. This is the prevention against the user's "we keep finding the same walls" complaint: the walls are now NAMED + LOCATED, not re-derived.

---

## §15 — Cross-reference index

| Pattern | Module precedent | Primary file | Test file |
|---|---|---|---|
| §1 Provider Interface | kite-mcp-kc | ports/alert.go + assertions.go | leaf_stability_test.go |
| §1.5 Drain-accessor wall | (memory) | session_2026-05-16_decomposition-arc-complete.md lines 134-136 | n/a (lesson) |
| §2 Decorator Chain | kite-mcp-decorators | decorators.go | decorators_test.go |
| §3 Middleware Chain | kite-mcp-tools-common | middleware/middleware_chain.go | middleware_chain_test.go |
| §4 Plugin Registry | kite-mcp-tools-common | plugin/tool_registry.go + bootstrap/mcp/plugin_aliases.go | plugin/* test files |
| §5 Port+Adapter+Conformance | kite-mcp-broker | broker.go + zerodha/ + conformance/conformance.go | conformance/conformance_test.go |
| §6 Factory | kite-mcp-kc | kite_client.go | kite_client tests in kc |
| §7 Fx-style DI | kite-mcp-bootstrap | app/providers/*.go + app/wire.go | app/wire_test (if exists) |
| §8 CQRS Bus | kite-mcp-cqrs | bus.go | bus_test.go + cqrs_test.go |
| §9 Event Sourcing | kite-mcp-eventsourcing | aggregate.go | aggregate_edge_test.go |
| §10 Aliases shim | kite-mcp-bootstrap | mcp/aliases.go | (compile-time only) |

---

## §16 — Update protocol

This doc is a Decision Record, not a tutorial. Update when:

1. **A new pattern is empirically promoted** from §13 (Candidate) → §1-§10 (full pattern). Requires 2+ precedents and a §11-criteria check.
2. **A pattern is empirically deprecated** — e.g. if Event Sourcing (§9) is wired into production, update §9's "Use when" and reclassify.
3. **A wall is discovered** that no pattern handles. Add to §14 (Empirical surprises) with file:line cite. Future agents must NOT re-derive.
4. **Pattern conflicts** that §12 doesn't resolve. Add new row.
5. **Re-verify cadence**: every 90 days (per `re-verify-by` frontmatter), re-probe each §15 file:line cite to ensure HEADs still match.

Edits must:
- Preserve §INPUTS verification format
- Cite real file:line (no synthesized examples)
- Date-stamp each addition (`Added 2026-MM-DD per <commit-sha>`)
- Pass a sanity-check: a refactor agent reading this doc should NOT need to read the underlying source files to understand WHEN/HOW to apply each pattern

---

*Generated 2026-05-16, read-only DR. 10 canonical patterns codified + 5 candidate patterns. NO code mutations. Next refactor agent dispatch (Audit's Manager-decomp re-survey) should cite `§N per architectural-patterns-record.md` instead of re-deriving.*
