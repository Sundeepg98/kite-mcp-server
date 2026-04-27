# ADR 0006: Fx Adoption for Composition-Root Wiring

**Status**: Accepted (2026-04-27)
**Author**: kite-mcp-server architecture
**Decision drivers**: Multi-agent parallel-development friction on `app/wire.go`; per-component tech-stack-portability optionality; Wave D Phase 1 had landed startup-once use-case construction (commits `e2946f8`-`4e12da9`) that made graph-resolved wiring genuinely possible without prior abort condition recurring.

---

## Context

By the end of Wave D Phase 1 (April 2026), every order/GTT/exit/margin/widget use case in `kc/manager_use_cases.go` was startup-constructed with stable dependencies. The `resolverFromContext` per-request closure had been removed; broker resolution flowed through `m.sessionSvc` for every dispatch. This unblocked the long-deferred question: should we adopt a dependency-injection container for the App's outer composition (`app/wire.go`)?

### The problem

`app/wire.go:initializeServices` was a single ~985-LOC function that constructed:

- The Kite Connect Manager (via `kc.NewWithOptions` with 16 functional options)
- Audit-trail wiring (InitTable, encryption, hash chain, hash publisher)
- Riskguard initialization (DB persistence, lookup adapters, auto-freeze closure, plugin discovery)
- Domain event dispatcher with 36 conditional Subscribe calls
- Outbox pump for async event persistence
- Paper trading engine + monitor
- Telegram briefings, P&L snapshot, audit cleanup tasks (scheduler)
- The 10-layer middleware chain
- Plugin hook registrations
- Billing tier setup with DB init
- Family invitation cleanup goroutine
- Elicitation + UI extension hooks
- The MCP server itself
- Tool registration

This was the codebase's most-touched file under multi-agent development. Per `.research/agent-concurrency-decoupling-plan.md` §3.5, `wire.go` had ~30%/week Mode-2 conflict probability at 4 sustained agents and ~80%/week at 8 agents — projected ~26 hours/year of conflict-resolution overhead at scale.

### Three-axis ROI evaluation

Per `feedback_decoupling_denominator.md`, every architectural decoupling decision must be evaluated against three axes:

| Axis | Verdict | Notes |
|---|---|---|
| User-MRR | Negative | ~3-week refactor with no user-visible feature output |
| Agent-concurrency throughput | Positive at 6+ sustained agents | Eliminates `wire.go` Mode-2 conflict file |
| Tech-stack portability (per-component swap freedom) | Positive if 2-year goal is concrete | Provider graph IS the architectural diagram, machine-readable; per-component rewrites in Rust/TypeScript/Python become "register a new provider" instead of "find-and-replace across 985 LOC" |

The user authorized Phase 2 with two-of-three positive (agent-concurrency + portability). User-MRR axis is negative but accepted because the other two axes were affirmed concrete.

## Decision

**Adopt `go.uber.org/fx` v1.24.0** for graph-resolved composition of `app/wire.go`'s subsystems. Migrate incrementally via per-domain provider files in `app/providers/`. Skip the inner `kc.Manager` migration (P2.5) because its 16 functional options + 16 named init helpers already give a structured surface; Mode-2 conflict on `manager_init.go` is low.

### Wire vs Fx

We chose Fx over Google Wire (`github.com/google/wire`) for four reasons:

1. **Lifecycle alignment.** Our existing `app.LifecycleManager.Append(name, fn)` pattern is near-isomorphic with Fx's `fx.Lifecycle.Append(fx.Hook{OnStart, OnStop})`. We can migrate lifecycle hooks 1:1 via a small adapter (`providers.FxLifecycleAdapter`), no translation layer.

2. **Active maintenance.** Fx ships monthly; Wire's last release was 2023. Multi-week investment requires upstream still merging fixes 2 years out.

3. **Better error UX.** Fx's runtime errors include type names; Wire's codegen errors are notoriously cryptic ("no provider found for X" with little debugger help). Faster iteration on slice migration.

4. **No `go generate` ceremony.** Wire requires a pre-build codegen step (and CI / pre-commit hooks must enforce it). Fx avoids this — at the cost of runtime errors instead of compile-time. Our scale doesn't change this calculus: a single binary's startup latency is unaffected by ~1ms of reflection cost.

The reflection cost (~1-3 ms additional startup latency) is below noise for a single-binary HTTP server.

## Consequences

### What changed

`app/providers/` was introduced as the canonical home for graph-composable wiring. The package contains:

| File | Purpose |
|---|---|
| `logger.go` | Passthrough provider for the externally-supplied `*slog.Logger` |
| `alertdb.go` | Opens (or returns nil for in-memory mode) the SQLite handle |
| `audit.go` | Wraps the alertDB as `*audit.Store` (post-init wrapping is in `audit_init.go`) |
| `audit_init.go` | Runs the InitTable + EnsureEncryptionSalt + SeedChain + StartWorker chain; returns `*InitializedAuditStore` wrapper |
| `audit_middleware.go` | Pure function: wraps `*InitializedAuditStore` as `server.ToolHandlerMiddleware` |
| `lifecycle.go` | `FxLifecycleAdapter` bridges `fx.Lifecycle` to the App's `*LifecycleManager` |
| `telegram.go` | Passthrough for `*alerts.TelegramNotifier` |
| `scheduler.go` | `BuildScheduler` — wires Telegram briefings + audit cleanup + P&L snapshot tasks |
| `riskguard.go` | `InitializeRiskGuard` — DB init + LoadLimits + lookup wiring + plugin discovery |
| `mcpserver.go` | `BuildMiddlewareChain` (assembles 10-layer chain) + `BuildMCPServer` (calls `server.NewMCPServer`) |
| `event_dispatcher.go` | `BuildEventSubscriptions` — wires the 36 canonical persister Subscribe calls |

Each provider is testable in isolation with no production-wiring dependency.

### Patterns established

Three patterns emerged from the implementation and are documented at the call site for future contributors:

**1. The `*InitializedXxx` wrapper-type convention.** Fx's type graph rejects `fx.Supply(*T)` and `fx.Provide(...) (*T, ...)` together — both providers register `*T` and the resolver fails with "type already provided." The fix: wrap the post-init pointer in a distinct type:

```go
type InitializedAuditStore struct {
    Store *audit.Store
}
```

The wrapper's nil-or-populated state additionally signals init success vs failure for downstream consumers. See `app/providers/audit_init.go` for the canonical example; same pattern applied to `InitializedRiskGuard`, `InitializedScheduler`, `InitializedEventDispatcher`.

**2. The fan-in struct convention for same-typed inputs.** When a provider needs many inputs of the same type (e.g., 10 `server.ToolHandlerMiddleware` values), use `fx.Annotate` name tags would be cleaner architecturally but produces uglier call sites. Instead: fan-in via a single struct:

```go
type MiddlewareDeps struct {
    Correlation, Timeout, Audit, Hooks, ... server.ToolHandlerMiddleware
}
```

The composition site assembles the struct once and supplies it via `fx.Supply(deps)`. The provider takes one argument. See `app/providers/mcpserver.go`.

**3. The "composition keeps adapters, provider takes ports" split.** When a provider needs an unexported app-package adapter (e.g., `briefingTokenAdapter`, `riskguardLTPAdapter`, `makeEventPersister`), the adapter cannot move into `app/providers/` without an import cycle or making the type public. Resolution: composition site constructs the adapter and supplies it via `fx.Provide(func() T { return adapter })` or as a closure. The provider takes the narrow interface (port). See P2.4b/c/f for examples.

### What stayed at the composition site

Three classes of work intentionally remain in `app/wire.go`:

- **Side-effect closures that capture `*App` state**: rate-limit reload goroutine (`app.rateLimitReloadStop`), hash-publisher cancel (`app.hashPublisherCancel`), invitation cleanup (`app.invitationCleanupCancel`). These keep their inline construction because moving them would require either passing `*App` into providers (broad coupling) or introducing the `FxLifecycleAdapter` more aggressively than current scale justifies.

- **Backward writes into `*kc.Manager`**: `kcManager.SetEventDispatcher`, `kcManager.SetEventStore`, `kcManager.SetMCPServer`, `kcManager.SetPaperEngine`, `kcManager.SetPnLService`, `kcManager.SetFamilyService`. These are calls into existing setter API; making them part of the Fx graph would require migrating the inner Manager (P2.5, intentionally skipped per `.research/wave-d-phase-2-recompute.md` §2).

- **Package-global side effects**: `stripe.Key = stripeKey` — touching a third-party package global from a provider is an anti-pattern.

### What was rejected

**P2.5 (inner Manager Fx migration)** was explicitly skipped. Recompute analysis (`.research/wave-d-phase-2-recompute.md` §2.2) projected ~1200 LOC for marginal benefit. The inner Manager already has a structured init surface (16 functional options + 16 named init helpers); Mode-2 conflict on `manager_init.go` is empirically low. Future work can revisit if conditions change.

**Logger Provider wrap (Investment B from `agent-concurrency-decoupling-plan.md`)** was rejected for both Wire-vs-Fx adoption decision: it's frequency-weighted to ~0 (config changes ~1/year) and does not eliminate any Mode-2 conflict file.

**Federated build / Bazel** was rejected as premature: cost dwarfs the realistic Mode-2 savings on `go.mod`.

### Per-axis outcome

- **User-MRR**: 0 features shipped during Phase 2. Negative axis as predicted.
- **Agent-concurrency**: `wire.go` reduced from 985 → ~920 LOC; the 36 Subscribe calls (formerly the most edit-prone block) now live in `CanonicalPersisterSubscriptions` as data; new providers added without `wire.go` edit. Mode-2 conflict surface materially reduced.
- **Tech-stack portability**: per-component rewrite path is now declarative — replace a provider file in `app/providers/` rather than scour `wire.go`. The provider graph also serves as machine-readable architectural documentation.

### Empirical observations

LOC actuals across Phase 2 slices (P2.1 through P2.4f, plus P2.6 cleanup):

| Slice | Net LOC | Notes |
|---|---:|---|
| P2.1 (Fx dep + sentinel) | +73 | Smallest |
| P2.2 (leaf providers) | +328 | Logger/AlertDB/Audit |
| P2.3a (lifecycle adapter) | +390 | Foundation for P2.4 |
| P2.3b (audit chain beachhead) | +593 | First production `fx.New` |
| P2.4a (telegram) | +107 | Passthrough |
| P2.4b (scheduler) | +383 | Pre-built services + provider wiring |
| P2.4c (riskGuard) | +418 | Wrapper-type pattern reused |
| P2.4d+e (mcpserver + middleware) | +423 | Fan-in struct pattern introduced |
| P2.4f (eventDispatcher) | +465 | Subscription list as data; -78 wire.go |
| P2.6 (this ADR + cleanup) | ~+150 | Doc + sentinel delete |

Total Phase 2: ~3,330 LOC across `app/providers/` package + ADR/docs. Wire.go net delta: +985 → ~920 = -65 LOC. The asymmetry (3,330 LOC added vs 65 LOC removed) reflects two tax categories: heavy doc-comments preserving design intent at the call site (~50% of new files), and TDD-first test files (~85% of impl LOC). Both pay forward.

### Migration discipline applied

The Wave D Phase 1 lessons (`.research/wave-d-resolver-refactor-plan.md` §3.2) were applied throughout Phase 2:

- **Slice-split when first 30 min reveals reusable infrastructure.** P2.3 was split into P2.3a (lifecycle adapter, foundation) and P2.3b (audit chain beachhead, consumer of foundation). Same heuristic later applied to P2.4d+e (combined; user authorization).
- **Honest-stop rules.** P2.4d standalone was declined because it was structurally too small (50 LOC, ceremonial); user authorized fold-into-P2.4e instead. Commit β (billing + family-invitation extractions) was declined twice for ROI-marginality after empirical evaluation.
- **Diagnostic discipline.** No `git stash` after the P2.3b incident (a one-time rule violation, surfaced and committed-for-posterity in `.research/wave-d-phase-2-recompute.md` §5). All subsequent diagnostics used `-run <TestName>` for isolation and `git diff` for state inspection.

## References

- `.research/wave-d-phase-2-wire-fx-plan.md` (`4b5120b`) — original Phase 2 scoping
- `.research/wave-d-phase-2-recompute.md` (`c2fefd4`) — LOC + lessons recompute after P2.1-P2.3b
- `.research/wave-d-resolver-refactor-plan.md` (`66de1ff`) — Wave D Phase 1 scoping (precondition)
- `.research/agent-concurrency-decoupling-plan.md` §3.5 — Mode-2 conflict ranking that promoted Wire/fx into the recommended sequence
- `.research/wave-d-phase-2-wire-fx-plan.md` §3.3 — Wire-vs-Fx tradeoff analysis
- `feedback_decoupling_denominator.md` — three-axis ROI framework
- `app/providers/` — the new composition module
