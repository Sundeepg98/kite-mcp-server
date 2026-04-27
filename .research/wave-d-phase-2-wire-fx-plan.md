# Wave D Phase 2 — Wire/fx adoption scoping

**Charter**: read-only research deliverable scoping the actual Wire/fx adoption sprint that Wave D Phase 1 (commits `e2946f8` D1 → `4e12da9` D7) enabled. No code changes in this PR. Companion to `.research/wave-d-resolver-refactor-plan.md` (commit `66de1ff`) — the Phase 1 scoping doc that mapped + executed the resolver-refactor preconditions.

**HEAD audited**: `4e12da9` (master, post-D7). All resolverFromContext / WithBroker machinery removed; 12 of 14 ctx-bound use cases now startup-constructed and held on `*kc.Manager`.

**Cross-references**:
- `.research/wave-d-resolver-refactor-plan.md` (`66de1ff`) — Phase 1 scoping doc; this doc executes its §6 Slice D-final.
- `.research/agent-concurrency-decoupling-plan.md` §3.5, §5 — Wire/fx promoted to Phase 3 of recommended sequence under merge-conflict-counted denominator.
- `.research/scorecard-final.md` (`562f623`) — current 90.04 equal-weighted, ~95 Pass-17 weighted; Wire/fx in anti-rec'd column for +5 Hex.
- `.research/path-to-100-business-case.md` — Wire/fx classified as ceremony under user-MRR denominator.
- `feedback_decoupling_denominator.md` — three-axis ROI framework: user-MRR, agent-concurrency, tech-stack portability. Phase 2 must evaluate against all three.

---

## 1. Problem statement (what Phase 2 actually is)

Wave D Phase 1 (Slices D1-D7) made every order/GTT/exit/margin/widget use case **startup-constructed** with stable dependencies — Wire-compatible by structure. The remaining work is the actual DI-container adoption:

> Replace `app/wire.go`'s 985-LOC bespoke composition root with a Wire-or-Fx provider graph so that adding a new service is "declare a provider in a new file" instead of "edit the central composition function". The mechanical edit-time and merge-time conflicts on `wire.go` then drop to ~zero.

This is a **fundamentally different sprint from Phase 1**. Phase 1 had 14 well-bounded use-case sites with zero new dependencies. Phase 2 has:

- ONE big composition function (`initializeServices`, `app/wire.go:37-815`, ~780 LOC) tightly interleaved with audit/encryption/event-dispatcher/middleware-chain wiring.
- A `go.mod` change introducing either `github.com/google/wire` (build-time codegen) or `go.uber.org/fx` (runtime DI).
- A new build-system step (Wire) or a new runtime initialization phase (Fx).
- Cryptic compiler-error mode on Wire upgrades; or runtime error mode on Fx.

The question is not "can Phase 2 work" — it can. The question is "what slice plan makes Phase 2 land safely without spending 3 weeks debugging `wire_gen.go`".

---

## 2. Empirical state at HEAD `4e12da9`

| Surface | LOC | Notes |
|---|---:|---|
| `app/wire.go` | 985 | One `initializeServices` + `registerLifecycle` + `initScheduler`. 16 functional options to `kc.NewWithOptions`. Constructs eventDispatcher, riskguard limits, audit/encryption/hash-publisher, middleware chain, MCP server, scheduler. |
| `app/app.go` | 775 | App struct + lifecycle + HTTP handlers wiring. |
| `kc/manager.go` | 402 | Manager struct (~60 fields, 17 of which are Wave-D-hoisted use cases). |
| `kc/manager_init.go` | 514 | 16 named init helpers; phase order load-bearing per its own doc comment. |
| `kc/manager_use_cases.go` | 170 | Wave D Phase 1 deliverable: startup-once UC construction. |
| Combined Manager-side composition | ~1086 | wire.go:99-117 (16 options) + manager_init.go (16 helpers) + manager_use_cases.go (12 hoisted UCs). |

**Two distinct composition roots** today:
1. `app/wire.go:initializeServices` — owns the OUTER composition (alertDB, audit, eventDispatcher, MCP server, middleware chain).
2. `kc.NewWithOptions` + `kc/manager_init.go` — owns the INNER composition (Manager fields, focused services, use cases).

Phase 2 should target the OUTER root first because:
- Inner root is already structured (16 functional options + 16 named helpers); merge-conflict friction on it is low.
- Outer root (`initializeServices`) is the Mode-2 conflict file per `agent-concurrency-decoupling-plan.md` §3.5 (~30%/wk at 4 agents, ~80%/wk at 8 agents).

---

## 3. Wire vs Fx — pick one

### 3.1 Google Wire (`github.com/google/wire`)

**Mechanism**: build-time code generation. You write `wire.go` files declaring `wire.NewSet(NewX, NewY, NewZ)` and `wire.Build(...)`; `go generate ./...` produces a `wire_gen.go` that calls each constructor in dependency order. The generated file is checked in.

**Pros**:
- Zero runtime overhead (it's just a normal call sequence, generated).
- Compile-time dependency graph correctness (Wire fails at codegen time if a provider is missing).
- No magic: the generated code is plain Go you can read.
- Used in production by Kubernetes, GCP go-cloud — battle-tested.

**Cons**:
- Notorious DX cliff on cryptic errors. Adding a provider that introduces a cycle reports "no provider found for X" with little debugger help.
- Adds `go generate` to CI / pre-commit. If a teammate edits a constructor signature without running `go generate`, the build breaks until someone regenerates.
- Currently in maintenance mode (last release 2023). Not abandoned, but no active development. Acceptable for stable codebases; risky for a project that wants forward-looking dependency upgrades.
- Provider sets are package-scoped — splitting into per-domain provider files means each file declares its own `wire.NewSet`, and the top-level `wire.Build(allSets...)` is the new shared coordination point (small but non-zero).

### 3.2 Uber Fx (`go.uber.org/fx`)

**Mechanism**: runtime dependency injection. Providers register via `fx.Provide(NewX, NewY, NewZ)`; `fx.New(...)` resolves the graph at startup using reflection.

**Pros**:
- Active upstream development; well-maintained; widely adopted at Uber, Tigris, etc.
- Better lifecycle hooks built in (`fx.Lifecycle.Append({OnStart, OnStop})`) — mirrors our existing `app.lifecycle.Append` pattern almost 1:1.
- More runtime introspection; failures surface clearer "missing dependency for type T" errors.
- Aligns with our existing functional-options pattern across `kc/`, `kc/ticker`, `kc/scheduler`.

**Cons**:
- Reflection-based; ~1-3 ms additional startup latency. Negligible at our scale.
- Runtime errors instead of compile-time. If a wiring is wrong, the binary starts and crashes on `fx.New` — observable but worse than compile-fail.
- Adds a dependency tree (`go.uber.org/fx`, `go.uber.org/dig`, `go.uber.org/zap` indirect via test helpers). Heavier `go.sum` footprint than Wire.

### 3.3 Verdict — recommend **Fx** over Wire

Reasons in priority order:

1. **Lifecycle alignment**. Our `app.registerLifecycle` (lines 818-897 of wire.go) already uses an `Append("name", stopFn)` pattern. Fx's `fx.Lifecycle.Append({OnStart, OnStop})` is a near-isomorphic match. We can migrate lifecycle hooks 1:1 without a translation layer.

2. **Active maintenance matters**. Phase 2 is a multi-week investment; we want the upstream still merging fixes 2 years from now. Wire's 2023 release vs Fx's monthly cadence tilts.

3. **Better error UX**. Phase 2's biggest risk is debugging cryptic wiring errors. Fx's runtime errors with type names beat Wire's codegen errors. Faster iteration on slice migration.

4. **Reflection cost is irrelevant at our scale**. We're a single-binary HTTP server. 1-3 ms startup overhead is below noise.

5. **The user's third denominator (tech-stack portability)** doesn't favor either — both are Go-only. Both decouple equally well from a per-component-swap perspective.

**Counter-argument considered**: if we ever need to fork the codebase for a non-Go target, having `wire_gen.go` as a checked-in source file is a translatable artifact that humans can read. Fx's runtime graph is opaque without running `fx.VisualizeError`. Marginal point — favoring Fx still wins on lifecycle alignment.

---

## 4. Three-denominator ROI evaluation

Per `feedback_decoupling_denominator.md`, every architectural decoupling decision must explicitly evaluate against three axes.

### 4.1 Axis A — User-MRR denominator

`kite-mrr-reality.md` target: ₹15-25k MRR at 12 months. Phase 2 ships zero user-visible features. Audit-side benefit (faster service-add for new MCP tools) is real but indirect.

**ROI under Axis A**: NEGATIVE. ~3-week sprint of pure refactor against a 12-month MRR runway is opportunity cost in the wrong direction. This was the original `path-to-100-business-case.md` §7 reasoning that put Wire/fx in the anti-rec'd column.

### 4.2 Axis B — Agent-concurrency denominator

Per `agent-concurrency-decoupling-plan.md` §3.5:
- `app/wire.go` Mode-2 conflict probability: ~30%/wk at 4 agents, ~80%/wk at 8 agents.
- Resolution cost: 5-15 min per conflict + cascade test reruns.
- Annual cost at 8 sustained agents: ~26 hours of pure conflict resolution on `wire.go`.

**Empirical recent data** at HEAD `4e12da9`:
- Sub-commits A/B/C in this very session show ≥3 agents working in parallel; commits like `12604ee`, `1bbd52f`, `16d2ea5` landed concurrently with the Wave D thread without merging on `wire.go` (but they touched mostly test files — the Mode-2 hotspot wasn't tested).
- This session's worktree `agent-a2e6c1ec` exists but is non-blocking — confirms the user is running parallel work.
- The Phase 1 commits (D1-D7) avoided `app/wire.go` entirely. Wave D made the resolver refactor possible WITHOUT touching wire.go. So the Mode-2 conflict on wire.go has not yet been measured at scale.

**ROI under Axis B**: POSITIVE if 6+ sustained agents are foreseeable; MARGINAL at the current observed 3-4 agents. The §3.5 ranking puts Phase 2 (Wire/fx) at #4 (after Worktree, Tool registry, Port-per-context). Phases 1+2 (worktree + tool registry) push the agent ceiling 4→8 alone; Wire/fx is what pushes 8→12.

**Open question**: are 6+ sustained agents a real plan or a hypothetical? If hypothetical, Axis B alone doesn't justify Phase 2 today.

### 4.3 Axis C — Tech-stack portability denominator

Per `feedback_decoupling_denominator.md` (2026-04-27 amendment): "100% decoupling = freedom to rewrite component X in language Y later."

What Wire/fx adoption buys for portability:
- **Per-component swap freedom**: a Wire/fx-graphed `app.App` exposes its component dependencies as a typed graph. Future per-component rewrites (e.g. Rust hot path for ticker WebSocket; TypeScript-based widget renderer; Python analytics piece) become "rewrite component X, register a new provider" instead of "find-and-replace across 985 LOC of bespoke composition".
- **Cross-language IPC boundary mapping**: today, the boundary between subsystems is a function-call signature. Post-Wire/fx, it's a typed provider — easier to factor into an IPC contract because the seam is already explicit.
- **Documentation as a side benefit**: the Fx provider graph IS the architectural diagram, machine-readable.

**Counter-evidence**: there is currently NO concrete plan to swap a component to a different language. The user's Apr-2026 framework note is forward-looking, not a triggered decision. So Axis C value is real but speculative.

**ROI under Axis C**: POSITIVE if portability is a ≤2-year goal; MARGINAL if speculative.

### 4.4 Combined verdict

| Axis | Verdict | Confidence |
|---|---|---|
| A (User-MRR) | Negative | High |
| B (Agent-concurrency) | Positive at 6+ agents; marginal at 3-4 | Medium |
| C (Tech-stack portability) | Positive if 2-year goal; marginal if speculative | Low |

**Two-of-three positive only if** (i) sustained 6+ agent work IS planned within 12 months, AND/OR (ii) component-swap to non-Go IS planned within 24 months.

If both (i) and (ii) are speculative — i.e., the user can't point to a concrete plan beyond "we might want to" — Phase 2 is still **defer-recommended** under the same three-axis math.

If at least one of (i) or (ii) is concrete (e.g. user has decided to launch a Telegram-bot product line that will run alongside Phase 1, demanding separate worker binaries; or has decided Rust-port the ticker for SEBI Algo-ID throughput) — Phase 2 is **ship-recommended**.

**This doc does not assume which.** §6 (slice plan) is conditional on user authorization.

---

## 5. Honest opacity

Items I cannot resolve from the codebase alone — explicit asks for the user:

1. **Sustained agent count over next 12 months**. Phase 1 saw 3-4 concurrent agents; Phase 2's Axis-B math hinges on whether 6+ becomes routine. If this session's pattern (~4 agents) is the steady state, Wire/fx is not justified by Axis B alone.

2. **Per-component language-swap intent**. Has the user decided that any specific subsystem (ticker, widgets, analytics) will be rewritten in Rust/TypeScript/Python within 24 months? If yes — Phase 2 is justified by Axis C even if Axis B is marginal. If no — Axis C is speculative.

3. **Wire vs Fx preference override**. §3.3 recommends Fx. If the user has personal preference or institutional bias for Wire (codegen-as-source, no runtime DI), I'll respect that. The slice plan structure is identical for both libraries; only the actual provider declarations differ.

4. **Acceptance of multi-week tail risk**. Wire/fx adoption has documented multi-week debugging tails when subtle wiring bugs surface only at startup. Phase 1's 7 slices each shipped in 1-2 hours; Phase 2 slices are likely 1-3 days each with the possibility of mid-slice abort. User should know this before authorizing.

5. **CI/build-system surgery tolerance**. Wire requires a `go generate` step before `go build` for any change touching providers. If user's CI pipeline + pre-commit hooks need updating, that's separate effort. Fx avoids this — but at the cost of runtime-error class.

---

## 6. Slice-by-slice execution plan (when authorized)

This plan presupposes user authorization. If executing today, **stop and ask first** per §5.

The plan assumes Fx (per §3.3 recommendation). The structural slices are identical for Wire — only provider declaration syntax differs.

### Slice P2.1 — Add Fx dependency, no callers (~30 LOC)

**Goal**: ship the `go.mod` change + a single sentinel test that imports `go.uber.org/fx` so the dependency tree is in `go.sum`. Zero production code changes.

**Files**:
- `go.mod`: `+ go.uber.org/fx v1.x.y` (latest stable)
- `go.sum`: regenerate via `go mod tidy`
- `app/fx_sentinel_test.go` (new): a one-line `var _ = fx.New` package import test

**Verification**:
- `go build ./...` clean
- `go test -count=1 -run TestFxSentinel ./app/` PASS
- `go.sum` change reviewed for transitive dependencies (expect `dig`, `multierr`, `zap` indirects — all stable)

**Honest stop**: if `go mod tidy` introduces an indirect dep we don't accept (e.g., a deprecated package), STOP. Reconsider Wire.

### Slice P2.2 — Provider files for the leaf services (~100 LOC)

**Goal**: declare Fx providers for the leaf-most services that have no incoming dependencies — the building blocks. No `fx.New` call yet; the providers exist as standalone functions ready to be composed.

**Targets** (in dependency order, leaves first):
- `app/providers/logger.go`: `provideLogger(cfg) *slog.Logger`
- `app/providers/alertdb.go`: `provideAlertDB(cfg) *alerts.DB` + lifecycle hook for `alertDB.Close()`
- `app/providers/audit.go`: `provideAuditStore(db, cfg) *audit.Store` + lifecycle hooks for `InitTable`/`StartWorker`/`Stop`

**Each provider file**: ~30-40 LOC. Pure functions; no Fx-specific code beyond the function signature accepting/returning the right types. Wired together later.

**Verification**:
- `go build ./...` clean
- Existing tests still pass (the provider functions are isolated; not yet replacing `initializeServices`).

**Honest stop**: if any leaf provider's signature requires a side-effect (e.g., schema migration that we'd want to re-run on every startup vs. once), document the lifecycle hook pattern and continue. If it requires global-state mutation, STOP — that's an indication the underlying API needs a Phase-1.5 fix first.

### Slice P2.3 — Wire one branch through `fx.New` end-to-end (~150 LOC)

**Goal**: replace the `app/wire.go` audit-side wiring (lines ~177-220) with an `fx.New(...)` call that constructs the audit chain via providers from P2.2. The rest of `initializeServices` stays unchanged; this is a beachhead, not a sweep.

**Files**:
- `app/wire.go`: replace ~50 lines of audit wiring with a 5-line `fx.New(...)` invocation that yields the wired `*audit.Store` + middleware.
- `app/providers/lifecycle.go` (new): adapter that bridges Fx's `fx.Lifecycle` to our existing `app.lifecycle.Append` so existing shutdown sequencing keeps working.

**Verification**:
- `go build ./...` clean
- `go test -count=1 ./app/ ./kc/...` clean (this is the critical run — audit middleware affects every tool call's logging path)
- Manual: start the binary in DevMode, dispatch a tool call, verify audit log persists.

**Honest stop**: if `fx.New` panics on startup with a "missing dependency" error AND the message is unclear, log the full chain via `fx.VisualizeError`. If THAT is unclear, abort the slice — the wiring complexity is exceeding the documented Fx UX, which means we have a Phase-1.5 misshapen-API problem.

### Slice P2.4 — Per-domain provider sets (~250 LOC)

**Goal**: convert the remaining `initializeServices` sections into per-domain provider sets:
- `app/providers/eventdispatcher.go`: dispatcher + persister subscriptions.
- `app/providers/riskguard.go`: limits load + auto-freeze closure.
- `app/providers/telegram.go`: bot factory + notifier wiring.
- `app/providers/scheduler.go`: scheduler tasks + lifecycle.
- `app/providers/middleware.go`: 10-layer middleware chain composition.
- `app/providers/mcpserver.go`: MCP server with tool registration hook.

Each provider file: ~30-50 LOC. The top-level `app/wire.go` shrinks from 985 LOC to ~150 LOC (the entrypoint + Fx graph composition).

**Verification per provider sub-slice**:
- Build clean.
- Per-domain tests pass.
- E2E smoke test: start binary, run a representative tool call (e.g. `place_order` for the riskguard provider, `get_holdings` for the broker provider), verify behaviour unchanged.

**Honest stop per sub-slice**: if any provider signature ends up requiring more than 5 input types, the type explosion signals the underlying domain has too many dependencies. STOP, refactor the domain first (likely a sub-port-extraction).

### Slice P2.5 — Migrate `kc.NewWithOptions` to Fx (optional, ~200 LOC)

**Goal**: replace `kc.NewWithOptions(WithX, WithY, ...)` with `fx.Module("kc", fx.Provide(...))`. Inner Manager composition becomes Fx-graphed.

**Justification for "optional"**: the inner `kc.NewWithOptions` already uses 16 functional options + 16 named init helpers. It's structured. Mode-2 conflict on `manager.go` / `manager_init.go` is much lower than on `app/wire.go`. P2.5 yields a smaller agent-concurrency dividend than P2.1-P2.4.

**If skipped**: `kc.NewWithOptions` becomes an Fx-managed singleton — Fx wires the Manager once via the existing options API. This is the cleanest hybrid: outer DI graph in Fx, inner Manager construction stays in its current shape.

**Verification**: same pattern as P2.4.

**Honest stop**: if migrating the inner Manager produces >300 LOC of provider declarations vs. the current 514-LOC `manager_init.go`, the LOC tradeoff is upside-down — STOP, leave inner Manager unchanged.

### Slice P2.6 — Cleanup pass (~50 LOC)

**Goal**: remove the now-dead init helpers in `app/wire.go` and `kc/manager_init.go` that have been superseded by Fx providers. Update `ARCHITECTURE.md` to reference the provider graph as the canonical composition root. Add `docs/adr/0006-fx-adoption.md` capturing the Wire-vs-Fx decision.

**Files**:
- `app/wire.go`: drop dead helpers (50-100 LOC reduction).
- `ARCHITECTURE.md`: 1-2 paragraphs replaced.
- `docs/adr/0006-fx-adoption.md`: new ADR (~150 LOC).

**Verification**: build + tests clean; `grep -n "initializeServices" app/` returns one definition + the entrypoint caller.

### Total Phase 2 LOC

| Slice | Estimated LOC | Risk profile |
|---|---:|---|
| P2.1 — Fx dependency add | ~30 | LOW |
| P2.2 — leaf providers | ~100 | LOW |
| P2.3 — first `fx.New` beachhead | ~150 | MED-HIGH (first real Fx error class) |
| P2.4 — per-domain provider sets | ~250 | MED (per-domain risk) |
| P2.5 — inner Manager migration (optional) | ~200 | HIGH (LOC explosion risk) |
| P2.6 — cleanup | ~50 | LOW |
| **Total** | **~530-780 LOC** | **3-week sprint, 2 weeks if P2.5 skipped** |

---

## 7. Risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Fx wiring panic at startup with cryptic message | MED-HIGH | 1-2 day debug per occurrence | Use `fx.VisualizeError` and Fx's debug log mode; iterate on smallest provider subgraph first. |
| `go.mod` indirect dependency surfaces a vuln | LOW | Block merge until upstream patches | `go list -m -u all` + `govulncheck` before P2.1 commit. |
| Lifecycle ordering changes break some non-obvious shutdown sequence | MED | Lost data on shutdown (e.g., audit buffer flush) | Migrate lifecycle hooks 1:1 from `app.registerLifecycle`; test shutdown sequence with `BenchmarkGracefulShutdown` (add if missing). |
| LOC explodes past 50% of estimate | MED | Sprint extends from 3 weeks to 5 | Per-slice honest-stop rules already documented. Re-evaluate after P2.4. |
| Fx upgrade breaks our wiring 6 months later | LOW (Fx is conservative on breaking changes) | Mid-sprint of breakage | Pin Fx version; subscribe to release-notes channel. |
| User authorizes Phase 2 then 6+ agents never materialize | MED | Phase 2 LOC sunk for ~zero Axis-B value | Acceptable IF Axis C (portability) genuinely justifies it; else regret. |
| Cryptic "type T not provided" errors during P2.4 | HIGH | 1 day per occurrence | Document each error encountered + its fix in `docs/adr/0006-fx-adoption.md` — turns the sprint into a runbook for future contributors. |
| Concurrent agent edits `app/wire.go` mid-slice | MED-HIGH | Merge conflict on a file Phase 2 is actively rewriting | Coordinate: ANNOUNCE Phase 2 start; ask other agents to gate `app/wire.go` edits during P2.3-P2.6. Or, use worktree-per-agent (per `user_team_commit_protocol.md`). |
| First `fx.New` call panics in DevMode but works in production OR vice versa | LOW | 1-day debug | Run both modes in CI; add `e2e_fx_startup_test.go` covering both. |

---

## 8. Honest assessment

### When to ship Phase 2

Ship NOW if at least ONE of these is true:
1. **Sustained 6+ agent count** is concrete plan within 6 months.
2. **Per-component language-swap** (e.g., Rust ticker, TypeScript widgets) is on roadmap within 24 months.
3. **Empirically measured** `app/wire.go` Mode-2 conflict cost exceeds 1 hour/week (vs. estimated 5-15 min/week today).

Defer if NONE of the above is concrete. Phase 1's value (resolver refactor) IS standalone — it cleaned up the codebase regardless of whether Phase 2 ships. So deferring Phase 2 doesn't waste Phase 1.

### Why NOT to ship Phase 2

- 3-week sprint of pure refactor with no user-visible feature output.
- Multi-week debugging tail risk.
- Adds a build-system step (Wire) or runtime layer (Fx) that future contributors must learn.
- The ~5pt Hex score lift it would unlock is ABOVE the documented anti-rec'd ceiling — under all three current denominators except agent-concurrency-at-scale.

### What deferral DOES NOT cost

- `app/wire.go` is in fine working condition today; the bespoke composition is readable and testable.
- The Wave D Phase 1 work that DID ship (D1-D7) is independently valuable: hoisted use cases are easier to test, Wire-compatibility-ready, and made the resolverFromContext fork measurably dead.
- Future Phase 2 can resume from the exact state of Phase 1; nothing in P1 commits forecloses on later DI adoption.

### Recommended next action

**Stop here. Do not start Phase 2 today.** Bring this scoping doc to the user (this very PR commits it) and ask the §5 questions explicitly:
1. Sustained 6+ agent count plan? Y/N + timeframe.
2. Per-component language-swap plan? Y/N + which component, when.
3. Wire vs Fx preference override? (Default: Fx per §3.3.)
4. Acceptance of 3-week sprint with multi-week tail risk? Y/N.
5. CI/build-surgery tolerance? Y/N (Wire-specific).

If user answers "yes" to (1) AND/OR (2) — schedule Phase 2 start.
If user answers "yes" only to "we might want to someday" without timeframes — the answer under the current three-denominator framework is **defer**, even with the framework correction. "Might want" doesn't trigger the Axis B/C weight uplift; concrete plans do.

---

## 9. Sources cited

- `app/wire.go` — empirical sizing (985 LOC) at HEAD `4e12da9`.
- `app/app.go`, `kc/manager.go`, `kc/manager_init.go`, `kc/manager_use_cases.go` — composition surface mapping.
- `.research/wave-d-resolver-refactor-plan.md` (`66de1ff`) — Phase 1 scoping; this doc executes its §6 Slice D-final.
- `.research/agent-concurrency-decoupling-plan.md` §3.5 — Mode-2 conflict ranking; `wire.go` at #4 priority.
- `.research/scorecard-final.md` (`562f623`) — Wire/fx anti-rec'd column; +5 Hex blocked.
- `.research/path-to-100-business-case.md` — Wire/fx as ceremony under user-MRR denominator (correct under that denominator).
- `feedback_decoupling_denominator.md` — three-axis ROI framework; 2026-04-27 amendment adds tech-stack portability axis.
- `docs/adr/0001-cqrs-bus-pattern.md` through `0005-tool-middleware-chain-order.md` — existing ADR format reference for the planned `0006-fx-adoption.md`.
- `kite-mrr-reality.md` — ₹15-25k MRR target; informs Axis A.

Verification at HEAD `4e12da9`:
- `go build ./kc/... ./mcp/ ./app/` — clean (per Phase 1 D7 commit verification).
- `go test ./kc/ ./kc/usecases/ ./mcp/ ./app/` — clean.
- `grep -c "kc.WithBroker\|resolverFromContext" --include='*.go' -r kc/ mcp/ app/` — zero live references; only history-marker comments remain.

---

*Generated 2026-04-26 evening against HEAD `4e12da9`. Read-only research deliverable. No source files modified. Authorization required to execute §6.*
