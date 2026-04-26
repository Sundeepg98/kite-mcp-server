# Anti-Rec'd Patterns + Plugin Discovery — Deep Research

**HEAD**: `04f311e`. Re-evaluating prior anti-rec verdicts post-AlertDB-inversion (`c647d62`+`3232286`+`43dd423`) and surveying real plugin-discovery alternatives. Read-only research.

**Context**: prior session synthesis (`8596138` PROMOTED Wire/fx; `ebfdf3d` DEMOTED Wire because of 4 structural blockers; `2a1f933` Class 4 re-rejected post-inversion). User asks: state SPECIFIC regression mechanism, conditions-for-flip, ship-plan-LOC if conditions met.

---

## BUCKET A — Anti-rec'd patterns

### A1 — Wire/fx DI container

**Specific regression mechanism (the WHY)**:

The original "Wire eliminates `wire.go` shared edit" claim from `8596138` § 3.5 assumed Wire could express the entire current 858-LOC `wire.go` as a dependency graph. Empirical re-count post-inversion at HEAD `04f311e`:

| Blocker | `ebfdf3d` count | Current count | Status |
|---|---|---|---|
| B1 — Runtime mode conditionals | 6 | **5** | unchanged in shape (`AlertDBPath`, `StripeSecretKey`, `OAuthJWTSecret`, `InstrumentsManager()!=nil`, `StripePricePro==""`) |
| B2 — `app.X = ...` field mutations | 14 | **17** | INCREASED (alertDB, fillWatcher added; AlertDB-inversion was about cycle direction, not field count) |
| B3 — `kcManager.SetX()` calls | 10 | **6** | DECREASED (4 setters eliminated via `WithAlertDB`/`With*Store` options; 6 remaining are genuine mutual-recursion) |
| B6 — Middleware `serverOpts = append(...)` slots | 11 | **10-13** | unchanged (correlation/timeout/audit/hooks/circuitbreaker/riskguard/ratelimit/billing/papertrading/dashboardurl + WithElicitation + WithHooks) |

**The post-inversion shape**: B3 dropped 40% (10→6) — that's the AlertDB-inversion's actual benefit. But B1, B2, B6 are unchanged in structure.

**Why Wire still doesn't fit**:
- **Wire (compile-time)** generates `wire_gen.go` from a builder spec. It cannot express runtime conditionals (B1's 5 mode flags). To handle 5 boolean flags, you'd need 2⁵=32 separate `wire.Build()` invocations — massively worse than 5 `if` blocks.
- **fx (runtime)** can handle conditionals via `fx.Options(condA, modA, modB)`. But fx introduces:
  - **Reflection-based DI resolution at startup**: 3.8ms for 100-dep graph (per Uber benchmarks). Our graph is ~80 deps post-inversion → ~3ms.
  - **Test scaffolding tax**: every unit test that constructs an App-shaped dep graph needs `fx.New(fx.Options(...)).Start()`. Empirically: there are 12 test files that mutate App fields directly today. Migrating to fx would add ~60-100 LOC each = ~720-1200 LOC of test boilerplate.
  - **Cryptic errors**: missing-type errors come as runtime DI-resolution stack traces, not compile errors. Agents debugging unfamiliar codebase regions would lose throughput here, not gain.

**Mode 2 reduction analysis**:
- Wire eliminates `wire.go` ~858 LOC = potentially -30%/wk conflict on that file.
- BUT: B6 middleware order (10-13 ordered slots) is structural — fx can express it as `fx.Provide(NewMiddlewareChain)` but the `NewMiddlewareChain` function is the new shared edit point, identical conflict surface.
- B2 field-list (`type App struct { ... }` 30+ fields) doesn't disappear with fx — fx-injected fields still need to be declared somewhere.
- Net Mode 2 reduction: optimistic estimate ~50% of `wire.go`'s 30%/wk = 15%/wk reduction. But the `App struct` declaration site replaces it.

**Conditions-for-flip** (when Wire/fx becomes net-positive):
1. **6+ permanent agents** routinely editing `wire.go` AND empirical telemetry shows Mode 2 conflict rate >50%/wk. Currently we run at 1-4 agents; no telemetry shows ≥30%/wk.
2. **App struct stabilizes** (no new fields for 6+ months). Currently fields are still being added (`alertDB` Apr 2026; `fillWatcher` Apr 2026). The struct is still growing.
3. **B1 conditionals collapse** — if deployment-mode flags consolidate to 1-2 (from 5). Currently 5 are genuine business requirements (Fly.io vs local vs dev-mode vs alert-db-presence vs Stripe-presence).

**Ship-plan if conditions met**: ~600 LOC fx migration + ~800 LOC test cascade = ~1400 LOC over 3-4 weeks. Score lift +6 (Hex 94→97 +3, SOLID 95→97 +2, Test-Arch 97→98 +1). Density: 6/1400 = **0.43 pts/100 LOC** — barely above floor at the OPTIMISTIC end.

**Verdict**: **DEFER** — none of the 3 flip-conditions met. The AlertDB inversion eliminated 4 SetX calls, which was the ONE blocker most amenable to fx. The remaining blockers (B1, B2, B6) are structural to deployment-mode and Go's struct-declaration model. Ship-plan does not become net-positive without external trigger.

---

### A2 — Logger Provider wrap

**Specific regression mechanism (the WHY)**:

The user's framing: "it's a one-time migration; after migration agents change ONE impl file instead of 50 callsites — that should IMPROVE throughput". Let's verify empirically.

**Empirical state at HEAD `04f311e`**:
- 329 production sites use `*slog.Logger` directly (grep -c production-only).
- Logger is ALREADY mockable: `slog.New(slog.NewTextHandler(io.Discard, nil))` is a 1-line mock. Tests pass `*slog.Logger` constructed in 5-10 LOC of helper.

**The ACTUAL frequency-weighted Mode 2 lift** (per `8596138` analysis, verified):
- Logger config changes occur ~1/year on stable codebases (e.g., switching format, adding sampling, adding correlation IDs).
- Each change today = touch 0-5 sites (most slog config is at construction in `app/app.go`, not at usage sites).
- Net annual conflict reduction: ~0 — logger usages don't conflict because they're additive (`logger.Info(...)`).

**Why "one-time migration improves throughput" is WRONG**:
- The 329 callsites are NOT shared edit points. Two agents adding `logger.Info("foo")` in different files never conflict. Logger usage is additive across the codebase.
- The "Logger interface" pattern would introduce a NEW shared edit point: the interface declaration. Adding a method to logging surface = touch the interface = serialization.
- **Empirical evidence from `2a1f933` Class 4**: pre-conditions for genuine logger-wrap value (multi-tenant logging, per-App audit-log routing, async dispatch) — none met. Audit log is single SQLite table. Single-tenant. `*slog.Logger` already supports async via handler design.

**Conditions-for-flip**:
1. **Multi-tenant logging requirement**: per-User log streams routed to different sinks. NOT currently a requirement (users access via shared dashboard).
2. **Per-App log routing**: separate App instances each writing to their own log file. NOT a current need (single Fly.io instance).
3. **Switching from slog to a 3rd-party logger** (e.g., zap for performance): MIGHT trigger the migration, but at that point you'd just `s/logger\.Info/zap.Info/g` — sed-replaceable, not interface-wrap-needing.

**Ship-plan if conditions met**:

Even IF a flip-condition triggers, the migration is:
- Define `kc/logging/Logger` interface (~30 LOC).
- Replace 329 `*slog.Logger` types with `logging.Logger` (~329 line edits = ~329 LOC of pure mechanical change).
- Adapter `*slogLogger` impl (~50 LOC).
- Test cascade: zero (mocks are 1-line slog impls already).
- **Total**: ~410 LOC.

**Score lift**: +1 SOLID (DIP improvement). Density: 1/410 = **0.24 pts/100 LOC** — BELOW 0.4 floor.

**Verdict**: **GENUINE DEFER** — the regression mechanism is "introduces shared interface edit point with no measurable Mode 2 benefit". The frequency-weighted lift is ~0 even AFTER migration. Below 0.4 density floor regardless. The user's "should improve throughput" instinct is wrong because logger usage is additive (non-conflicting), not shared-edit.

---

### A3 — Middleware split

**Specific regression mechanism (the WHY)**:

Current state: 10-13 middleware appends in `app/wire.go:454-623`. Each middleware lives in its own package (`mcp/circuitbreaker`, `kc/riskguard`, `kc/billing`, etc.) — **the implementations are already split**. What's monolithic is the **chain composition** in `wire.go`.

**Why the user's "registry-based ordered chain" idea is interesting**:

The user proposes: "similar to tool registry pattern shipped in B77 — eliminate the central edit". Let me investigate the analogy.

**Tool registry pattern (B77)** works because:
- Each tool has a unique name (no ordering dependency between tools).
- `mcp.Register(name, handler)` is order-independent.
- The registry is queried at request time; agents adding new tools never coordinate.

**Middleware ordering is FUNDAMENTALLY DIFFERENT**:
- correlation MUST wrap timeout (so cancellation propagates correctly).
- audit MUST wrap riskguard (so blocked orders get logged).
- billing MUST wrap papertrading (so paper trades don't bypass billing).
- ratelimit MUST wrap riskguard (so rate-limit rejects don't trigger riskguard counters).

These are 4 ordering constraints. A "registry-based middleware" would need to express these constraints declaratively. Two patterns work:

**Pattern α — Topological-sort registry** (each middleware declares "I run AFTER X, BEFORE Y"):
```go
RegisterMiddleware("audit", AuditMW, AfterCorrelation, BeforeRiskguard)
```
- Cost: ~100 LOC registry + sort logic.
- Per-middleware: 1 line registration.
- Mode 2 conflict surface: declarations live with middleware impls → no shared file.
- Verification: cycle detection at startup; constraint conflicts surface as panic.
- **Risk**: order-edge cases when constraints under-specify. E.g., if X says "AfterY" and Z also says "AfterY" but doesn't specify order with X, the order between X and Z is undefined. This is a real bug-risk surface.

**Pattern β — Phase-numbered registry**:
```go
RegisterMiddleware("audit", AuditMW, Phase: 30)
```
- Phases hardcoded: 10=correlation, 20=timeout, 30=audit, 40=hooks, 50=circuitbreaker, 60=riskguard, 70=ratelimit, 80=billing, 90=papertrading, 100=dashboardurl.
- Cost: ~30 LOC.
- Per-middleware: 1 line registration with phase number.
- Mode 2 conflict surface: phase-number list lives in registry constants → IS a shared file.

**Verdict on patterns**:
- α is more elegant but has constraint-underspecification risk.
- β has the same shared edit surface as today (the phase-number list).

**Mode 2 reduction**:
- Today: 10-13 lines in `wire.go:454-623`. Adding a new middleware = +1 line in this block. Conflict prob: 15%/wk per `8596138`.
- Pattern α: each middleware self-registers in its own package → conflict prob: ~0% per individual middleware, BUT new constraint conflicts at startup time = different failure mode.
- Pattern β: shared file moves from `wire.go:454-623` to `mcp/middleware_phases.go`. Same conflict prob.

**Conditions-for-flip**:
1. **8+ middleware ADDED per quarter** (currently ~1-2 per quarter). Then per-middleware shared-edit reduction would matter. Empirically: middleware count grew from 7 (Apr 2025) to 10-13 (Apr 2026) = 3-6 middlewares/year. Below the threshold.
2. **External plugin authors adding middleware**: this would justify pattern α (plugin author shouldn't edit central registry). Currently zero plugin-authored middleware.

**Ship-plan if conditions met**:
- Pattern α: ~150 LOC registry + topological sort + 10-13 in-place migrations. ~250 LOC total.
- Score lift: +1 Middleware (95→96, but 95 was already declared "permanent ceiling" — would re-open).
- Density: 1/250 = **0.4 pts/100 LOC** — at the floor, not above.

**Verdict**: **GENUINE DEFER** — middleware-add frequency is too low to justify cost. Pattern α has constraint-underspec risk. Pattern β doesn't actually move the shared edit. The 95 "permanent ceiling" verdict in `87e9c17` rubric calibration was correct. The user's "registry-based ordered chain" idea is real but won't return positive ROI until middleware count grows 5×.

---

### A4 — Full ES reconstitution

**Specific regression mechanism (the WHY)**:

User asks: "could a hybrid (event store as source-of-truth + materialized SQL views rebuilt from events) achieve same agent-concurrency wins?"

**Empirical state at HEAD `04f311e`**:
- `kc/eventsourcing/projection.go` (238 LOC): **the hybrid pattern is already PARTIALLY shipped**.
- `Projector` maintains live in-memory aggregates (orders/alerts/positions) by subscribing to `domain.EventDispatcher`.
- 3 aggregates have full reconstitution: `LoadAlertFromEvents`, `LoadOrderFromEvents`, `LoadPositionFromEvents` (verified at `kc/eventsourcing/aggregate_edge_test.go:611`).
- Outbox pump (`kc/eventsourcing/outbox.go`) drains `event_outbox` → published.
- `domain_events` table is the append-only event log (the source-of-truth substrate).

**What the "full ES" gap is**:
The 85 score is from `path-to-100-business-case.md`: "+8 to 100 needs (a) outbox crash-safety (b) billing webhook events (c) oauth ClientStore events (d) paper-engine events (e) admin-read events". That's 5 bullet items, NOT "full state-from-events for ALL aggregates".

**Re-reading the gap**: NOT "replay-from-history-on-startup". The current 85 score is missing **event coverage** for billing/oauth/paper/admin-read paths. These can be added incrementally. Each is ~30-80 LOC.

**Why the original "full ES" rejection was correct**:
- Replay-from-history on startup = O(N) where N = lifetime event count. For ~1M events at 0.5ms each (conservative SQLite read+apply), that's 500s = 8min. Unacceptable startup latency.
- Real ES systems use **snapshots** to avoid full replay (e.g., snapshot at every 1000 events, replay from last snapshot). That's another 200+ LOC of snapshot logic + tested rollback.
- For our scale (single-tenant Fly.io, ~10K-100K events lifetime), full replay would take ~5-50s on startup — borderline acceptable but no real benefit since SQLite-backed read models survive restarts.

**Hybrid pattern that's actually shippable**:

The hybrid the user describes IS the current architecture, just not advertised. Code path:
- Write: use case → CQRS command bus → handler → SQLite write → emit domain event → Projector subscribes + updates aggregate.
- Read: query side reads from SQLite read models (covers crash recovery for free — SQLite IS the materialized view).
- Replay: only used in tests (`LoadAlertFromEvents`); production never replays.

**The gap "full ES" claims 85→100 means** ≠ "switch to event-replay-on-startup". It means **fill the event coverage matrix**:
- Billing tier change events (currently no event emitted on `Tier=TierFree` write).
- OAuth ClientStore events (currently no `client.registered` event).
- Paper engine state events (currently no `paper.order.placed` event).
- Admin-read events (currently no `admin.read.X` event for read-side audit).

These are 4 separate ~30-50 LOC additions. Each is a discrete value.

**Conditions-for-flip on FULL replay-from-history**:
1. **Audit reconstruction requirement**: regulator demands "show me state at time T from events alone". DPDP §17 / SEBI subpoena scenario. NOT a current requirement.
2. **Event-store database growth**: if we move event store to its own DB (Postgres), full reconstitution becomes the migration mechanism. NOT a current need (SQLite suffices).

**Ship-plan for the INCREMENTAL gap (not full replay)**:
- Billing tier events: ~40 LOC.
- OAuth ClientStore events: ~50 LOC.
- Paper engine events: ~60 LOC.
- Admin-read audit events: SKIP (already covered by `kc/audit/store.go` tool-call audit trail; full equivalent).

**Total: ~150 LOC**, +3 ES (85→88). Density: 3/150 = **2.0 pts/100 LOC** — above floor. NOT what was rejected.

**Verdict**: **PARTIAL SHIP-PLAN VIABLE** — the "full ES" anti-rec is correct (replay-from-history doesn't return value at our scale). But "billing/oauth/paper events" are INCREMENTAL extensions of the already-hybrid architecture, NOT full ES. These were lumped under "full ES" anti-rec but should be reclassified.

**SHIP-NOW candidate**: billing tier change event (~40 LOC, isolated). Already in `.research/blockers-to-100.md` as deferred. Re-evaluate per-blocker.

---

## BUCKET B — Plugin discovery alternatives

**Current state at HEAD `04f311e`**:
- HashiCorp `go-plugin` v1.7.0 IS adopted: `kc/riskguard/subprocess_check.go` (379 LOC) + `kc/riskguard/checkrpc/types.go` (216 LOC) + `kc/riskguard/hclog_shim.go` (119 LOC) + `examples/riskguard-check-plugin/main.go` (123 LOC).
- Used for ONE specific extension point: subprocess riskguard checks.
- Compile-time tool plugins (B77 per-App `*mcp.Registry`) cover everything else.

**The "discovery" gap**: there's no filesystem-based plugin LOADER. Plugins are either:
1. Compile-time registered (via `init()` and import).
2. Subprocess-spawned via `RegisterSubprocessCheck(executable, args)` — caller provides the path.

There's no `plugins/` directory scan + auto-load. That's the irreducible "1pt residual" claim in `blockers-to-100.md`.

### B1 — HashiCorp go-plugin: extend to "discovery"

**Capability**: subprocess RPC. Fully adopted.

**Windows compat**: yes (Windows is a first-class go-plugin target via `os/exec`).

**Perf**: ~1-2ms per RPC call (per `kc/riskguard/subprocess_check.go:39-41` empirical claim).

**Security model**: subprocess isolation. Plugin crash doesn't kill host. Optional checksum verification + TLS for RPC. Strong.

**Integration LOC for "discovery" extension**: ~100 LOC.
- Watch a `~/.kite-mcp/plugins/` directory (or `--plugin-dir` flag).
- For each `*.plugin` file (or just executables with a manifest sidecar), call `RegisterSubprocessCheck`.
- Reload on SIGHUP or fsnotify event.

**Verdict**: **ADD-AS-OPTION viable** — extends current adoption. ~100 LOC builds on the existing 837 LOC go-plugin infrastructure. Score lift: +1 Plugin (99→100). Density: 1/100 = **1.0 pts/100 LOC** — above floor.

### B2 — Wasm plugins (wazero / extism)

**Capability**:
- `tetratelabs/wazero` v1.6+: zero-CGO WebAssembly runtime. Compile in-process.
- `extism/go-sdk`: higher-level Wasm plugin host built on wazero.

**Windows compat**: wazero is pure-Go, supports Windows fully (no CGO requirement).

**Perf**: wazero compiler mode is comparable to native Go for math-heavy code; interpreter mode is 5-10× slower. Per [wazero README](https://github.com/tetratelabs/wazero): "wazero 1.0+ is in production use".

**Security model**: Wasm sandbox is stronger than subprocess (no syscall access by default; explicit host-function imports control what plugin can do). Tighter than HashiCorp go-plugin.

**Integration LOC**: ~250-400 LOC for first wasm plugin loader.
- wazero runtime construction.
- WASI imports (memory, time, random) for plugin compatibility.
- Host-function imports for our domain (place_order, get_quote, etc.) — each tool exposed needs a host-function bridge.
- Plugin loader scans `~/.kite-mcp/wasm-plugins/*.wasm`, instantiates module, invokes `_start` or named export.

**Critical issue for THIS codebase**: the value-add of Wasm over subprocess is (a) language-agnostic plugins (Rust/JS/Python compile to Wasm), (b) finer sandbox. Both nice-to-have, but our existing go-plugin adoption already gives us strong isolation. **Marginal value: low**.

**Verdict**: **DEFER** — Wasm is genuinely better for hostile-untrusted plugin environments (e.g., user-uploaded plugins). For our trusted-author single-maintainer scenario, the marginal benefit doesn't justify ~400 LOC + new dep. Score lift: +1 Plugin (99→100), but density ~0.25 pts/100 LOC which is BELOW floor.

### B3 — gRPC subprocess (alternative to net/rpc)

**Capability**: HashiCorp go-plugin already supports gRPC mode (vs net/rpc default). Switching is config-only.

**Windows compat**: yes.

**Perf**: gRPC is faster for streaming/bidi than net/rpc but ~5-10% slower for simple unary calls (protobuf marshaling overhead).

**Security model**: identical to net/rpc go-plugin (subprocess isolation).

**Integration LOC**: ~50 LOC (wire `plugin.NewClient` with `plugin.HandshakeConfig.GRPCConn`).

**Verdict**: **DEFER** — pure perf optimization with no agent-concurrency or score-lift benefit. Trade-off is bidirectional streaming support which we don't need.

### B4 — Build-tag-based plugin compilation

**Capability**: Go build tags allow conditional compilation. `//go:build kite_plugin_X` at top of plugin file → `go build -tags kite_plugin_X` includes it.

**Windows compat**: yes (build tags are compiler-side).

**Perf**: zero runtime cost (compiled in).

**Security model**: same as main binary (no isolation; plugin crashes the host).

**Integration LOC**: ~0 LOC (it's a build-time pattern, no runtime code).

**Verdict**: **EXPERIMENTAL — interesting for forks**. A self-host operator who wants custom riskguard checks compiled in could `go build -tags my_check ./...`. It's NOT discovery (still requires rebuild), but it's a viable plugin model for trusted-fork-host. Doesn't lift Plugin dim score because the gap is runtime discovery.

### B5 — Embedded scripting (Tengo/Starlark/goja)

**Capability**:
- `Starlark` (Google, used in Bazel): hermetic dialect of Python. No filesystem/network/clock access by default. Per [starlark-lang.org](https://starlark-lang.org/): designed for safe, parallel, deterministic execution.
- `Tengo`: Go-native scripting language, simpler than Starlark.
- `goja`: ECMAScript 5.1 in Go. Good for JS-author plugins.

**Windows compat**: all three are pure-Go, full Windows support.

**Perf**: 5-50× slower than native Go for compute-heavy code; fast enough for rules-engine-style plugins.

**Security model**: Starlark is the strongest — fully hermetic. Tengo and goja are NOT hermetic by default (require explicit sandbox setup).

**Integration LOC for a Starlark-based "rules plugin"**: ~150 LOC.
- `kc/scripting/starlark_runtime.go` — interpreter setup with our domain bindings (ToolCall, RiskCheck, OrderRequest types as Starlark values).
- `kc/scripting/loader.go` — scan `~/.kite-mcp/rules/*.star` files, evaluate.
- Per-rule sandbox time-limit (Starlark supports execution-step limits).

**Use case fit for Kite MCP**: a USER could write `.star` files defining custom riskguard rules without compiling a Go binary. e.g., `if order.notional > Decimal("100000") and instrument.exchange == "BSE": deny("BSE-large")`. This is a real value-add for power users.

**Verdict**: **EXPERIMENTAL — worth a spike**. Starlark gives us:
- Runtime-loaded user plugins (the discovery gap).
- Strong hermetic sandbox (better than subprocess for untrusted code).
- No compilation barrier for plugin authors.
- Pure-Go, no CGO, full Windows compat.

BUT: the use case is speculative (no current user requesting). Score lift: +1 Plugin (99→100). Density: 1/150 = **0.67 pts/100 LOC** — ABOVE floor. The cost isn't crazy but the value is unproven.

### B6 — OCI plugin distribution

**Capability**: distribute plugins as OCI artifacts (Docker registries). Tools: `oras-go`, `containerd/registry`.

**Windows compat**: pulling/verifying OCI artifacts works on Windows; running them requires the underlying runtime (subprocess for binaries, wazero for Wasm).

**Perf**: pull-time fetch overhead; runtime depends on plugin format.

**Security model**: OCI signature verification (`cosign`) is strong. Distribution trust strengthens.

**Integration LOC**: ~200 LOC (oras-go pull + verify + write to local dir + delegate to B1/B2 for execution).

**Verdict**: **DEFER** — distribution layer over execution layer. Useful for marketplace scenarios. Currently no marketplace exists for our plugins. Not a discovery solution; it's a distribution solution.

---

## Summary tables

### Bucket A verdicts

| Pattern | Mechanism | Conditions-for-flip | Ship if flipped (LOC) | Density | Verdict |
|---|---|---|---|---|---|
| Wire/fx | fx ~3.8ms startup tax + ~1000 LOC test cascade; B1/B2/B6 still structural | 6+ permanent agents AND telemetry shows >50%/wk wire.go conflict AND App struct stable 6mo | ~1400 | 0.43 | **DEFER** |
| Logger wrap | usage is additive (non-conflicting); interface declaration BECOMES new shared edit point | multi-tenant logging or per-App routing required | ~410 | 0.24 | **DEFER (below floor)** |
| Middleware split | order constraints make registry-pattern NOT analogous to tool registry; Pattern α has constraint-underspec risk | 8+ middleware adds/quarter (currently 1-2/q) | ~250 | 0.4 | **DEFER (at floor; cost not justified)** |
| Full ES (full replay) | O(N) replay = 500s for 1M events; SQLite already does the materialization | regulator demand for state-at-time-T reconstruction | ~600 | varies | **DEFER (full replay)** |
| ES incremental events | NOT actually anti-rec'd — was lumped together | already viable | ~150 | 2.0 | **SHIP-LATER (extract from anti-rec bundle)** |

### Bucket B verdicts

| Alternative | Capability | Win compat | Perf | Security | LOC | Density | Verdict |
|---|---|---|---|---|---|---|---|
| HashiCorp discovery extension | extend existing adoption | full | 1-2ms RPC | strong | ~100 | 1.0 | **ADD-AS-OPTION** |
| Wasm (wazero/extism) | language-agnostic + tighter sandbox | full | comparable native | tighter | ~400 | 0.25 | **DEFER** |
| gRPC subprocess | perf swap | full | 5-10% slower unary | identical | ~50 | 0 | **DEFER** |
| Build-tag plugins | compile-time | full | zero | none | ~0 | 0 | **EXPERIMENTAL — useful for fork ergonomics** |
| Starlark scripting | hermetic user-rules | full | 5-50× slower | strongest | ~150 | 0.67 | **EXPERIMENTAL — worth a spike** |
| OCI distribution | marketplace | full | pull overhead | strong | ~200 | 0 | **DEFER** |

---

## Final disposition

**SHIP-NOW (this dispatch)**:
1. **HashiCorp discovery extension** (~100 LOC): scan `~/.kite-mcp/plugins/` for executable manifests, auto-register via existing `RegisterSubprocessCheck`. +1 Plugin (99→100). Density 1.0.

**SHIP-LATER (precondition triggers documented)**:
2. **ES incremental events** (~150 LOC): billing tier + oauth client + paper engine events. Was incorrectly lumped under full-ES anti-rec. Re-classified.

**EXPERIMENTAL — separate spike branch**:
3. **Starlark scripting plugin** — value-prop is power-user-rules without compilation. No current user demand. Spike-worthy when first user asks for custom scriptable rules.
4. **Build-tag plugins** — useful for fork-host operator ergonomics. Document in `docs/byo-api-key.md`.

**GENUINE DEFER**:
- Wire/fx: 1400 LOC, 0.43 density. Conditions not met (1-4 agents, struct still growing, 5 mode flags).
- Logger wrap: 410 LOC, 0.24 density (below floor). Mechanism is wrong (usage is additive, interface IS the new shared edit).
- Middleware split: 250 LOC, 0.4 density (at floor). Add-frequency too low.
- Full ES replay: 600 LOC + snapshot logic. Out-of-scope without regulator trigger.
- Wasm/gRPC/OCI: marginal value over current adoption.

---

*Generated 2026-04-26 against HEAD `04f311e`. Read-only research deliverable; ship-list executed in subsequent commits.*

**Sources cited**:
- [HashiCorp go-plugin GitHub](https://github.com/hashicorp/go-plugin)
- [Extism Go SDK](https://github.com/extism/go-sdk)
- [tetratelabs/wazero GitHub](https://github.com/tetratelabs/wazero)
- [Starlark in Go](https://github.com/google/starlark-go)
- [Uber fx benchmarks (Medium)](https://medium.com/@geisonfgfg/dependency-injection-in-go-fx-vs-wire-vs-pure-di-structuring-maintainable-testable-applications-61c13939fd66)
- Internal: `8596138` (decoupling plan), `ebfdf3d` (4-blocker analysis), `2a1f933` (Class 4), `c647d62`+`3232286`+`43dd423` (AlertDB cycle inversion)
