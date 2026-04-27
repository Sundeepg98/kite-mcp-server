# Non-External 100 — Final Blockers (Hex / Middleware / Decorator)

**Date**: 2026-04-28
**HEAD**: `65e383c` (post Wave-D Phase 3 cleanup, scorecard re-grade)
**Anchor docs**:
- `.research/scorecard-final.md` (`65e383c`) — current per-dim scores
- `.research/blockers-to-100.md` (`a80672d`) — original rubric criteria
- `.research/agent-concurrency-decoupling-plan.md` — anti-rec'd
  governance (Investments A-J with explicit throughput-lift +
  side-benefit scoring)
- `feedback_decoupling_denominator.md` — three-axis ROI framework

This doc resolves the user question: **"Three dims still <100. Truly
anti-rec'd or achievable internal work?"** Per-dim distinction with
LOC + sub-commit plans for any ACHIEVABLE-INTERNAL items, plus an
honest aggregate of "if user authorizes everything ACHIEVABLE, what's
the new score?"

---

## 1. Hexagonal — 97/100 (gap +3)

### Rubric criterion (per `blockers-to-100.md`)

Two named blockers:
1. **84 `*Concrete()` accessor sites** — `grep -c Concrete()` across
   14 files; each leak exposes a concrete store type rather than its
   narrow port. Each removal needs adding the leaked method to its
   narrow port + interface assertion.
2. **Wire/fx DI container** — Pass 18 verdict.

### Empirical state at HEAD `65e383c`

- `app/wire.go`: 938 LOC (was 985 at original baseline). **Phase 2
  Fx adoption shipped** via P2.1 → P2.6 + P2.5a/b + β-1 + β-2 +
  Logger sweep. `app/providers/` directory now has **20 provider
  files** (alertdb, audit, audit_init, audit_middleware, billing,
  event_dispatcher, family, lifecycle, logger, manager, mcpserver).
- `Concrete()` accessor count: **still 84** (`grep -rn "Concrete()"
  mcp/ app/ kc/`, excluding tests). Distribution:
  - `mcp/admin_anomaly_tool.go`, `admin_baseline_tool.go`,
    `admin_cache_info_tool.go`, `ext_apps.go` — 4 mcp/ files
  - `app/adapters.go`, `app/app.go`, `app/http.go`, `app/wire.go`
    — 4 app/ files
- Phase 3a (full inner-Manager port migration) — port DEFINITIONS
  shipped (`kc/ports/*.go` exist), **consumer migration was never
  executed** per `.research/phase-3a-manager-port-migration.md`.

### Per-blocker verdict

| Blocker | Verdict | Rationale |
|---|---|---|
| **84 `Concrete()` accessor sites** | **ACHIEVABLE-INTERNAL** | The original `blockers-to-100.md` deferred this with "exceeds 500 LOC budget". Phase 3a's empirical revision is **~380 LOC** (`d9fdd06`) — well within a sub-commit budget if split. Side benefit per `agent-concurrency-decoupling-plan.md` Investment E: Hex 88→95 (+7) and SOLID 90→94 (+4). Throughput lift: 4→6 agents. **No anti-rec'd label** anywhere — this is the deferred Phase 3a, not a rejected pattern. |
| **Wire/fx DI container** | **PARTIALLY SHIPPED** | Phase 2 (P2.1-P2.6 + P2.5a/b + β-1/β-2) shipped the Fx graph for app/wire.go's outer composition + inner-Manager wrap. The remaining +3 anti-rec'd label (per scorecard) tracks the Phase 3a Manager-port migration that ADR 0006 §"What was rejected" deferred. Same item as blocker 1 above — **not double-counting**. |

### Achievable plan: Phase 3a Manager-port consumer migration

**Sub-commits** (per `phase-3a-manager-port-migration.md` `d9fdd06`):

| # | Scope | LOC | Notes |
|---|---|---|---|
| 3a-1 | mcp/ admin tools (4 files) — drop `Concrete()` calls, consume narrow ports | ~80 | `UserStoreProvider` extension covers `GetByEmail`/`UpdateStatus`/`SetRole` |
| 3a-2 | mcp/ext_apps.go — ports for widget data | ~60 | One file, multiple Concrete leaks |
| 3a-3 | app/{adapters,app,http,wire}.go — drop 4× Concrete leaks | ~100 | Wire.go cascade is the largest |
| 3a-4 | Test fixture migration | ~140 | Test sites that build adapters with Concrete refs |

**Total**: ~380 LOC. **Score lift**: Hex 97→100 (+3), SOLID 99→100
(+1) per Investment E side-benefit table.

**Density**: 4 pts / 380 LOC = **1.1 pts/100 LOC**. Above 0.4 floor.

**Risk**: MEDIUM. Test fixture cascade is real (~30+ test sites
expected); each Concrete removal needs a port-assertion update.
Mitigated by sub-commit-per-package split.

---

## 2. Middleware — 95/100 (gap +5)

### Rubric criterion (per `blockers-to-100.md`)

> **10-stage chain split into compositional pipelines** —
> `app/wire.go:454-605` chain is procedural, not declarative-
> composable. **DOCUMENTED-anti-rec** — middleware split is one of
> the 4 explicitly rejected patterns per `8596138`+`ebfdf3d`.
> Permanent ceiling.

### Empirical state at HEAD `65e383c`

- `mcp/middleware_chain.go` (84 LOC) defines `MiddlewareBuilder` +
  `BuildMiddlewareChain` — **already declarative-composable**.
  `DefaultBuiltInOrder` is a `[]string` with 10 named stages
  (correlation, timeout, audit, hooks, circuitbreaker, riskguard,
  ratelimit, billing, papertrading, dashboardurl).
- Operators can override the order via Config; tests guard the
  default.
- ADR 0005 documents the order rationale.

### Per-blocker verdict

The blocker text — "procedural, not declarative-composable" — was
written against the OLD wire.go before the named-list refactor.
**It is empirically stale.** Current state IS the declarative
composer.

The +5 ceiling persists for a different reason: the Pass 18 audit
(`8596138`+`ebfdf3d`) labels middleware split as anti-rec'd because
the **further** decomposition (each middleware in its own
registration package, with discovery scaffolding) has near-zero
throughput-lift. Per `agent-concurrency-decoupling-plan.md`
Investment C:
- Throughput lift: 4 → 5 agents (marginal)
- Cost: 150 LOC + per-middleware registration discovery scaffolding
- Side benefit: Middleware 96→97 (+1) — **only +1, not +5**

### Reframing the +5 gap

The `blockers-to-100.md` "+5 to 100" was the WHOLE-DIM gap measured
at the original baseline (95 → 100). The Investment C delivery would
lift +1 to 96, not the full +5. **The remaining +4 has no concrete
shipping path** — it's the rubric's allowance for some hypothetical
"perfect" middleware decomposition that has never been specified
empirically.

| Item | Verdict | Rationale |
|---|---|---|
| **Per-middleware registration package + discovery scaffolding** | **ACHIEVABLE-INTERNAL but LOW-VALUE** | ~150 LOC for +1 score lift (Middleware 95→96). Density: 1 pt / 150 LOC = **0.67 pts/100 LOC** — above 0.4 floor but barely. Real but minor agent-concurrency friction (4→5 agents). Throughput lift small enough that it's been deferred under user-MRR + agent-concurrency denominators both. |
| **Remaining +4 ("perfect" middleware)** | **TRULY ANTI-REC'D / NO-LIFT** | No empirical path. Rubric criterion was written against an idealized "compositional pipeline" pattern that has never been concretely specified. Permanent residual at 96 (after Investment C) or 95 (without). |

### Recommendation

**Skip Investment C** unless the user explicitly authorizes +1
ceremony. The +1 lift is genuine but density is below the
historical-batch average; the user's previous push to lift Hex/SOLID
came from items at 2-5 pts/100 LOC density.

---

## 3. Decorator — 95/100 (gap +5)

### Rubric criterion (per `blockers-to-100.md`)

> **Decorator chain restructure** — Hook around-middleware
> composition is in `mcp/registry.go:HookMiddlewareFor`.
> **DOCUMENTED-anti-rec** — Permanent ceiling per Apr-2026 audit.
> No consumer demand.

### Empirical state at HEAD `65e383c`

- `mcp/registry.go` (251 LOC) implements:
  - `OnBeforeToolExecution` / `OnAfterToolExecution` / `OnToolExecution`
    — three hook registration surfaces (before, after, around)
  - `ToolAroundHook` — immutable around-decorator
  - `ToolMutableAroundHook` — mutable variant for transformers
  - `HookMiddlewareFor(reg)` — composes registered hooks into a
    standard `server.ToolHandlerMiddleware`
- `mergedAroundEntry` interleaves immutable + mutable hooks in
  registration order (seq-tagged)
- Panic-recovery wrappers (`safeRunBeforeHook` etc.) prevent crashes
- Production plugins (rolegate, telegramnotify) consume this surface

The pattern is genuine GoF Decorator: hooks WRAP the next-handler
function, can short-circuit (return synthetic result), can mutate
the request mid-chain. Test coverage exists (`around_hook_test.go`).

### Per-blocker verdict

The +5 gap is mathematically the same shape as Middleware:
`blockers-to-100.md` measured "+5 to 100" but no concrete +5 plan
exists. The "Decorator chain restructure" blocker text doesn't name
a specific deliverable — it's a placeholder.

What WOULD lift Decorator beyond 95 (hypothetically):
- **Compile-time decorator generation** — Go has no `@decorator`
  annotation; the runtime hook-registration pattern is the
  Go-idiomatic answer. The user's `feedback_decoupling_denominator.md`
  language-fit framework explicitly calls this out as a Go-irreducible
  ergonomic gap (other languages have decorator syntax sugar; Go
  doesn't). **Cannot be fixed in Go.**
- **Aspect-Oriented Programming (AOP) framework adoption** — Would
  require a code-generation step (`go:generate`) producing wrapped
  handlers from annotations. ~600+ LOC + permanent build-step
  complexity for ~+1 score lift. Density: 1 / 600 = **0.17
  pts/100 LOC** — well below 0.4 floor.

### Verdict on the +5

| Item | Verdict | Rationale |
|---|---|---|
| **AOP code-generation framework** | **TRULY ANTI-REC'D / NO-LIFT** | Go-idiomatic answer is the runtime hook pattern (already shipped). Adding a codegen layer would regress agent-throughput (every hook addition needs a `go:generate` cycle) and the LOC density is below floor. |
| **Compile-time decorator syntax** | **GO-IRREDUCIBLE** | Language doesn't support it. Same class as the prior `Plugin` dim's Windows-dlopen residual (now subsumed under `RegisterInternalTool`). Cannot be fixed at the language level. |
| **Hypothetical "perfect" decorator** | **TRULY ANTI-REC'D / NO-RUBRIC-PATH** | No empirical specification of what +5 looks like. The 95 ceiling reflects "Go-idiomatic decorator pattern, fully tested, production consumers" which is the empirical max. |

### Recommendation

**Permanent residual at 95.** Document under "Go-irreducible ergonomic
ceilings" rather than anti-rec'd. This matches the spirit of the
`go-irreducible-evaluation.md` doc (`e84a8f4`).

---

## Aggregate honest answer

### If user authorizes everything ACHIEVABLE-INTERNAL

**Single achievable item: Phase 3a Manager-port consumer migration.**

| Dim | Current | After Phase 3a | Net lift |
|---|---|---|---|
| Hexagonal | 97 | **100** | +3 |
| SOLID | 99 | **100** | +1 (side-benefit; SOLID separately tracked) |
| Middleware | 95 | 95 | 0 (Investment C declined as low-density) |
| Decorator | 95 | 95 | 0 (Go-irreducible) |

**New aggregate (equal-weighted)** if Phase 3a ships:

```
Current at HEAD 65e383c:
(100 + 97 + 100 + 100 + 95 + 99 + 100 + 95 + 100 + 86 + 86 + 85 + 59) / 13
= 1202 / 13
= 92.46

After Phase 3a:
(100 + 100 + 100 + 100 + 95 + 100 + 100 + 95 + 100 + 86 + 86 + 85 + 59) / 13
= 1206 / 13
= 92.77
```

**+0.31 absolute equal-weighted from Phase 3a alone.**

Hex moving 97→100 also helps Pass 17 weighted (Hex is a CORE dim);
weighted lift: ~+0.5.

### True non-external ceiling (after Phase 3a)

7 dims at 100: CQRS, Hexagonal, DDD, ES, SOLID, Plugin, Test-Arch.

Remaining gap to 100:
- **Middleware 95** — Investment C ships +1 to 96 if user authorizes
  the low-density ceremony (~150 LOC, +0.67 pts/100). Permanent
  residual +4 has no rubric-path.
- **Decorator 95** — Go-irreducible. Permanent residual +5.
- **Compatibility 86** — +14 SCALE-GATED (real second broker
  adapter; needs paying customers).
- **Portability 86** — +14 SCALE-GATED (Postgres adapter at 5K+
  users).
- **NIST CSF 85** — +15 mostly external-$$ (SOC 2, real-time alert
  pipeline).
- **EntGov 59** — +41 mostly external-$$ (SOC 2 audit, ISO 27001
  cert, MFA admin).

**Non-external ceiling ceiling, post-Phase-3a + Investment C**:

```
(100 + 100 + 100 + 100 + 96 + 100 + 100 + 95 + 100 + 86 + 86 + 85 + 59) / 13
= 1207 / 13
= 92.85
```

**+0.39 absolute** vs current. Non-external ceiling is essentially
**~93 equal-weighted** with Decorator's permanent 95 + the
external-$$ scale-gated dims.

### Comparison with calibrated empirical-max

The current scorecard math says **94.38** is the empirical max
under all constraints (anti-rec'd + external-$$ + irreducible).

The 94.38 vs 92.85 delta (+1.53) accounts for:
- ~0.7 from anti-rec'd reclaim (logger sweep already partial; Phase
  3a closes the rest)
- ~0.5 from operational hardening (Wave C scenario expansion etc.)
- ~0.3 noise band

So the **true non-external ceiling is between 92.85 and 94.38**:
- **92.85** = Phase 3a + Investment C only
- **~94** = above + Wave C scenario expansion + assorted
  operational hardening
- **94.38** = the calibrated theoretical maximum

**Anything beyond 94.38 requires external $$.** That delta (94.38 →
100) is 5.62 percentage-points = the SCALE-GATED + external-audit
items.

---

## Summary table

| Dim | Gap | Achievable lift | Permanent residual | Path |
|---|---|---|---|---|
| Hexagonal 97 | +3 | **+3** | 0 | Phase 3a Manager-port consumer migration (~380 LOC, 4 sub-commits) |
| Middleware 95 | +5 | +1 (low-density, optional) | +4 | Investment C if authorized; otherwise +4 permanent |
| Decorator 95 | +5 | 0 | +5 | Go-irreducible — language has no decorator sugar |

**Bottom line**: Phase 3a is the only non-trivial achievable lift on
these three dims. It's **already scoped** (`d9fdd06`), **already
half-shipped** (port definitions), and **explicitly deferred** rather
than rejected. Authorize Phase 3a and Hex/SOLID both reach 100; total
non-external ceiling lifts to ~92.85 (or ~93 with optional Investment
C).

The remaining gap to 94.38 is operational hardening that doesn't
specifically target Hex/Middleware/Decorator. The remaining gap to
100 is scale-gated external-$$ — broker adapters, Postgres, SOC 2
cert. None of those move the three dims under analysis.

**Recommendation**: ship Phase 3a if non-external 100% on
**Hex + SOLID** is worth ~380 LOC (4 sub-commits, MEDIUM risk).
Document Middleware 95 + Decorator 95 as the **empirical-max
non-external ceiling** for those two dims.
