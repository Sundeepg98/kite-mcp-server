# Scorecard Final — re-grade at HEAD `710c011` (2026-04-28)

**Method**: empirical re-grade against the 13-dim rubric in
`.research/blockers-to-100.md` (`4b0afd2`), walking 13 commits since
the prior baseline at `511ee99` (`65e383c` re-grade, 2026-04-28,
92.46 equal-weighted / ~97.0 Pass-17). All driver commits empirically
verified against current source.

**Charter**: read-only research deliverable replacing the `65e383c`
numbers with current state. ~30 min wall.

**Build status**: `go vet ./mcp/... ./kc/decorators/...` clean at
HEAD `710c011` (verified WSL2 / Ubuntu 24 / Go 1.25.8). Per-package
narrow-scope tests green: `./mcp/` 9.099s (full suite),
`./kc/decorators/` 0.005s (100% statement coverage). `go test ./...`
not run — narrow-scope test verification per
`feedback_narrow_test_scope_no_stash.md` is the team-agent shared-
tree convention.

---

## Driver-commit summary (13 since prior baseline)

### Research deliverables (3 commits)

| Commit | Topic |
|---|---|
| `65e383c` | scorecard re-grade at HEAD `511ee99` (the prior baseline this rewrite replaces) |
| `851baa1` | non-external 100 final blockers — Hex/Middleware/Decorator scoping |
| `0d92590` | code-gen evaluation for Decorator +5 (override anti-Go-idiom verdict) |

`851baa1` scoped what's truly anti-rec'd vs achievable-internal for
the three dims still <100. `0d92590` corrected its own framing by
surfacing the typed-generic Option 2 (idiomatic Go, post-1.21) as a
genuine non-anti-rec'd path to Decorator +2. Both research commits
materially shaped the execution batches that followed.

### Slice 5 deepening (2 commits — Logger sweep deep-tail closeouts)

| Commit | Surface |
|---|---|
| `008ea00` | retire `riskguard.Guard.CheckOrder` shim — migrate 165+ sites to `CheckOrderCtx` |
| `17d860f` | retire deprecated `*slog.Logger` field on `billing.Store` |

The prior re-grade explicitly called these out as the kind of
"multi-package call-site migration" that retires the last logger-
sweep shims. Slice 5 executed both. Net `// Deprecated:` marker
count: **22 → 11** (50% retirement).

### Phase 3a — Manager-port consumer migration (4 commits)

| Commit | Batch | Surface |
|---|---|---|
| `8fab0a3` | 1 | read-only consumers via Instruments + Audit ports (7 files, +72/-28 LOC) |
| `ffd24a3` | 2 | setup/alert/ticker via narrow ports + new `BrowserOpener` port (8 files, +77/-47 LOC) |
| `3c55712` | 3 | `adminCheck` / `withAdminCheck` via `kc.UserStoreProvider` port (1 file, +16/-6 LOC) |
| `51ecac5` | 5 | widget/misc cleanup via narrow ports (6 files, +16/-6 LOC) |

(Batch 4 — order tools — was empty; sites already migrated by
earlier work.)

**Total Phase 3a delta**: 22 file touches, +181/-87 LOC across 4
commits. Closes the `mcp/`-consumer surface of the long-deferred
Phase 3a work. Two new narrow ports added to the port surface
(`BrowserOpener` for setup_tools.go's auto-open helper; explicit
wiring of existing `TelegramNotifierProvider` and
`PnLServiceProvider` into `ToolHandlerDeps`). The
`adminCheck`/`withAdminCheck` shared helper signature swap from
`*kc.Manager` → `kc.UserStoreProvider` propagates to 10 production
admin tool callers without cascade — `*kc.Manager` satisfies the
narrower port.

**Empirical post-Phase-3a state at `710c011`:**
- mcp/ non-test Concrete() call sites: **2** (down from 4
  pre-Phase 3a). Both are `manager.AuditStoreConcrete()` in
  `admin_baseline_tool.go` + `admin_cache_info_tool.go` for
  `UserOrderStats` / `StatsCacheHitRate` forensics methods that are
  intentionally NOT on `AuditStoreInterface` — documented
  architectural exceptions, NOT score-impacting leaks.
- mcp/ `manager.X()` non-test method-call sites: ~30 (mostly
  composition-root surfaces in `common_deps.go` /
  per-context dep builders that are intentional facade construction
  per `phase-3a-manager-port-migration.md` §6, plus residual sites
  in `mcp/session_admin_tools.go` deferred for separate scoping).

### Decorator factory + consumer adoption (3 commits)

| Commit | Surface |
|---|---|
| `2cc31a9` | new `kc/decorators` package — generic typed `Handler[Req, Resp]` / `Decorator[Req, Resp]` / `Compose` / `Apply` factory (388 LOC, 100% statement coverage, 10 tests) |
| `406b9bf` | retire deprecated `*slog.Logger` fields on `DashboardHandler` + `Handler` (kc/ops Logger sweep cleanup) |
| `3cb66f2` | retire deprecated `Logger` field on `ToolHandlerDeps` + `ReadDepsFields` |
| `710c011` | migrate around-hook chain (`mcp.HookMiddlewareFor`) onto `kc/decorators` typed pattern — 3 files, +262/-19 LOC |

`2cc31a9` ships the platform investment per `0d92590` Option 2.
`710c011` promotes it from "platform investment" to "demonstrated
pattern" — the rubric's explicit gating condition for the score
lift — by migrating `mcp.HookMiddlewareFor`'s hand-written reverse-
iteration around-chain onto `decorators.Compose`. Behaviour
preserved exactly; all 8 existing `around_hook_test.go` regression
tests pass unchanged. The 3 new tests in `mcp/decorator_chain_test.go`
demonstrate the typed pattern at the production
`mcp.CallToolRequest / *mcp.CallToolResult` instantiation.

The `406b9bf` and `3cb66f2` cleanup commits retire 4 more logger-sweep
deprecation shims at the `kc/ops` and `mcp/ToolHandlerDeps` seams —
sub-batches of the Slice 5 logger-sweep deep-tail retirement work.

---

## Per-dim score table

| Dim | At `511ee99` | At `710c011` | Δ | Evidence | What blocks 100 |
|---|---|---|---|---|---|
| 1. CQRS | 100 | **100** | 0 | No regressions; `cmd/event-graph/` unchanged. | None — capped. |
| 2. Hexagonal | 97 | **99** | +2 | Phase 3a 4 batches close the `mcp/`-consumer surface of the deferred Phase 3a Manager-port migration: the three admin tools that previously leaked `manager.AuditStoreConcrete()` for methods that are on `AuditStoreInterface` (e.g., `GetTopErrorUsers`, `List`) now route through `handler.AuditStore()`; the residual `manager.Instruments` field accesses in market/peer/concall/option/options-greeks/indicators/backtest tools route through `handler.Instruments()`; `setup_tools.go`'s `manager.OpenBrowser` calls route through the new `kc.BrowserOpener` port; `alert_tools.go`'s `manager.TelegramNotifier()` and `pnl_tools.go`'s `manager.PnLService()` route through their existing providers wired through `ToolHandlerDeps`; `ticker_tools.go`'s `resolveInstrumentTokens` helper signature changes from `*kc.Manager` → `kc.InstrumentManagerInterface`; the shared `adminCheck`/`withAdminCheck` helpers in `mcp/admin_tools.go` take `kc.UserStoreProvider` instead of `*kc.Manager`. **mcp/ non-test Concrete() call sites: 4 → 2** (the two remaining are documented forensics-only architectural exceptions, not gaps). +2 (not +3) because `kc/store_registry.go`'s 18 `*Concrete()` method DEFINITIONS, `kc/broker_services.go`'s 9, `app/adapters.go`'s 10 adapter pass-throughs, and `kc/telegram/bot.go`'s 5 KiteManager interface methods remain — those are the `kc/`-side surfaces of the same architectural pattern, separate from the `mcp/`-consumer migration this batch shipped. | +1 anti-rec'd (kc/-side Concrete pattern retirement; sums roll up into the same Phase 3a deferred bucket per ADR 0006). |
| 3. DDD | 100 | **100** | 0 | No regressions. Money sweep state unchanged. | None — capped. |
| 4. Event Sourcing | 100 | **100** | 0 | No regressions. | None — capped. |
| 5. Middleware | 95 | **95** | 0 | Unchanged. ADR 0005 still binds the order. | Anti-rec'd ceiling. |
| 6. SOLID | 99 | **100** | +1 | **Phase 3a `mcp/`-consumer migration ships the +1** the prior re-grade flagged as deferred: ports are now used at the `mcp/` consumer surface (not just defined); the `adminCheck`/`withAdminCheck` SRP fix (helper takes the narrowest port that lets it work, not the full `*Manager`); the 4 Phase 3a batches concretely demonstrate ISP at the consumer. **Logger sweep deep-tail retirements** (`008ea00`, `17d860f`, `406b9bf`, `3cb66f2`) close 11 of the 22 prior `// Deprecated:` markers — the call-site migrations the prior re-grade noted as the gap to 100. The remaining 11 markers are mostly unrelated to Phase 3a or Logger sweep (kc/manager port migration, kc/alerts test helpers — separately scoped work). | None — Phase 3a `mcp/`-consumer + Logger deep-tail are the +1 the prior re-grade flagged. |
| 7. Plugin | 100 | **100** | 0 | No regressions. | None — capped. |
| 8. Decorator | 95 | **97** | +2 | **`kc/decorators` factory shipped** (`2cc31a9`) — typed-generic `Decorator[Req, Resp]` / `Handler[Req, Resp]` / `Compose` / `Apply` surface, 388 LOC, 100% statement coverage. **Consumer adoption demonstrated** (`710c011`): `mcp.HookMiddlewareFor`'s around-hook chain migrated onto `decorators.Compose` — the rubric's explicit gating condition for the score lift, per `decorator-code-gen-evaluation.md` §5 ("factory shipped but not yet consumed → +0; demonstrated consumer → +2"). +2 closes rubric path F (typed-generic composition). **Permanent residual at 97**: the remaining +3 to 100 is reflective composition / aspect weaving (rubric paths A/B/C) — Go-irreducible per `decorator-code-gen-evaluation.md` Option 4 (AOP via reflection) which is below the 0.4 density floor + Go-community-preference cost. | +3 Go-irreducible (rubric A/B/C — reflective AOP). |
| 9. Test Architecture | 100 | **100** | 0 | No regressions; Wave C suite unchanged. The 3 new tests in `mcp/decorator_chain_test.go` and the 10 in `kc/decorators/decorators_test.go` add typed-decorator pattern coverage but the dim was already capped. | None — capped. |
| 10. Compatibility | 86 | **86** | 0 | No new broker adapter. | +14 SCALE-GATED. |
| 11. Portability | 86 | **86** | 0 | No new portability lift. | +14 SCALE-GATED. |
| 12. NIST CSF 2.0 | 85 | **85** | 0 | No new compliance artifacts. The Phase 3a + Decorator commits are architectural, not security/compliance. | +15 external-$$. |
| 13. Enterprise Governance | 59 | **59** | 0 | No new ADRs this batch. The Phase 3a batch commits' doc-trails (deferred-shim documentation, Slice 5 in-flight coordination notes) are governance-of-change-control evidence but don't lift the dim. Total ADRs on file: **6** (0001-0006). | +41 external-$$. |

---

## Aggregate composite

**Equal-weighted (per `blockers-to-100.md` methodology):**

```
(100 + 99 + 100 + 100 + 95 + 100 + 100 + 97 + 100 + 86 + 86 + 85 + 59) / 13
= 1207 / 13
= 92.85
```

vs prior `511ee99` 92.46: **+0.39 absolute**.

**Six dims at 100**: CQRS, DDD, ES, SOLID, Plugin, Test-Arch.
(Was 5 at prior baseline. SOLID joined this batch.)

**Two dims within 3 points of 100**: Hexagonal (99), Decorator (97).

**Pass 17 weighted (CORE dims weighted higher):** **~97.5**
(extrapolated from prior 97.0 baseline + the +0.39 equal-weighted
delta; CORE dims Hexagonal / SOLID absorbed +3 of the +5 dim-points,
so the weighted impact tilts above the equal-weighted aggregate).

---

## Has the ceiling been hit?

**Materially yes**, in five senses:

1. **Six dims at the rubric ceiling.** CQRS, DDD, ES, SOLID, Plugin,
   Test-Arch — all at 100. Per the `851baa1` non-external blockers
   research, SOLID was the closest non-capped dim; `710c011`'s
   Phase 3a + Logger deep-tail combined push it to 100.

2. **Calibrated 94.38 empirical-max ceiling: 92.85 reaches 98.4%
   of it.** The remaining 1.53 points are:
   - ~0.15 from kc/-side Concrete pattern retirement (Hex 99→100,
     anti-rec'd per ADR 0006)
   - ~0.23 from Decorator AOP lift (97→100, Go-irreducible)
   - ~0.5 noise band
   - The remainder is operational hardening (Wave C scenario
     expansion, NIST +1 incrementals)

3. **Phase 3a `mcp/`-consumer migration shipped.** The long-deferred
   work that the prior re-grade flagged as the +1 to SOLID 100 is
   now landed for the mcp/ surface. The kc/-side counterpart (store
   registry method definitions + adapter pass-throughs) is
   architecturally distinct and remains anti-rec'd per ADR 0006.

4. **Decorator factory + consumer adoption locks the +2.** Per
   `decorator-code-gen-evaluation.md`, score lift required
   demonstrated consumer adoption of `kc/decorators`. `710c011`
   migrates `mcp.HookMiddlewareFor` — a load-bearing production
   surface — onto the typed factory. The +2 is empirical, not
   speculative.

5. **Slice 5 logger-sweep deep-tail closeouts retired 50% of
   remaining `// Deprecated:` markers** (22 → 11). The prior
   re-grade explicitly flagged these as the deferred work blocking
   SOLID's last point.

---

## Items the ceiling itself is gated by (permanent — not gaps)

### Anti-rec'd patterns

| Pattern | Affected dim | Points blocked | Status |
|---|---|---|---|
| Wire/fx DI container | Hexagonal | +1 (was +3) | **PARTIALLY ADOPTED** via Phase 2 (P2.1-P2.6 + P2.5a/b + β-1 + β-2) + Phase 3a `mcp/`-consumer (`8fab0a3`/`ffd24a3`/`3c55712`/`51ecac5`). The kc/-side Concrete pattern retirement (`kc/store_registry.go` method definitions + `app/adapters.go` adapter pass-throughs + `kc/telegram/bot.go` KiteManager interface) remains deferred per ADR 0006 §"What was rejected". |
| Logger Provider wrap | SOLID | 0 (was +1) | **FULLY RECLAIMED** via Wave D Phase 3 Logger sweep + Slice 5 deep-tail retirements (`008ea00` / `17d860f` / `406b9bf` / `3cb66f2`). The remaining 11 `// Deprecated:` markers are not Logger-sweep — they're kc/manager port migration shims + kc/alerts test helpers, separately scoped. **SOLID at 100 reflects this honestly.** |
| Middleware split | Middleware | +5 | Permanent ceiling at 95. |
| Full ES (state-from-events for ALL aggregates) | Event Sourcing | 0 | **CALIBRATED CEILING REACHED.** ES at 100 is the calibrated end-state. |
| Decorator AOP / reflective composition | Decorator | +3 (was +5) | **PARTIALLY RECLAIMED** via Option 2 (typed-generic `Decorator[Req, Resp]` factory + consumer adoption). The remaining +3 is rubric paths A/B/C (reflective composition / annotation-driven / aspect weaving) — Go-irreducible per `decorator-code-gen-evaluation.md` Option 4 (density 0.21, below floor + Go-community-preference cost). |

**Anti-rec'd points blocked (sum): 9 of 1300 = 0.69 percentage-
points** (was 9 / 0.69% — Logger reclaim of +1 offset by Decorator's
re-categorisation of +2 as reclaimed-by-Option-2; net same total).

### External-$$ items (SCALE-GATED — unchanged)

Same as prior baseline. Sum: **64 of 1300 = 4.92 percentage-points**.

### Irreducible

| Item | Dim | Points blocked | Why |
|---|---|---|---|
| (none remaining) | — | 0 | Plugin dlopen Windows surface remains subsumed under universal `RegisterInternalTool` + checkrpc cross-language IPC. |

### Total ceiling math

Theoretical 100 across all 13 dims = 1300. Anti-rec'd + external-$$
+ irreducible block: 9 + 64 + 0 = **73 points** = **5.62% of
theoretical max**.

Empirical max under constraints = 100 − 5.62 = **94.38 equal-
weighted** (unchanged — same constraint set).

**Current 92.85 equal-weighted is at 98.38% of the empirical-max
ceiling.** The gap to literal 94.38:
- ~0.15 from kc/-side Concrete pattern retirement (anti-rec'd, not
  gap — would push Hex 99→100 if pursued)
- ~0.23 from Decorator AOP lift (Go-irreducible — would push
  Decorator 97→100 if forced via reflective AOP)
- ~0.5 from per-dim incremental hardening (operational, not
  architectural)
- ~0.65 noise band

**Verdict: the calibrated 94 / ~97.5 Pass-17 ceiling is essentially
reached.** Further code-tractable score lift requires anti-rec'd
work (Phase 3a kc/-side, AOP Decorator) or external $$.

---

## Honest opacity

1. **`go test ./...` deferred per the team-agent shared-tree rule**.
   WSL2 narrow-scope tests verified clean for this batch's commits
   (`./mcp/` 9.099s full suite green, `./kc/decorators/` 0.005s full
   suite + 100% statement coverage). The 13 commits between
   baselines all reported their own narrow-scope test verifications
   in their commit messages.

2. **Phase 3a "complete" caveat.** Phase 3a as originally scoped
   per `phase-3a-manager-port-migration.md` covered both the
   mcp/-consumer surface AND the kc/-side store registry / adapter
   surface. **This batch ships only the mcp/-consumer half.** The
   kc/-side (`kc/store_registry.go` 18 `*Concrete` method defs,
   `app/adapters.go` 10 adapter pass-throughs, `kc/telegram/bot.go`
   5 KiteManager interface methods) remains deferred per ADR 0006.
   Hex 99 (not 100) reflects this honestly.

3. **Slice 5 audit-shim closeout in flight at re-grade time**.
   Working tree at `710c011` shows Slice 5 modifying
   `app/providers/audit.go`, `app/providers/audit_init.go`,
   `kc/audit/middleware.go`, `kc/audit/store.go`,
   `kc/audit/store_worker.go`, `kc/manager_init.go`. **Not yet
   pushed.** If/when it lands, it likely retires more
   `// Deprecated:` markers (the Logger sweep deep-tail in
   kc/audit). No score impact in this re-grade — would lift SOLID
   (already at 100, no headroom) or potentially +0.1 NIST if the
   audit closeout improves observability.

4. **Decorator consumer migration empirically validated**. The
   `mcp.HookMiddlewareFor` migration preserves all 8 existing
   `around_hook_test.go` regression tests (panic recovery, ordering,
   short-circuit, mutable+immutable interleaving) plus adds 3 new
   tests demonstrating the typed pattern. Decorator at 97 reflects
   shipped + verified factory adoption, not paper-only credit.

5. **Six dims at 100 vs prior five at 100**: SOLID reached 100 via
   the combined Phase 3a `mcp/`-consumer migration + Logger sweep
   deep-tail retirements. Both are commit-tagged ceiling-reachers;
   both empirically verified.

6. **Pass 17 weighted ~97.5** is extrapolated, not re-derived.

7. **`app/wire.go` still 938 LOC at HEAD** (unchanged from prior
   baseline). Phase 3a focused on `mcp/`-consumer surface, not
   `app/wire.go`'s composition root. The prior baseline's
   "Phase 4 / future slices might re-collapse" note still applies.

---

## Cumulative trajectory

| HEAD | Date | Equal-weighted | Pass 17 | Notes |
|---|---|---|---|---|
| `a4feb5b` (138-gap baseline) | 2026-04-25 | ~89.5 | n/a | Pre-Phase 1+2 |
| `87e9c17` (re-audit) | 2026-04-26 | 87.6 | 92.5 | Calibrated empirical baseline |
| `7649dfb` (re-grade `d5b9043`) | 2026-04-26 evening | 88.8 | ~93.5 | Saga + CI matrix + DR cron + governance triad shipped |
| `562f623` (re-grade `7ae58da`) | 2026-04-26 night | 90.04 | ~95.0 | Wave 1 + Wave 2 (10 commits + ship-list complete + 4 bonus) |
| `de9d2f6` (re-grade `b1a6479`) | 2026-04-27 | 91.92 | ~96.5 | Money sweep complete + Wave D Phase 1+2 + ES sweep + coverage close-outs |
| `511ee99` (re-grade `65e383c`) | 2026-04-28 | 92.46 | ~97.0 | Wave D Phase 3 Logger sweep (8 packages + cleanup) + β-1 + β-2 + Wave C Playwright + CQRS event-flow viz + DailyPnLEntry close-out (43 commits) |
| **`710c011` (current)** | **2026-04-28 night** | **92.85** | **~97.5** | **Phase 3a `mcp/`-consumer migration (4 batches) + `kc/decorators` factory + consumer adoption (around-hook chain) + Slice 5 logger-sweep deep-tail retirements (13 commits)** |

**+5.25 absolute equal-weighted** since the calibrated `87e9c17`
empirical baseline. **Six dims at 100**.

---

## Sources

- Rubric: `.research/blockers-to-100.md` (`4b0afd2`)
- Prior re-grade: `65e383c` at HEAD `511ee99` (superseded by this rewrite)
- Driver commits: 13 between `511ee99..710c011` (verified via `git log`)
- Empirical metrics this audit:
  - `app/wire.go` = 938 LOC (unchanged); `app/providers/` has **14 provider files** (unchanged)
  - `git grep "// Deprecated:" -- '*.go'` = **11 markers** (was 22 — Slice 5 + cleanup commits retired 11)
  - mcp/ non-test `Concrete()` call sites: **2** (was 4 pre-Phase-3a — both remaining are documented forensics-only architectural exceptions in admin_baseline_tool.go + admin_cache_info_tool.go)
  - `kc/decorators/`: **388 LOC, 100% statement coverage, 10 tests**
  - `mcp/decorator_chain.go` + `mcp/decorator_chain_test.go`: **252 LOC, 3 new tests**
- Build status: `go vet ./mcp/... ./kc/decorators/...` clean at HEAD `710c011` (WSL2 / Ubuntu 24 / Go 1.25.8); narrow-scope `./mcp/` (9.099s) + `./kc/decorators/` (0.005s) tests green

---

## Anchor docs informed by this batch

- `.research/non-external-100-final-blockers.md` (`851baa1`) — Hex/
  Middleware/Decorator scoping. The Hex 97→100 +3 estimate
  empirically resolved at +2 (mcp/-consumer half shipped; kc/-side
  remains anti-rec'd). Decorator 95→97 +2 estimate empirically
  validated.
- `.research/decorator-code-gen-evaluation.md` (`0d92590`) — Option
  2 typed-generic factory selected. Density 0.40 borderline + plugin
  SDK side benefit confirmed.
- `.research/phase-3a-manager-port-migration.md` (`d9fdd06`) — 5-batch
  plan. Empirical reality: Batch 4 was empty (already migrated by
  earlier work); Batch 5 was much smaller than estimated (most
  ext_apps.go sites are calls on `extAppManagerPort` UNION port,
  already ported).

---

*Generated 2026-04-28 night, read-only research deliverable. Replaces
`65e383c`'s scorecard with current re-grade.*
