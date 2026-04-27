# Post-Wave-D skipped-items re-evaluation

**Charter**: read-only re-evaluation of every "intentionally skipped" architectural item now that Wave D Phase 1 (resolver refactor, commits `e2946f8`-`4e12da9`) and Wave D Phase 2 (Fx adoption, commits `4b5120b`-`de9d2f6`) are in production. Many items were skipped because of structural blockers that are NOW gone. This doc tells the user which to ship, which to leave, and where the score lands if everything genuinely shippable lands.

**HEAD audited**: `de9d2f6` (master). Companion to `.research/scorecard-final.md` (90.04 equal-weighted, ~95.0 Pass-17 baseline) and `docs/adr/0006-fx-adoption.md` (Phase 2 design-decision capture).

**Cross-references**:
- `.research/scorecard-final.md` — 13-dim per-dim scores; remaining gaps cataloged
- `.research/wave-d-phase-2-recompute.md` (`c2fefd4`) — empirical 5x LOC ratio; pattern catalog
- `.research/money-vo-slice6-scoping.md` — `broker.PnL` Option A/B/C analysis (relevant to item 6)
- `.research/features-ux-coverage-audit.md` — Wave C Playwright scoping (relevant to item 2)
- `feedback_decoupling_denominator.md` — three-axis ROI framework

---

## 1. Logger sweep — `SOLID +3-4`, `DDD +0` (port hygiene)

**Original skip reason** (`532da34` ship-then-defer): "Wire/fx wasn't ready, so the 4 accessors plus the port can't yet drive a graph-resolved sweep — converting 554 call sites without a graph would just shuffle imports."

**Has the structural blocker actually changed?** **PARTIAL.** Wire/fx IS now ready (Phase 2 shipped). But the structural argument for "blocker = no Wire/fx" was always thin: a logger sweep is a search-and-replace from `*slog.Logger` → `logger.Logger` across call sites. Wire/fx's role is at the construction site (where the logger is supplied), not the consumption site (where most call sites live). Phase 2 doesn't actually unlock anything mechanical here — it just removes the "wait for it" excuse.

**Empirical scope at HEAD `de9d2f6`**:
- 521 `*slog.Logger` references in `kc/` (non-test).
- 163 `logger.` calls in `app/` (non-test).
- 5 files use the new `kc/logger` port (port itself + 4 accessors).
- ~684 call sites total still on raw slog.

**Re-scoped LOC estimate**:
- 684 call sites × ~1 LOC change each = **~684 mechanical LOC**.
- Plus interface compliance asserts + tests for any new behaviour: **+200 LOC**.
- Plus an ADR documenting why the port exists at all: **+150 LOC**.
- **Total: ~1,034 LOC**, sweepable in 4-6 sub-batches by package.

**Re-scoped wall-time**: 6-12 hours (sweeping is mechanical but tedious; per-package batches each take 1-1.5h with TDD discipline).

**Three-denominator ROI**:
- **User-MRR**: 0 features. Negative as ever.
- **Agent-concurrency**: ZERO. The original `feedback_decoupling_denominator.md` and `agent-concurrency-decoupling-plan.md` §3.4 both flagged Logger wrap as "ceremony — frequency-weighted to ~0" because the cascade fires ~1/year (logger config changes are rare). Phase 2 doesn't change this. The 684 call sites are not concurrent-edit hot spots; they're mostly stable.
- **Tech-stack portability**: MARGINAL. A `logger.Logger` port is one fewer `*slog.Logger` import to swap if a per-component rewrite happens. But the slog package itself is std-library Go since 1.21 — porting to a non-Go runtime drops the whole logger surface anyway, so the wrapping doesn't compound.

**Verdict: PERMANENT-SKIP** (or ROI-marginal-low-priority).

The original anti-rec verdict in `agent-concurrency-decoupling-plan.md` Investment B holds: "Eliminates 50-callsite cascade for logger config changes — but config changes happen ~1/year. Mode 2 lift is real but frequency-weighted to ~0." Phase 2 didn't change the frequency. The +3-4 SOLID lift is anti-rec'd ceremony — score-inflation-only.

**If the user insists** (because it's mechanical and nobody else is doing it): ship it as a multi-week background task across 4-6 packages, expect zero throughput payoff but +3 SOLID points. Defensible only on tech-stack-portability grounds **if** there's a concrete plan to rewrite a component in a non-Go language — and even then, the logger port doesn't carry across runtimes.

---

## 2. Wave C — Playwright e2e (browser-level coverage)

**Original skip reason**: maintenance burden ("each time we make changes, we have to") and the absence of the surface-lock tests that would catch silent breakage between Playwright runs.

**Has the structural blocker actually changed?** **YES, partially.**
- Tool surface lock test shipped (commit `b5b500e`, `mcp/tool_surface_lock_test.go`, hash-snapshot + diff).
- Widget surface lock test shipped (commit `fd840a6`, `mcp/widget_surface_lock_test.go`, 138 LOC frozen inventory of ui:// URIs + templates + page maps).

These two locks catch the most common silent breakage: a tool description silently rewritten by an LLM-coded refactor, or a widget template URI changed without a corresponding registration update. Pre-locks, a Playwright suite was the only safety net for those classes.

**With both locks in place**, the maintenance burden of a thinner Playwright suite drops materially. The locks catch ~80% of regressions cheaply; Playwright only needs to catch the remaining 20% — visual layout regressions, AppBridge JS bugs surfacing post-deploy, OAuth flow break, mobile breakpoints.

**Re-scoped LOC estimate (thin-suite proposal)**:
- Critical-journey Playwright spec files (8-10 specs, not the original 17+):
  - OAuth login round-trip (sandbox Kite)
  - place_order via widget (smoke; widget renders, button clicks, response decoded)
  - get_holdings widget render
  - dashboard load + auth
  - admin freeze flow
  - billing tier upgrade (Stripe checkout return)
  - Telegram pairing browser leg
  - mobile viewport smoke (375×812)
- Total: ~400-600 LOC of Playwright TS + ~200 LOC of GH Actions + auth fixtures + `package.json`.
- **Total: ~600-800 LOC** for a "smoke-only" suite. (Original P0 in `features-ux-coverage-audit.md` was 800-1500 LOC for full coverage.)

**Re-scoped wall-time**: 2-3 weeks (one focused sprint), assuming Playwright + a sandbox Kite developer app are obtained without external bottlenecks.

**Three-denominator ROI**:
- **User-MRR**: POSITIVE. `features-ux-coverage-audit.md` correctly identifies this as the single biggest leverage point pre-launch. A silent dashboard regression on launch day = public refund. Smoke-suite catches the worst class.
- **Agent-concurrency**: NEUTRAL. Browser-level tests run in CI, not multi-agent edit paths.
- **Tech-stack portability**: NEUTRAL.

**Verdict: SHIP NOW** (as a thin smoke suite, not the original 17-spec full coverage).

**Slice plan** (~600-800 LOC, ~3 weeks):
- WC.1: Add `playwright.config.ts` + `package.json` + GH Actions workflow + OAuth sandbox fixture (~200 LOC, ~3-4 days)
- WC.2: 4 critical-journey specs — login round-trip, place_order widget, get_holdings widget, dashboard load (~250 LOC, ~3-4 days)
- WC.3: 4 secondary specs — admin freeze, billing tier upgrade return, Telegram pairing, mobile viewport smoke (~200 LOC, ~3-4 days)
- WC.4: snapshot baseline + first-run review + flake-fix pass (~50 LOC, ~2 days)

**Score impact**: NIST CSF +1 (real-time validation of user-touching surfaces), Test-Arch +1 (browser-level coverage was the lone unfilled slot in the test pyramid). **+2 aggregate.**

---

## 3. P2.5 — Inner Manager Fx migration

**Original skip reason** (ADR 0006 §"What was rejected"): "Inner Manager already has structured init surface (16 functional options + 16 named init helpers); Mode-2 conflict on `manager_init.go` is empirically low. Recompute analysis projected ~1200 LOC for marginal benefit."

**Has the structural blocker actually changed?** **NO. Empirical edit-cadence data confirms the deferral was correct.**

`git log --since='1 month ago' -- kc/manager_init.go` returns **3 commits**.
`git log --since='1 month ago' -- app/wire.go` returns **48 commits**.

**16× edit-cadence delta.** Phase 2 absorbed all the wave-D activity on `wire.go` (48 commits in a month) while `manager_init.go` stayed quiet (3 commits). The "Wave D was masking Mode-2 contention on manager_init.go" hypothesis is empirically false — the cadence asymmetry is structural, not absorbed.

**Why it stays low**: `manager_init.go` is named-helper-per-concern (initAlertSystem, initPersistence, initCredentialWiring, etc.). Adding a new concern means adding a new helper file, not editing the existing chain. `wire.go` was historically one giant function, so every change touched the central composition. Phase 2 fixed wire.go's structural problem; manager_init.go never had one.

**Re-scoped LOC estimate**: ~1,200 LOC (unchanged from recompute §2.2 projection).

**Three-denominator ROI**:
- **User-MRR**: 0 features. Negative.
- **Agent-concurrency**: NIL. 16× edit-cadence delta confirms manager_init.go is not a contention point.
- **Tech-stack portability**: MARGINAL. The Manager would be one of the last per-component swap candidates (it owns the Kite SDK integration; can't be swapped without replacing the broker layer entirely).

**Verdict: PERMANENT-SKIP.** The empirical data refutes the hypothesis that Phase 2 was masking inner-Manager contention. Manager_init.go is the kind of structured surface Phase 2 produced for wire.go — already done. Migrating it again to Fx would replace a working pattern with a heavier pattern for no measured benefit.

If conditions change (e.g., inner Manager gains 5+ new helpers per month consistently), revisit.

---

## 4. Commit β extractions (billing + family-invitation)

**Original skip reason** (Phase 2 Batch 3, declined twice during execution): structural issues — `stripe.Key = stripeKey` package-global side effect for billing; family-invitation goroutine + cancel-fn pattern requiring first-time `FxLifecycleAdapter` production wiring (~50 LOC of bridge code beyond the extraction).

**Has the structural blocker actually changed?** **PARTIAL.**

The structural blockers are still real:
- `stripe.Key = stripeKey` — this is a third-party package global mutation. Moving it into a provider doesn't make it less of an anti-pattern; it just relocates the eyesore.
- The `app.invitationCleanupCancel` field + 6h goroutine still needs `FxLifecycleAdapter` to migrate cleanly.

What HAS changed: the `FxLifecycleAdapter` (P2.3a, `88e6d71`) is now production-tested via P2.3b's audit chain. Wiring it into family-invitation cleanup is no longer "first-time use in production" risk — it's "second use of a proven pattern."

**Re-scoped LOC estimate**:

For **billing extraction**:
- Provider file ~60 LOC + tests ~50 LOC + wire.go edit -40 LOC = **~70 net LOC**.
- Cannot fix the `stripe.Key = ` side effect; lives at composition site forever (or wrapped in a thin "stripeBootstrap" function with package-global comment).

For **family-invitation extraction**:
- Provider file ~80 LOC + tests ~60 LOC + lifecycle hook wiring ~30 LOC + wire.go edit -45 LOC = **~125 net LOC**.

**Total Commit β: ~195 LOC**, ~3-4h wall-time.

**Three-denominator ROI**:
- **User-MRR**: 0 features. Negative.
- **Agent-concurrency**: LOW. `wire.go` after Phase 2 is at 920 LOC (down from 1031). Billing block (~40 LOC) and family block (~43 LOC) together are ~9% of the file. Removing them brings wire.go to ~835 LOC — modest delta. Mode-2 conflict on these specific blocks is rare (billing init changes ~1/quarter; family-invitation changes never).
- **Tech-stack portability**: MARGINAL. Per `a03694a` (concrete language-swap plan), neither billing nor family-invitations are flagged as language-swap candidates. They're stable Go code with no compelling reason to rewrite.

**Verdict: PERMANENT-SKIP** unless a specific use case emerges. The original Phase-2 abort decision holds under empirical re-evaluation: ROI-marginal then, still ROI-marginal now.

The exception: **if the Logger sweep (item 1) is authorized**, billing might pair-extract during the same multi-week pass to amortize the per-package boilerplate. Standalone, no.

---

## 5. DailyPnLEntry SQL Money

**Original skip reason** (Slice 4 prior verdict): "DailyPnLEntry is a SQL row struct with `float64` columns. Lifting to Money requires custom MarshalJSON for wire compatibility + SQL Scanner/Valuer plumbing + cascading 35+ read sites. Defer indefinitely."

**Has the structural blocker actually changed?** **NO.**

Empirical state at HEAD:
- `kc/alerts/db.go:308` defines DailyPnLEntry with 4 `float64` columns (HoldingsPnL, PositionsPnL, NetPnL, plus Date/Email/Counts).
- `kc/alerts/db_commands.go:314` SaveDailyPnL(entry).
- `kc/alerts/db_queries.go:303` LoadDailyPnL — uses `var e DailyPnLEntry` literal scan.
- 4-5 test sites construct DailyPnLEntry literals.

Migrating to Money requires:
- Custom MarshalJSON to preserve `{"holdings_pnl": 1234.56}` wire format.
- Custom Scanner/Valuer (or change column types from REAL to TEXT/numeric).
- Cascading test fixtures (~5 sites).
- ~150-250 LOC.

Phase 2's ADR 0006 doesn't change this calculus. The Fx graph doesn't compose with SQL row types — they're at the persistence boundary, not the wiring graph.

**Three-denominator ROI**:
- **User-MRR**: 0 features. Negative.
- **Agent-concurrency**: NIL.
- **Tech-stack portability**: NEGATIVE. Custom MarshalJSON + custom Scanner add coupling that makes this struct HARDER to port, not easier.

**Verdict: PERMANENT-SKIP.** The original "defer indefinitely" verdict holds. Per Slice 6 scoping doc (`money-vo-slice6-scoping.md`), Money VO across the float64 surface is SCALE-GATED to "Money VO across 873 float64 sites" + "MWPL F&O aggregate" — DailyPnLEntry is part of that gated scope, not a standalone migration.

---

## 6. broker.PnL Option B (wholesale type change)

**Original skip reason** (`money-vo-slice6-scoping.md` recommendation: Option A): "Wholesale (B) is high-risk-low-value at current scale. 35 read sites + custom MarshalJSON + adapter cascades is ~600-900 LOC for zero behavioural improvement."

**Has the structural blocker actually changed?** **NO, and Phase 2 actually argues for keeping Option A even more strongly.**

Empirical state:
- `broker/broker.go` lines 50, 63, 288 define `PnL float64` on Holding, Position, OrderResponse.
- `kc/domain/holding.go:55` already exposes `Holding.PnL() Money` accessor (Option A keystone).
- `kc/domain/position.go:86` already exposes `Position.PnL() Money` accessor.
- 236 non-test consumers of `broker.{Holding, Position, OrderResponse}` types in the codebase — large migration surface.
- 3 callers in `mcp/analytics_tools.go` already use the Money accessor (Option A in production).

**Why Phase 2 reinforces Option A**:

The `*InitializedXxx` wrapper-type pattern that emerged in Phase 2 (audit_init.go, scheduler.go, riskguard.go, event_dispatcher.go) shows that **graph-distinguishable wrapper types are the idiom for "different representation of the same underlying data".** Domain.Holding wrapping broker.Holding (with PnL() Money accessor) is exactly this pattern — already established, already working.

Option B (wholesale type change) would force `broker.Holding.PnL` to be Money internally with custom MarshalJSON, replacing the wrapper-accessor pattern with a coupled-marshalling pattern. That's the WRONG direction post-Phase-2: Phase 2 explicitly chose wrappers over coupled marshalling.

**Re-scoped LOC estimate**: unchanged at ~600-900 LOC.

**Three-denominator ROI**:
- **User-MRR**: 0 features. Negative.
- **Agent-concurrency**: NEUTRAL.
- **Tech-stack portability**: NEGATIVE. Custom MarshalJSON couples internal type to wire format — same anti-pattern as item 5. Worse: it's at a layer (broker DTO) that's load-bearing for cross-language port. A Rust ticker rewrite would have to either re-implement the custom marshaller or accept a different wire format.

**Verdict: PERMANENT-SKIP.** Option A (accessor-wrapper pattern, already in production) IS the canonical idiom post-Phase-2. The wrapper-type pattern Phase 2 catalogued in ADR 0006 is structurally identical and is the right answer.

If a second-broker adapter ever lands (true cross-currency need), revisit. Until then, Option A is permanent.

---

## 7. External-$$ items — listing what each unlocks

These are NOT agent-dispatchable. Listed here for the user's budget calculus.

### 7.1 Microsoft Trusted Signing (`35d7eb2` analysis)

**Cost**: $9.99/mo Azure subscription (paid, not free) + individual eligibility GLOBALLY PAUSED since April 2025 — only USA/Canada residents can enroll.

**Score impact**: Compatibility +1 (Windows binary signing eliminates SmartScreen friction).

**Verdict: BLOCKED — eligibility unavailable for India residents. Defer until Microsoft resumes global rollout.** Use WSL2 for build/test workflows where signing isn't needed.

### 7.2 SOC 2 Type II audit

**Cost**: $15-30k initial + $10-20k annual renewal + ~6 person-weeks of doc preparation.

**Score impact**: NIST CSF +6 (Govern + Identify functions formalized via auditor letter).

**Trigger**: First B2B enterprise RFP requesting it. Per `kite-mrr-reality.md`, target MRR ₹15-25k/month at 12mo — SOC 2 cost is ~10x annual revenue. Premature.

**Verdict: SCALE-GATED.** Revisit when first paying B2B customer asks.

### 7.3 ISMS / ISO 27001 certification

**Cost**: ₹5-15L (₹6L-18L USD ~$7-22k) + multi-month + permanent ISMS staff overhead + annual recert.

**Score impact**: Enterprise Governance +20 (the single biggest dim lift available at any cost).

**Trigger**: First enterprise customer with procurement requirement. Solo project would fail "people" theme controls anyway (background checks, awareness training, separation of duties).

**Verdict: PERMANENT-SKIP at solo-project scale.** Revisit if 3+ FTE team forms or if a 5K+ paying-user enterprise demand materializes.

### 7.4 Multi-broker partnerships (Upstox/Groww/Angel adapter)

**Cost**: $20-30k engineering + ongoing maintenance (each broker SDK has independent upgrade cadence, breaking changes, bug parity work).

**Score impact**: Compatibility +13 (real second adapter validates the Hex port).

**Trigger**: First paying customer explicitly requesting Upstox/Groww/Angel.

**Verdict: SCALE-GATED.** The kc/usecases architecture is Wave-D-cleaned and would compose well with a second broker adapter — Phase 1 D7's resolverFromContext removal means swapping the BrokerResolver implementation is one provider change, not 14 use-case-handler changes. **Phase 2 actually reduced this LOC by ~20% by making the wiring path declarative.**

### 7.5 External pen-test (CERT-In VAPT)

**Cost**: ₹3-5L/yr (~$3,500-6,000/yr).

**Score impact**: Enterprise Governance +5.

**Trigger**: First B2B contract or SEBI RA application.

**Verdict: SCALE-GATED.**

### 7.6 Real-time alert pipeline (PagerDuty/Opsgenie)

**Cost**: ~$10-50/mo + 100 LOC + on-call rotation policy + escalation matrix.

**Score impact**: NIST CSF +2.

**Trigger**: First production incident demanding sub-15min MTTR. Solo maintainer = no on-call rotation possible at current scale.

**Verdict: PERMANENT-SKIP at solo-project scale.** Telegram alerts (already shipped) are sufficient.

---

## 8. Test-Arch +1 close (98 → 99 → 100)

**Original status**: scorecard re-grade (`562f623`) put Test-Arch at 98 with "+2 SCALE-GATED (full mutation-score gate noise risk)".

**Re-evaluation**:

Genuinely shippable items between 98 and 100:
- **Tool-surface lock test** — scorecard line 67 lists this as "still NOT shipped" but commit `b5b500e` actually ships it (`mcp/tool_surface_lock_test.go`). **The scorecard is stale by 1 point.** No new work needed; the +1 is already paid for.
- **Widget-surface lock test** — scorecard doesn't mention this. Commit `fd840a6` ships it (`mcp/widget_surface_lock_test.go`, 138 LOC). **Another stale +0.5-1 point.**
- **Browser-level coverage** (Wave C item 2 above) — would close the lone unfilled slot in the test pyramid. +1.

Mutation-score gate (the +2 SCALE-GATED item) stays SCALE-GATED — full mutation testing introduces noise without proportionate benefit at current LOC scale.

**Re-scoped LOC estimate**: 0 (lock tests already shipped) + Wave C smoke-suite (~600-800 LOC, item 2 above).

**Three-denominator ROI**:
- **User-MRR**: POSITIVE (Wave C catches user-facing regressions). Other items are score-only.
- **Agent-concurrency**: NEUTRAL.
- **Tech-stack portability**: NEUTRAL.

**Verdict for the +1 close**: **SCORECARD UPDATE-ONLY** — re-grade against current HEAD will pick up `b5b500e` and `fd840a6` and surface +1-2 points without any new work. Recommend: dispatch a re-grade agent (or update the scorecard inline) to refresh against HEAD `de9d2f6`.

**Verdict for full 100**: SHIP NOW (Wave C, item 2 above) gets us to 99. Mutation-score gate stays SCALE-GATED.

---

## 9. CQRS +2 close (97 → 99)

**Original status**: scorecard puts CQRS at 97 with "+3 anti-rec'd (domain-event-flow viz, saga UI — out of code-tractable surface)".

**Re-evaluation**: do Phase 2's Fx graph + ADR 0006's pattern catalog naturally produce one of these as a side effect of further work?

**Domain-event-flow viz**: this is "draw a diagram of where events are dispatched and where they're consumed". Phase 2's `CanonicalPersisterSubscriptions` slice (in `app/providers/event_dispatcher.go`) is ALREADY a machine-readable list of 36 (event-type, aggregate-type) pairs. A simple Go test or generator could walk this slice and emit a Mermaid diagram of the event flow. **+1 CQRS.**

**Re-scoped LOC**: ~50 LOC of Go test that walks `CanonicalPersisterSubscriptions` + emits Mermaid syntax to stdout/file + a markdown wrapper that includes the Mermaid block. Run as `go run` or as a `go test` artifact.

**Saga UI viz**: `kc/usecases/saga.go` (140 LOC) is a single saga today. A "UI" for a single saga is over-engineering. **STAYS anti-rec'd.**

Phase 2's other emergent property: the `MiddlewareDeps` fan-in struct + 10-layer ordering doc is a natural place to add a Mermaid diagram of the middleware chain. ADR 0005 already documents the order verbally; a generator could produce a diagram from the `MiddlewareDeps` struct field order. **NOT a CQRS lift** (middleware is its own dim, already at 95 ceiling) but a free side benefit.

**Three-denominator ROI**:
- **User-MRR**: 0.
- **Agent-concurrency**: 0.
- **Tech-stack portability**: MARGINAL — the diagram surfaces a contract that's reusable across language ports (the event-type → aggregate-type mapping IS the public schema; a Rust port of the dispatcher would need the same list).

**Verdict for +1 (event-flow viz): SHIP NOW**, as a small side-batch (~50 LOC, ~1h). Closes the natural gap that Phase 2 inadvertently set up.

**Verdict for the second +1 (saga UI): PERMANENT-SKIP.** Single-saga UI is anti-rec'd correctly.

---

## Aggregate honest answer

### What's available without external $$

| Item | Verdict | Score impact | LOC | Wall-time |
|---|---|---:|---:|---:|
| 1. Logger sweep | PERMANENT-SKIP | (anti-rec'd) | — | — |
| 2. Wave C Playwright (thin smoke suite) | SHIP NOW | NIST +1, Test-Arch +1 | ~600-800 | 2-3 weeks |
| 3. P2.5 inner Manager | PERMANENT-SKIP (16× edit-cadence delta confirms) | — | — | — |
| 4. Commit β (billing + family) | PERMANENT-SKIP | — | — | — |
| 5. DailyPnLEntry SQL Money | PERMANENT-SKIP (SCALE-GATED with item 6) | — | — | — |
| 6. broker.PnL Option B | PERMANENT-SKIP (Option A IS canonical post-P2) | — | — | — |
| 7. External-$$ items | EXTERNAL-$$ / SCALE-GATED | varies | — | — |
| 8. Test-Arch +1 close | SCORECARD UPDATE-ONLY (stale by 1-2 pts) + Wave C above | Test-Arch +1 (re-grade), +1 (Wave C) | 0 | 0 (re-grade) |
| 9. CQRS +1 (event-flow viz) | SHIP NOW (~50 LOC side-batch) | CQRS +1 | ~50 | ~1h |

### Where does the score land?

**Current scorecard baseline**: 90.04 equal-weighted.

**Scorecard updates from already-shipped-but-unrecognised work** (no new code):
- Test-Arch: 98 → 99 (Tool-surface lock + widget-surface lock; scorecard line 67 stale).

**Subtotal after re-grade only: 90.12** (1 / 13 ≈ 0.08 pt for the Test-Arch nudge).

**If user authorizes the two SHIP NOW items**:
- Wave C smoke suite (item 2): NIST CSF +1, Test-Arch +1 (full bucket close from re-grade-99 to 100).
- Event-flow viz (item 9): CQRS +1 (97 → 98).

**Subtotal after SHIP NOW + re-grade: 90.35** ((+0.08 + 1/13 + 1/13 + 1/13) ≈ +0.31 over current baseline).

The Pass-17-weighted equivalent is ~95.4 (from current 95.0).

### Where's the irreducible ceiling now?

The remaining gap to 100 = anti-rec'd ceremony (27 pts) + external-$$ items (64 pts) + irreducible (0.5 pt) = **91.5 pts of theoretical 1300 = 7.04% of the rubric is structurally unreachable** at solo-project scale.

**Empirical max under constraints**: 100 - 7.04 = **92.96 equal-weighted**. (Pass-17-weighted: ~96-97.)

**After SHIP NOW items**: 90.35 / 92.96 = **97.2% of the empirical ceiling** is reached. The remaining 2.6 pts are:
- ~0.5 pt of operational hardening (per-package threshold tuning on benchmark CI; minor)
- ~1.5 pt of noise-band uncertainty in re-grade
- ~0.6 pt of items requiring SCALE-GATED conditions (5K paying users, second broker request, B2B enterprise RFP)

### Final honest answer

**The score is at the calibrated ceiling.** Phase 2 was the last code-tractable lift available at solo-project scale under the three-denominator framework. SHIP NOW items take us another +0.3 pts; everything else is either external-$$ gated or anti-rec'd.

The biggest remaining lever **is not architectural** — it's **empirical ceiling-validation work**:
- Re-grade the scorecard against HEAD `de9d2f6` (will pick up Test-Arch +1 stale)
- Ship Wave C smoke suite (NIST +1, Test-Arch +1, real user-touching protection pre-launch)
- Ship the 50-LOC event-flow viz side-batch (CQRS +1, free)

If those land, we're at ~90.35 / 92.96 empirical-max. The gap to literal 100 stays scale-gated forever; that's a calibration of the rubric against this codebase's actual scale, not a deficiency.

The user's "push to 100" instinct, applied honestly: the right next move is **stop pushing the architectural lever — push the user-facing-quality lever (Wave C) and the documentation lever (re-grade + viz)**. Those are the only remaining axes with non-zero ROI.

---

## Sources cited

- Phase 2 commits cited: `de9d2f6` (P2.6), `aaec9aa` (P2.4f), `b41f55a` (P2.4d+e), `ce52fd8` (P2.4c), `d09d65d` (P2.4b), `5deddac` (P2.4a), `c2fefd4` (recompute), `be0e327` (P2.3b), `88e6d71` (P2.3a), `11d0850` (P2.2), `310652e` (P2.1)
- Wave D Phase 1 commits: `4e12da9` (D7), `e2946f8` (D1)
- Lock test commits: `b5b500e` (tool-surface), `fd840a6` (widget-surface)
- Logger port commit: `532da34` (port + 4 accessors, 0/554 sites converted)
- MS Trusted Signing analysis: `35d7eb2`
- Empirical metrics this audit:
  - manager_init.go: 3 commits/month
  - wire.go: 48 commits/month
  - Logger call sites: 521 in `kc/`, 163 in `app/`
  - broker.{Holding,Position,OrderResponse} consumers: 236 non-test
- Scorecard baseline: `.research/scorecard-final.md` 90.04 equal-weighted
- Pattern catalog: `docs/adr/0006-fx-adoption.md`
- Build status: `go vet ./app/ ./app/providers/` clean at HEAD `de9d2f6`.

---

*Generated 2026-04-27 evening against HEAD `de9d2f6`. Read-only research deliverable. No source files modified. Authorizes the SHIP NOW items in §"Aggregate honest answer".*
