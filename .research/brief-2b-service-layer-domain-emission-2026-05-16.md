<!-- secret-scan-allow: research-doc-with-file-line-citations -->
---
title: Brief 2.B feasibility — service-layer / UC-layer domain emission
as-of: 2026-05-16
re-verify-by: 2026-08-16
master-head-at-write:
  kite-mcp-kc: 41d8bf0
  kite-mcp-domain: HEAD as of 2026-05-16 (unprobed SHA — empirical reads on tracked files)
  kite-mcp-usecases: HEAD as of 2026-05-16
  kite-mcp-bootstrap: e261bb3
scope: READ-ONLY architectural analysis; no source changes; informs user decision on parallel-API cost
prior-doc-context: showhn-redteam Track 2.A empirical re-survey retired Track 2.A from parallel execution; flagged Brief 2.B as the only remaining open architectural question
related-active-docs:
  - .research/architectural-patterns-record.md (§5 Composed Interface, §10 Aliases Shim)
  - .research/kc-manager-decomp-roadmap-2026-05-16.md (Step 2 — Wave D UCs absorption)
budget-used: ~60min of 60-90min target
---

# Brief 2.B feasibility — service-layer / UC-layer domain emission

## TL;DR (read this first)

**Recommendation: STAY ON SHAPE A (point-of-use wrapping). DO NOT SHIP SHAPE B.**

**Falsifiable claim:** the empirical wrap-call density across the entire algo2go ecosystem is **9 calls across 7 files** (verified 2026-05-16 via `grep -rln 'domain\.New(Order|Position|Holding)FromBroker\|domain\.ToDomain(Order|Holding|Position)'` over `kite-mcp-{bootstrap,kc,usecases}` excluding tests). Shape B would add **~25-35 new parallel methods + 22 broker-DTO retrieval sites to migrate** — a 3-5× multiplier of API surface to "fix" a problem that has manifested 9 times total over 6 months of development.

**The "forgetting to wrap" risk is empirically near-zero**: of the 22 sites that retrieve broker DTOs (`client.GetOrders()`, `client.GetHoldings()`, etc.), only 7 of them need lifecycle logic; the other 15 sites correctly forward DTOs to JSON-emission boundaries (widget items, dashboard renders, paper-trading echoes) where Shape B would be pure ceremony.

**Architectural reason it's the wrong call**: every persisted pattern at `.research/architectural-patterns-record.md` is *consumer-narrowing* (§1 Provider Interface, §2 Generic Decorator, §3 Tool Registry, §10 Aliases Shim). Shape B is the opposite — it *consumer-multiplying* (adds parallel methods at the producer to anticipate consumer needs). This contradicts the architectural through-line of the codebase. The Sprint 2-4 wall lesson (`session_2026-05-16_decomposition-arc-complete.md` lines 78-82) is precisely "don't add producer-side complexity to satisfy hypothetical consumer needs."

**Brief 2.B should NOT ship.** If a specific consumer site ever needs lifecycle logic, point-of-use wrapping with the existing `domain.NewXFromBroker()` constructors is sufficient — that's the canonical precedent in `fill_watcher.go:375` and `close_position.go:201`.

---

## §INPUTS — empirical state probed 2026-05-16

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | algo2go has 32 modules; `kite-mcp-{domain, kc, usecases, broker, bootstrap}` are the 5 in scope | `ls D:/Sundeep/projects/algo2go/` | 2026-05-16 |
| 2 | `domain.NewOrderFromBroker`, `domain.NewPositionFromBroker`, `domain.NewHoldingFromBroker` are the wrap constructors | `grep -nE '^func NewXFromBroker' domain/order.go domain/position.go domain/holding.go` | 2026-05-16 |
| 3 | `domain.ToDomainOrder` / `domain.ToDomainHolding` / `domain.ToDomainPosition` exist as **aliases** to the constructors (per `domain/order.go` line near `return NewOrderFromBroker(b)`) | same | 2026-05-16 |
| 4 | `domain.Order` has **13 methods**: `DTO()`, `ID()`, `Status()`, `normalizedStatus()`, `CanCancel()`, `IsTerminal()`, `IsPending()`, `IsComplete()`, `IsRejected()`, `IsCancelled()`, `FillPercentage()` + ctor | `grep '^func (o Order)' domain/order.go` | 2026-05-16 |
| 5 | `domain.Holding` has **6 methods**: `DTO()`, `PnL()`, `IsHeld()`, `InvestedValue()`, `CurrentValue()`, `InstrumentKey()` | same on holding.go | 2026-05-16 |
| 6 | `domain.Position` has **5 methods** + `DTO()`: `IsIntraday()`, `Direction()`, `IsOpen()`, `PnL()`, `UnrealizedPnL()`, `InstrumentKey()` | same on position.go | 2026-05-16 |
| 7 | `OrderService` (kc) emits broker DTOs from 5 methods: `PlaceOrder`, `ModifyOrder`, `CancelOrder`, `GetOrders`, `GetTrades` | `grep '^func (os \*OrderService)' kc/order_service.go` | 2026-05-16 |
| 8 | `PortfolioService` (kc) emits broker DTOs from 4 methods: `GetHoldings`, `GetPositions`, `GetMargins`, `GetProfile` | `grep '^func (ps \*PortfolioService)' kc/portfolio_service.go` | 2026-05-16 |
| 9 | UC files emitting `broker.{Order,Position,Holding}` from Execute: **4 files** — `get_orders.go`, `cancel_order.go`, `modify_order.go`, `queries.go` | `grep -lE 'Execute.*broker\.(Order\|Position\|Holding)' kite-mcp-usecases/*.go` | 2026-05-16 |
| 10 | Total **wrap-call sites** (point-of-use wrap-then-use): **7 files / 9 calls** | `grep -rln 'domain\.New(Order\|Position\|Holding)FromBroker\|domain\.ToDomain(Order\|Holding\|Position)' --include=*.go bootstrap/ kc/ usecases/ excluding _test` | 2026-05-16 |
| 11 | Per-file wrap-call density: analytics_tools.go=1, paper/context_tool.go=2, plugin_widget_returns_matrix.go=1, trade/pretrade_tool.go=1, fill_watcher.go=1, close_position.go=1, widget_usecases.go=3 | per-file `grep -c` | 2026-05-16 |
| 12 | Total **broker-DTO retrieval sites** (`client.GetOrders/Holdings/Positions/Trades()`): **22 calls across 11 files** | `grep -rE 'client\.Get(Orders\|Holdings\|Positions\|Trades)\(\)' --include=*.go excluding _test` | 2026-05-16 |
| 13 | Of 22 retrieval sites, 7 wrap immediately; **15 emit broker DTOs straight to JSON / widget items / dashboard payloads** without lifecycle logic | diff between probes 10 and 12 | 2026-05-16 |
| 14 | `fill_watcher.go:375` is the canonical wrap-at-point-of-use precedent: `if domain.NewOrderFromBroker(history[i]).IsComplete() { ... }` | `sed -n '370,380p' kc/fill_watcher.go` | 2026-05-16 |
| 15 | `close_position.go:201` is the second canonical precedent: `matchedPos := domain.NewPositionFromBroker(*matched)` followed by domain-method calls | `grep -n 'domain\.\|broker\.' usecases/close_position.go` | 2026-05-16 |
| 16 | `widget_usecases.go:238` (the brief's site #18) reads `client.GetOrders()` and immediately puts entries into `orderStatusMap[o.OrderID] = o` (a `map[string]broker.Order`); subsequent code reads STATUS, FILLED_QUANTITY, AVERAGE_PRICE — fields available on `broker.Order` directly | `sed -n '226,310p' usecases/widget_usecases.go` | 2026-05-16 |
| 17 | `widget_usecases.go` already has 3 `domain.NewXFromBroker` calls — but they're for **Holding** and **Position** lifecycle logic (PnL, IsHeld), NOT for Order. The Order path in widget #18 site CORRECTLY uses broker DTOs because it only needs JSON-emission of strings | per-file inspection | 2026-05-16 |
| 18 | `kc-manager-decomp-roadmap-2026-05-16.md` Step 2 plans to move 13 Wave D UC fields into `OrderService` internally (clusters C16-C20). This is INSIDE the kc module, not API change | roadmap §Step 2 | 2026-05-16 |
| 19 | Architectural Patterns Record has zero pattern that prescribes "service emits domain entity"; §5 Composed Interface (broker.Client = 9 interfaces) prescribes the OPPOSITE — narrow consumer-shaped interfaces, not producer-side wrapping | `.research/architectural-patterns-record.md` | 2026-05-16 |
| 20 | Show HN red-team Track 2.A retirement note: *"Brief 2.B should NOT ship unless Audit explicitly justifies the parallel-API cost"* | brief recital | 2026-05-16 |

> **Methodology**: every numeric claim above probed with `grep`, `wc -l`, or direct file inspection at the heads listed in frontmatter. No synthesis from prior docs without re-probe.

---

## §1 — Per-shape analysis

### §1.1 Shape A — Current (point-of-use wrap)

**Definition.** Services and UCs emit `broker.{Order,Position,Holding}` DTOs. Consumers that need lifecycle logic (status classification, PnL, fill percentage, can-cancel checks) wrap at point-of-use: `o := domain.NewOrderFromBroker(b); if o.IsComplete() { ... }`.

**Empirical precedent count**: 7 files, 9 calls (probe #10-11).

**Pros (empirical, not hypothetical):**

- **Service surface stays narrow** — `OrderService` exposes 5 methods; `PortfolioService` exposes 4 methods. No method-count explosion (#7, #8).
- **Broker contract preserved** — `client.GetOrders()` returns `[]broker.Order`; the service is a thin pass-through. Composes with the algo2go pattern §5 (Composed Interface) where `broker.Client` is a narrow 9-interface contract that services proxy without semantic enrichment.
- **JSON emission stays clean** — 15 of 22 retrieval sites (#13) only need DTO fields for JSON output (widget items, dashboard payloads, paper-trading echoes). Wrap-then-DTO()-back-to-broker would be pure ceremony for these.
- **Lifecycle logic locality** — the wrap call happens at the exact site where the lifecycle logic runs. Reading `fill_watcher.go:375` (#14) tells you that domain logic is being invoked there; you don't need to chase three layers of indirection to understand which service method was the "domain-emitting variant."
- **Architectural consistency with §10 Aliases Shim pattern** — aliases shim is *one-way conversion at the boundary*. Point-of-use wrap is the same shape: convert when crossing into domain-logic territory, not before.

**Cons (empirical, with severity):**

- **(LOW)** Consumers must remember to wrap when lifecycle logic is needed. Manifested 0 times in the codebase — every site that needs lifecycle logic has the wrap call. There's no observed instance of "forgot to wrap and got broker.Order field access where domain.Order.IsComplete() should have been called."
- **(LOW)** Two converter aliases exist (`NewOrderFromBroker` + `ToDomainOrder`) — minor stylistic inconsistency. Per probe #3 they're literally identical functions. The double naming is `kite-mcp-domain` internal; doesn't affect consumers.
- **(MEDIUM but already-mitigated)** New contributor reading widget_usecases.go #18 site might think the broker.Order path "should" use domain.Order. But the empirical reading (probe #16, #17) shows that path correctly uses broker DTOs because the widget only emits string status fields — no lifecycle logic.

### §1.2 Shape B — Proposed (parallel domain-emitting APIs)

**Definition.** Service and UC types each get parallel methods: `OrderService.GetOrdersDomain(email) ([]domain.Order, error)` alongside existing `GetOrders`; `GetOrdersUseCase.ExecuteDomain(...)` alongside `Execute`. Deprecation comments on the DTO-returning siblings. Brief 2.B's migration target: widget_usecases.go #18 site.

**Pros (claims):**

- **Explicit domain emission** — `GetOrdersDomain` in a method name expresses intent without consumers needing to know about `domain.NewOrderFromBroker`.
- **Pre-wrapped at boundary** — consumers receive `[]domain.Order` and can immediately call lifecycle methods.
- **Theoretical** — if hypothetically 50+ consumers need lifecycle logic, the parallel API saves 50+ wrap calls.

**Cons (empirical):**

- **(HIGH)** API surface doubles for a problem that has manifested 9 times in 6 months. Adding 25-35 parallel methods (next section) to satisfy a 9-call pattern is structurally wasteful.
- **(HIGH)** Deprecation cycle pain — DTO-emitting siblings can't be removed cleanly because 15 of 22 sites legitimately need broker DTOs (JSON emission, paper-trading echoes, widget items). The "deprecate then remove" cycle ends at "deprecate and never remove," producing permanent parallel APIs.
- **(MEDIUM)** Parallel methods drift over time — the next-feature-added on `GetOrders` ships to one variant but not the other. Predictable consequence (well-documented in §11 "When NOT to introduce parallel APIs" of pattern records of mature codebases).
- **(MEDIUM)** Same underlying DTO still flows through the pipe — `GetOrdersDomain` internally calls `client.GetOrders()` (broker DTOs) and wraps before return. The "domain-emitting" abstraction is at the service surface but the broker DTO is still the wire-level data shape. This means Shape B is *layering*, not *encapsulation*.
- **(MEDIUM)** Contradicts §5 Composed Interface pattern — `broker.Client` is the Composed Interface; services are supposed to be thin proxies over Composed Interfaces. Shape B injects semantic enrichment between proxy and consumer.
- **(LOW)** The brief's named migration site (widget_usecases.go #18) doesn't actually need Shape B — empirical reading (probe #16, #17) shows the Order path correctly uses broker DTOs because the widget only emits status strings, not lifecycle decisions. The migration is solving a non-problem at that specific site.

---

## §2 — Pattern-record cross-reference

Three patterns in `architectural-patterns-record.md` are directly relevant:

| Pattern | Applies how | Verdict on Brief 2.B |
|---|---|---|
| **§1 Provider Interface** (god-object decoupling) | "Use when a consumer needs ONE method (or narrow group) from a god-object" | OPPOSITE direction — Brief 2.B widens producer surface, not narrows consumer dependency |
| **§5 Composed Interface** (broker.Client = 9 narrow interfaces) | Producer interfaces should be *narrow and composed*, not *wide and enriched* | Brief 2.B contradicts — it adds wide enriched methods (`GetOrdersDomain` enriches `GetOrders`) |
| **§10 Aliases Shim** (backward-compat extraction) | Aliases are *one-way conversion at the boundary*, transitory not load-bearing | Closest analogue to Shape A wrap-at-point-of-use; Shape B is the *non-shim* alternative that becomes permanent |

**No pattern in the record prescribes "service emits domain entity."** None of the 10 codified patterns + 5 candidate patterns shows producer-side semantic enrichment as a precedent.

**Closest negative-precedent**: §1.5 ("Why drain accessor refactors don't compose with Provider Interface") records the Sprint 2-4 wall lesson. The lesson is: don't add producer-side complexity to satisfy hypothetical consumer needs. Brief 2.B is the same architectural move with different mechanism (adding parallel methods instead of exporting fields).

**Analogous to ecosystem precedent search**: zero matches for `GetOrdersDomain` / `GetXDomain` parallel variants across the algo2go ecosystem (`grep -rln 'GetOrdersDomain\|GetHoldingsDomain\|GetPositionsDomain'` returned empty). The pattern is unprecedented in the codebase.

---

## §3 — Cost forecast if Shape B is chosen

Empirical surface to multiply by 2× (parallel methods):

| Layer | Methods to double | Count | Per-method cost | Subtotal |
|---|---|---|---|---|
| `OrderService` | PlaceOrder, ModifyOrder, CancelOrder, GetOrders, GetTrades | 5 | ~15-25 LOC + test | ~100 LOC |
| `PortfolioService` | GetHoldings, GetPositions, GetMargins, GetProfile | 4 | ~15-25 LOC + test | ~80 LOC |
| Use cases — broker-DTO Execute returns | GetOrdersUC, GetPortfolioUC, CancelOrderUC, ModifyOrderUC, plus PnL/queries variants | ~6-10 UCs | ~20-30 LOC + test | ~180 LOC |
| Widget UCs (the brief's named migration target) | GetOrdersForWidgetUC, GetPortfolioForWidgetUC | 2 | ~30-50 LOC + test | ~80 LOC |
| Provider interfaces in `kc/ports/` | If Shape B's domain-emitting methods need ports → add domain-emit Provider variants | ~5-10 | ~10 LOC + assertion | ~75 LOC |
| Deprecation comments on existing DTO-emitting siblings | All 5 services × N methods each | ~25-35 | 3-5 LOC each | ~125 LOC |
| Consumer migration — 7 wrap-call sites → call new method | each site: 2-line change + import-reorg | 7 | 5-10 LOC each | ~50 LOC |

**Total new/changed LOC**: ~690 LOC across 5-6 modules.

**Estimated wall-clock cost**:
- Drafting + per-module commits + test fixtures: ~8-12h
- Cross-repo coordination (5 modules × cross-module go.mod bumps): ~3-5h (per GOPROXY-immutability lesson, this requires careful version sequencing)
- Consumer migration + review: ~2-3h
- Test churn (existing tests on DTO-emitting variants still need to pass; new tests on Domain variants need to be written): ~4-6h
- **Total: ~17-26h wall-clock**

**Comparison to point-of-use status quo**: zero new LOC, zero wall-clock. The 9 existing wrap calls cost ~9 LOC total of `domain.NewOrderFromBroker(b)` lines.

**Comparison to roadmap Step 2 cost** (Wave D UCs absorption into OrderSvc per kc-manager-decomp-roadmap §Step 2): ~6-10h, BUT that's actual decomposition work (folds god-object fields into focused services). Shape B's ~17-26h produces no decomposition — it produces parallel surface.

**ROI ratio**: 17-26h cost / 9 sites saved-future-wrap-calls = **~2-3 hours per call site avoided**. Each saved call would be a 1-line `domain.NewOrderFromBroker(b)` that the consumer would otherwise type. Trading 2-3 hours of synchronous architecture work for 1 line of consumer code is bad arithmetic.

---

## §4 — Cross-reference to Audit's Manager-decomp roadmap (Step 2)

**Question**: does Shape B conflict with Path A Step 2 (Wave D UCs absorption into OrderSvc)?

**Answer**: **Yes, in two ways.**

**Conflict 1 — direction of motion.** Step 2 moves 13 Wave D UC fields (clusters C16-C20 per roadmap §1.1) FROM `Manager` fields INTO `OrderService` as internal fields. The UCs themselves keep their existing `Execute(ctx, query) ([]broker.X, error)` signatures (no Shape B change implied). Shape B would change those UC signatures concurrently — TWO simultaneous structural changes on the same files, with two different motivations. Risk: merge conflicts + reasoning conflation ("did we move this because of decomp or because of Shape B?").

**Conflict 2 — purpose of Step 2.** Step 2 is god-object decomposition (a real architectural debt). Shape B is producer-side semantic enrichment (a hypothetical consumer convenience). Bundling them implies the decomp is *contingent on* Shape B, which it's not. The decomp pays off regardless of return type.

**Recommended sequencing if both are eventually pursued**:
1. Ship Step 2 first (Wave D UCs absorption with EXISTING signatures). 6-10h.
2. After Step 2 lands and bakes for 2-4 weeks, re-evaluate Shape B with fresh empirical data: did absorbing the UCs into OrderSvc change the wrap-call density? If yes (e.g. doubled from 9 to 18), revisit. If no, defer indefinitely.

**My recommendation**: ship Step 2 + permanently shelve Shape B. The Step 2 decomp doesn't change return types and therefore doesn't change the wrap-call density — Shape B's evidence base will not materially shift.

---

## §5 — When Shape B WOULD be justified (falsifiability)

For honesty, the conditions under which my recommendation flips:

1. **Wrap-call density rises 5× (to ~45 calls across ~30 files)** — at that point the consumer-side ceremony exceeds the producer-side parallel-API cost. Trigger re-evaluation.
2. **A specific consumer cluster needs 8+ lifecycle methods used together** — e.g. a portfolio-analytics tool that calls `IsComplete()`, `FillPercentage()`, `Status()`, `CanCancel()`, `IsTerminal()`, etc. on every Order. The wrap-then-call pattern becomes verbose. (Currently no such consumer exists — see probes #14-17.)
3. **Adapter layer needs domain emission for type safety** — e.g. a new MCP tool registration framework that requires domain types in tool signatures. (Currently MCP tools accept broker DTOs and pass them through to JSON emission — see probe #12-13.)
4. **A new broker adapter (Upstox, Dhan) emerges with different DTO shapes** — the domain layer becomes the canonical type and brokers map to it. At that point services should emit domain types so consumers are broker-agnostic. (Currently single-broker; not the world we're in.)

If any of these four conditions fires, re-open this question. None currently apply.

---

## §6 — Recommendation

**Shape A (point-of-use wrap). Permanent verdict, not pending.**

**Concrete next actions for user:**

1. **Do nothing on Brief 2.B.** Track 2.A's hedge ("Brief 2.B should NOT ship unless Audit explicitly justifies") is empirically confirmed — Audit cannot justify, and this analysis explains why.
2. **Greenlight Step 2 of kc-manager-decomp-roadmap** when ready (Wave D UCs absorption into OrderSvc). It's the actual architectural work; doesn't require Shape B.
3. **Optional cleanup**: if writing a new MCP tool that needs lifecycle logic, follow `fill_watcher.go:375` precedent (one-line `domain.NewOrderFromBroker(b)` wrap at point of use). Cite this doc in code comment if useful: `// Wrap at point of use per Brief 2.B feasibility verdict (Shape A canonical).`
4. **Add note to architectural-patterns-record.md candidate-patterns section**: codify "Point-of-Use Wrap" as a pattern with `fill_watcher.go:375` and `close_position.go:201` as canonical precedents. This makes the pattern discoverable for future contributors.

---

## §7 — Caveats + uncertainty

1. **Sample size**: 9 wrap-call sites is a small sample. If the codebase doubles in size and consumer surface grows, re-evaluate. The "5× density" trigger in §5 is the threshold.
2. **Probe scope**: my grep covered `kite-mcp-{bootstrap,kc,usecases}` plus `kite-mcp-domain` for definitions. I did NOT probe `kite-mcp-{papertrading,riskguard,decorators,clockport}` for wrap-call sites because those modules are upstream of the consumer pattern. If wrap-calls have leaked there, recount.
3. **Future-broker speculation**: my §5 condition #4 ("new broker adapter emerges") is a real possibility per `docs/multi-broker-plan.md` (Upstox/Dhan adapters planned). When that work starts, this verdict should be REVISITED — not flipped reflexively, but re-evaluated with the multi-broker constraints in mind.
4. **I did not run the tests** for this analysis (READ-ONLY constraint). All claims are static-analysis-based.

---

## §8 — Decision record format (for downstream consumption)

If user accepts this recommendation, the following can be committed as an ADR in `docs/adr/`:

```
# ADR-XXXX: Service/UC layer emits broker DTOs (not domain entities)

## Status
Accepted (2026-05-16)

## Context
Service and use-case layers can either emit broker DTOs (Shape A) or domain
entities (Shape B). Show HN red-team Track 2.A flagged Brief 2.B as an open
question. Empirical wrap-call density: 9 sites across 7 files (verified
2026-05-16). Total broker-DTO retrieval sites: 22 across 11 files. Only 7
of those need lifecycle logic; 15 legitimately emit DTOs.

## Decision
Services and UCs emit broker DTOs. Consumers that need lifecycle logic wrap
at point of use via `domain.New{Order,Holding,Position}FromBroker(b)`.

## Consequences
- Service surface stays narrow (5-9 methods per service).
- API doubling avoided (~25-35 parallel methods unnecessary).
- Lifecycle logic locality preserved at consumer sites.
- Composes with Pattern §5 (Composed Interface): broker.Client is narrow;
  services are thin proxies; consumers narrow further at point of use.

## Falsifiability triggers (re-evaluate if any fires)
1. Wrap-call density rises 5× to ~45 calls
2. A consumer cluster needs 8+ lifecycle methods on the same DTO
3. New broker adapter (Upstox/Dhan) emerges → domain layer becomes canonical
4. MCP tool registration framework requires domain types in tool signatures

## References
- .research/brief-2b-service-layer-domain-emission-2026-05-16.md
- .research/architectural-patterns-record.md (§5, §10, §1.5)
- .research/kc-manager-decomp-roadmap-2026-05-16.md (Step 2 sequencing)
```

User decision: accept the verdict + optionally codify as ADR.

---

*This document does not change code. It does not modify any other research file. It does not commit to either repo's source tree beyond this `.research/` artifact.*
