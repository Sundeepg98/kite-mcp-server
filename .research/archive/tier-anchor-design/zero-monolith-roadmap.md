# Zero-Monolith Roadmap — empirical path to absolute-zero-root-module-decomposition

**Date**: 2026-05-04
**HEAD**: `1cccfaf` (5/5 multi-module decomp complete: kc/money, broker, kc/audit, kc/riskguard, kc/billing)
**Charter**: read-only research. No code changes. User directive: *"Push for 100% decomposition. Absolutely zero monolith."*

---

## Q1 — Define "zero monolith" precisely

**Empirical end-state**: root module contains exactly `main.go` + `cmd/` + minimal wiring glue (`*_test.go` for the binary's startup tests). Everything else extracted.

**Why this is the literal limit**: `main.go` (file:1 in repo root) declares `package main` and imports the `app` package. The link target MUST live in `package main`. `cmd/` follows the same rule for auxiliary binaries (`cmd/event-graph`, `cmd/rotate-key` per `cmd/` having 4 files at HEAD). Beyond these, every package is in principle extractable. A "root contains only `app/` wiring + tests" definition is softer (allows `app/` to stay) — empirically `app/` (92 files) is the application-runtime layer and is extractable in principle if its 6 direct extracted-module deps + N-fold internal-package deps get replace-resolved.

**Defensible literal definition**: ≤5 root .go files (current 3 + room for 2 generated) + `cmd/`. Everything in `app/`, `mcp/`, `oauth/`, `plugins/`, `testutil/`, and all 22 `kc/*` packages becomes its own module.

---

## Q2 — Per-package extraction inventory

Empirical at HEAD `1cccfaf`. `internal_deps` = unique kc-prefix imports per `grep -h github.com/zerodha/... | sort -u | wc -l`. `transitive` = direct imports of already-extracted modules (broker, kc/money, kc/audit, kc/billing, kc/riskguard). Class per the brief's a/b/c/d.

| Package | Files | Class | Internal deps | Transitive ext | Replace count | Hours |
|---|---:|:---:|---:|---:|---:|---:|
| kc/i18n | 2 | **a** | 0 | 0 | 1 (root only) | 0.3 |
| kc/isttz | 2 | **a** | 0 | 0 | 1 | 0.3 |
| kc/legaldocs | 1 | **a** | 0 | 0 | 1 | 0.3 |
| kc/logger | 5 | **a** | 0 | 0 | 1 | 0.3 |
| kc/templates | 1 | **a** | 0 | 0 | 1 | 0.3 |
| kc/watchlist | 4 | **a** | 0 | 0 | 1 | 0.3 |
| kc/registry | 2 | **a** | 1 | 0 | 1 | 0.4 |
| kc/scheduler | 7 | **a** | 1 | 0 | 1 | 0.4 |
| kc/decorators | 2 | **a** | 1 | 0 | 1 | 0.4 |
| kc/users | 8 | **a** | 1 | 0 | 1 | 0.4 |
| kc/instruments | 6 | **a** | 1 | 0 | 1 | 0.5 |
| kc/aop | 6 | **a** (already gated `//go:build research`, ca9996c) | 1 | 0 | 1 | 0.3 |
| kc/cqrs | 15 | **a** | 2 | 0 | 1 | 0.6 |
| kc/ticker | 9 | **a** | 2 | 1 (broker) | 2 | 0.7 |
| kc/eventsourcing | 16 | **a** | 3 | 1 (broker) | 2 | 0.8 |
| kc/alerts | 37 | **a** | 5 | 1 (broker) | 2 | 1.2 |
| kc/papertrading | 17 | **a** | 7 | 2 (broker, riskguard) | 3 | 1.0 |
| kc/telegram | 15 | **a** | 10 | 2 (broker, riskguard) | 3 | 1.0 |
| kc/usecases | 55 | **a** | 13 | 4 (broker, money, audit, riskguard) | 5 | 2.0 |
| **kc/domain** | 32 | **b** (shared upstream — every kc/* via riskguard/audit/billing pattern depends on it) | 3 | 2 (broker, money) | 3 | 2.5 |
| **kc/ports** | 6 | **b** (cycle anchor — `kc/ports/*.go` imports `kc` per `kc/ports/session.go:18`, so extracting forces redesign) | 4 | 1 (riskguard) | n/a | redesign |
| **kc/ops** | 70 | **c** (anchor — depends on 17 internal kc/* + 4 already-extracted; HTTP admin-UI surface) | 17 | 4 (broker, audit, billing, riskguard) | 5+ | 3.0 |
| **mcp/** | 207 | **c** (anchor — MCP tool surface; depends on most kc/*) | many | 7 unique import lines | 8+ | redesign |
| **app/** | 92 | **c** (anchor — wiring + HTTP surface; depends on ~everything) | many | 6 unique import lines | 8+ | redesign |
| oauth/ | 33 | **a** | 2 (kc/templates, kc/users) | 0 | 1-2 | 1.0 |
| plugins/ | 6 | **a** | 1 | 0 | 1 | 0.5 |
| testutil/ | 7 | **d** (test-only helper, mechanical extraction adds zero engineering value but completes the goal) | 4 | 1 | 2 | 0.6 |
| examples/ | 1 | **d** (one demo file; can stay or move to `cmd/example` — trivial) | 0 | 0 | 1 | 0.2 |
| kc-root files | 44 | **b** (the `kc.Manager` god-struct + adapters + `interfaces.go` lives here; not a single package, IS the kc package) | many | 4 | n/a | redesign |

**Tractable (a)**: 19 packages. Total: ~12.5 hours estimated.
**Structural blockers (b)**: 3 (kc/domain, kc/ports, kc-root) — require redesign to extract cleanly.
**Architectural anchors (c)**: 3 (kc/ops, mcp/, app/) — surface-area redesign needed.
**Trivial-pointless (d)**: 2 (testutil/, examples/) — ~0.8 hours combined.

---

## Q3 — Optimal extraction order

Topological sort by replace-line count growth. Leaves first:

**Tier 1 — zero-internal-dep leaves** (replace count = 1, ~30 min each): `kc/i18n`, `kc/isttz`, `kc/legaldocs`, `kc/logger`, `kc/templates`, `kc/watchlist`. ~3 hours.

**Tier 2 — single-internal-dep** (replace count = 1, after Tier 1 done): `kc/registry`, `kc/scheduler`, `kc/decorators`, `kc/users`, `kc/instruments`. ~2 hours.

**Tier 3 — moderate-fan-in** (replace count = 1-2): `kc/cqrs`, `kc/ticker`, `kc/eventsourcing`. ~2 hours.

**Tier 4 — heavy-fan-in but tractable** (replace count = 2-5): `kc/alerts`, `kc/papertrading`, `kc/telegram`, `kc/usecases`. ~5 hours.

**Tier 5 — peripheral**: `oauth/`, `plugins/`, `testutil/`, `examples/`. ~2 hours.

**Total tractable: ~14 hours across 19 narrow extractions** + ~10-15 minutes per Dockerfile redeploy verification across 5-7 Fly.io v200-v206 deploy cycles.

---

## Q4 — Honest cost (the structural ceiling)

**Replace-line count per new module**: empirical curve from commits 3-5 plateaued at **3** (root + broker + kc/money) for kc-package extractions. With kc/usecases (4 transitive: broker, money, audit, riskguard) the count goes to **5**. With future tier-4 extractions all five could need replace lines for every prior extracted sibling that they transitively reach, growing to **6-8 lines per go.mod**. Worst case at full 5/5 + 19 more extractions = ~24 modules × ~6 avg replaces = **~144 replace lines spread across 24 go.mod files**. Maintenance cost: every domain-package upgrade ripples.

**Dockerfile pre-COPY layers**: current 5 → ~24-28. Cache-busting risk on every go.mod edit grows with N. Build time cost: each layer adds ~50-100ms; total +1-2s per build (negligible).

**`go work sync` cold-cache time** at N≈24: empirically per commit-4 sync took ~5-8s. Linear in N. Cold-cache at N=24 ≈ 30-45s (within prior research watermark).

**Total ship cost (tractable group, excludes anchors/blockers)**: **~14 hours of code work** + **~5-7 redeploy cycles** at ~10 min each = **~16 hours** for 19 more extractions. Plus blockers: kc/domain redesign 4-6 hours, kc/ports redesign 2-4 hours, kc-root god-struct decomposition 8-16 hours. Anchors: mcp/ + app/ redesign 20-40 hours each.

**Realistic 100% (everything except `main.go` + `cmd/`)**: **~80-120 hours** total spread across multiple sessions, including the architectural redesigns.

---

## Q5 — Architectural anchor problem

**Empirical reality**: `mcp/` is 207 files of MCP tool handlers; `app/` is 92 files of HTTP routing + Fx wiring + lifecycle; `kc/ops/` is 70 files of admin-dashboard routes. These three are **not** "packages" in the bounded-context sense — they are **the application's runtime composition layer**.

`mcp/common_deps.go:30-71` (the `ToolHandlerDeps` struct) wires every kc/* package as a dep field; extracting `mcp/` to its own module would require turning that struct into a port + adapter layer, which is multi-month rearchitecture, not a chore.

**Defensible answer**: option **(ii)** — accept that `mcp/`, `app/`, and `kc/ops/` stay in root module as the application's runtime composition layer. **Root != monolith** when everything else is modular and root is just the wiring graph. Per `28169b6` `.research/100-pct-decomposition-strategy.md` Q1 hybrid definition: "100% of modules with defensible standalone-consumer story" — the runtime composition layer has no consumer story; it IS the application.

This matches the prior `5437c32` `.research/disintegrate-and-holistic-architecture.md` end-state: 22-package "core monorepo" + 5-7 extracted modules. Pushing past 5 is in scope; pushing the runtime composition out is architecturally coherent only via genuine port-adapter rearchitecture (not "add go.mod").

---

## Q6 — Should orchestrator dispatch this?

**Honest verdict (push-back with empirical evidence)**:

**The 19 tractable extractions ARE achievable** (~14 hours, scattered across 4-5 sessions with redeploy verification). **The 3 structural blockers + 3 anchors are NOT achievable as "add go.mod" chores** — they're 50+ hours of architectural redesign.

**Per `feedback_decoupling_denominator.md`, state preconditions explicitly**:

- **Axis A (user-MRR)**: Zero direct lift. None of the 24 modules will gain external consumers post-launch at <50 GitHub stars (per `5437c32` empirical 31% promotion probability).
- **Axis B (agent-concurrency)**: Marginal gain only when 3+ agents work on disjoint kc/* packages simultaneously. Empirically did NOT happen across F1-F7 + 5/5 sessions (single-thread chain with chain agent).
- **Axis C (tech-stack-portability)**: Per `parallel-stack-shift-roadmap.md`, modules become language-port targets. Most-likely targets per the audit: `kc/riskguard` (Rust), `kc/ticker` (Rust), `mcp/widgets` (TS). Of 19 tractable extractions, ~3-4 align with the stack-shift shortlist. The other 15 extractions buy zero portability.

**My prior `28169b6` "stop at 3" was vindicated by the cost-curve plateau** at commit 3-5 (replace count stayed at 3, not super-linear as I'd warned). User's override on commits 4-5 was vindicated empirically — the ceremony cost was ~50 min per extraction, not the 2-3 hours I estimated.

**My empirical recommendation for the literal-zero-monolith goal**:

1. **Ship the 19 tractable extractions** (~14 hours, 4-5 sessions). Each is a `1cccfaf`-shape commit. No new architectural work. Pure plateau-shape extension.
2. **Stop at the 3 anchors + 3 blockers**. Do NOT redesign mcp/, app/, kc/ops/, kc/domain, kc/ports, or kc-root for module-extraction purposes. Their port-adapter redesigns should happen for OTHER reasons (multi-broker integration, language-stack-shift activation, mcp-widget TS port) — and the module-extraction will fall out of THOSE projects naturally.
3. **End-state at 5/5 + 19 = 24 modules**. Root contains main.go + cmd/ + 6 unmodularizable packages (mcp/, app/, kc/ops/, kc/domain, kc/ports, kc-root god-struct). That IS the literal-zero-monolith achievable today; "absolute zero" requires multi-month architectural work the user has not authorized.

**Dispatchable plan**: 19 narrow commits across 4-5 sessions, ~14 hours total. Same shape as commits 4-5. After 24/24 (all-tractable shipped), stop and flag whether the user accepts root-as-composition-layer as the end-state, OR commits to the architectural redesign budget for the anchors.

---

## Sources

- HEAD `1cccfaf` empirical inventory (this audit)
- `.research/disintegrate-and-holistic-architecture.md` `5437c32` Q1 hybrid definition
- `.research/100-pct-decomposition-strategy.md` `28169b6` cost-curve framework
- `.research/parallel-stack-shift-roadmap.md` `8361409` per-component language targets
- `feedback_decoupling_denominator.md` three-axis ROI framework
- Empirical commits 1-5: `b7fedcc`, `5d74acf`, `9ce2248`, `5982aff`, `1cccfaf`
- F7 build-tag pattern: `ca9996c` (kc/aop already research-gated)

---

*2026-05-04. Read-only. End-state: 24 modules + 6 anchors as runtime composition layer. ~14 hours dispatchable; +50-120 hours of architectural redesign for true literal-zero requires explicit user-authorization.*
