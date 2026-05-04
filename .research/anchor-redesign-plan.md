# Anchor Redesign Plan — Path B Multi-Month Restructure

**Date**: 2026-05-04
**HEAD audited**: `a5e7e76` (`research: zero-monolith-roadmap`)
**Charter**: read-only research. Single doc. NO code changes. Coordinated read-only — architecture agent `ac06fb8a7f7d864a6` is in flight on Tier-1 leaf extractions; this plan extrapolates from the **post-Tier-1 state**.
**Per `feedback_decoupling_denominator.md`**: ROI denominator is multi-agent parallel-dev velocity + multi-broker readiness, NOT user-MRR. Drop "ceremony" labels; state preconditions empirically.

**Empirical at HEAD (verified, not dispatch-claimed)**:

| Anchor | Files (mine) | Dispatch claim | Reconciled |
|---|---:|---:|---|
| `mcp/` | 207 | 207 | match |
| `app/` (root only) | 60 | 92 | dispatch counted `app/providers/` recursively; verified 60 root-level + ~32 in providers ≈ 92 |
| `kc/ops/` | 70 | 70 | match |
| `kc/domain/` | 32 | ? | new datum |
| `kc/ports/` | 6 | ? | new datum |
| `kc-root` | 75 | 44 | dispatch counted only `manager_*.go` siblings; verified 75 incl. service+helper files |

**`kc.Manager` empirical**: 137 methods total across all `manager_*.go` files. **This is the god-struct in absolute terms.**

---

## Anchor 1 — `mcp/` (207 files)

**Empirical structural read**: 61 `*tools*.go` (tool definitions, ~111 NewTool registrations), 16 `*middleware*.go`, 113 `*_test.go`, ~17 supporting files (common, ext_apps, response envelopes). Imports 16 distinct `kc/*` subpackages: `alerts, audit, billing, cqrs, decorators, domain, instruments, logger, ports, riskguard, scheduler, templates, ticker, usecases, users, watchlist`. Three dominant patterns: (1) tool registration via `RegisterInternalTool`, (2) middleware chain (audit + riskguard + papertrading + billing wrappers around ToolHandlerFunc), (3) shared `ToolHandler` deps struct at `mcp/common.go` reaching kc.Manager via 11 `*Provider` getters.

**Redesign options**:
- **Option X (single big extract)**: cheap, preserves all 207 files in one new module. Solves nothing — still imports 16 kc/* subpackages, so the entire kc tree extracts with it.
- **Option Y (split into N bounded contexts)**: 6 candidate sub-modules — `mcp/tools-trade` (post/exit/gtt/options ~8 files), `mcp/tools-portfolio` (get/account/margin/dividend/sector ~8), `mcp/tools-analytics` (backtest/indicators/peer/concall/fii_dii ~8), `mcp/tools-alerts` (alert/composite/native/trailing ~10), `mcp/tools-admin` (10 admin*.go), `mcp/middleware` (16 middleware files). Each ~12k LOC.
- **Option Z (port-adapter)**: declare a `kc/mcp-host` port (the ToolHandler interface surface) in `kc/ports`; mcp/ stays as-is but consumes via the port. Doesn't change LOC; changes import direction.

**Recommended**: **Option Y after kc.Manager → port migration completes**. mcp/ has clean tool-domain seams already (tool files cluster by domain). Pre-condition: kc.Manager 137-method surface must be replaced by ports.AlertPort/SessionPort/etc. (already started — `106f24e`/`633a3fd`/`79ce6c8`/`86edb33` in this session).

**Cost**: ~6-8 engineering weeks (real hours, not agent dispatch hours) — moves 6×~12k-LOC sub-packages, rewrites ToolHandler factory per sub-package, regen schema-lock golden table for each.

**Pre-conditions**: (a) kc.Manager 137-method surface < 50 methods (port migration done); (b) at least 2 sub-packages independently maintainable by separate agents — empirical trigger for this is "I edited mcp/post_tools.go and mcp/get_tools.go in parallel and merge-conflicted ≥3 times in a sprint"; today's session shows zero such conflicts. Premature.

**Risk**: schema-lock golden table breakage on every split (drift CI per `tool-count-drift.yml`); cycles surface if tool-domain sub-packages share helpers (mitigation: extract `mcp/common` first as shared lib).

---

## Anchor 2 — `app/` (60 root + ~32 in providers/ ≈ 92)

**Empirical structural read**: HTTP server (http.go 1500+ LOC), Fx wiring (wire.go), middleware (recovery, ratelimit, requestid), lifecycle (graceful_restart_*.go 4 files), legal/healthz/integration test infrastructure. `app/providers/` is already a clean Fx-recipe partition (alertdb / audit / billing / event_dispatcher / mcpserver / scheduler / lifecycle ~32 files). Three dominant patterns: (1) HTTP route handlers in http.go, (2) Fx provider recipes in providers/, (3) lifecycle hooks for graceful shutdown.

**Redesign options**:
- **Option X (single extract)**: meaningless — `app/` literally is the runtime entry point composing everything. Can't extract without losing the `main.go` wiring story.
- **Option Y (split http vs runtime)**: `app/http/` (route handlers, ~25 files) vs `app/runtime/` (Fx wiring + lifecycle + providers, ~67 files). Marginal value.
- **Option Z (extract `app/providers` only)**: providers/ is already isolated; could become its own module `kite-mcp-fx-recipes`. Useful for multi-server reuse.

**Recommended**: **leave as-is until multi-deployment trigger fires**. Pre-condition: a second top-level binary (CLI tool, alternate server) needs the Fx recipes — then extract `app/providers/`. Today: single binary, single deployment.

**Cost**: 0 weeks today; ~2 weeks to extract `app/providers/` when triggered.

**Pre-conditions**: second top-level binary exists OR ≥3 providers reused outside app/. Neither true today.

**Risk**: low — `app/` is the natural "everything else" sink; splitting is cosmetic without a real second consumer.

---

## Anchor 3 — `kc/ops/` (70 files)

**Empirical structural read**: admin dashboard handlers (api_handlers, api_activity, api_alerts, dashboard.go), per-page renderers (page_handlers.go), templates wiring. Imports 10 kc/* subpackages: `alerts, audit, billing, cqrs, domain, logger, registry, templates, ticker, users`. Three dominant patterns: (1) HTTP→CQRS dispatch (writeJSON/writeJSONError envelope), (2) admin authn/authz checks (selfDeleteAccount + admin user CRUD), (3) page render handlers using `kc/templates`.

**Redesign options**:
- **Option X (single extract)**: would form `kite-mcp-ops` dashboard library — possibly reusable. 10-package import surface stays; not a clean leaf.
- **Option Y (split user-facing vs admin)**: `kc/ops/user/` (dashboard, activity, alerts, paper) vs `kc/ops/admin/` (admin_*, billing, registry). Each independently extractable.
- **Option Z (port-adapter for admin commands)**: declare admin ops as use-case input ports; `kc/ops` stays as the HTTP adapter, no extraction.

**Recommended**: **Option Y after kc/ops own admin-feature stabilization**. Today's admin surface still has feature drift (admin_billing_tools, admin_anomaly_tool added in last 30d). Wait for stability + actual contributor needing to maintain admin separately.

**Cost**: ~3-4 weeks to split user vs admin; ~1 week to single-extract.

**Pre-conditions**: separate admin contributor OR admin surface stops mutating for 60 days OR admin auth becomes pluggable (e.g., SSO). None yet.

**Risk**: shared template helpers in `kc/templates` would duplicate or require third extraction; users of dashboard might want admin views (cycle).

---

## Anchor 4 — `kc/domain/` (32 files)

**Empirical structural read**: pure domain value objects + specs — `alert/credential/instrument/money/order/position/profile/session/holding/family/quantity` plus their `*_test.go`. **Zero downstream imports** beyond stdlib + kc/money. **143 importing files** depend ON it (highest fan-in in the codebase). Three dominant patterns: (1) value-object structs with domain invariants, (2) `*_spec.go` for specification pattern, (3) `events.go` for domain event types.

**Redesign options**:
- **Option X (single extract)**: ideal leaf candidate — zero internal deps, 143 reverse-deps. Trivial extraction; massive cascading replace updates.
- **Option Y**: not applicable; domain is already cohesive.
- **Option Z**: not applicable; domain has no adapter aspect.

**Recommended**: **Option X — extract as next module after current Tier-1 batch closes**. This is the highest-leverage anchor: domain is the **pre-requisite for cleanly extracting mcp/, kc/ops/, kc-root, and kc/ports** — every one of those imports `kc/domain`. Promote it first; downstream extracts become 1-replace not N-replace.

**Cost**: ~3-5 days. Mostly Dockerfile manifest-staging + 143-site sed rewrite (`kite-mcp-server/kc/domain` → `algo2go/kite-mcp-domain` or staying in-tree as `./kc/domain` go.mod). Mechanical.

**Pre-conditions**: none beyond Tier-1 close; this UNBLOCKS others.

**Risk**: if domain types are mutated frequently (e.g., add fields to `Order` struct), every reverse-dep needs go.mod bump. Mitigation: stay in-tree as multi-module via `replace` until domain types stabilize for ≥30 days; only THEN promote to GitHub repo.

---

## Anchor 5 — `kc/ports/` (6 files)

**Empirical structural read**: 6 port interface files — `alert/assertions/credential/instrument/order/session`. **All 6 import `kite-mcp-server/kc`** (the parent package), which is empirically a circular surface — ports are supposed to flow downward to consumers, not upward to the monolith. Three dominant patterns: (1) interface declarations exposing kc.Manager methods through narrowed contracts, (2) `assertions.go` for port-implementation type assertions, (3) zero adapter logic — pure port declarations.

**Redesign options**:
- **Option X (single extract as-is)**: would carry the `kc` parent import with it — extraction would create a literal cycle in module graph (broker imports algo2go-ports which imports kite-mcp-server-root). **Impossible without redesign.**
- **Option Y**: split each port into its own bounded context paired with its domain (alert port → kc/alerts, session port → kc/session-svc).
- **Option Z (port-adapter inversion)**: rewrite ports to import only `kc/domain` types, NOT `kc` parent. This is the actual redesign — flip the import direction.

**Recommended**: **Option Z — invert imports. PRE-REQUISITE for kc-root god-struct cleanup.** Today, ports.AlertPort returns `kc.AlertStoreInterface` (defined in `kc/interfaces.go`), creating the circular surface. Move `*Interface` declarations from `kc/interfaces.go` to `kc/ports/*.go`, drop the `import "kc"` lines.

**Cost**: ~2-3 weeks. Each port file is small (~50 LOC) but the assertion infrastructure + 5 reverse-imports + every consumer's interface check must update.

**Pre-conditions**: kc/domain extracted first (Anchor 4) — gives ports a clean upstream to depend on without touching kc parent.

**Risk**: high — interface drift between `kc/interfaces.go` and `kc/ports/*.go` (already exists per `redundancy-audit.md` F1+F2). Race condition: refactor must move declarations atomically per port. Mitigation: one-port-per-PR, full CI green between ports.

---

## Anchor 6 — `kc-root god-struct` (75 root files, 137-method `Manager`)

**Empirical structural read**: `kc.Manager` is the literal monolith glue. 137 methods spanning session/credential/order/alert/admin/setup/exit/oauth/lifecycle. Files: `manager.go` (struct + ctor), `manager_accessors.go` (16 getter methods), `manager_init.go` (14), `manager_commands_*.go` (12 across account/admin/exit/oauth/orders/setup), `manager_lifecycle.go` (3), plus services (alert/order/portfolio/family/session/credential/scheduling/eventing) declared as siblings. Three dominant patterns: (1) Manager-as-DI-container (every kc/* type assembled here), (2) sibling Service structs for narrow domain commands, (3) test mocks_test.go.

**Redesign options**:
- **Option X (extract as-is)**: meaningless; the Manager IS the monolith. Extracting it means extracting kc/.
- **Option Y (split Manager into N domain-services)**: 8-10 narrower service structs (AlertService, OrderService, SessionService — already partially exists per `kc/session_service.go`/`alert_service.go`). Manager becomes a thin assembler.
- **Option Z (Fx app-wiring replaces Manager)**: move all DI from `kc.Manager` constructor into `app/providers/*.go`; Manager becomes essentially empty. Per `app/providers/` already showing 32-recipe partition, this is partly underway.

**Recommended**: **Option Z — let Fx assume DI ownership; gut Manager**. The empirical signal: `app/providers/` already has alertdb/audit/billing/event_dispatcher/mcpserver/scheduler recipes. Each method on Manager that just `return m.<field>` is a candidate to delete (consumer takes the dep directly via Fx). Empirical estimate: ~60-80 of 137 methods are pure getters → delete-able.

**Cost**: ~8-12 weeks (longest single anchor). Touches every Manager call site. Must run after Anchors 4+5 (domain + ports stable).

**Pre-conditions**: kc/domain extracted (Anchor 4); kc/ports inverted (Anchor 5); ≥3 services already standalone (`kc/session_service.go`, `kc/alert_service.go`, `kc/order_service.go` exist — partial start). Trigger: ≥2 contributors editing Manager simultaneously and merge-conflicting (none observed today).

**Risk**: highest of all 6. Cycles likely surface during interim states (Manager has fields → service has fields → Fx assembles both); test coverage on Manager constructor path is the safety net (verify `kc/manager_construction_test.go` stays green after every method removal).

---

## Cross-Anchor Topological Order

Empirical dependency:

```
Anchor 4 (kc/domain) ─┬─→ Anchor 5 (kc/ports invert) ─→ Anchor 6 (kc-root)
                       └─→ Anchor 1 (mcp/ split) ─→ —
                       └─→ Anchor 3 (kc/ops split) ─→ —
                            Anchor 2 (app/) — independent, fires only on 2nd binary trigger
```

**Execution order if user wants all 6**:
1. **Anchor 4 (kc/domain)** — 3-5 days, unblocks 1, 3, 5, 6
2. **Anchor 5 (kc/ports inversion)** — 2-3 weeks, unblocks 6
3. **Anchor 6 (kc-root god-struct)** — 8-12 weeks (longest)
4. **Anchor 1 (mcp/ Y-split)** — 6-8 weeks (parallelizable with 3 if separate contributors)
5. **Anchor 3 (kc/ops split)** — 3-4 weeks (parallelizable with 1 + 3)
6. **Anchor 2 (app/providers extract)** — 0 weeks today; ~2 weeks when 2nd-binary trigger fires

**Total calendar (sequential single-developer)**: ~5-7 months. **Parallel 3-agent**: ~3-4 months. **Realistic given current 0-stars / 0-external-contributors / pre-launch state**: defer 2, 3, 6 until triggers fire; execute 4 + 5 opportunistically; defer 1 until mcp/ contributor pain emerges.

---

## Honest Verdict

**Anchors GENUINELY worth the cost today (post-Tier-1)**:
- **Anchor 4 (kc/domain)** — cheap (3-5 days), unblocks four others, 143-file fan-in means downstream module-extracts get 1 replace not N. **Execute next, opportunistic.**
- **Anchor 5 (kc/ports inversion)** — required prerequisite for clean kc-root cleanup; the circular surface (`kc/ports/alert.go:6` imports `"github.com/zerodha/kite-mcp-server/kc"`) is a real architectural defect that pre-empts Anchor 6. **Execute when Anchor 4 closes.**

**Anchors that are pure ceremony at our scale today**:
- **Anchor 2 (app/)** — single binary; nothing to gain.
- **Anchor 1 (mcp/)** — 207 files, but zero merge conflicts in current sessions. Splitting is empirical-trigger gated.
- **Anchor 3 (kc/ops)** — admin surface still mutating; premature.
- **Anchor 6 (kc-root)** — highest cost (8-12 weeks), highest risk; only fires when ≥2 Manager-touching contributors collide. Today: 1 maintainer.

**Net recommendation**: execute Anchors **4 + 5** in the next 4-6 weeks (~1 calendar month including stabilization). Defer 1, 2, 3, 6 explicitly until empirical triggers fire. Re-evaluate at N=8 modules, second-broker ship, or first external contributor PR touching `kc/`.

---

**End of plan. No code changes. No tests run. Doc-only deliverable.**
