# Anchor 1 (mcp/ Y-split) + Anchor 3 (kc/ops split) PR-Level Design

**Date**: 2026-05-04
**HEAD audited**: `b922a20` (Anchor 4 PR 4.7 landed; **24/24 ZERO MONOLITH REACHED** — Tier 4 complete; all kc/* subpackages extracted)
**Builds on**: `7ac9d34 b-full-pr-shapes.md`, `fd603f3 b-full-20-agent-reframe.md`, `5fbd4a1 tier-5-and-anchor-6-pre-stage.md`
**Charter**: read-only research. Doc-only. NO code changes.

**Critical empirical correction to `7ac9d34`**:
- mcp/ has **94 prod files** at HEAD (not 207 — that was test-inclusive). **60 actual tool-registration sites** via `grep -lE "RegisterInternalTool|mcp\.NewTool"`.
- kc/ops/ has **41 prod files** (not 70 — test-inclusive). 25 import kc parent (cycle surface).
- Reverse-deps: mcp/ has 11 importing files; kc/ops/ has 3.

---

## Q1 — Anchor 1 (mcp/ Y-split, 12 PRs)

### Empirical clustering at HEAD `b922a20`

| Sub-package | Files | Examples |
|---|---:|---|
| **mcp/common** | 9 | mcp.go, common.go, common_deps.go, common_response.go, common_tracking.go, cache.go, decorator_chain.go, elicit.go, integrity.go |
| **mcp/middleware** | 7 | circuitbreaker_middleware.go, correlation_middleware.go, middleware_chain.go, middleware_dsl.go, plugin_middleware.go, ratelimit_middleware.go, timeout_middleware.go |
| **mcp/plugin** | 13 | plugin_events.go, plugin_lifecycle.go, plugin_manifest.go, plugin_register_full.go, plugin_registry.go, plugin_sbom*.go (2), plugin_watcher.go, plugin_widget_*.go (5), plugin_widgets*.go (2) |
| **mcp/admin** | 10 | admin_*_tool*.go (9) + admin_deps.go |
| **mcp/trade** | 9 | post_tools.go, exit_tools.go, gtt_tools.go, option_tools.go, options_greeks_tool.go, native_alert_tools.go, trailing_tools.go, mf_tools.go, pretrade_tool.go |
| **mcp/portfolio** | 9 | account_tools.go, get_tools.go, margin_tools.go, dividend_tool.go, sector_tool.go, rebalance_tool.go, pnl_tools.go, position_history_tool.go, order_history_tool.go |
| **mcp/analytics** | 6 | backtest_tool.go, indicators_tool.go, peer_compare_tool.go, concall_tool.go, fii_dii_tool.go, analytics_tools.go |
| **mcp/alerts** | 6 | alert_tools.go, alert_history_tool.go, composite_alert_tool.go, volume_spike_tool.go, alert_deps.go, projection_tool.go |
| **mcp/paper** | 5 | paper_tools.go, setup_tool.go, setup_tools.go, context_tool.go, observability_tool.go |
| **mcp/misc (deferred)** | 15 | compliance_tool.go, market_tools.go, ticker_tools.go, tax_tools.go, watchlist_tools.go, version_tool.go, prompts.go, resources.go, ext_apps.go, mutable_request.go, response_sanitize.go, retry.go, registry.go, tool_registry.go, session_admin_tools.go |

That's 89 categorized files; 5 left for cleanup PR. Tool-registration count = 60 (verified empirically).

### Per-PR Design

**PR 1.1 — `refactor(mcp/common): extract shared response envelope + ToolHandler factory`**
- **Files**: 9 files moved into `mcp/common/` subpackage. Update imports across remaining mcp/ files to `mcp/common`.
- **Build verification**: `go build ./...` + `GOWORK=off go build ./...` + `go test ./mcp/common/...`. Critical: 60 tool registrations all reference `ToolHandler` from common; verify all 60 still compile.
- **Acceptance**: `mcp/common/` is leaf (no internal mcp/ imports); 60 tool-registration sites all compile.
- **Time**: ~45 min (largest single move; touches everything).
- **Inter-PR coupling**: PRE-REQUISITE for PRs 1.3-1.10. Independent of 1.2.

**PR 1.2 — `refactor(mcp/middleware): extract 7 middleware files`**
- **Files**: 7 middleware files moved to `mcp/middleware/`.
- **Build verification**: same gate; verify middleware-chain wiring at app-level still resolves.
- **Acceptance**: middleware compiles standalone; chain test passes.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PR 1.1 (middleware imports common types). **Parallel-safe with 1.3-1.10 once 1.1 lands.**

**PR 1.3 — `refactor(mcp/plugin): extract plugin infrastructure (13 files)`**
- **Files**: plugin_events.go, plugin_lifecycle.go, plugin_manifest.go, plugin_register_full.go, plugin_registry.go, plugin_sbom*.go (2), plugin_watcher.go, plugin_widget_*.go (5), plugin_widgets*.go (2). Total 13.
- **Build verification**: same gate. Plugin loader integration test must pass.
- **Acceptance**: plugin/ subpackage compiles; widget runtime intact.
- **Time**: ~40 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with 1.2/1.4-1.10.**

**PR 1.4 — `refactor(mcp/admin): extract admin_*_tool*.go + admin_deps.go (10 files)`**
- **Files**: 10 admin files.
- **Build verification**: `go test ./mcp/admin/... -count=1`; tool-count-drift CI green.
- **Acceptance**: admin subpackage tools register correctly; tool-count unchanged.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with 1.2/1.3/1.5-1.10.**

**PR 1.5 — `refactor(mcp/trade): extract 9 trade tool files`**
- **Files**: post_tools.go, exit_tools.go, gtt_tools.go, option_tools.go, options_greeks_tool.go, native_alert_tools.go, trailing_tools.go, mf_tools.go, pretrade_tool.go.
- **Build verification**: tool registrations re-verified; `mcp/trade/` standalone build.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with 1.2/1.3/1.4/1.6-1.10.**

**PR 1.6 — `refactor(mcp/portfolio): extract 9 portfolio tool files`**
- **Files**: account_tools.go, get_tools.go, margin_tools.go, dividend_tool.go, sector_tool.go, rebalance_tool.go, pnl_tools.go, position_history_tool.go, order_history_tool.go.
- **Build verification**: same gate; `mcp/portfolio/` standalone.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with 1.2-1.5/1.7-1.10.**

**PR 1.7 — `refactor(mcp/analytics): extract 6 analytics tool files`**
- **Files**: backtest_tool.go, indicators_tool.go, peer_compare_tool.go, concall_tool.go, fii_dii_tool.go, analytics_tools.go.
- **Build verification**: `mcp/analytics/` standalone build; LLM-coordinator pattern preserved (per `a757139`).
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with 1.2-1.6/1.8-1.10.**

**PR 1.8 — `refactor(mcp/alerts): extract 6 alert tool files`**
- **Files**: alert_tools.go, alert_history_tool.go, composite_alert_tool.go, volume_spike_tool.go, alert_deps.go, projection_tool.go.
- **Build verification**: alert registration intact; `mcp/alerts/` standalone build.
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe.**

**PR 1.9 — `refactor(mcp/paper): extract 5 paper/setup tool files`**
- **Files**: paper_tools.go, setup_tool.go, setup_tools.go, context_tool.go, observability_tool.go.
- **Build verification**: `mcp/paper/` standalone; paper-trading middleware integration test.
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe.**

**PR 1.10 — `refactor(mcp/misc): extract 15 misc tool files`**
- **Files**: compliance_tool.go, market_tools.go, ticker_tools.go, tax_tools.go, watchlist_tools.go, version_tool.go, prompts.go, resources.go, ext_apps.go, mutable_request.go, response_sanitize.go, retry.go, registry.go, tool_registry.go, session_admin_tools.go.
- **Build verification**: same gate; verify mcp/ root has only init/registration glue remaining.
- **Time**: ~40 min (heterogeneous; needs careful per-file categorization).
- **Inter-PR coupling**: depends on PR 1.1. **Parallel-safe with all other 1.X (the misc files are leaf-like).**

**PR 1.11 — `chore(go.work,Dockerfile): add 9 mcp sub-packages to workspace`**
- **Files**: `go.work` (add 9 use paths), root `go.mod` (add 9 replace directives), `Dockerfile` (pre-stage 9 manifests).
- **Build verification**: `go work sync` clean; root + GOWORK=off build green; full Docker build.
- **Acceptance**: 9 mcp sub-modules registered; build pipeline updated.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PRs 1.1-1.10 (each subpackage must have its own go.mod by this point — implied in each PR's setup).

**PR 1.12 — `chore: deploy v204+ with mcp/ Y-split; verify tools=111 unchanged across 9 sub-packages`**
- **Files**: zero (deploy-only).
- **Build verification**: `flyctl deploy`; healthz green; tool-count-drift CI green; 24h observation window.
- **Acceptance**: production stable; tool count unchanged.
- **Time**: ~30 min + 24h observation.
- **Inter-PR coupling**: depends on PR 1.11.

**Anchor 1 total**: 12 PRs / ~6 hours review (re-derived from per-PR; vs prior `7ac9d34` 38h estimate which budgeted serial calendar).

### Cross-PR for Anchor 1

**Topological order at N=20**:
```
PR 1.1 (common) ── PRE-REQUISITE
       │
       ├─→ PR 1.2 (middleware) ─┐
       ├─→ PR 1.3 (plugin)      ├─→ 9-WAY PARALLEL FAN-OUT
       ├─→ PR 1.4 (admin)       │   (1.2 through 1.10 all run simultaneously)
       ├─→ PR 1.5 (trade)       │
       ├─→ PR 1.6 (portfolio)   │
       ├─→ PR 1.7 (analytics)   │
       ├─→ PR 1.8 (alerts)      │
       ├─→ PR 1.9 (paper)       │
       └─→ PR 1.10 (misc)       ┘
                  │
                  └─→ PR 1.11 (workspace + Dockerfile)
                              │
                              └─→ PR 1.12 (deploy + verify)
```

**Mid-Anchor checkpoints**: codebase deployable at every PR boundary. PR 1.1 leaves mcp/ root with same surface but routing through `mcp/common`. PRs 1.2-1.10 each move a cluster but the parent mcp/ package retains a re-export shim (1-line aliases pointing to subpackages) to preserve backward-compat for the 11 mcp/ reverse-dep files.

**Risk floor (smallest first PR)**: **PR 1.7 (analytics, 6 files)** if user wants smallest LOC. **PR 1.1 (common, 9 files)** is the actual unavoidable first PR — it's the prerequisite. The 9 common files include `mcp.go` itself which is the package init point.

**Anchor 1 calendar at N=20**: PR 1.1 (~45 min) → 9-PR parallel fan-out (~45 min including review queue) → PR 1.11 (~30 min) → PR 1.12 (~30 min + 24h). **Total: ~2 days calendar** vs prior estimate 6-8 weeks at solo.

---

## Q2 — Anchor 3 (kc/ops split, 8 PRs)

### Empirical clustering

41 prod files in kc/ops. Breakdown:

| Sub-domain | Files | Names |
|---|---:|---|
| **api_*** (HTTP API) | 8 | api_activity, api_alerts, api_handlers, api_orders, api_paper, api_portfolio, api_tax, plus shared deps |
| **dashboard_*** (per-page renderers) | 9 | dashboard.go, dashboard_activity.go, dashboard_alerts.go, dashboard_orders.go, dashboard_paper.go, dashboard_portfolio.go, dashboard_safety.go, dashboard_templates.go, plus user_render.go |
| **handler_*** (route handlers) | 11 | handler.go, handler_account.go, handler_admin.go, handler_alerts.go, handler_credentials.go, handler_logs.go, handler_metrics.go, handler_orders.go, handler_paper.go, handler_portfolio.go, handler_safety.go, handler_tax.go, handler_telemetry.go |
| **user_*_render.go** | 7 | user_activity_render.go, user_alerts_render.go, user_orders_render.go, user_paper_render.go, user_portfolio_render.go, user_render.go, user_safety_render.go |
| **shared/admin** | 5 | admin_render.go, data.go, logbuffer.go, overview_render.go, overview_sse.go, page_handlers.go |
| **misc/util** | 1 | (any remainder) |

**The kc/ops split should follow the audit's recommendation in `7ac9d34`**: `kc/ops/admin/` (admin-facing routes + handlers) vs `kc/ops/user/` (user-facing dashboard + APIs). The `handler_admin.go`, `admin_render.go`, `handler_metrics.go`, `handler_credentials.go`, `handler_logs.go`, `handler_telemetry.go` go to admin. Everything else (api_*, dashboard_*, user_*, handler_alerts/orders/paper/portfolio/safety/tax) stays user.

### Per-PR Design

**PR 3.1 — `refactor(kc/ops/shared): extract data + logbuffer + page_handlers + overview_*`**
- **Files**: 5 shared files moved to `kc/ops/shared/`.
- **Build verification**: `go build ./...` + `GOWORK=off go build ./...`.
- **Acceptance**: shared subpackage is leaf-like (zero internal kc/ops imports).
- **Time**: ~20 min.
- **Inter-PR coupling**: PRE-REQUISITE for 3.2/3.3.

**PR 3.2 — `refactor(kc/ops/admin): extract admin handlers + render`**
- **Files**: handler_admin.go, admin_render.go, handler_metrics.go, handler_credentials.go, handler_logs.go, handler_telemetry.go (6 files).
- **Build verification**: kc/ops/admin/ standalone build; admin route registration intact.
- **Acceptance**: admin subpackage compiles; 14 admin-flagged files cohabit cleanly.
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on PR 3.1. **Parallel-safe with 3.3.**

**PR 3.3 — `refactor(kc/ops/user): extract user-facing api_* + dashboard_* + user_*_render.go`**
- **Files**: 8 api_*.go + 9 dashboard_*.go + 7 user_*_render.go + 6 user-handler_*.go (handler.go, handler_account.go, handler_alerts.go, handler_orders.go, handler_paper.go, handler_portfolio.go, handler_safety.go, handler_tax.go) = 30 files.
- **Build verification**: kc/ops/user/ standalone build; dashboard route registration intact.
- **Acceptance**: user subpackage compiles; per-page dashboard renders unchanged.
- **Time**: ~40 min (largest move).
- **Inter-PR coupling**: depends on PR 3.1. **Parallel-safe with 3.2.**

**PR 3.4 — `chore(go.work,Dockerfile): add kc/ops/{shared,admin,user} to workspace`**
- **Files**: go.work (add 3 use paths), root go.mod (add 3 replace), Dockerfile (pre-stage 3 manifests).
- **Build verification**: workspace sync; full build green.
- **Time**: ~20 min.
- **Inter-PR coupling**: depends on PRs 3.1-3.3.

**PR 3.5 — `refactor(kc/ops): drop kc-parent imports (Anchor-6 prep)`**
- **Files**: 25 kc/ops/*.go files (currently importing kc parent). Replace with ports.* imports per Anchor 5.
- **Build verification**: same gate; cycle-detection: kc/ops sub-packages have zero `kc` parent imports after this PR.
- **Acceptance**: 25 import-line replacements verified; build green.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on Anchor 5 PR 5.8 (ports leaf-stability) AND PRs 3.1-3.3.

**PR 3.6 — `test(kc/ops): integration tests pass per sub-package`**
- **Files**: NEW per-subpackage test fixtures (~50 LOC each).
- **Build verification**: `go test ./kc/ops/{shared,admin,user}/... -count=1`.
- **Acceptance**: each subpackage independently testable.
- **Time**: ~30 min.
- **Inter-PR coupling**: depends on PRs 3.1-3.5.

**PR 3.7 — `chore: deploy v205+ with kc/ops split`**
- **Files**: zero (deploy-only).
- **Build verification**: dashboard renders; admin/ops routes work; tools count unchanged.
- **Time**: ~30 min + 24h observation.
- **Inter-PR coupling**: depends on PRs 3.1-3.6.

**PR 3.8 — `chore(kc/ops): cleanup stub package + verify zero kc-parent imports`**
- **Files**: delete kc/ops root files (now empty); verify final state via `grep -rE "kite-mcp-server/kc\"" kc/ops/` returns 0.
- **Build verification**: full integration test pass.
- **Time**: ~20 min.
- **Inter-PR coupling**: depends on PR 3.7.

**Anchor 3 total**: 8 PRs / ~3.5 hours review.

### Cross-PR for Anchor 3

**Topological order at N=20**:
```
PR 3.1 (shared) ── PRE-REQUISITE
       │
       ├─→ PR 3.2 (admin)  ─┐  Both parallel after 3.1
       └─→ PR 3.3 (user)    ┘
                  │
                  └─→ PR 3.4 (workspace + Dockerfile)
                              │
                              └─→ PR 3.5 (kc-parent import drop) ─→ PR 3.6 (tests)
                                                                          │
                                                                          └─→ PR 3.7 (deploy) ─→ PR 3.8 (cleanup)
```

**Coordination with Anchor 6**: Anchor 6's deletion of Manager methods (PRs 6.2/6.4/6.6/6.8/6.10/6.12/6.14) requires kc/ops consumers to route via ports — that's exactly what PR 3.5 does. **Anchor 3 PR 3.5 must merge BEFORE Anchor 6 PRs 6.2-6.14**, else those Manager-method deletions break kc/ops compilation.

**Mid-Anchor checkpoints**: deployable at every PR boundary. After PR 3.1: shared package extracted but no behavior change. After PR 3.5: kc/ops free of kc-parent dependencies — clean state for Anchor 6.

**Risk floor**: PR 3.1 (shared, 5 files, ~20 min) is the smallest unavoidable first PR.

**Anchor 3 calendar at N=20**: ~2-3 days (includes 1-day deploy observation).

---

## Cross-Anchor (Anchor 1 ↔ Anchor 3)

**Are they parallel-safe?** **YES.** mcp/ and kc/ops/ are disjoint packages. The 5 mcp/ files that import kc/ports (alert_deps.go, common_deps.go, context_tool.go, read_deps.go, session_deps.go) do NOT touch kc/ops; the 3 kc/ops files that import mcp do NOT touch mcp/ tool registrations directly.

**At N=20 capacity**: Anchor 1 + Anchor 3 fan-outs (PR 1.1 + PR 3.1 as Wave-D-1 prerequisites) can ship simultaneously. Then Wave-D-2 has 9-way Anchor 1 parallel + 2-way Anchor 3 parallel = **11 simultaneous PRs**.

**Shared infrastructure changes**: zero couplings detected. Each anchor edits its own go.work entries, Dockerfile manifests, and CI suites disjointly.

**Per `feedback_decoupling_denominator.md` preconditions**: both anchors require Anchor 4 (kc/domain) extracted — done at HEAD `b922a20`. Both require Anchor 5 (ports inversion) for clean dependency surface — required PR for Anchor 3 PR 3.5 specifically. **Anchor 1 doesn't strictly need Anchor 5** (mcp/ already routes through ports for alert/common/context/read/session deps).

---

## Honest Verdict

**Anchor 1: subdividable as 12 PRs.** Empirical evidence: tool clusters are file-name-disjoint (no `post_tools.go` references inside `analytics_tools.go`); the 60 tool registrations are independent calls; `mcp/common.go` provides a clean ToolHandler factory used uniformly. Each cluster moves cleanly to its own subpackage. Green-light Wave D execution.

**Anchor 3: subdividable as 8 PRs.** Empirical evidence: kc/ops file naming is disjoint by prefix (`api_*`, `dashboard_*`, `handler_*`, `user_*_render`, `admin_*`); shared infrastructure is small (5 files in 3.1). Green-light.

**Total B-Full calendar at N=20** (composing all prior anchor estimates):
- Anchor 4 (kc/domain): ~1.5 days (well underway at HEAD)
- Anchor 5 (kc/ports invert): ~3 days
- Tier 5 (testutil/oauth/aop): ~1 day
- Anchor 2 (app/providers): ~3-5 days
- Anchor 6 (kc-root god-struct): ~9-10 days (24h observation gates × 7 dominate)
- **Anchor 1 (mcp/ Y-split): ~2 days** (this dispatch)
- **Anchor 3 (kc/ops split): ~2-3 days** (this dispatch)
- **B-Full total: ~21-26 days calendar at N=20** (vs `7ac9d34` 9-14 months solo)

The 24h-observation-gate × 7 in Anchor 6 remains the dominant critical path. Anchors 1 + 3 add ~5 days but can overlap with Anchor 6's deploy-and-wait cycles, reducing net delta to ~2-3 days incremental.

**Final B-Full execution plan complete. Zero remaining unbounded items.**

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Honest verdict** (final).
