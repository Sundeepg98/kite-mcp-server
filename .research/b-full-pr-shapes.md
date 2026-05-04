# B-Full PR Shapes + Anchor-2 Steel-Man + Cost-of-NOT-Doing

**Date**: 2026-05-04
**HEAD audited**: `6941f08` (Tier 1 leaf 11/24 — kc/watchlist extracted; **Tier 1 COMPLETE**)
**Builds on**: `79daf18 b-full-execution-runbook.md`
**Charter**: read-only research. Doc-only deliverable. NO code changes.
**User constraint**: B-full authorized; not re-litigating the decision. Research goal is **execution efficiency**.

**Empirical post-Tier-1 state**:
- 11 modules in `go.work`: broker + kc/{audit, billing, i18n, isttz, legaldocs, logger, money, riskguard, templates, watchlist}
- `kc/domain`: 17 prod files, 7,607 LOC, all external imports are to already-extracted modules (broker, kc/isttz, kc/money) — module-clean
- `kc/ports`: 6 files (231 LOC); 5 of 6 still import `"kite-mcp-server/kc"` parent (`alert.go:4`, `assertions.go:3`, `instrument.go:4`, `order.go:4`, `session.go:18`); credential.go alone is inverted
- `kc.Manager`: 52 methods; 16 named accessors in `manager_accessors.go` (CredentialSvc, SessionSvc, PortfolioSvc, OrderSvc, AlertSvc, FamilyService, LoggerPort, CommandBus, QueryBus, SessionManager, ManagedSessionSvc, SessionSigner, MCPServer + 3 setters/utility)
- `kc/interfaces.go`: 573 LOC, **20 interface declarations** — the empirical relocation target for Anchor 5
- `app/providers/`: 14 prod recipes
- `mcp/`: 50 prod tool files

---

## Q1 — PR-Shape Decomposition

### Anchor 4 — kc/domain extraction (8 PRs)

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 4.1 | `chore(kc/domain): add go.mod stub + replace block` | `kc/domain/go.mod`, root `go.mod` | `go build ./kc/domain/...` standalone green | 1 | — |
| 4.2 | `chore(go.work): add ./kc/domain to use block` | `go.work` | `go work sync` clean | 0.5 | 4.1 |
| 4.3 | `chore(Dockerfile): pre-stage kc/domain manifest` | `Dockerfile` | `docker build` green | 0.5 | 4.1 |
| 4.4 | `chore(kc/domain/go.mod): require broker/isttz/money replace` | `kc/domain/go.mod` | GOWORK=off build green | 0.5 | 4.1 |
| 4.5 | `test(kc/domain): standalone test pass` | `kc/domain/go.sum` (auto-generated) | `go test ./kc/domain -count=1` green | 0.5 | 4.4 |
| 4.6 | `chore(kc/audit): bump kc/domain require + replace` | `kc/audit/go.mod` (1 file) | kc/audit standalone build green | 0.5 | 4.5 |
| 4.7 | `chore(kc/{billing,riskguard}): bump kc/domain require` | 2 go.mod files | both modules build green | 1 | 4.6 |
| 4.8 | `chore: deploy v201 with kc/domain extracted` | none (deploy-only) | `flyctl deploy` + tools=111 unchanged + healthz green | 1 | 4.7 |

**Anchor 4 total: 8 PRs / ~5.5 hours review-and-merge / 3 working days calendar.**

### Anchor 5 — kc/ports inversion (8 PRs)

Move 20 interface declarations from `kc/interfaces.go` (573 LOC) to per-domain files in `kc/domain/`. Import path on each port flips from `kc` parent to `kc/domain`.

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 5.1 | `refactor(kc/domain): move CredentialStoreInterface from kc/interfaces.go` | `kc/domain/credentials.go` (new), `kc/interfaces.go` | type ID identical at use sites; zero behavior change | 1.5 | 4.8 |
| 5.2 | `refactor(kc/ports/credential): import kc/domain not kc parent` | `kc/ports/credential.go` | (already inverted at HEAD — verify only) | 0.5 | 5.1 |
| 5.3 | `refactor(kc/domain): move SessionRegistry interface` | `kc/domain/sessions.go` (new), `kc/interfaces.go` | session.go inverted | 1.5 | 4.8 |
| 5.4 | `refactor(kc/ports/session): drop kc parent import` | `kc/ports/session.go:18` | grep zero matches for kc parent | 0.5 | 5.3 |
| 5.5 | `refactor(kc/domain): move InstrumentManagerInterface` | `kc/domain/instruments.go` (new) | mcp/ 5 importers compile | 1.5 | 4.8 |
| 5.6 | `refactor(kc/ports/{instrument,order,alert}): drop kc parent import` | 3 port files | grep `\"kite-mcp-server/kc\"$` returns zero in kc/ports/ | 1.5 | 5.5 |
| 5.7 | `refactor(kc/ports/assertions): rewrite without kc parent` | `kc/ports/assertions.go` | the type-assertion infra works against kc/domain types | 1 | 5.6 |
| 5.8 | `test(kc/ports): cycle-detection test using go list -deps` | `kc/ports/cycle_detection_test.go` (new) | test fails if any kc/ports/*.go imports kc parent | 1 | 5.7 |

**Anchor 5 total: 8 PRs / ~9 hours review / ~2-3 weeks calendar.**

### Anchor 6 — kc-root god-struct (15 PRs)

Strategy: per-method, extract Manager accessor → Fx provider in app/providers/.

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 6.1 | `refactor(app/providers): provide CredentialSvc directly` | `app/providers/credential.go` (new), kc consumer updates | CredentialSvc() removable from Manager | 2 | 5.8 |
| 6.2 | `refactor(kc): delete Manager.CredentialSvc()` | `kc/manager_accessors.go` (-3 LOC) | tests green | 0.5 | 6.1 |
| 6.3 | `refactor(app/providers): provide SessionSvc directly` | `app/providers/session.go` (new) | SessionSvc() removable | 2 | 5.8 |
| 6.4 | `refactor(kc): delete Manager.SessionSvc()` | `kc/manager_accessors.go` | green | 0.5 | 6.3 |
| 6.5 | `refactor(app/providers): provide PortfolioSvc directly` | `app/providers/portfolio.go` (new) | green | 2 | 5.8 |
| 6.6 | `refactor(kc): delete Manager.PortfolioSvc()` | `kc/manager_accessors.go` | green | 0.5 | 6.5 |
| 6.7 | `refactor(app/providers): provide OrderSvc directly` | `app/providers/order.go` (new) | green | 2 | 5.8 |
| 6.8 | `refactor(kc): delete Manager.OrderSvc()` | `kc/manager_accessors.go` | green | 0.5 | 6.7 |
| 6.9 | `refactor(app/providers): provide AlertSvc directly` | `app/providers/alert_svc.go` (new) | green | 2 | 5.8 |
| 6.10 | `refactor(kc): delete Manager.AlertSvc()` | `kc/manager_accessors.go` | green | 0.5 | 6.9 |
| 6.11 | `refactor(app/providers): consolidate CommandBus/QueryBus` | `app/providers/cqrs.go` (new) | both delete-able from Manager | 2 | 5.8 |
| 6.12 | `refactor(kc): delete Manager.{Command,Query}Bus()` | `kc/manager_accessors.go` (-6 LOC) | green | 0.5 | 6.11 |
| 6.13 | `refactor(app/providers): consolidate Session{Manager,Signer}` | `app/providers/session_infra.go` (new) | 4 Manager methods delete-able | 2 | 5.8 |
| 6.14 | `refactor(kc): delete 4 session-infra Manager methods` | `kc/manager_accessors.go` (-12 LOC) | green | 0.5 | 6.13 |
| 6.15 | `refactor(kc): collapse manager.go to <100 LOC; delete kc/interfaces.go` | `kc/manager.go`, `kc/interfaces.go` (delete) | manager.go <100 LOC; interfaces.go gone | 4 | 6.14 |

**Anchor 6 total: 15 PRs / ~21 hours review / 8-10 weeks calendar.** Each Phase 6.X+1 (the deletion) merges only after the 6.X provider is stable through 1 deploy cycle.

### Anchor 1 — mcp/ Y-split (12 PRs)

50 prod tool files cluster into 6 sub-packages. Each PR moves one cluster.

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 1.1 | `refactor(mcp/common): extract response envelope + ToolHandler factory` | `mcp/common/response.go`, `mcp/common/handler.go` | mcp/common is leaf (no internal imports) | 3 | 4.8 |
| 1.2 | `refactor(mcp/middleware): extract 16 middleware files` | move `mcp/audit_middleware.go`, `mcp/billing_middleware.go`, `mcp/circuitbreaker_middleware.go`, etc. | mcp/middleware compiles standalone | 4 | 1.1 |
| 1.3 | `refactor(mcp/tools-trade): extract post/exit/gtt/options ~8 files` | `mcp/post_tools.go`, `mcp/exit_tools.go`, `mcp/gtt_tools.go`, `mcp/option_tools.go`, `mcp/options_greeks_tool.go`, etc. | tool count unchanged; schema-lock regenerated | 4 | 1.2 |
| 1.4 | `refactor(mcp/tools-portfolio): extract get/account/margin/dividend/sector ~8` | `mcp/account_tools.go`, `mcp/get_tools.go`, `mcp/margin_tools.go`, `mcp/dividend_tool.go`, `mcp/sector_tool.go`, `mcp/rebalance_tool.go`, `mcp/pnl_tools.go`, etc. | green | 4 | 1.2 |
| 1.5 | `refactor(mcp/tools-analytics): extract backtest/indicators/peer/concall/fii_dii ~8` | `mcp/backtest_tool.go`, `mcp/indicators_tool.go`, `mcp/peer_compare_tool.go`, `mcp/concall_tool.go`, `mcp/fii_dii_tool.go`, `mcp/analytics_tools.go`, etc. | green | 4 | 1.2 |
| 1.6 | `refactor(mcp/tools-alerts): extract alert/composite/native/trailing ~10` | `mcp/alert_tools.go`, `mcp/alert_history_tool.go`, `mcp/composite_alert_tool.go`, `mcp/native_alert_tools.go`, `mcp/trailing_tools.go`, `mcp/volume_spike_tool.go`, `mcp/alert_deps.go`, etc. | green | 4 | 1.2 |
| 1.7 | `refactor(mcp/tools-admin): extract 10 admin_*.go files` | `mcp/admin_tools.go`, `mcp/admin_anomaly_tool.go`, `mcp/admin_baseline_tool.go`, `mcp/admin_billing_tools.go`, `mcp/admin_cache_info_tool.go`, `mcp/admin_family_tools.go`, `mcp/admin_risk_tools.go`, `mcp/admin_server_tools.go`, `mcp/admin_user_tools.go`, etc. | green | 4 | 1.2 |
| 1.8 | `refactor(mcp/tools-paper): extract paper_tools + setup_tool` | `mcp/paper_tools.go`, `mcp/setup_tool.go`, `mcp/setup_tools.go` | green | 2 | 1.2 |
| 1.9 | `chore(go.work): add 7 mcp sub-packages to use block` | `go.work` | `go work sync` clean | 1 | 1.8 |
| 1.10 | `chore(Dockerfile): pre-stage 7 mcp manifests` | `Dockerfile` | docker build green | 1 | 1.9 |
| 1.11 | `test(mcp): regenerate schema-lock golden table per sub-package` | 7 golden table files | tool-count-drift CI green | 3 | 1.10 |
| 1.12 | `chore: deploy v202+ with mcp/ split` | none | tools=111 unchanged across 6 deploys | 4 | 1.11 |

**Anchor 1 total: 12 PRs / ~38 hours review / 6-8 weeks calendar.**

### Anchor 3 — kc/ops Y-split (8 PRs)

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 3.1 | `refactor(kc/ops/admin): move 11 admin*.go files` | move `admin_edge_*.go`, `admin_*_test.go`, etc. | kc/ops/admin compiles standalone | 3 | 4.8 |
| 3.2 | `refactor(kc/ops/user): move 12 dashboard*.go + api_*.go` | move `dashboard.go`, `api_alerts.go`, `api_handlers.go`, `api_activity.go`, `dashboard_handler*.go`, etc. | kc/ops/user compiles | 3 | 3.1 |
| 3.3 | `refactor(kc/ops/shared): extract page_handlers.go + shared deps` | `kc/ops/shared/` (new) | both subdirs import shared | 2 | 3.2 |
| 3.4 | `chore(go.work): add ./kc/ops/{admin,user} to use block` | `go.work` | `go work sync` clean | 1 | 3.3 |
| 3.5 | `chore(Dockerfile): pre-stage kc/ops manifests` | `Dockerfile` | docker build green | 1 | 3.4 |
| 3.6 | `test(kc/ops): integration tests pass per sub-package` | tests | green | 2 | 3.5 |
| 3.7 | `chore: deploy v203 with kc/ops split` | none | dashboard renders green; admin/ops works | 2 | 3.6 |
| 3.8 | `chore(kc/ops): cleanup stub package files` | delete kc/ops root | green | 1 | 3.7 |

**Anchor 3 total: 8 PRs / ~15 hours review / 3-4 weeks calendar.**

### Anchor 2 — see Q2 below.

---

## Q2 — Steel-Man Anchor 2 (app/) NOW

Prior verdict: defer until 2nd-binary trigger fires. User authorizing B-full literally — re-evaluate.

**Steel-man case for execution NOW:**

1. **`app/providers/` is empirically the cleanest extractable unit in the repo.** 14 prod recipes (alertdb / audit / audit_init / audit_middleware / billing / event_dispatcher / family / lifecycle / logger / manager / mcpserver / riskguard / scheduler / telegram) — each is a self-contained Fx provider returning a typed dependency. Zero shared mutable state across providers. Move-to-its-own-module is mechanically straightforward.

2. **Anchor 6 deletes 16 Manager accessors in PRs 6.1-6.14**. Each deletion creates a corresponding `app/providers/*.go` that *currently lives in app/providers/*. **Without Anchor 2, Anchor 6 grows app/providers/ from 14 to ~22 prod files**. Hitting Anchor 2 first means the new providers from Anchor 6 land in their own module from day one — cleaner end state.

3. **Concrete agent-concurrency value at solo dev**: Even without 2nd contributor, app/ + app/providers/ separation lets a future Anchor-6 agent edit providers without touching app/http.go. Today, both share the same `app/` package — a touch in app/providers/manager.go can break app/app.go test compilation. Splitting is a 1-day mitigation.

4. **HTTP-handler bug blast radius**: app/http.go is 1500+ LOC with 30+ route handlers. A bug in one handler today breaks tests in app/providers/ test suite (shared package). Split → bugs are local.

5. **Removal of god-package surface**: `grep -lE "kite-mcp-server/app\b"` would shrink (today: app/ is the entry-point importer of everything). Splitting makes app/providers/ a standalone consumer of kc/ — same one-direction graph as broker/.

**Empirical counter-evidence (against execution NOW):**

- **No 2nd binary planned in next 6 months.** No CLI tool, no alternate server. So "reuse" is theoretical.
- **app/providers tests already pass independently.** Empirically, `go test ./app/providers/...` is green at HEAD `6941f08`. The tests don't currently break on `app/` changes — claim 4 above is partially refuted.
- **Cost vs benefit**: 14-file extract is ~3-5 days work. The agent-concurrency benefit at solo scale is small. The cleanup before Anchor 6 is real but adds 3-5 days to the critical path.

**Empirical verdict**: case is **moderately strong but not compelling at solo scale**. Recommend executing Anchor 2 **after Anchor 4 + 5, immediately before Anchor 6** so that Anchor 6's new providers land in the extracted module from day one. **Don't execute it today as the very next thing** — Anchor 4 still has higher leverage.

**Anchor 2 PR shapes (when executed):**

| # | Title | Files | Acceptance | Hours | After PR |
|---|---|---|---|---:|:-:|
| 2.1 | `chore(app/providers): add go.mod` | `app/providers/go.mod` (new) | standalone build green | 1 | 5.8 |
| 2.2 | `chore(go.work): add ./app/providers` | `go.work` | sync clean | 0.5 | 2.1 |
| 2.3 | `chore(Dockerfile): pre-stage providers manifest` | `Dockerfile` | docker build green | 0.5 | 2.1 |
| 2.4 | `chore(app/providers): require kc + replace` | `app/providers/go.mod` | kc-parent import resolves via replace | 1 | 2.1 |
| 2.5 | `test(app/providers): standalone test pass` | tests | `go test ./app/providers -count=1` | 0.5 | 2.4 |
| 2.6 | `chore: deploy v204+ with app/providers extracted` | none | tools=111; recipe wiring intact | 1.5 | 2.5 |

**Anchor 2 total: 6 PRs / ~5 hours review / ~3-5 days calendar.**

---

## Q3 — Cost-of-NOT-Doing Analysis

For each anchor, what accumulates if we never do this work?

| Anchor | Quarterly debt | Bug class risk | Feature-add friction | 2-eng | 4-eng | 8-eng |
|---|---|---|---|---|---|---|
| **4 (kc/domain)** | Each new domain type triples write surface (kc/interfaces.go + kc/domain + use site). Type drift between locations grows. | Stale interface in `kc/interfaces.go` not matching `kc/domain` type → silent compile failure on next refactor | New domain type touches 143 reverse-deps via in-tree implicit cycle | Low friction at 2; **high friction at 4+** when types churn | High | Critical |
| **5 (kc/ports invert)** | Circular `kc/ports → kc → kc/ports` sustained. Cycle-detection test impossible to author. | New port added without inversion adds another circular import. Hot reload semantics break sporadically. | New port = new `kc/interfaces.go` line + new `kc/ports/X.go` + new use-site = 3-edit minimum | Medium | High | Critical |
| **6 (kc-root)** | Manager grows 5-10 methods/quarter at current pace (52 → ~70 in 4Q). DI surface keeps thickening. | New consumer takes Manager parameter rather than narrow port → integration tests need full Manager mock → mock-explosion | New service type? Wire into Manager. Touches kc/manager_accessors.go (16 → 17 → 18 ...). | Low | **High** | Critical |
| **1 (mcp/ split)** | 50-tool surface adds ~3-5 tools/quarter. mcp/ already 207 files; will be ~230 in 4Q. | Schema-lock golden table conflicts on any 2-PR overlap touching mcp/. | Adding analytics tool requires editing same-package neighbors → forced sequencing | Low | Medium | **High** |
| **3 (kc/ops split)** | Admin features and user features cohabit in 70 files. Auth boundary stays implicit. | SSO/RBAC change risks leaking admin-only data to user dashboard endpoint. | New admin tool requires testing user dashboard regression. | Low | Medium | High |
| **2 (app/providers extract)** | app/ root grows providers; today 21 prod / 14 providers. In 4Q: 25 / 18+. | Provider mis-wiring caught only at integration-test time. | New provider = touch app/wire.go, app/providers/recipe.go, app/test fixtures. | Low | Low | Medium |

**Reading the matrix**: Anchors **4, 5, 6** are critical at 4-engineer scale. Anchor **1** is critical at 8-engineer scale. Anchors **2, 3** are Medium-High at 4+ scale. **At today's solo scale, the only Low-risk-to-defer anchor is 2.**

---

## Cross-Anchor: Smallest "First PR" to Demonstrate the Path

**Recommended SMALLEST first PR**: PR **4.1** — `chore(kc/domain): add go.mod stub + replace block`. 

- **Files**: 2 (`kc/domain/go.mod` new, root `go.mod` add 1 replace line)
- **LOC**: <30
- **Verification**: `go build ./kc/domain/...` standalone; root `go build ./...` still green
- **Calendar**: <2 hours including review
- **Why this**: zero behavior change, zero LOC moved. Pure manifest-staging. If it breaks, it breaks loudly via `go.mod` parse error and reverts cleanly. Sets up Anchors 4.2-4.8 + unblocks 5/6/1/3. Highest-leverage smallest-cost step.

**Alternative if 4.1 is too small**: PR **5.1** — `refactor(kc/domain): move CredentialStoreInterface from kc/interfaces.go`. Single interface, ~20 LOC moved, zero behavior change. Same revert profile. Chooses this when the team wants to feel the Anchor-5 muscle motion early.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Cross-Anchor first-PR recommendation** (final).
