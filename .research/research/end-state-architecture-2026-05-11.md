<!-- secret-scan-allow: synthesis-doc-no-secrets -->
---
title: End-State Architecture Vision — internal code synthesis
as-of: 2026-05-11
re-verify-by: 2026-08-11
master-head-at-write: db8fd7a
scope: META-SYNTHESIS — read-only; no source mutations; consumes sibling reports
synthesis-of:
  - .research/research/god-object-inventory-2026-05-11.md (Path A: 10-step decomposition roadmap, 47-71h)
  - .research/research/github-transfer-bootstrap-2026-05-11.md (Audit: GitHub transfer + bootstrap module)
  - .research/research/zero-in-tree-feasibility-2026-05-11.md (Chain: zero-in-tree TRUE blocker = Tool.Handler(*kc.Manager))
inflight-when-written:
  - test coverage audit (Chain follow-up)
  - E2E + UI completeness (Playwright specialist)
  - architecture integration audit (fix agent)
budget-used: ~4h of 4-6h target; 8h hard halt
methodology: synthesis from sibling reports + .claude/CLAUDE.md architectural directives; no re-derivation of empirical data
---

# End-State Architecture Vision

**User's question (verbatim)**: *"What is the best architecture? 100% test cases, everything right end to end, UI, UX, everything. If that is done, focus on the code first."*

This doc answers — synthesizing today's three sibling reports into a single end-state target the codebase converges to. It is the **meta-vision** dispatch: the sibling reports each have their slice of empirical data; this doc says what "done" looks like in a single page.

The honest framing first: **"best architecture" is not a static end-state.** It is a CONVERGENT shape the codebase should tend toward, with explicit acceptance criteria that gate "we got there." This doc names the shape, the gap, the sequence, and the gates.

---

## §1 — End-state vision (what the codebase looks like when done)

### §1.1 The three-layer target

When complete, the codebase is **three concentric layers**:

```
┌──────────────────────────────────────────────────────┐
│  DEPLOY (kite-mcp-server, ~12 files)                 │
│  Dockerfile, fly.toml, smithery.yaml, .mcp.json,     │
│  funding.json, README, LICENSE, NOTICE, SECURITY,    │
│  PRIVACY, server.json, ~10-line main.go              │
│  ─── ZERO Go source other than main.go ───           │
└──────────────────────────────────────────────────────┘
       │
       │ imports
       ▼
┌──────────────────────────────────────────────────────┐
│  COMPOSITION ROOT (algo2go/kite-mcp-bootstrap)        │
│  app/ wire + HTTP mux + lifecycle + adapters         │
│  PLUS narrow re-export shims (3-4 packages)          │
│  ─── ~3,000 LOC (vs today's 49,400) ───              │
└──────────────────────────────────────────────────────┘
       │
       │ imports 33 modules
       ▼
┌──────────────────────────────────────────────────────┐
│  DOMAIN MODULES (algo2go/kite-mcp-*, 33 total)        │
│  Today's 28 algo2go modules + 5 new from kc.Manager  │
│  decomposition (manager-core, manager-init,          │
│  manager-cqrs, manager-ports, manager-tools)         │
│  Each module: cohesive single-domain bundle:         │
│   - types + interfaces + implementations             │
│   - its OWN tool registrations (init() blank-import) │
│   - its OWN tests (>=80% coverage, 90% critical)     │
│   - its OWN release cadence (independent versions)   │
└──────────────────────────────────────────────────────┘
```

### §1.2 Concrete end-state counts

| Dimension | Today (2026-05-11) | End-state target |
|---|---|---|
| algo2go external modules | 28 (`grep -c 'algo2go/kite-mcp-' go.mod` = 28) | 33 |
| In-tree non-test LOC | 54,241 (kc=9519 + kc/ops=8017 + mcp=24358 + app=6999 + others) | <500 (main.go + fly.toml + Dockerfile only) |
| In-tree .go files (deploy repo) | 261 non-test | 1–2 (main.go + maybe a thin cmd/) |
| `kc.Manager` fields | 63 (`kc/manager_struct.go:65-186`) | ≤10 (per Path A roadmap step 8) |
| `kc.Manager` methods | 47 across 17 files | ~15 (init + CQRS + accessors all move out) |
| `Tool.Handler(*kc.Manager)` callsites | 123 (`grep -rn 'Handler(.*\*kc.Manager)' mcp/`) | 0 (signature changes to typed-deps) |
| Interfaces in `package kc` | 39 (`kc/interfaces.go` + `kc/manager_interfaces.go`) | 0 (relocate to algo2go/kite-mcp-ports) |
| `app.App` fields | 34 | ≤15 (extract lifecycle, HTTP, background services) |
| `app/wire.go` initializeServices | 805-LOC megamethod | ~10–15 phase functions × ~50–80 LOC |
| Module count via Fx | scattered imperative wiring | Declared `fx.Module` per algo2go module |
| Tests | 7,000+ existing tests (per CLAUDE.md) | 7,000+ preserved + new tests for decomposed types |
| Coverage (per CLAUDE.md targets) | TBD (Chain audit in flight) | New code 80%+, critical paths (billing/auth/orders) 90%+, pure functions 100% |
| `/healthz total_available` tools | 111 (5.4-day-uptime live probe) | 111 (invariant; refactor must preserve) |
| E2E flows (Playwright) | 33-strict matrix from prior session (TBD count current) | Every user flow has at least one Playwright test |
| CI gates | exists | Enforces every dimension above |

### §1.3 What "everything right end to end" means concretely

User wants: **UI, UX, code, tests, integration — all green at once.** Translated to specific acceptance criteria (the §5 list expands on this):

- **Code**: every module compiles standalone; `go build ./...` passes at every commit; no in-tree spaghetti cycles.
- **Tests**: every module ships its own tests; coverage hits the per-class targets; `go test ./... -count=1 -race` passes.
- **UI**: every dashboard surface (`/`, `/dashboard`, `/dashboard/activity`, `/admin/ops`, widget hosts) renders without 500s, has documented loading/error/empty states, passes accessibility check (a11y baseline).
- **UX**: every user flow (OAuth, MCP install, place_order with elicitation, paper-trade, alert creation, dashboard navigation, dr-decrypt recovery) has a Playwright happy-path test that lives in `algo2go/kite-mcp-e2e` or equivalent.
- **Integration**: every cross-module boundary has at least one integration test that exercises the wiring (not just unit tests of leaves). The 10-step middleware chain (per CLAUDE.md "Middleware Chain (order matters)") has a chain-order-verifying test.
- **End-to-end**: a single CI workflow (`launch-readiness.yml` per the launch-readiness verdict doc) runs: build → unit tests → integration tests → E2E Playwright → smoke test against staging → security scan → coverage check. All green = release-ready.

### §1.4 Module classes (target taxonomy)

When the 33 algo2go modules exist, they fall into 5 classes — each with distinct test/quality targets:

| Class | Examples (end-state) | Coverage target | Test pattern |
|---|---|---|---|
| **Pure domain** (no I/O, no time) | money, domain, sectors, ports, validators | 100% | table-driven, fast |
| **Stateful service** (uses stores) | broker, alerts, users, billing, watchlist, instruments, paper, riskguard, audit | 90% (per CLAUDE.md critical) | mock store + table-driven |
| **Integration adapter** (Kite SDK, R2, Telegram) | kite-adapter, r2-adapter, telegram-bot | 80% (per CLAUDE.md baseline) | httptest fake + race-tested |
| **Tool registration** (MCP tools per domain) | kite-mcp-broker-tools, kite-mcp-alerts-tools, etc. | 80% | `callToolWithManager` + table-driven |
| **Composition root** (bootstrap module) | algo2go/kite-mcp-bootstrap | 70% (integration-test heavy) | startup + shutdown + healthz |

The deploy repo (`kite-mcp-server` post-transfer) has no Go tests — its CI is just `flyctl deploy --dry-run` + Dockerfile lint.

---

## §2 — Gap from today (per-dimension)

Each dimension cites which sibling report has the empirical data; this doc does not re-derive.

### §2.1 Code organization gap

**Per Path A (`god-object-inventory-2026-05-11.md` §2)**: ONE dominant god-object — `kc.Manager` at 63 fields / 47 methods / 4,104 LOC across 17 files. Four significant subordinate god-files: `app/wire.go.initializeServices` (805-LOC megamethod), `app.App` (34 fields, ~80 methods scattered), `mcp.plugin.Registry` (26 fields / 39 methods / 693 LOC), `app/adapters.go` (884 LOC, 21+ adapter zoo).

**Per Chain (`zero-in-tree-feasibility-2026-05-11.md` §1.5)**: in-tree non-test LOC is 54,241 across 261 files. Per-area: kc=9519 + kc/ops=8017 + kc/ports=531 + mcp=24358 + app=6999 + app/providers=2859 + app/metrics=513 + plugins=321 + testutil=825 + cmd=546 + main.go=140.

**Gap**: 54,241 → <500 LOC in deploy repo. That's the literal "zero-in-tree" target. The path is Pattern C (bootstrap relocation, Chain §5.2) followed by Pattern D.2 (per-module tool registration, Chain §5.2).

### §2.2 Test coverage gap

**Today**: Chain audit in flight. CLAUDE.md states test patterns and locations exist (`mcp/*_test.go`, `kc/usecases/usecases_test.go`, `mcp/admin_tools_test.go`), targets are documented (80%/90%/100% by class), but per-package empirical coverage numbers aren't visible in the sibling reports surveyed here.

**Per CLAUDE.md "Coverage targets"**:
- New code: 80%+
- Critical paths (billing, auth, orders): 90%+
- Pure functions: 100%

**Gap**: cannot quantify without Chain's audit landing. Synthesis assumption: assume coverage is currently mixed (some modules at 100%, some at <50%); end-state target is per-class targets above, enforced in CI via per-package coverage gates.

### §2.3 UI/UX completeness gap

**Today**: dashboard surfaces exist (`/dashboard`, `/dashboard/activity`, `/admin/ops`, widget hosts) per MEMORY.md. Per `pre-launch-ux-audit-2026-05-11.md` (sibling, sampled headline only): first-5-min UX has been audited. Per `playwright-empirical-drill-2026-05-11.md` (sibling, sampled headline only): Playwright storageState/TOTP/sudo-mode confirmed.

**Gap**: not all user flows have Playwright tests; the 33-strict matrix from prior session covers some. End-state target is every user flow (OAuth, MCP install, OAuth refresh, place_order with elicitation, paper-trade order, alert create+trigger, dashboard navigation, admin freeze/unfreeze, DR-decrypt verification) has at least one Playwright happy-path test.

### §2.4 Integration test gap

**Today**: 7,000+ unit tests exist (per CLAUDE.md). Cross-module integration tests exist but unenumerated in the sibling reports.

**Gap**: every cross-module boundary needs a smoke test. Specifically:
- Middleware chain order (10 middleware per CLAUDE.md) → 1 integration test verifying order at runtime.
- CQRS bus wiring → 1 test that posts a Command and asserts the right handler runs.
- Plugin registration → 1 test asserting all init() registrations resolved at startup.
- HTTP mux → 1 test per public route asserting status code + handler match.
- Litestream backup chain → already covered by `cmd/dr-decrypt-probe` + `25b201a` DR drill.

### §2.5 CI gate gap

**Today**: `go build ./...`, `go test ./... -count=1`, `go vet`, `staticcheck`, `just lint` exist per CLAUDE.md. `flyctl deploy --remote-only` for deploy. dr-drill.yml monthly cron exists but secrets not provisioned (per Day-1 runbook refresh).

**Gap**: no single CI workflow that gates "everything green" pre-merge or pre-release. End-state target is `launch-readiness.yml` that runs the full chain (per §1.3) as a required check on every PR.

### §2.6 Composition root gap

**Per Chain (`zero-in-tree-feasibility-2026-05-11.md` §3.1)**: 6 concrete structural blockers, with the load-bearing one being `Tool.Handler(*kc.Manager) server.ToolHandlerFunc` at `mcp/common/tool.go:62-65` (123 callsites). Composition root (`app/wire.go`) imports 12 internal-root packages.

**Gap**: `app/wire.go` (1,008 LOC) and the 805-LOC `initializeServices` megamethod stay until decomposed. Step 6 of Path A's roadmap addresses this. Plus: Chain's recommended Path X (bootstrap relocation, ~24-40h) absorbs `app/` into a new module without decomposing it — this is a useful intermediate state.

---

## §3 — Path X + Path Y sequencing

Per Chain's §5.3 explicit recommendation: **Path X NOW, Path Y INCREMENTALLY.** This doc accepts that framing as the meta-sequence.

### §3.1 Path X — bootstrap relocation (~24–40h)

**Goal**: brand completion + repo separation. Deploy repo becomes a thin shell.

Per Audit's `github-transfer-bootstrap-2026-05-11.md` §2 design. Concrete steps:

1. GitHub transfer `Sundeepg98/kite-mcp-server` → `algo2go/kite-mcp-server` (~5 min)
2. Create `algo2go/kite-mcp-bootstrap` repo (~5 min)
3. Mass-move ~49,400 LOC (kc/, kc/ops/, mcp/, app/, app/metrics/, plugins/, testutil/) into bootstrap (~8h with git mv preserving history)
4. Bootstrap module exposes `Run(ctx) error` (~2h scaffold)
5. Deploy repo main.go reduces to `import bootstrap; bootstrap.Run(ctx)` (~30 min)
6. Update Dockerfile multi-stage to `go install algo2go/kite-mcp-bootstrap/cmd/server` (~2h)
7. server.json `name` field decision (critical gotcha per Audit §1.6 — register CLAIM **before** any Path X work): probe `https://registry.modelcontextprotocol.io/api/v1/servers?name=io.github.Sundeepg98/kite-mcp-server`; if published, accept legacy name OR mark deprecated and re-publish under `io.github.algo2go/kite-mcp-server` (~1h decision)
8. Patch the 72 GitHub URL references (audit §1.7) in same window (~3h)
9. Patch `.github/workflows/dr-drill.yml` repo-equality check (Audit §1.9 NEAR-CERTAIN risk) (~30 min)
10. CI re-run on both repos; smoke test (~2h)

**Total**: 24–40h. Reversible per Audit §1.10 (single `gh api -X POST` call).

**What Path X delivers** (per Chain §5.4):
- Brand: algo2go owns every Go source file.
- Smaller deploy repo (clones are fast; CI checkouts tiny).
- Independent versioning (bootstrap is a Go module; pinnable).
- Tighter blast radius for deploy repo audits.

**What Path X does NOT deliver** (per Chain §5.5):
- Decomposition (god-struct is still a god-struct, just lives in bootstrap).
- Test isolation (testutil/kcfixture still builds whole Manager).
- Cycle freedom (in-package mcp↔kc↔ops cycles same, inside bootstrap).
- Pattern-A self-registration of services (wrong shape; services still need DI).

### §3.2 Path Y — substantive decomposition (~200–400h)

**Goal**: god-object dissolved into cohesive types; tools register into their owning algo2go modules.

Per Path A's `god-object-inventory-2026-05-11.md` §5 (10-step roadmap, 47–71 agent-hours). The synthesis adds: **after Path X lands, Path Y commits arrive INTO the bootstrap module**, and each Path Y batch shrinks bootstrap and grows the target algo2go module (per Chain §5.3 "Sequencing" para 3).

The end-state of Path Y is what §1.1's "DOMAIN MODULES" layer describes: 33 modules, each self-contained.

### §3.3 Why both, in this order

Per Chain §5.3 verbatim: *"Path X is fast and reversible. Ships the brand outcome at 24-40h. Path Y is the real architectural work — but it's gated on god-object-inventory's roadmap."*

Path X gives the user the **public-facing narrative** (algo2go is the home for all source). Path Y gives the user the **internal-architecture truth** (god-struct is actually dissolved). The user's question explicitly conjoins both — UI/UX/code/tests all done at once — so both paths are necessary. Sequencing them serially avoids the wide blast-radius risk of doing both simultaneously.

---

## §4 — Slicing plan for Path Y (10-step roadmap, refined order)

Path A's audit (`god-object-inventory-2026-05-11.md` §5) gave a 10-step roadmap with effort estimates. The synthesis here refines the ORDER based on three considerations:

1. **Risk-tier first** (Phase 1 of Path A's recommended sequencing): pure file-moves before semantic refactors.
2. **Dependency order** (Chain §3.1): blockers must be unblocked before their dependents move.
3. **CI-greenness preservation**: every step must be a single PR that leaves master compile-clean and test-green.

The order below MATCHES Path A's recommended sequencing (Path A §5 phases 1–4); this doc cites and reinforces, doesn't replace.

| Slice # | Action (verbatim from Path A §5) | LOC moved | Hours | Risk | Phase |
|---|---|---|---|---|---|
| 1 | **Drain Manager accessors** — push 40–60 call sites from `m.X()` to `m.facade.X()` for the 5 already-extracted Tier-1 facades | ~120 obsoleted | 3–4 | LOW | 1 |
| 2 | **Split `app/adapters.go`** into per-domain files (briefing, paper, riskguard, etc.) — pure file move | 884 redistributes | 1–2 | LOW | 1 |
| 3 | **Split `mcp/ext_apps.go`** into per-widget data files (`mcp/widgets/data/portfolio.go`, etc.) — pure file move | 998 redistributes | 1–2 | LOW | 1 |
| 4 | **Consolidate App shutdown-coordination fields** into `LifecycleManager` (15+ fields → 1 field on App) | App: 34→~20 fields | 3–4 | LOW | 1 |
| 5 | **Extract `ManagerInit`** — move 16 init phases to package-level funcs in `kc/init/` (test in isolation) | 538 moves | 4–6 | LOW-MED | 2 |
| 6 | **Split `mcp.plugin.Registry`** into 4 sub-registries (Hook, Widget, EventSubscription, Plugin+Tool) | 693 restructures | 4–6 | LOW-MED | 2 |
| 7 | **Extract `ManagerCQRSWiring`** — move 10 register* methods to `kc/cqrs/wiring.go` | 1,400+ moves out | 8–12 | MED | 3 |
| 8 | **Decompose `App.initializeServices`** — 805-LOC megamethod into 10–15 phase functions in `app/wire/phases/` | 805 restructures | 6–10 | MED | 3 |
| 9 | **Extract `app/http/` package** — 1,596 LOC moves from `app/http.go` to per-concern files | 1,596 redistributes | 8–12 | MED-HIGH | 3 |
| 10 | **Drain Manager raw fields** — replace 33 raw fields with delegation to 5 Tier-1 facades | Manager: 63→~15 fields | 8–12 | MED | 4 |

**Phase totals**:
- Phase 1 (slices 1–4): ~10h, ~3,000 LOC redistributed, all LOW-risk, parallel-safe, mostly file moves.
- Phase 2 (slices 5–6): ~10h, foundation for larger moves.
- Phase 3 (slices 7–9): ~25h, big LOC moves.
- Phase 4 (slice 10): ~10h, capstone — drains Manager raw fields once facades are the only access path.

**Total Path Y**: 47–71 agent-hours **assuming god-object decomposition only** (per Path A §5). Adding the harder Chain §5.2 "Pattern D.2" work (tool registration migration including `Tool.Handler(*kc.Manager)` → `Tool.Handler(deps)` at 123 callsites + 39-interface relocation to algo2go/kite-mcp-ports) brings total Path Y to ~200–400h per Chain §5.2 estimate. The 10-step roadmap above is the prerequisite; Pattern D.2 work is the follow-on.

**Validation gate per slice** (per Path A §6):
1. `go build ./...` passes at every commit.
2. `go test ./... -count=1 -race` passes at every commit.
3. `/healthz total_available` == 111 before AND after (compile-and-run, not grep).
4. Single-PR pattern (no cross-slice refactors).
5. Coverage maintenance — new test files inherit parent's coverage.
6. `mcp/integrity.go` tool-hash manifest stays green.

---

## §5 — Acceptance criteria + CI gates

This section names what "done" looks like operationally. When all of these are green simultaneously, the code IS "everything right end-to-end."

### §5.1 Build & static analysis

| Check | Command | Gate | Owner |
|---|---|---|---|
| Compile-clean (root + workspace) | `go build ./...` | exit 0 | CI pre-merge |
| Compile-clean per algo2go module | `cd algo2go/kite-mcp-<X> && go build ./...` × 33 | exit 0 each | per-module CI |
| Vet-clean | `go vet ./...` | exit 0 | CI pre-merge |
| Lint-clean | `just lint` or staticcheck ./... | exit 0 | CI pre-merge |
| Race detector | `go test ./... -race -count=1` | exit 0 | CI pre-merge |
| Tool integrity manifest | `mcp/integrity.go` startup log | no mismatches | CI pre-merge (in startup test) |

### §5.2 Test coverage gates

| Class | Target | CI gate command |
|---|---|---|
| Pure domain (money, domain, sectors, ports) | 100% | `go test ./... -coverprofile=cover.out && go tool cover -func=cover.out \| awk '$3 != "100.0%" { exit 1 }'` |
| Stateful service (broker, alerts, users, ...) | 90% | per-package threshold gate |
| Integration adapter (kite-adapter, R2, Telegram) | 80% | per-package threshold gate |
| Tool registration (per-domain MCP tools) | 80% | per-package threshold gate |
| Bootstrap (composition root) | 70% (integration-heavy) | per-package threshold gate |

Per-package threshold gate pattern (CI snippet):
```bash
go test ./kc/billing/... -coverprofile=billing.out
COVERAGE=$(go tool cover -func=billing.out | grep total | awk '{print $3}' | tr -d '%')
[ "$(echo "$COVERAGE >= 90" | bc)" = "1" ] || exit 1
```

### §5.3 Integration tests

Every cross-module boundary has ≥1 test. The minimum set (10 tests):

1. **Middleware chain order** — start App, dispatch a tool call, assert each of the 10 middleware layers fires in documented order (per CLAUDE.md "Middleware Chain (order matters)").
2. **CQRS bus wiring** — post Command, assert matching handler runs; post Query, assert matching handler runs.
3. **Plugin self-registration** — assert all `init() { plugin.Register... }` resolved at startup; `/healthz total_available == 111`.
4. **HTTP mux completeness** — for each public route in `app/http.go`, assert status code + handler match.
5. **OAuth flow** — synthetic Kite-OAuth roundtrip (mcp-remote-style) → expect access_token issued → expect persistence to KiteTokenStore.
6. **Riskguard chain** — 11 pre-trade checks (per CLAUDE.md) all fire in order on a synthetic place_order; verify each rejection reason taxonomy entry triggers (17 RejectionReason constants).
7. **Audit log integrity** — invoke 10 tools, verify hash-chain holds, verify external hash publish triggers if configured.
8. **Litestream → R2 backup chain** — already covered by `cmd/dr-decrypt-probe` + `scripts/dr-drill-prod-keys.sh` + `25b201a` DR drill.
9. **Telegram briefings** — mock TG bot, assert morning + EOD scheduler dispatch HTML messages.
10. **Tool integrity** — assert `mcp/integrity.go` manifest matches tool descriptions at startup; refuse start on mismatch.

### §5.4 E2E (Playwright) — user-flow coverage

Every user flow has ≥1 Playwright test. Minimum 11 flows:

1. Landing page renders (anonymous).
2. OAuth login (full flow including Kite redirect).
3. Dashboard renders (authenticated).
4. Place_order with elicitation confirm.
5. Paper-trade order placed and reflected in /dashboard.
6. Alert creation + trigger fires Telegram message (mocked).
7. Native price alert (Kite ATO) created and visible.
8. Admin freeze tool triggers kill switch globally.
9. DR-decrypt-probe runs and reports exit 0.
10. Server version + healthz reflects expected build SHA.
11. Widget host renders portfolio widget inline in MCP client.

### §5.5 UI/UX baseline gates

| Gate | Tool | Pass criterion |
|---|---|---|
| Accessibility | axe-core via Playwright | zero serious violations |
| Page-load p95 | Playwright trace | <2s for `/`, `/dashboard` |
| 500-on-any-route | smoke test | zero 500s across documented routes |
| Loading/error/empty states | manual code review | each fetcher renders all three explicitly |
| Mobile viewport | Playwright @ 375px | landing + dashboard render without overflow |

### §5.6 Single CI gate workflow

`launch-readiness.yml` runs the above sequentially, single source of truth for "ready":

```yaml
jobs:
  build:        # §5.1 build & static
  unit-tests:   # §5.2 coverage gates
  integration:  # §5.3 integration tests
  e2e:          # §5.4 Playwright matrix
  ui-baseline:  # §5.5 a11y + perf
  smoke:        # ./scripts/smoke-test.sh against staging
  security:    # gosec + trivy on Docker image
```

Required check on `master` branch protection. Green = release-ready.

### §5.7 Maintainability budget

Specific numeric budgets that any new code must respect (else CI fails on lint or human reviewer rejects):

| Budget | Limit | Why |
|---|---|---|
| LOC per file | ≤500 (≤1000 with reason) | enforces decomposition pressure |
| Methods per type | ≤25 | counter-example to the 47-method Manager |
| Fields per struct | ≤15 | counter-example to the 63-field Manager |
| Cyclomatic complexity per function | ≤15 (go-cyclo `>=15` triggers warn) | matches counter-examples in code |
| LOC of `app/wire.go` initializeServices equivalent | ≤200 | no megamethods |
| Tool registrations per file | ≤5 | enforces domain-cohesive registration |

---

## §6 — Total effort estimate (synthesis)

Three sub-totals, each cited:

| Workstream | Effort | Source |
|---|---|---|
| **Path X** (bootstrap relocation + GitHub transfer) | 24–40 agent-hours | Audit + Chain §5.2 |
| **Path Y Phase 1–4** (god-object decomposition) | 47–71 agent-hours | Path A §5 |
| **Path Y Pattern D.2** (tool registration migration; Tool.Handler signature + 39 interfaces relocate) | 200–400 agent-hours (cumulative; supersedes Y1–4 in scope) | Chain §5.2 |
| **Test coverage gap filling** (raise per-class targets to per-§5.2 thresholds) | Unknown — pending Chain's coverage audit landing | TBD |
| **E2E test buildout** (11 flows from §5.4) | ~40–60 agent-hours (11 flows × 4–6h each) | Synthesis estimate |
| **CI gate construction** (launch-readiness.yml + per-package coverage thresholds) | ~16–24 agent-hours | Synthesis estimate |

**Conservative total**: 200–600 agent-hours (NOT calendar-hours — agent-hours assume serial work; with 3–5 parallel agents on disjoint slices, calendar time compresses 3–5×).

**Practical sequence the user can act on**:

- **Sprint 0 (~30h, 1 week)**: Path X. Brand outcome shipped. Deploy repo becomes thin shell. **Acceptance**: GitHub transfer complete + bootstrap module compiles + flyctl deploys + `/healthz total_available=111`.
- **Sprint 1 (~10h, 1 week)**: Path Y Phase 1 (slices 1–4 from §4). Low-risk file moves. **Acceptance**: ~3,000 LOC redistributed; existing 7,000-test suite green; no behavior change.
- **Sprint 2 (~10h, 1 week)**: Path Y Phase 2 (slices 5–6). Manager init extracted + Registry split. **Acceptance**: per-package tests for new `kc/init/` and 4 sub-registries; coverage held or improved.
- **Sprint 3–4 (~25h, 2 weeks)**: Path Y Phase 3 (slices 7–9). Big LOC moves. **Acceptance**: ~3,800 LOC restructured; manager_commands_*.go shrunk; app/http.go split.
- **Sprint 5 (~10h, 1 week)**: Path Y Phase 4 (slice 10). Drain Manager raw fields. **Acceptance**: Manager struct 63→~15 fields.
- **Sprint 6+ (~200–400h, 8–16 weeks)**: Pattern D.2 — Tool.Handler signature change + 39-interface relocation + tool registration migration into per-domain algo2go modules. This is the deep work.
- **Throughout**: Test coverage + E2E + CI gate work runs in parallel with above sprints.

**End-state-1 (after Sprint 5)**: god-struct decomposed; deploy repo thin shell; in-tree LOC down to ~30,000 (the residual after Path Y Phase 1–4).

**End-state-2 (after Sprint 6+)**: literal zero-in-tree (per Chain §5.2 Path Y); 33 algo2go modules each self-contained including their tools; deploy repo <500 LOC.

---

## §7 — Conflicts surfaced + open questions

### §7.1 Path A vs Chain on effort

- Path A §5: 47–71 agent-hours for 10-step decomposition.
- Chain §5.2: 200–400 agent-hours for "true zero-in-tree" (Pattern D.2).

**Resolution**: these measure DIFFERENT scopes. Path A measures the decomposition slices (steps 1–10 from its roadmap). Chain measures Path A's work PLUS the Tool.Handler signature change PLUS 39-interface relocation PLUS tool registration migration. The 200–400h is cumulative; the 47–71h is a subset.

**Honest aggregate**: **~250–470 agent-hours** for the full Path X + Y end-state (this synthesis), not counting test coverage gap filling or E2E build-out.

### §7.2 server.json `name` immutability gotcha (Audit §1.6)

If MCP Registry has already published `io.github.Sundeepg98/kite-mcp-server`, the `name` field is immutable. Per memory: registry entry IS live (`io.github.Sundeepg98/kite-mcp-server@1.2.0` per `publishedAt 2026-04-19`). **The window is closed; the registry name is locked to Sundeepg98 owner.**

**End-state implication**: post-transfer, the MCP Registry still references the legacy name. Options per Audit §1.6:
- Accept legacy name (Registry shows `Sundeepg98` ownership; repo URL field updates fine to point at `algo2go/kite-mcp-server`).
- Publish a new entry under `io.github.algo2go/kite-mcp-server` and mark the old `deprecated: true`.

Recommendation: **accept legacy name**. The Registry's `repository.url` field is mutable and can point to the new repo; users see the new owner via the URL. A `deprecated` flag on the old entry would split registry-side discoverability for no real gain.

### §7.3 What "100% test cases" means (CLAUDE.md vs aspirational)

Per CLAUDE.md: 80%+ new code, 90%+ critical, 100% pure. **User's question is "100% test cases" — literally 100% coverage.**

**Resolution**: "100%" in user's framing likely means "every relevant case has a test," not literal line-coverage 100%. The CLAUDE.md targets ARE the operational definition of "100% test cases" — every CRITICAL path covered, every PURE function fully tested, every NEW code path baseline-covered. End-state CI gates enforce these.

**Caveat**: if the user really means literal 100% line-coverage across all 54k LOC, that's a different (much more expensive) project and would gate-block testing-incidental glue code unnecessarily. The synthesis defers to CLAUDE.md's per-class targets as the operational definition.

### §7.4 Inflight reports not yet landed

Three reports flagged inflight in dispatch brief:
- Test coverage audit (Chain doing it) → will quantify §2.2 gap.
- E2E + UI completeness (Playwright specialist) → will quantify §2.3 gap.
- Architecture integration audit (fix agent) → will surface integration gaps not visible from Path A/Audit/Chain.

**This doc remains valid** when those land; gaps just get specific numbers. If any inflight report falsifies an assumption here (e.g., "kc.Manager is decomposed already, no Path Y needed"), this doc's end-state vision stays — Path A, Audit, Chain mutually corroborate the dominant god-object.

### §7.5 Order-of-operations vs parallel agents

The 10-slice roadmap from Path A assumes sequential single-agent work. With parallel agents working on DISJOINT slices (e.g., slice 1 + slice 2 + slice 3 in parallel — all are LOW-risk file moves with no cross-slice conflicts), Phase 1 compresses from 10h serial to 3–4h parallel.

**Caveat**: slices 4–10 have implicit ordering (slice 5 depends on slice 4's File-move foundation; slice 7 depends on slice 5's CQRS-init extraction; etc.). Past Phase 1, parallelism opportunities narrow.

### §7.6 The "best architecture" framing — explicit limit

The user's question presumes a single best architecture exists. **This synthesis says: the best architecture is the convergent target above — three concentric layers (Deploy / Bootstrap / Domain modules), per-class test coverage gates, single CI workflow, every user flow has a Playwright test.** It is NOT a Platonic ideal; it's a pragmatic target consistent with CLAUDE.md's directives, today's empirical state, and the sibling reports' recommendations.

A counter-architecture (e.g., "rewrite in Rust" or "switch from Go modules to a monorepo with Bazel") could be argued to be "best" by different criteria. This synthesis takes "the user's Go + Fly.io + MCP stack stays" as the load-bearing constraint and minimizes change-cost to reach the convergent target.

---

## §8 — One-paragraph summary

The best architecture for this codebase has **three concentric layers** (Deploy / Bootstrap / Domain modules), with 33 algo2go modules (today's 28 plus 5 from kc.Manager decomposition) each self-contained including their tool registrations, a thin <500-LOC deploy repo, every user flow covered by a Playwright test, every cross-module boundary by an integration test, per-class coverage gates enforced by a single `launch-readiness.yml` CI workflow, and per-file/per-type/per-method maintainability budgets that prevent the next god-struct from forming. The gap from today is 54k → <500 LOC in deploy repo; the Manager god-struct's 63 fields → ≤10 fields after decomposition; 123 `Tool.Handler(*kc.Manager)` callsites → 0 after signature change. The path is **Path X (bootstrap relocation, ~30h) NOW, Path Y (10-slice god-object decomposition, ~50h Phase 1–4) INCREMENTALLY, with Pattern D.2 tool migration (~200–400h) as the substantive end-state work**. Total: ~250–470 agent-hours for the architectural moves, plus uncounted hours for coverage gap-filling and E2E build-out that run in parallel.

---

*End of synthesis. READ-ONLY. Single commit + push per brief.*
