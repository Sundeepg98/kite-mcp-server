# Phase 3 Dispatch-Ready Briefs (5 sub-gits, pre-staged 2026-05-16)

_Authored: 2026-05-16 IST_
_Source agent: Audit (Phase 3 pre-flight + Track 3+2+1 prep chain)_
_Status: DRAFT-FOR-EXECUTION — fire when Phase 2 (tools-common) lands_

---

## Provenance + source HEADs

- bootstrap: `640755a2` (mcp/ subdirs intact; deps current)
- kite-mcp-kc: `41d8bf0` (5 ports satisfied + Brief 3 prereq Provider ports shipped; 4 of 8 accessors drained)
- kite-mcp-server: `449aff1` (master)

## Combined output expected

99 of 128 tools (77%) and ~16,000 source LOC move from bootstrap to 5 external algo2go modules. Wall-clock ~2h with all 5 agents firing in parallel.

| # | Brief | Sub-git | Tools | Source LOC | Wall-clock |
|---|---|---|---|---|---|
| 1 | **kite-mcp-tools-trade** | mcp/trade | 28 | 3,710 | ~1.5-2h |
| 2 | **kite-mcp-tools-portfolio** | mcp/portfolio + mcp/analytics | 28 | 6,575 | ~1.5-2h |
| 3 | **kite-mcp-tools-ops** | mcp/admin + mcp/misc | 27 | 2,709 | ~1-1.5h |
| 4 | **kite-mcp-tools-alerts** | mcp/alerts | 8 | 1,508 | ~1.5h |
| 5 | **kite-mcp-tools-paper** | mcp/paper | 8 | 1,326 | ~2h |

Each brief is dispatch-ready: 400-600 words, hard gates first, concrete commands, halt conditions specific to that sub-git. Orchestrator pastes brief → dispatches → agent executes → halts at gate violation.

---

## BRIEF 1 — kite-mcp-tools-trade

```markdown
# Phase 3 Sub-Git 1 — Execute extraction of mcp/trade

You are dispatched to extract `bootstrap/mcp/trade` to a new external module `algo2go/kite-mcp-tools-trade`. This runs in parallel with 4 sibling dispatches (portfolio, ops, alerts, paper). Zero cross-subdir imports verified empirically — no git conflicts will occur.

## Pre-flight verification (HARD GATES — block at any failure)
1. **Phase 2 landed**: `algo2go/kite-mcp-tools-common` exists on GOPROXY at v0.1.0+. Verify: `go list -m github.com/algo2go/kite-mcp-tools-common@latest` resolves.
2. **bootstrap clean at HEAD**: `cd ~/wsl-mirror/kite-mcp-bootstrap && git fetch && git checkout master && git pull && go build ./... && go vet ./...` all exit 0.
3. **2 residual `manager.X()` refs** at `mcp/trade/options_greeks_tool.go:471` (`a.manager.GetBrokerForEmail(email)`) and `mcp/trade/pretrade_tool.go:159` (`handler.Manager().Logger.Error(...)`) verified present. Both are 1-line fixes inside this brief.
4. **kite-mcp-kc v0.1.0+** GOPROXY-resolvable. The new module will pull kc transitively via `kite-mcp-tools-common`.

## Scope
- Source: `bootstrap/mcp/trade/` (9 source files, 3,710 LOC, 28 tools)
- Destination: `github.com/algo2go/kite-mcp-tools-trade` (new module)
- Files: `exit_tools.go`, `gtt_tools.go`, `mf_tools.go`, `native_alert_tools.go`, `option_tools.go`, `options_greeks_tool.go`, `post_tools.go`, `pretrade_tool.go`, `trailing_tools.go`
- Test files: 0 in subdir (root mcp/ has full-chain integration tests that exercise these tools via plugin registry — those tests stay at bootstrap)
- algo2go deps to pull: kite-mcp-alerts, kite-mcp-broker, kite-mcp-cqrs, kite-mcp-domain, kite-mcp-instruments, kite-mcp-oauth, kite-mcp-ticker, kite-mcp-usecases (8) + kite-mcp-tools-common (Phase 2)

## Execution sequence

### Phase A (canary cutover, ~45-75min)
1. `gh repo create algo2go/kite-mcp-tools-trade --public --description "Trading tools (28 tools) for kite-mcp ecosystem"`
2. `git clone git@github.com:algo2go/kite-mcp-tools-trade ~/algo2go/kite-mcp-tools-trade`
3. In new repo: create `go.mod` with module path `github.com/algo2go/kite-mcp-tools-trade`, `go 1.25.0`, add the 8 algo2go deps + tools-common
4. Copy 9 source files from bootstrap; rewrite imports: `bootstrap/kc` → `github.com/algo2go/kite-mcp-kc`, `bootstrap/mcp/common` → `github.com/algo2go/kite-mcp-tools-common/common`, package name `trade` preserved
5. **Fix residual #1**: `options_greeks_tool.go:471` — change `optionsAnalyzer.manager` field type from `*kc.Manager` to `kc.BrokerResolverProvider`. Provider port already exists; 1-line struct-field type change.
6. **Fix residual #2**: `pretrade_tool.go:159` — replace `handler.Manager().Logger.Error(...)` with `handler.LoggerPort().Error(ctx, ...)`. Method already exposed on ToolHandlerDeps.
7. In new repo: `go build ./...` + `go vet ./...` exit 0. WSL2 only.
8. `go test -count=1 -short ./...` (no in-subdir tests; expect 0 packages tested but exit 0)
9. Commit + push + tag `v0.1.0`: `git tag v0.1.0 && git push origin master --tags`
10. Verify GOPROXY: `GOPROXY=https://proxy.golang.org go list -m github.com/algo2go/kite-mcp-tools-trade@v0.1.0`

### Phase B (canary deletion, ~30-45min)
1. In bootstrap clone: bump `go.mod` to require `github.com/algo2go/kite-mcp-tools-trade v0.1.0`
2. Delete `mcp/trade/` directory entirely
3. Add side-effect import in bootstrap main wiring (wherever sub-git imports live): `_ "github.com/algo2go/kite-mcp-tools-trade"` — this triggers init() registrations into `mcp/plugin.internalToolRegistry`
4. WSL2 `go build ./... && go vet ./... && go test -count=1 -short ./...` exit 0
5. Run 5 full-chain integration tests: `go test -count=1 -run 'Test.*_FullChain_AuditAndRiskguard' ./mcp` — must pass in <15s
6. **Tool count gate**: After re-deploying via `go run ./cmd/server`, hit `/healthz` and confirm `total_available=111` (unchanged — same tools just sourced externally)
7. Commit + push

## Verification at finish
- bootstrap `go.mod` lists `github.com/algo2go/kite-mcp-tools-trade v0.1.0`
- bootstrap `mcp/trade/` directory does NOT exist
- WSL2 build + vet + integration tests all green
- `/healthz total_available=111` invariant preserved
- New tag pushed and GOPROXY-resolvable

## Halt conditions (ABORT on any of these)
- Tool count drift in `/healthz` (was 111, becomes anything else) — likely missing side-effect import in bootstrap main
- Residual `manager.X()` ref count goes UP (you should have fixed 2, expect 0 remaining inside extracted module)
- `kc.BrokerResolverProvider` doesn't exist at kite-mcp-kc HEAD — check `git tag` and bump kc dep version if needed (compile-and-run is authoritative per orchestrator rule)
- Any cross-subdir import discovered post-extraction (empirically zero, but if discovered → halt + report)
- Test failures referencing extracted types from outside mcp/trade — likely a missed type-identity site

## Per-git compliance
- You own: `algo2go/kite-mcp-tools-trade` (new module) + `algo2go/kite-mcp-bootstrap` (your slice = go.mod bump + mcp/trade/ deletion + side-effect import)
- You do NOT touch: any sibling sub-git (portfolio, ops, alerts, paper) — those are parallel dispatches
- You do NOT touch: kite-mcp-kc, kite-mcp-server, any other algo2go module
- Empirical isolation: zero cross-subdir imports verified at HEAD `640755a2` (per bootstrap-decomp-empirical-mapping.md §7)

Push commits to your new module on `master` and to bootstrap on a branch named `phase3-extract-trade`. Report tag + branch + tool count + integration test runtime back to orchestrator.
```

---

## BRIEF 2 — kite-mcp-tools-portfolio

```markdown
# Phase 3 Sub-Git 2 — Execute extraction of mcp/portfolio + mcp/analytics

You are dispatched to extract `bootstrap/mcp/portfolio` AND `bootstrap/mcp/analytics` to a new external module `algo2go/kite-mcp-tools-portfolio` (combined as a single module — portfolio holds positions/PnL/sectors, analytics holds backtest/indicators/concall/FII-DII/peer-compare; tight conceptual coupling justifies single module). Parallel with 4 sibling dispatches. Zero cross-subdir imports verified.

## Pre-flight verification (HARD GATES)
1. **Phase 2 landed**: `algo2go/kite-mcp-tools-common` v0.1.0+ GOPROXY-resolvable.
2. **bootstrap clean**: WSL2 `go build ./... && go vet ./...` exit 0 at HEAD.
3. **Zero residual `manager.X()` refs** in both subdirs verified at HEAD `640755a2` (re-verify in your clone: `grep -rEn 'manager\.[A-Z]' mcp/portfolio mcp/analytics` should return empty for production code).
4. **kite-mcp-kc v0.1.0+** GOPROXY-resolvable (transitive via tools-common).
5. **12 in-subdir tests** (10 analytics + 2 portfolio) must move with code: `tools_pure_backtest_test.go`, `tools_pure_indicators_test.go`, `tools_pure_math_test.go`, `tools_pure_portfolio_test.go`, `helpers_test.go`, `concall_tool_test.go`, `fii_dii_tool_test.go`, `get_tools_backtest_test.go`, `indicators_property_test.go`, `peer_compare_tool_test.go` (analytics), `pure_analytics_test.go`, `sector_tool_property_test.go` (portfolio).

## Scope
- Source: `bootstrap/mcp/portfolio/` (9 prod + 2 test = 2,380 prod LOC + 394 test LOC) + `bootstrap/mcp/analytics/` (6 prod + 10 test = 4,195 prod LOC + 2,190 test LOC) = **15 prod files, 6,575 prod LOC, 12 in-subdir test files**, **28 tools** (20 portfolio + 8 analytics)
- Destination: `github.com/algo2go/kite-mcp-tools-portfolio` with subpackages `portfolio/` and `analytics/`
- algo2go deps: kite-mcp-alerts, kite-mcp-broker (+ broker/mock for tests), kite-mcp-cqrs, kite-mcp-domain, kite-mcp-money, kite-mcp-oauth, kite-mcp-sectors, kite-mcp-usecases (8) + kite-mcp-tools-common
- **MUST also**: keep 6 root-test sites that exercise portfolio tools across subdir boundaries — verify they still build after extraction (these tests stay at bootstrap root; they import bootstrap's plugin registry, not portfolio directly)

## Execution sequence

### Phase A (canary cutover, ~50-80min)
1. `gh repo create algo2go/kite-mcp-tools-portfolio --public --description "Portfolio + analytics tools (28 tools)"`
2. Clone; create `go.mod` for `github.com/algo2go/kite-mcp-tools-portfolio`, go 1.25.0, add 8 algo2go deps + tools-common
3. Copy 9 portfolio + 6 analytics prod files into `portfolio/` and `analytics/` subpackages. Copy all 12 in-subdir test files alongside.
4. Rewrite imports in all 27 files (15 prod + 12 test): `bootstrap/kc` → `github.com/algo2go/kite-mcp-kc`, `bootstrap/mcp/common` → `github.com/algo2go/kite-mcp-tools-common/common`
5. Package names preserved: `package portfolio`, `package analytics`
6. WSL2 `go build ./... && go vet ./... && go test -count=1 -short ./...` exit 0 in new module (all 12 tests must pass)
7. Commit + push + tag `v0.1.0`; verify GOPROXY resolution

### Phase B (canary deletion, ~30-45min)
1. In bootstrap: `go.mod` add `github.com/algo2go/kite-mcp-tools-portfolio v0.1.0`
2. Delete `mcp/portfolio/` AND `mcp/analytics/` entirely (including in-subdir tests — they're now in the new module)
3. Add side-effect import to bootstrap main: `_ "github.com/algo2go/kite-mcp-tools-portfolio/portfolio"` AND `_ "github.com/algo2go/kite-mcp-tools-portfolio/analytics"`
4. **Critical**: 6 root-test sites likely reference `portfolio.X` or `analytics.X` types. Re-verify: `grep -rEn 'portfolio\.|analytics\.' mcp/*_test.go` and rewrite to use the new external import paths if needed
5. WSL2 build + vet + test + full-chain integration tests exit 0
6. `/healthz total_available=111` invariant gate
7. Commit + push

## Verification at finish
- bootstrap `go.mod` lists external portfolio module
- bootstrap `mcp/portfolio/` and `mcp/analytics/` directories deleted
- All 12 in-subdir tests now run in new module (verify with `go test -v -count=1 -short ./...` in new module — counts should be 12 packages with ~30+ test functions)
- 5 full-chain integration tests at bootstrap pass in <15s
- `/healthz total_available=111`

## Halt conditions
- Any of the 12 in-subdir tests fails to compile/run in the new module (likely missing test-only dep like `broker/mock`)
- Tool count drift in `/healthz`
- 6 root-test sites fail post-extraction (likely import path rewrite incomplete)
- `sectors.X` type-identity violation if analytics or portfolio touches sectors package types incompatibly
- Test file count delta ≠ -12 in bootstrap (you should have removed exactly 12 in-subdir test files)

## Per-git compliance
- You own: `algo2go/kite-mcp-tools-portfolio` (new module — 2 subpackages) + bootstrap slice
- 6 root-test sites at bootstrap might need touch (read-and-fix-imports, no logic change)
- You do NOT touch sibling sub-gits
- Empirical isolation: zero cross-subdir imports between portfolio↔analytics (per §7); they're combined here for module-cohesion reasons

Push to new module `master` + bootstrap branch `phase3-extract-portfolio`. Report.
```

---

## BRIEF 3 — kite-mcp-tools-ops

```markdown
# Phase 3 Sub-Git 3 — Execute extraction of mcp/admin + mcp/misc

You are dispatched to extract `bootstrap/mcp/admin` AND `bootstrap/mcp/misc` to a new external module `algo2go/kite-mcp-tools-ops` (admin + misc combined — both are operator-facing tooling, no end-user tools). Parallel with 4 sibling dispatches.

## Pre-flight verification (HARD GATES)
1. **Phase 2 landed**: tools-common v0.1.0+ GOPROXY-resolvable.
2. **bootstrap clean** at HEAD.
3. **4 residual `manager.X()` refs** verified present:
   - `mcp/admin/admin_baseline_tool.go:110` — `auditStore := manager.AuditStoreConcrete()`
   - `mcp/admin/admin_cache_info_tool.go:121` — same `manager.AuditStoreConcrete()`
   - `mcp/misc/session_admin_tools.go:93` — `reg := manager.SessionManager` (field access)
   - `mcp/misc/session_admin_tools.go:211` — same `manager.SessionManager`
4. **NEW PORTS REQUIRED at kite-mcp-kc BEFORE this brief executes**:
   - `AuditStoreConcreteProvider` port returning `*audit.Store` (for `UserOrderStats()` + `StatsCacheHitRate()` forensics methods NOT on AuditStoreInterface)
   - `SessionRegistryProvider` port returning `*SessionRegistry` (for `ListActiveSessions()` + `TerminateByEmail()`)
   - Both ports must be in kite-mcp-kc `ports/` package, with compile-time assertions in `ports/assertions.go`. Bump kc to v0.1.1+ and update tools-common dep.
   - **If these ports don't exist at dispatch time → HALT immediately and request orchestrator to dispatch port-creation pre-step.**

**Status update 2026-05-16**: This prerequisite has LANDED. kite-mcp-kc v0.1.2 (commit `41d8bf0`) ships both `AuditStoreConcreteProvider` and `SessionRegistryProvider` ports with `*kc.Manager` compile-time satisfaction assertions. See `phase-3-ops-port-prereq-2026-05-16.md` micro-report for details.

## Scope
- Source: `bootstrap/mcp/admin/` (8 files, 1,791 LOC, 18 tools) + `bootstrap/mcp/misc/` (4 files, 918 LOC, 9 tools) = **12 prod files, 2,709 LOC, 27 tools**
- Destination: `github.com/algo2go/kite-mcp-tools-ops` with `admin/` + `misc/` subpackages
- Test files: 0 in subdir (admin tests live at mcp/ root — `admin_anomaly_tool_test.go`, `admin_baseline_tool_test.go`, `admin_cache_info_tool_test.go`, `admin_integration_test.go`, `admin_tools_test.go`. These STAY at bootstrap root and exercise tools via plugin registry post-extraction.)
- algo2go deps: kite-mcp-audit, kite-mcp-billing, kite-mcp-cqrs, kite-mcp-domain, kite-mcp-oauth, kite-mcp-riskguard, kite-mcp-ticker, kite-mcp-usecases (8) + kite-mcp-tools-common

## Execution sequence

### Phase A (canary cutover, ~40-65min)
1. `gh repo create algo2go/kite-mcp-tools-ops --public --description "Admin + misc operator tools (27 tools)"`
2. Clone; create go.mod, add 8 algo2go deps + tools-common (kite-mcp-kc v0.1.2+ with new Provider ports)
3. Copy 12 files into `admin/` + `misc/` subpackages with package names preserved
4. **Fix residual #1, #2**: `admin_baseline_tool.go:110` + `admin_cache_info_tool.go:121` — replace `manager.AuditStoreConcrete()` with `handler.AuditStoreConcreteProvider()` (or whatever the new port method is named on ToolHandlerDeps — verify against tools-common's deps surface)
5. **Fix residual #3, #4**: `session_admin_tools.go:93,211` — replace `manager.SessionManager` field access with `handler.SessionRegistryProvider()`
6. Rewrite imports (bootstrap/kc, bootstrap/mcp/common → algo2go equivalents)
7. WSL2 `go build ./... && go vet ./... && go test -count=1 -short ./...` exit 0
8. Commit + push + tag v0.1.0; GOPROXY-verify

### Phase B (canary deletion, ~25-40min)
1. bootstrap go.mod: add tools-ops v0.1.0
2. Delete `mcp/admin/` AND `mcp/misc/`
3. Add side-effect import: `_ "github.com/algo2go/kite-mcp-tools-ops/admin"` AND `_ "github.com/algo2go/kite-mcp-tools-ops/misc"`
4. 5 admin tests at mcp/ root must still build — verify they import via plugin registry, not direct `admin.X` (if they do reference admin types, rewrite to external path)
5. WSL2 build + vet + test + full-chain integration tests exit 0
6. `/healthz total_available=111` gate
7. Commit + push

## Verification at finish
- 4 residual `manager.X()` refs gone (zero in admin + misc)
- New 2 Provider ports compile-clean at kite-mcp-kc
- 5 admin root-tests still pass via plugin registry path
- bootstrap `mcp/admin/` and `mcp/misc/` deleted
- `/healthz total_available=111`

## Halt conditions
- New ports not present in kite-mcp-kc at dispatch time — HALT, request prerequisite
- `*audit.Store` concrete type leaks outside the new Provider port abstraction (regression on encapsulation)
- 5 admin root-tests fail
- Tool count drift
- Compile error referencing forensics methods (UserOrderStats / StatsCacheHitRate) means Provider port surface incomplete

## Per-git compliance
- You own: `algo2go/kite-mcp-tools-ops` + bootstrap slice (mcp/admin/ + mcp/misc/ deletion + go.mod bump + 2 side-effect imports)
- You do NOT touch sibling sub-gits
- **Cross-dependency**: this brief depends on kite-mcp-kc having `AuditStoreConcreteProvider` + `SessionRegistryProvider` ports. Orchestrator coordinates port creation BEFORE this brief fires. (LANDED 2026-05-16 in kc v0.1.2.)

Push + report.
```

---

## BRIEF 4 — kite-mcp-tools-alerts

```markdown
# Phase 3 Sub-Git 4 — Execute extraction of mcp/alerts

You are dispatched to extract `bootstrap/mcp/alerts` to a new external module `algo2go/kite-mcp-tools-alerts`. Parallel with 4 sibling dispatches. Zero residual `manager.X()` refs — cleanest extraction in the batch.

## Pre-flight verification (HARD GATES)
1. **Phase 2 landed**: tools-common v0.1.0+ GOPROXY-resolvable.
2. **bootstrap clean** at HEAD.
3. **Zero residual `manager.X()` refs** in mcp/alerts/ — verify: `grep -rEn 'manager\.[A-Z]' mcp/alerts/` should return empty.
4. **testutil/kcfixture dep** handling: in-subdir tests (`composite_alert_tool_test.go`, `instrument_resolver_adapter_test.go`, `volume_spike_tool_test.go`) may import `bootstrap/testutil` or `bootstrap/testutil/kcfixture`. Verify which: `grep -E 'testutil' mcp/alerts/*_test.go`. If they do, the new module needs `github.com/algo2go/kite-mcp-bootstrap/testutil` as a test-only dep (testutil sub-module already has its own go.mod at v0.1.1+; this is the established cross-module test-fixture pattern).

## Scope
- Source: `bootstrap/mcp/alerts/` (5 prod + 3 test = 1,508 prod LOC + 338 test LOC, 8 tools)
- Files: `alert_history_tool.go`, `alert_tools.go`, `composite_alert_tool.go`, `projection_tool.go`, `volume_spike_tool.go` (prod) + 3 test files
- Destination: `github.com/algo2go/kite-mcp-tools-alerts` (single package, no subpackages)
- algo2go deps: kite-mcp-broker, kite-mcp-cqrs, kite-mcp-instruments, kite-mcp-oauth, kite-mcp-ticker (5) + kite-mcp-tools-common
- Test-only dep: `github.com/algo2go/kite-mcp-bootstrap/testutil` (if used) — confirm at clone time

## Execution sequence

### Phase A (canary cutover, ~35-55min)
1. `gh repo create algo2go/kite-mcp-tools-alerts --public --description "Alert tools (8 tools)"`
2. Clone; create go.mod for `github.com/algo2go/kite-mcp-tools-alerts`, add 5 algo2go deps + tools-common
3. Copy 5 prod + 3 test files; rewrite imports
4. Package `alerts` preserved
5. If tests depend on bootstrap/testutil → add it to go.mod as a require (it has its own go.mod, version 0.1.1+)
6. WSL2 `go build ./... && go vet ./... && go test -count=1 -short ./...` exit 0 (3 in-subdir test packages should pass)
7. Commit + push + tag v0.1.0; GOPROXY-verify

### Phase B (canary deletion, ~25-35min)
1. bootstrap go.mod: add tools-alerts v0.1.0
2. Delete `mcp/alerts/` entirely (5 prod + 3 test files)
3. Add side-effect import: `_ "github.com/algo2go/kite-mcp-tools-alerts"`
4. Verify root mcp/ tests that reference alert tools still build via plugin registry: `alert_history_tool_test.go`, `composite_alert_tool_test.go` (if these are at root — verify location)
5. WSL2 build + vet + test exit 0; full-chain integration tests pass
6. `/healthz total_available=111`
7. Commit + push

## Verification at finish
- All 3 in-subdir tests run in new module (post-Phase-A)
- bootstrap `mcp/alerts/` directory deleted (5 prod + 3 test files removed)
- bootstrap test file delta = -3
- Tool count 111 preserved

## Halt conditions
- testutil import path fails to resolve in new module — fix go.mod require line and retry
- 3 in-subdir tests fail post-relocation (likely missing test-only dep)
- Tool count drift
- Any cross-module test fixture circular dep — testutil/kcfixture is the standard one-way test-fixture import (kc/bootstrap test dep). Should NOT form a cycle.

## Per-git compliance
- You own: `algo2go/kite-mcp-tools-alerts` + bootstrap slice
- You do NOT touch sibling sub-gits
- The bootstrap/testutil cross-module test-only dep is acceptable per established pattern (3 kc test files already use it — production graph stays clean)

Push + report.
```

---

## BRIEF 5 — kite-mcp-tools-paper

```markdown
# Phase 3 Sub-Git 5 — Execute extraction of mcp/paper

You are dispatched to extract `bootstrap/mcp/paper` to a new external module `algo2go/kite-mcp-tools-paper`. Parallel with 4 sibling dispatches. **HIGHEST COUPLING in batch** due to `paper.TradingContext` type alias and 10 root-test references — handle with care.

## Pre-flight verification (HARD GATES)
1. **Phase 2 landed**: tools-common v0.1.0+ GOPROXY-resolvable.
2. **bootstrap clean** at HEAD.
3. **Zero residual `manager.X()` refs** in mcp/paper/.
4. **TradingContext type alias** at `bootstrap/mcp/aliases.go:60` verified: `type TradingContext = paper.TradingContext`. This alias is consumed by 2 root-mcp test files. Choose preservation strategy:
   - **Strategy A**: Keep `mcp/aliases.go:60` after extraction, rewrite to `type TradingContext = toolspaper.TradingContext` (with `toolspaper "github.com/algo2go/kite-mcp-tools-paper"` import alias). Lowest blast radius. **RECOMMENDED.**
   - **Strategy B**: Migrate the 2 root-mcp test files to import `kite-mcp-tools-paper.TradingContext` directly; delete the alias. Cleaner but touches test files.
   - **Pick Strategy A first; fall back to B only if alias chain fails to compile.**
5. **10 root-test coupling** verified: 10 test files at bootstrap mcp/ root reference paper types via the alias (per `bootstrap-decomp-empirical-mapping.md §6.5`). Re-grep: `grep -rEn 'TradingContext|paper\.' mcp/*_test.go` and note count for post-extraction comparison.

## Scope
- Source: `bootstrap/mcp/paper/` (5 prod files, 1,326 LOC, 8 tools)
- Files: `context_tool.go`, `observability_tool.go`, `paper_tools.go`, `setup_tool.go`, `setup_tools.go`
- Test files: 0 in subdir
- Destination: `github.com/algo2go/kite-mcp-tools-paper` (single package `paper`)
- algo2go deps: kite-mcp-audit, kite-mcp-cqrs, kite-mcp-domain, kite-mcp-oauth, kite-mcp-papertrading (the engine), kite-mcp-scheduler, kite-mcp-usecases (7) + kite-mcp-tools-common
- **CRITICAL dep**: `algo2go/kite-mcp-papertrading` is the engine. This new tools-paper module is the MCP-tool layer that surfaces the engine. Confirm engine module version compatibility.

## Execution sequence

### Phase A (canary cutover, ~50-70min)
1. `gh repo create algo2go/kite-mcp-tools-paper --public --description "Paper trading tools (8 tools)"`
2. Clone; create go.mod for `github.com/algo2go/kite-mcp-tools-paper`, add 7 algo2go deps + tools-common
3. Copy 5 prod files; package name `paper` preserved
4. Rewrite imports
5. WSL2 `go build ./... && go vet ./...` exit 0
6. Commit + push + tag v0.1.0; GOPROXY-verify

### Phase B (canary deletion + alias migration, ~40-60min)
1. bootstrap go.mod: add tools-paper v0.1.0
2. **Strategy A — alias rewrite**: edit `bootstrap/mcp/aliases.go:60` to import the new external module:
   ```go
   import toolspaper "github.com/algo2go/kite-mcp-tools-paper"
   type TradingContext = toolspaper.TradingContext
   ```
   This single alias preservation means the 10 root-test sites do NOT need changes (they reference `mcp.TradingContext` via aliases.go).
3. Delete `mcp/paper/` directory (5 prod files)
4. Add side-effect import: `_ "github.com/algo2go/kite-mcp-tools-paper"` in main wiring
5. WSL2 `go build ./... && go vet ./... && go test -count=1 -short ./...` exit 0
6. **Specifically run the 10 root-tests**: `grep -lE 'TradingContext|paper\.' mcp/*_test.go | xargs -I{} go test -count=1 -v ./mcp -run "Paper|TradingContext" -timeout 30s` — they MUST pass
7. Full-chain integration tests pass
8. `/healthz total_available=111`
9. Commit + push

## Verification at finish
- bootstrap `mcp/paper/` directory deleted
- `mcp/aliases.go:60` still defines `TradingContext` (now type-aliased to external)
- 10 root-test files still build and pass without modification (Strategy A success criterion)
- Tool count 111 preserved

## Halt conditions
- `paper.TradingContext` type-identity violation across module boundary — Go type aliases ARE preserved across modules, but if the engine module `kite-mcp-papertrading.TradingContext` is the actual source of truth, the chain may double-alias incorrectly. Investigate at HALT.
- Any of the 10 root-test files fails to compile post-Strategy-A — fall back to Strategy B (migrate test imports). Document the test file list.
- Tool count drift
- The engine module `kite-mcp-papertrading` has version skew with what tools-paper requires — bump engine version or pin compatible tag

## Per-git compliance
- You own: `algo2go/kite-mcp-tools-paper` + bootstrap slice (mcp/paper deletion + aliases.go edit + side-effect import + go.mod bump)
- You do NOT touch sibling sub-gits, do NOT touch `algo2go/kite-mcp-papertrading` (engine — read-only dep)
- **Highest care**: the alias.go preservation is what makes this extraction non-breaking for root-tests. If Strategy A fails empirically, halt and report — DO NOT migrate test files reactively without orchestrator sign-off.

Push + report; include explicit confirmation of which Strategy (A or B) was used and any test count delta.
```

---

## Coordination notes for orchestrator (NOT part of any brief)

**Sequencing**:
1. **Phase 2 lands first** (Path A's current work). Confirm tools-common v0.1.0+ on GOPROXY.
2. **Pre-step for Brief 3 (ops)**: kite-mcp-kc v0.1.2 ships the `AuditStoreConcreteProvider` + `SessionRegistryProvider` ports. **LANDED 2026-05-16.** Then tools-common bumps to consume kc v0.1.2+; tools-common ships v0.1.1+.
3. **Briefs 1, 2, 4, 5 fire in parallel immediately after Phase 2 lands** (no inter-brief dependencies).
4. **Brief 3 fires after ops-port pre-step AND Phase 2** (sequential after both gates).

**Wall-clock optimistic**:
- Phase 2 lands: T+0
- Briefs 1, 2, 4, 5 fire: T+5min, complete by T+2h (parallel)
- Brief 3 fires: T+5min (port pre-req already shipped 2026-05-16), completes by T+2.5h
- **Total Phase 3 wall-clock: ~2.5h after Phase 2 lands**

**Bootstrap commit conflict risk**: each brief edits bootstrap go.mod + bootstrap main wiring (side-effect imports) + deletes one subdir. Five parallel agents on five branches → no conflict at file level (different subdirs). go.mod and main wiring will conflict if all 5 agents touch them concurrently. **Recommend per-teammate git worktrees per `user_team_commit_protocol.md`** OR sequential bootstrap PRs after each parallel external-module is tagged (preferred — simpler, gates on tool count per merge).

**Tool count invariant**: every brief preserves `/healthz total_available=111`. Use as the single objective gate; any drift triggers halt.

**Empirical surprises** (vs the dispatch description, verified 2026-05-16):
1. Dispatch counted "trade: 9 prod files, 3,710 LOC, 28 tools" — verified matches `bootstrap-decomp-empirical-mapping.md §6.7` (`9 + 0 test = 9, 3,710 LOC, 28 tools`).
2. Dispatch counted "ops: 12 prod files, 2,709 LOC, 27 tools" — admin (8 files, 1,791 LOC, 18 tools) + misc (4 files, 918 LOC, 9 tools) = 12 files, 2,709 LOC, 27 tools.
3. Dispatch counted "alerts: 5 prod files, 1,508 LOC, 8 tools" — matches §6.2 exactly.
4. Dispatch counted "paper: 5 prod files, 1,326 LOC, 8 tools" — matches §6.5.
5. Dispatch counted "portfolio: 15 prod files, 6,575 LOC, 28 tools" — portfolio (9 prod, 2,380 LOC, 20 tools) + analytics (6 prod, 4,195 LOC, 8 tools) = 15 files, 6,575 LOC, 28 tools.
6. **All 5 numeric specs match the empirical mapping doc verbatim**; the briefs are dispatch-ready against current HEAD.

**One specification adjustment vs dispatch description**: dispatch said "Ops: 4 residual manager refs (AuditStoreConcrete × 2 + SessionRegistry × 2)". Empirical re-check of `bootstrap-decomp-empirical-mapping.md §5` and HEAD `640755a2` confirms exactly: admin (×2 AuditStoreConcrete) + misc (×2 SessionManager field access — was `SessionManager()` pre-B4, now field access). Brief 3 has both mapped to specific file:line pairs and the required port creation prerequisite is explicit.

---

## Follow-up status

- Brief 3 port-creation prerequisite: **CLOSED 2026-05-16** (kc v0.1.2 commit `41d8bf0`)
- Phase 2 (tools-common): in flight on Path A track at dispatch time
- Briefs are dispatch-ready when Phase 2 lands
- Recommend dispatching 5 parallel agents per `user_team_agents_default.md` once Phase 2 confirms

## Cross-references

- `.research/bootstrap-decomp-strategy.md` — Audit's Shape A* sequencing
- `.research/research/decomposition-blockers-comprehensive-2026-05-11.md` — blocker analysis
- `algo2go/kite-mcp-bootstrap/.research/bootstrap-decomp-empirical-mapping.md` — file:line + dep mapping per sub-git
- `.research/research/option-b-expose-properties-2026-05-11.md` — accessor-drain pattern
- `.research/research/sprint-5-pattern-d2-prep-2026-05-11.md` — Tool.Handler signature migration
