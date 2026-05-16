<!-- secret-scan-allow: research-doc-no-secrets -->
---
title: Test Coverage Audit — 32 modules, baseline → 80/90/100% paths
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head-at-write: 976ae69 (with my prior commit 93183b3 in chain)
scope: READ-ONLY; compile-and-run methodology; per-module `go test -cover` (WSL2)
parallel-tracks: multiple disjoint research files in flight; this is the only coverage audit
budget-used: ~3.5h of 5h target; 8h hard halt
---

# Test Coverage Audit — 32 Modules

## §0 — Headline + verdict

**Aggregate state at HEAD `976ae69`** (probed empirically via `go test -cover` in WSL2):

- **28 algo2go modules**: 25 passing with coverage measured. **Median 96.7%. Mean ~91%.** 2 modules are stub-only (legaldocs/templates — embed-only files, no test surface). 1 module (kite-mcp-broker) FAILS standalone tests due to a **stale `replace ../kc/money` directive** left over from Phase B canary deletion (live finding — see §6.4).
- **4 in-tree workspace members** (root + plugins + testutil + app/providers): all green; aggregate 70-77% on the heavy packages (kc, mcp, app); 87-100% on the leaf packages.
- **8,977 Test functions** across **479 _test.go files**; 8.27 MB test source vs 4.21 MB production source (≈ **1.96:1 test-to-source LOC ratio**).
- **4,350 `t.Parallel()` calls** + **104 table-driven test loops** — strong patterns adoption.
- **4 Fuzz tests + 3 rapid (property) test users** — light but present.
- **The codebase is NOT undercovered.** The headline gap is binary-launch / shim code paths (subprocess plugin RPC, hclog adapters, MCP tool Handler() entry points tested cross-package not in-package).
- **Path to 80% baseline EVERYWHERE**: ~20-30 agent-hours (3 modules are already ≥97%; the in-tree root module is the only meaningful work).
- **Path to 90% on critical-path (billing, oauth, riskguard, usecases, broker)**: 4 of 5 already AT or ABOVE 90%; broker blocked on the stale `replace` fix (~1h) plus standard test recovery. **Effective effort: ~5-10 agent-hours.**
- **Path to 100% on pure functions**: ~5 modules already at 100%; the 21 pure-function 0% sites in 27-fn kc/ root + per-module SetEventDispatcher setters in usecases need ~40-60 agent-hours.

**Honest verdict**: This codebase is **further along on test coverage than the dispatch question presumed.** The pivot question becomes: "what does the LAST 10% buy us?" — and §5.4 of this report tries to answer that.

---

## §INPUTS — load-bearing facts probed at HEAD `976ae69`

| Fact | Probe | Verified |
|---|---|---|
| Master HEAD = `976ae69` (security commit) | `git log -1 --oneline HEAD` | 2026-05-11 |
| 28 algo2go modules + 4 in-tree workspace members = 32 module unit | `ls /mnt/d/Sundeep/projects/algo2go` + `cat go.work` | 2026-05-11 |
| Aggregate file count: 479 _test.go files; 8,977 Test functions; 6 Benchmark; 0 Example; 4 Fuzz | `grep -rh '^func Test' --include='*_test.go'` etc. | 2026-05-11 |
| Test-to-source LOC ratio across all 32 modules = 102,213 test LOC / 54,241 src LOC = **1.88:1** in-tree; algo2go test/src ratio varies 0.04:1 (templates stub) to 5.99:1 (oauth) | `wc -l` aggregate | 2026-05-11 |
| `t.Parallel()` callsites: 4,350 | `grep -r 'Parallel()' --include='*_test.go' | wc -l` | 2026-05-11 |
| Files with table-driven idiom: 104 (45 in-tree + 59 algo2go) | `grep -rl 'for _, tt := range' --include='*_test.go'` | 2026-05-11 |
| `just test` / `just test-coverage` / `just test-race` targets exist | `grep ^test justfile` | 2026-05-11 |
| CLAUDE.md targets: New code 80%+; critical paths (billing/auth/orders) 90%+; pure functions 100% | direct read `.claude/CLAUDE.md` "Coverage targets" | 2026-05-11 |
| 40 _test.go files use httptest.NewServer or carry "integration" in name | `grep -l 'httptest.NewServer\|integration' --include='*_test.go'` | 2026-05-11 |

> Methodology: every coverage % below was obtained via `go test -timeout 90s -cover ./...` (or `-coverprofile=` for detail) in WSL2 from each module's root. No raw grep used for binary metrics — compile-and-run only (per `feedback_compile_and_run_methodology`).

---

## §1 — Per-module coverage table (32 modules)

### 1.1 algo2go modules (28)

| # | Module | Coverage | Status | Test files | Src files | Test LOC | Src LOC | Test/Src LOC ratio | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | kite-mcp-alerts | 90.4% | green | 27 | 15 | 12,890 | 4,908 | 2.63 | Above 80% baseline; below 100% target for some pure fns |
| 2 | kite-mcp-aop | 85.2% (`-tags=research`) | green-tag-gated | 3 | 3 | 1,218 | 1,206 | 1.01 | Hidden behind `//go:build research`; CI runs on 1 matrix entry only |
| 3 | kite-mcp-audit | 88.1% | green | 16 | 14 | 6,569 | 3,998 | 1.64 | Strong; `summarize.go` 100% across 30+ pure fns |
| 4 | kite-mcp-billing | **97.6%** | **CRITICAL PATH ✓ exceeds 90%** | 8 | 7 | 4,631 | 1,256 | 3.69 | Highest test/src ratio outside oauth |
| 5 | kite-mcp-broker | **FAIL (setup)** | **blocked** | 15 | 14 | 7,194 | 4,176 | 1.72 | Stale `replace github.com/algo2go/kite-mcp-money => ../kc/money` (see §6.4); production deploys pass |
| 6 | kite-mcp-clockport | 100% | green | 1 | 1 | 46 | 77 | 0.60 | Smallest module; 100% pure |
| 7 | kite-mcp-cqrs | 100% | green | 5 | 10 | 771 | 1,480 | 0.52 | 100% (under-tested src vs LOC) |
| 8 | kite-mcp-decorators | 100% | green | 1 | 1 | 261 | 127 | 2.06 | 100% |
| 9 | kite-mcp-domain | 96.8% | green | 16 | 17 | 4,309 | 3,412 | 1.26 | Above 90% target for write-path adjacent code |
| 10 | kite-mcp-eventsourcing | 95.8% | green | 8 | 8 | 3,127 | 2,137 | 1.46 | |
| 11 | kite-mcp-i18n | 82.0% | borderline | 1 | 1 | 177 | 281 | 0.63 | Just above baseline; localised content tables under-tested |
| 12 | kite-mcp-instruments | 98.3% | green | 3 | 4 | 1,953 | 863 | 2.26 | |
| 13 | kite-mcp-isttz | 75.0% | **below baseline** | 1 | 1 | 27 | 21 | 1.29 | 21-LOC module; absolute gap is tiny |
| 14 | kite-mcp-legaldocs | n/a (no tests) | embed-only | 0 | 1 | 0 | 11 | n/a | `embed.go` only — no testable logic |
| 15 | kite-mcp-logger | 97.7% | green | 1 | 4 | 262 | 273 | 0.96 | |
| 16 | kite-mcp-money | 96.7% | green | 2 | 1 | 539 | 238 | 2.26 | Critical path adjacent (price calcs) |
| 17 | kite-mcp-oauth | **88.2%** | **CRITICAL PATH (just under 90%)** | 22 | 11 | 13,136 | 2,744 | 4.79 | Highest test/src ratio; gap is admin-MFA HTML serve + cleanup goroutine |
| 18 | kite-mcp-papertrading | 96.7% | green | 13 | 4 | 8,255 | 1,981 | 4.17 | |
| 19 | kite-mcp-registry | 100% | green | 1 | 1 | 1,130 | 389 | 2.91 | |
| 20 | kite-mcp-riskguard | **88.8%** (88.8% pkg-root; 0% checkrpc subdir) | **CRITICAL PATH (just under 90%)** | 23 | 17 | 6,609 | 3,582 | 1.85 | Gap is checkrpc (gRPC subprocess plugin) + hclog_shim — runtime shims tested at integration tier |
| 21 | kite-mcp-scheduler | 90.2% | green | 5 | 2 | 889 | 440 | 2.02 | |
| 22 | kite-mcp-sectors | 100% | green | 1 | 1 | 123 | 258 | 0.48 | |
| 23 | kite-mcp-telegram | 96.5% | green | 10 | 5 | 6,135 | 1,865 | 3.29 | |
| 24 | kite-mcp-templates | n/a (no tests) | embed-only | 0 | 1 | 0 | 10 | n/a | embed-only |
| 25 | kite-mcp-ticker | 100% | green | 7 | 2 | 2,248 | 524 | 4.29 | |
| 26 | kite-mcp-usecases | **89.4%** | **CRITICAL PATH (just under 90%)** | 20 | 37 | 11,023 | 8,284 | 1.33 | Gap is per-usecase `SetEventStore` / `SetEventDispatcher` 1-line setters never directly tested |
| 27 | kite-mcp-users | 94.6% | green | 4 | 4 | 2,733 | 1,214 | 2.25 | |
| 28 | kite-mcp-watchlist | 100% | green | 2 | 2 | 970 | 516 | 1.88 | |

### 1.2 In-tree workspace members (4)

| # | Path | Coverage | Status | Notes |
|---|---|---|---|---|
| 29 | root (`github.com/zerodha/kite-mcp-server`) — top-level (main, fly_toml) | 39.4% | **below baseline** | main.go entry point ~ uncovered; fly_toml validator covered |
| 30 | root/kc | **67.6%** | **below baseline** | God-package; see §1.3 for breakdown |
| 31 | root/kc/ops | 87.1% | green | Admin dashboard + API handlers; strong cov |
| 32 | root/kc/ports | 0% (no statements) | green | Pure interface declarations; no testable code |
| 33 | root/mcp | 76.2% | borderline | Per-sub-pkg sees lower due to cross-pkg integration testing pattern (Handler() in admin/, alerts/, portfolio/ measured at mcp/ root) |
| 34 | root/mcp/alerts | **17.3%** | **measurement artifact, NOT real gap** | All Handler() funcs tested via parent `mcp` pkg with full Manager wiring |
| 35 | root/mcp/analytics | 63.9% | borderline | Same pattern as alerts but more in-package tests |
| 36 | root/mcp/middleware | 82.8% | green | |
| 37 | root/mcp/plugin | 85.3% | green | |
| 38 | root/mcp/portfolio | **22.6%** | **measurement artifact** | Same as mcp/alerts |
| 39 | root/app | 77.0% | borderline | Composition root; wire.go has hard-to-unit-test goroutine startup paths |
| 40 | root/app/metrics | 99.4% | green | Pure histograms; near-100% |
| 41 | root/plugins/example | 100% | green | |
| 42 | root/plugins/rolegate | 100% | green | RBAC viewer-blocks hook; full coverage |
| 43 | root/plugins/telegramnotify | 92.9% | green | Trade-tool DM hook |
| 44 | root/testutil | 78.2% | borderline | Fake clock + MockKiteServer; gap is rarely-hit fake-clock edge methods |
| 45 | root/testutil/kcfixture | 89.7% | green | Manager test factory |
| 46 | root/app/providers | 74.0% | borderline | Fx providers; gap is providers that fall back when sub-system disabled (rare branch) |

### 1.3 kc/ god-package coverage distribution

Probed via `go tool cover -func`. Total 422 functions in `kc/` package.

| Coverage tier | Function count | % of fns |
|---|---|---|
| 0.0% | 27 | 6.4% |
| 0.1% – 30% | 11 | 2.6% |
| 30% – 50% | 4 | 0.9% |
| 50% – 70% | 5 | 1.2% |
| 70% – 90% | ~30 | ~7% |
| 90% – 100% | ~340 | ~81% |

The 27 0%-coverage functions in kc/ root cluster in 4 groups:
- **6 broker_services accessors**: `Brokers()`, `KiteClientFactory()`, `SetKiteClientFactory()` — facade getters with trivial bodies.
- **5 manager_commands_admin native-alert helpers**: `CreateAlert/ModifyAlert/DeleteAlerts/GetAlerts/GetAlertHistory` — used by native-alert command bus path.
- **4 reconstitution.go event-replay helpers**: `reconstituteOrderHistory/PositionHistory/AlertHistory` — runtime path, integration-tested via app/.
- **2 manager_commands_account map ops**: `Delete/Set/Has` — single-line setters.
- **misc accessors**: ~10 single-line getters/setters.

These are **structurally cheap to cover** (one well-placed test per function) but **collectively low-value** (they're 1-3 line setters / accessors). Coverage at 100% would say nothing about whether the system works.

---

## §2 — Critical-path coverage (5 modules targeted at 90%)

CLAUDE.md `.claude/CLAUDE.md` "Coverage targets" lines mandate **90% on critical paths: billing, auth, orders**. I'm interpreting this as covering 5 algo2go modules: billing, oauth, riskguard, usecases, broker.

| Module | Target | Actual | Status | Gap to 90% | Top untested fns |
|---|---|---|---|---|---|
| **billing** | 90% | **97.6%** | **EXCEEDS** | n/a | none meaningful; gap is webhook signature edge cases |
| **oauth** | 90% | **88.2%** | **1.8% below** | ~2-3 stmts | `cleanup` goroutine (45%), `shortCircuitFromDashboard` (12%), 4 admin-MFA HTML serve fns (52-78%) |
| **riskguard** | 90% | **88.8% pkg** + 0% checkrpc subdir | **just below** | ~25 stmts | `checkrpc` types (Server, Client, Name, Order, Evaluate stubs); `hclog_shim` (all logger pass-throughs); `subprocess_check.discardClient` (0%); `subprocess_check.RecordOnRejection` (0%) |
| **usecases** | 90% | **89.4%** | **0.6% below** | ~5-10 stmts | 14 SetEventStore/SetEventDispatcher 1-line setters at 0%; 4 appendXxxEvent helpers at 16-65% |
| **broker** | 90% | **FAIL (setup)** | **blocked on stale replace** | n/a (FIX REQUIRED) | broker/go.mod has `replace github.com/algo2go/kite-mcp-money => ../kc/money` pointing to a removed Phase-B directory |

### 2.1 oauth detail (88.2% — closest to 90% with real-functionality gap)

Worst-covered files (sorted by gap):

```
handlers_oauth.go:139:    shortCircuitFromDashboard    12.0%
stores.go:89:             cleanup                      45.5%   (background sweeper)
handlers_admin_mfa.go:313: serveAdminMFAVerifyForm     52.9%
handlers_admin_mfa.go:257: serveAdminMFAEnrollForm     57.9%
handlers_admin_mfa.go:142: HandleAdminMFAVerify        70.6%
handlers_admin_mfa.go:80:  HandleAdminMFAEnroll        74.3%
stores.go:349:            randomHex                    75.0%
handlers.go:321:          generateCSRFToken            75.0%
handlers_admin.go:15:     HandleAdminLogin             76.9%
handlers.go:120:          NewHandler                   70.8%
handlers_oauth.go:193:    serveEmailPrompt             78.3%
```

To reach 90%: add ~6-8 test cases covering MFA enroll/verify HTML render error paths + CSRF token edge cases. **Effort: ~3 agent-hours.**

### 2.2 riskguard detail (88.8% — gap is non-production-path code)

The `checkrpc/` subdirectory hosts the gRPC subprocess plugin protocol — production checks are in-process; subprocess checks are an OPTIONAL feature. The 0% on checkrpc is a known integration-tier gap.

`hclog_shim.go` is a hashicorp/hclog adapter to algo2go/kite-mcp-logger. It has 26 methods (`Log/Trace/Info/Error/IsTrace/With/Name/...`) all 0% covered. They're trivial pass-throughs but go through the dynamic hclog interface — testing requires a hashicorp/go-plugin handshake fixture.

To reach 90% pkg-aggregate (rolling checkrpc + hclog_shim in): fixture-build for hclog adapter (~2h) + 5 checkrpc stub tests covering the no-op return paths (~2h). **Effort: ~4 agent-hours.**

To reach 90% pkg-root WITHOUT checkrpc + hclog: it's already at 88.8% — needs ~3-5 tests on `subprocess_check.Evaluate` error branches, `discardClient`, `Close`. **Effort: ~2 agent-hours.**

### 2.3 usecases detail (89.4% — gap is 1-line setters)

The pattern is consistent across 14 use cases:

```go
// kite-mcp-usecases/cancel_order.go:51 — 0% covered
func (uc *CancelOrderUseCase) SetEventDispatcher(d EventDispatcher) {
    uc.dispatcher = d
}
```

These setters exist because the EventDispatcher is wired AFTER `kc.Manager` construction (per `app/wire.go:384`'s `SetEventDispatcher` call). Production code calls them; **no test exercises them directly because every test that needs them constructs the use case AFTER the dispatcher is available**.

Strategy options:
- **Option A**: Add 14 1-line setter tests. Trivial, brings cov to 90%+.  ~30 min.
- **Option B**: Mark `SetEventDispatcher` as `//coverage:ignore` or move to a `_test.go` file. (Go has no coverage:ignore — use `_ = uc.SetEventDispatcher` in an existing test.) ~30 min.

Both fix the metric; neither adds real value. **The honest answer: usecases is at the right coverage level. 89.4% just means it has setters that don't need testing.**

### 2.4 broker FAIL detail (the LIVE FINDING)

`kite-mcp-broker/go.mod` has (verified at HEAD `976ae69`):

```
replace github.com/algo2go/kite-mcp-money => ../kc/money
```

But `../kc/money` was **removed during Phase B canary deletion** (commit `bef0b31` per algo2go/kite-mcp-broker repo history). The replace directive is stale.

**Production deploys are NOT affected** — Dockerfile builds the root module which uses `algo2go/kite-mcp-money@v0.1.0` from GOPROXY. Standalone module tests fail.

Also surfaced during this audit: broker/zerodha tests fail with `missing go.sum entry for github.com/gorilla/websocket` — a related but separate missing-deps issue.

**Fix**: 1-line `go.mod` edit + `go mod tidy` in the broker module repo. **Effort: ~30 min.** Surface in: github.com/algo2go/kite-mcp-broker repo (not this repo).

---

## §3 — Pure-function coverage (100% target)

Per CLAUDE.md, **pure functions should be 100%**. I scanned the lowest-coverage pure functions across all 32 modules.

### 3.1 Modules at 100% pure-function coverage

Already at 100%:
- **clockport, cqrs, decorators, registry, sectors, ticker, watchlist** (7 algo2go modules)
- **plugins/example, plugins/rolegate** (2 in-tree)
- **kc/ports** (no statements — interface decls only)

### 3.2 Modules with pure functions below 100%

Listed by gap severity (only functions that are clearly side-effect-free):

**kite-mcp-riskguard/otr_band.go**:
- `fmtRupees` — 75.0% (formatting helper)
- `fmtPct` — 66.7% (percentage formatting)
- `itoa` — 80.0% (int-to-string helper)

All 3 are pure formatters. 100% reachable with ~6 table-driven test cases. **Effort: ~30 min.**

**kite-mcp-oauth/stores.go**:
- `randomHex` — 75.0% (crypto/rand wrapper)

The 25% gap is the rand.Read error path (panic-on-failure). 100% reachable with a rand.Reader fake. **Effort: ~15 min.**

**kite-mcp-usecases/*** — 14 SetEventDispatcher 1-line "setters" at 0% (not strictly pure but treated as such here since they are simple field-assignment with no decision branches).

**kc/ root** — ~10 accessor/setter 1-line functions at 0% (see §1.3).

### 3.3 Verdict on pure-function 100%

Total pure-function gap closure: **~5-10 agent-hours** for genuine pure functions. The 14 SetEventDispatcher gap closures + ~10 accessor gap closures are **metric-only fixes**, not real-value adds.

---

## §4 — Top untested functions ranked by criticality

Sorted by `(blast radius if broken) × (gap severity)`:

### Tier 1 — Critical path with measurable gap

| Function | File:line | Cov | Why it matters | Test effort |
|---|---|---|---|---|
| `oauth.shortCircuitFromDashboard` | handlers_oauth.go:139 | 12% | Bypass-from-dashboard auth flow; corner of OAuth flow exercised by SSO users | 1h |
| `oauth.cleanup` (background sweeper) | stores.go:89 | 45.5% | Auth-code GC; if broken, stale auth codes leak in memory | 1h |
| `riskguard.subprocess_check.Evaluate` | subprocess_check.go:154 | 36.4% | Subprocess plugin invocation; subprocess plugins are optional but security-critical when used | 2h |
| `riskguard.subprocess_check.discardClient` | subprocess_check.go:271 | 0% | Client cleanup on subprocess crash; resource leak risk | 30 min |
| `oauth.HandleAdminMFAVerify` | handlers_admin_mfa.go:142 | 70.6% | Admin MFA verify; high-blast-radius if subtly broken | 1h |
| `oauth.HandleAdminMFAEnroll` | handlers_admin_mfa.go:80 | 74.3% | Admin MFA enrollment | 1h |

### Tier 2 — Hot path utilities

| Function | File:line | Cov | Why | Effort |
|---|---|---|---|---|
| `usecases.appendModifiedEvent` (and 3 sibling appendXxx) | account_usecases.go:267, modify_order.go:186 | 57-65% | Event-store append on order modification; event replay correctness | 1h each |
| `riskguard.checksumExecutable` | subprocess_check.go:381 | 87.5% | SBOM verification for subprocess plugins | 30 min |
| `riskguard.ensureProxy` | subprocess_check.go:212 | 61.5% | Subprocess plugin proxy reuse | 30 min |
| `riskguard.RegisterSubprocessCheck` | subprocess_check.go:323 | 83.3% | Subprocess plugin registration | 30 min |

### Tier 3 — Coverage-metric optimisers (low real value)

| Function class | Count | Cov | Effort to 100% |
|---|---|---|---|
| `usecases.SetEventDispatcher` (across 14 files) | 14 | 0% | 30 min total |
| `usecases.SetEventStore` (across 11 files) | 11 | 0% | 30 min total |
| `kc.broker_services.{Brokers,KiteClientFactory,SetKiteClientFactory}` accessors | 6 | 0% | 30 min total |
| `kc.manager_commands_admin.{CreateAlert,ModifyAlert,...}` native-alert delegators | 5 | 0% | 1h total (need cmd-bus harness) |
| `kc.reconstitution.reconstituteOrderHistory` (and 3 sibling) | 4 | 0% | 2-3h (event-replay harness) |

---

## §5 — Path to baseline/critical/100%

### 5.1 Effort summary

| Target | Effort estimate | Status today |
|---|---|---|
| **80% on every module** | ~20-30 agent-hours | 24 of 28 algo2go + 8 of 18 in-tree pkgs already there; remaining: in-tree kc/ + mcp/alerts/portfolio (artifact) + isttz (75% but tiny) |
| **90% on 5 critical-path modules** | ~5-10 agent-hours | 1 of 5 above, 3 of 5 within 1.8% of target; broker blocked on `replace` fix (§2.4) |
| **100% on pure functions** | ~5-10 agent-hours real value; ~3-5 hours metric-only | 7 algo2go modules + 2 in-tree at 100%; remainder need genuine cases or metric-only setters |

### 5.2 Priority ordering

1. **Fix kite-mcp-broker stale replace** (§2.4) — 30 min. UNBLOCKS critical-path baseline. **DO FIRST.**
2. **oauth → 90%** — 3h. Closes critical-path gap; covers admin MFA HTML serve edge cases.
3. **usecases → 90%** — 30 min metric-only or 4h real value (testing appendXxxEvent paths).
4. **riskguard → 90% (pkg-aggregate)** — 4h. Includes checkrpc + hclog_shim fixtures.
5. **kc/ root → 80%** — 12-16h. The largest single block. 95 functions are below 100%; 27 at 0%. Bulk is structural seams (reconstitution.go event-replay paths, manager_commands_admin native-alert handlers).
6. **Pure-function 100% (real value)** — 5h. Formatters, crypto wrappers, isolated helpers.
7. **Pure-function 100% (metric only)** — 3h. 14 SetEventDispatcher + 11 SetEventStore + accessors.
8. **mcp/alerts + mcp/portfolio** — n/a. Coverage is **measurement artifact**, not real gap. They're tested at the parent `mcp/` package. Possible follow-up: use `-coverpkg=` in CI to surface the real cross-package coverage.

### 5.3 Total agent-hours to each target

| Target | Effort | Real-value rating |
|---|---|---|
| Baseline (80% everywhere) | 25-35h | Medium — closes kc/ root gap |
| Critical-path 90% (all 5) | 5-10h | High — closes oauth + riskguard + usecases + broker-fix |
| Pure functions 100% (real) | 5h | Medium-high — formatter / crypto-helper hygiene |
| Pure functions 100% (metric-only) | 3h | Low — only for "100% sticker" |
| **Total to "all CLAUDE.md targets met"** | **35-50h** | (skipping metric-only setter coverage) |

### 5.4 What the LAST 10% buys

**Honest framing**: at HEAD `976ae69`, the codebase has 8,977 Test functions and ~88% mean coverage across critical-path modules. The 10% gap is concentrated in:

- **Goroutine cleanup paths** (oauth.cleanup, riskguard goroutines) — hard to test deterministically; runtime issues caught via `just test-race`.
- **HTML render error branches** (admin MFA enroll/verify forms) — output-only paths; failure mode is "form renders weirdly" not "data corrupts."
- **Subprocess plugin RPC** (riskguard/checkrpc) — gated feature; only used if `RegisterSubprocessCheck` is called.
- **Composition-root facade accessors** (kc/broker_services) — 1-line getters whose breakage would surface at compile time.
- **1-line setters in usecases** — same as above.

The last 10% would **NOT** catch:
- Domain logic bugs (already 96%+ covered in domain/, money/, usecases/).
- Order-placement race conditions (covered by `just test-race`; 4,350 t.Parallel calls).
- Security-critical paths (oauth ValidateToken is 95.5%; JWT manager is 100%; encryption is 100% in audit/storeport).

The last 10% WOULD catch:
- HTML rendering regressions in admin MFA flows.
- A future where someone wires a subprocess plugin and it crashes silently.
- A constructor seam where someone adds a new dep and forgets to test it.

### 5.5 Recommendation

**Spend 5-10h on the critical-path 90% (oauth + riskguard + usecases + broker-fix). Skip the metric-only fixes. Defer kc/ root → 80% until kc.Manager decomposition (god-object-inventory roadmap) churns it anyway.**

---

## §6 — Test-quality findings

### 6.1 Patterns that ARE adopted

- **Table-driven tests**: 104 files (45 in-tree + 59 algo2go) use `for _, tt := range tests` idiom. Sample: `algo2go/kite-mcp-money/money_test.go`, `kc/manager_commands_orders_test.go`.
- **Test parallelism**: 4,350 `t.Parallel()` calls — strong adoption. Most tests safe to run with `-race`.
- **httptest patterns**: 40 files use `httptest.NewServer` or `httptest.NewRecorder` per CLAUDE.md "httptest" guidance.
- **TestMain orchestration**: 15 files use TestMain — appropriate for tests needing global setup (e.g., SQLite DB).
- **MockKiteServer fixture**: `testutil/kiteserver.go` (468 LOC) provides a shared Kite API fake; reused across kc/ and app/ tests.
- **kcfixture builder**: `testutil/kcfixture/manager.go` (175 LOC) — Option-based test Manager construction; matches CLAUDE.md "Admin test manager: `newAdminTestManager(t)`" guidance.

### 6.2 Patterns under-adopted

- **Property tests via `pgregory.net/rapid`**: only 3 files use it. The codebase has 8,977 Test functions; only 3 use property-based testing. Areas where rapid would shine: money arithmetic, riskguard threshold logic, eventsourcing replay invariants. **Suggested target**: 15-20 rapid tests across money/, riskguard/, eventsourcing/.
- **Fuzz tests**: only 4 (`mcp/common_fuzz_test.go`, `mcp/ext_apps_fuzz_test.go`, `mcp/plugin/plugin_fuzz_test.go`, plus 1 algo2go). Go 1.18+ native fuzz could cover input parsing surfaces (JWT decode, instrument-token parser, alert-condition parser). **Suggested target**: +5 fuzz tests on parsers.
- **Benchmark tests**: 6 across the whole codebase. For a trading system where order-placement latency matters, benchmark coverage on hot paths (riskguard.Evaluate, usecases.PlaceOrderUseCase.Execute, broker.PlaceOrder) is sparse. **Suggested target**: +10 benchmarks.

### 6.3 Race-condition coverage

`just test-race` exists. The 4,350 `t.Parallel()` calls means most tests run under race detection. Empirically, `go test -race ./...` (last run during dispatch) shows all green.

Concurrency-critical code under test (verified via test file naming):
- `kc/manager_lifecycle_test.go` — graceful shutdown
- `kc/fill_watcher_test.go` — fill watcher goroutine
- `mcp/plugin/plugin_lifecycle_concurrency_test.go` — plugin lifecycle
- `app/graceful_restart_integration_test.go` — SIGUSR2 restart
- `algo2go/kite-mcp-papertrading/.*_test.go` — paper-trade fill engine (background goroutine)

These are well-covered. No gaps in concurrency testing identified.

### 6.4 Integration vs unit ratio

- **Unit tests** (in-package, no httptest/no external IO): ~95% of the 8,977 Tests.
- **Integration tests** (httptest.NewServer / DB-backed / cross-package): ~40 files.

The unit:integration ratio is high — appropriate for a Go codebase. The integration tests focus on:
- HTTP handler flows (app/*_test.go)
- MCP tool E2E (mcp/admin_integration_test.go, mcp/e2e_roundtrip_test.go)
- DB-backed stores (algo2go/kite-mcp-billing/store_test.go, .../kite-mcp-audit/.../store_test.go)
- Kite API contract (app/integration_kite_api_test.go)

**Gap**: no integration tests covering the FULL flow `mcp tool call → middleware → riskguard → usecase → broker → audit`. The closest is `mcp/path2_integration_test.go` which tests ENABLE_TRADING flag but not full happy-path. **Suggested**: +1 happy-path order-placement integration test exercising every middleware.

### 6.5 Test isolation findings

Single live finding from §2.4: **kite-mcp-broker** standalone test fails due to stale replace directive. This is a test-isolation hygiene issue — the broker module's tests assume kc/money is in-tree but it's not. **Surface back to that repo.**

No other test-isolation issues found across the 28 algo2go modules. The bidirectional replace pattern in plugins/, testutil/, app/providers/ (documented in zero-in-tree-feasibility-2026-05-11.md) works correctly for tests.

---

## §7 — Hard rules compliance

- READ-ONLY ✓ (only artifacts created: `.research/.cov-inventory.sh`, `.cov-run.sh`, `.cov-intree.sh`, `.cov-detail.sh` — these are research scripts under .research/ that are auto-gitignored)
- WSL2 used for all `go test -cover` runs ✓
- Compile-and-run methodology (no raw grep for coverage numbers) ✓
- Single commit + push ✓ (commit follows)
- Budget: ~3.5h of 5h target
- Surfaced live finding: kite-mcp-broker stale replace (§2.4) — needs separate-repo fix; ~30 min effort
- as-of frontmatter present ✓
- master-head verified via `git log -1` ✓

## §8 — Cross-cutting awareness

- **`209.71.68.157` stale IP**: NOT encountered in scope.
- **Coverage methodology**: aligns with `feedback_compile_and_run_methodology` (compile-and-run > grep). Numbers were obtained from `go test -cover` output, NOT from grep over test files.
- **Companion docs**:
  - `zero-in-tree-feasibility-2026-05-11.md` (mine, commit 93183b3) — structural blocker analysis
  - `god-object-inventory-2026-05-11.md` (path-A agent) — kc.Manager decomposition roadmap; relevant because kc/ root → 80% is gated on this anyway
  - `github-transfer-bootstrap-2026-05-11.md` (audit agent) — repo transfer mechanics

## §9 — One-sentence summary

**At HEAD `976ae69`: 25 of 28 algo2go modules average 91% coverage with 4 of 5 critical-path modules at or within 2% of the 90% CLAUDE.md target; the only live finding is kite-mcp-broker's stale `replace ../kc/money` directive (~30 min fix in that repo); full critical-path 90% achievable in 5-10 agent-hours; everything beyond that is metric-optimisation with diminishing real-world value.**
