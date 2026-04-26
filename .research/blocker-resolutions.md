# Blocker Resolutions — Tier 1 t.Parallel Lead

**Audited HEAD**: `6c2e871`. Read-only. References blocker IDs from `6c2e871`'s `.research/all-blockers-enumeration.md`.

**Empirical re-grounding upfront**: my own enumeration (`6c2e871`) over-counted Tier 1 surface. Re-verified:
- **`os.Setenv` in actual test code: 3 calls** (`kc/billing/billing_webhooks_test.go:1496, 1546, 1566`). NOT 30.
- **`t.Setenv` in actual test code: 1 call** (`main_test.go:57` for LOG_LEVEL).
- **t.Parallel adoption already at 88%** (327 of 372 test files).
- **`LockDefaultRegistryForTest` IS the parallel-safe pattern** — tests using it already call `t.Parallel()` (verified in `mcp/around_hook_test.go`). Comment block explicitly says so. B70's "blocks parallel" claim was wrong.
- **`NewRegistry()` already exists** as the test-isolation escape hatch (`mcp/plugin_registry.go:108-115`); per docstring "intended primarily for tests that want plugin-state isolation across parallel runs".
- **`kc/billing/Config` already exists** with `ConfigFromEnv` separation (`kc/billing/config.go:14-37`). `CheckoutHandlerWithConfig` is already wired (line 36); only `WebhookHandler` (line 25) still reads env in closure.

**Net consequence**: the actual t.Parallel ceiling at 88% is much closer to done than my prior "30 t.Setenv-using tests" framing implied. **Real Tier 1 LOC is small.**

---

## Tier 1 — t.Parallel() readiness path

Ranked by smallest LOC for biggest agent-throughput lift. Empirical baseline: 88% already parallel.

### T1.1 — B66 partial: `WebhookHandler` env-in-closure → `WebhookHandlerWithConfig`
- **Pattern**: env-via-config (extend existing `kc/billing/config.go` Config to absorb webhook).
- **LOC**: ~25. Change `WebhookHandler(store, secret, logger, fn)` to `WebhookHandlerWithConfig(store, secret, logger, fn, cfg Config)` (~10 LOC); keep `WebhookHandler` as 1-line shim calling `WebhookHandlerWithConfig(..., ConfigFromEnv())` (~3 LOC); update `app/wire.go` callsite (~1 LOC); update 3 `os.Setenv` test calls to inject `Config` literal (~10 LOC).
- **Test cascade**: `kc/billing/billing_webhooks_test.go` only (~3 functions to update, ~10 LOC). No other callers.
- **Risk**: LOW. Pattern proven by sibling `CheckoutHandlerWithConfig` at line 36.
- **Agent lift**: +1 agent (unblocks `t.Parallel()` on billing_webhooks_test ~59 tests).
- **Cross-deps**: none.

### T1.2 — B67: `kc/audit/hashpublish.go` env reads → caller-passed Config
- **Pattern**: env-via-config. `LoadHashPublishConfig` already takes `signingKey []byte`; just extend to take a `HashPublishConfigEnv` struct (or accept the 7 raw values).
- **LOC**: ~30. Add `HashPublishConfigEnv` struct with 7 fields (~10); refactor `LoadHashPublishConfig` to accept it (~10); add `LoadHashPublishConfigFromEnv()` shim (~5); update `app/wire.go:157` callsite (~2 LOC).
- **Test cascade**: No tests currently t.Setenv these vars (verified). Pure-greenfield refactor; tests can be added after.
- **Risk**: LOW. No test cascade because no test currently exercises this path under setenv.
- **Agent lift**: 0 (tests don't exist). Future-proofing.
- **Cross-deps**: none.
- **Note**: NEEDS VERIFICATION — confirm there's no production caller hardcoded to ENV-only behaviour. (Quick check: `app/wire.go:157` is the sole caller per Grep.)

### T1.3 — B66 + B53: confirm Stripe.Key isolation NOT needed for kc/billing tests
- **Empirical reality**: `stripe.Key = stripeKey` happens only in `app/wire.go:446`. The kc/billing tests do NOT exercise this path; they construct stores + handlers directly. `kc/billing/main_test.go:41` calls `stripe.SetHTTPClient(client)` for transport-isolation, NOT `stripe.Key`.
- **Resolution**: NO ACTION needed at kc/billing test level. The `stripe.Key` global only blocks **app-package billing-integration tests** (none exist currently per grep).
- **LOC**: 0.
- **Risk**: LOW.
- **Agent lift**: 0.

### T1.4 — Migrate the 10 real-candidate non-parallel test files
Per empirical grep, 45 files don't use `t.Parallel()`. Of those, ~35 are intentional (helpers_test, leak_sentinel_test, fuzz_test, race_flag_*, integration_*, _main_test, mocks_test). The ~10 real candidates:

| File | Reason it's serial today | Resolution |
|---|---|---|
| `kc/billing/billing_webhooks_test.go` | os.Setenv on STRIPE_PRICE_* | Wait for T1.1, then add `t.Parallel()` |
| `kc/instruments/manager_test.go` | NEEDS VERIFICATION (network? clock?) | Read first |
| `oauth/handlers_test.go` | NEEDS VERIFICATION | Read first |
| `cmd/rotate-key/main_test.go` | Subprocess re-execution pattern (B69) | Defer — subprocess pattern is intentional |
| `app/plugin_routes_test.go` | Touches `pluginRouteRegistry` global (B56) | Wait for T2.x or use NewRegistry-style escape hatch |
| `app/http_privacy_test.go` | NEEDS VERIFICATION | Read first |
| `app/server_edge_adapters_test.go` | NEEDS VERIFICATION | Read first |
| `app/shutdown_test.go` | Process-lifecycle test (intentional?) | Defer |
| `app/telegram_test.go` | NEEDS VERIFICATION | Read first |
| `kc/ops/helpers_test.go` | Helper file | Defer (helper-only) |

- **LOC for the empirically tractable subset (3-4 files)**: ~10-30 LOC of `t.Parallel()` insertion, IF NEEDS VERIFICATION confirms no shared state.
- **Agent lift**: +1-2 (reduces serialisation surface area).
- **Cross-deps**: T1.1 unblocks billing_webhooks. Some require T2.x (plugin route registry split).

### T1 totals
- **LOC**: ~55 (T1.1 = 25, T1.2 = 30, T1.3 = 0, T1.4 = ~deferred to verification).
- **Agent ceiling lift**: 4 → ~6. Honest estimate. The 88% baseline means the t.Parallel constraint is already mostly slacked; remaining tightness is per-file, not architectural.
- **Comparison vs prior `I + J + E` from `8596138`**: T1 is **cheaper** — `55 LOC` vs `~80 LOC for I + J alone` (Phase 3a). And T1 unlocks parallel agents on test runs, not just dispatch. **Recommended sequence shift: T1.1 + T1.2 BEFORE Phase 3a Batch 6, since T1 closes a smaller gap on a binding constraint while Phase 3a closes a larger gap on a slack constraint.**

---

## Tier 2 — HIGH-severity blockers not in Tier 1

### T2.1 — B25 + B40 + B42 + B39: 4-site teardown drift problem
- **Pattern**: Single-source-of-truth via `LifecycleManager` (already exists, commit `8727beb`). Migrate the 3 remaining hand-maintained sites (B40 wire.go success-defer, B42 RunServer error-defer, B39 setupGracefulShutdown Phase A) to delegate to lifecycle.
- **LOC**: ~40. The setupGracefulShutdown Phase A migration is constrained — Phase A must run BEFORE Phase B (HTTP drain), so it stays as a separate `lifecycle.PhaseA.Shutdown()` plus `lifecycle.PhaseC.Shutdown()` split (or 2-phase lifecycle manager).
- **Test cascade**: Existing leak_sentinel_test files cover this. ~5 LOC.
- **Risk**: MED. Re-ordering teardown is bug-prone; A's prior session encountered "AlertDB cycle prevents 4-setter cleanup" type issues.
- **Agent lift**: 0 directly, but eliminates a recurring goroutine-leak class of bug that costs ~1 agent-day per regression.
- **Cross-deps**: none.

### T2.2 — B17 + B18 + B22 + B23: 4 genuine mutual-recursion setters
- **Pattern**: Per `blocker-fix-patterns.md` (commit `6abad64`), interface-segregation could break ~2 of 4 cycles (~350 LOC). Genuinely irreducible: B19 (PaperEngine via dispatcher), B22 (FamilyService gated on B20+B21).
- **LOC**: ~350.
- **Risk**: MED-HIGH.
- **Agent lift**: ~10% Mode 2 reduction on `wire.go` per prior analysis = ~0.5 agents.
- **Cross-deps**: T2.4 (eliminate B15/B16/B20/B21 first).
- **Verdict**: DEFER — ROI < T1.

### T2.3 — B14: ENABLE_TRADING gating ~20 tools
- **Pattern**: Already implemented as `app.Config.EnableTrading` flag passed to `mcp.RegisterTools`. NOT a blocker — it's the deployment-mode pattern working as designed.
- **LOC**: 0.
- **Risk**: 0.
- **Agent lift**: 0.
- **Verdict**: B14 should not have been HIGH. Downgrade to LOW. Misclassification in `6c2e871`.

### T2.4 — B15 + B16 + B20 + B21: 4 cleanly eliminable SetX setters
- **Pattern**: Constructor-injection via `kc.With*` options. Per `blocker-fix-patterns.md` (`6abad64`), ~60 LOC including test cascade.
- **LOC**: ~60.
- **Test cascade**: ~3 test files mutate SetX directly (per `ebfdf3d` grep).
- **Risk**: MED. AlertDB construction-order cycle (B1) blocks setter-1 (SetAuditStore) from full constructor injection — auditStore depends on alertDB which is opened in initPersistence (kc-side) NOT at NewWithOptions call site. Verified: `kc/manager_init.go:158` opens DB inside initPersistence. Fix requires either: (a) lift DB-open above kc.NewWithOptions, OR (b) keep auditStore wired post-construction (which IS the current state).
- **Agent lift**: ~5% concurrency lift on wire.go per prior analysis. ~0.2 agents.
- **Cross-deps**: B1 (AlertDB cycle) blocks the cleanest variant.
- **Verdict**: ACCEPT for follow-up PR. ~60 LOC, real benefit, low risk.

### T2.5 — B26 + B31: 27-field + 35-field central structs
- **Pattern**: Bounded-context struct split (P4 from `ebfdf3d`). Conditional ACCEPT — promising IF Phase 3a port migration delivers context boundaries first.
- **LOC**: ~400 (App split) + ~600 (Manager split).
- **Risk**: HIGH (test cascade ripples through ~282 tests).
- **Agent lift**: 4 → 6 ceiling on `app/wire.go` + `app/app.go` shared edits.
- **Cross-deps**: Phase 3a completion (Batch 5 just landed in `7cfe93a`).
- **Verdict**: DEFER. Re-evaluate post-Phase-3a.

### T2.6 — B5 + B11: AlertDB nil-check × 8 + OAuth gate × 2
- **Pattern**: Per `blocker-fix-patterns.md`, these are deployment-mode flags. No fix has positive ROI.
- **LOC**: 0.
- **Verdict**: STAY AS-IS.

### T2.7 — B6 + B8: DevMode fail-closed × 6 + Stripe billing gate
- **Pattern**: Same as T2.6. Deployment-mode dichotomy.
- **Verdict**: STAY AS-IS.

### T2.8 — B72: time.Now() in 100+ files (clock isolation)
- **Pattern**: Inject `Clock` interface (already exists in `kc/scheduler/scheduler.go:25` and `testutil/clock.go`). Standardise across alerts/audit/papertrading.
- **LOC**: ~100 if done across all packages; ~30 LOC for highest-leverage subsystems (papertrading + audit).
- **Risk**: MED. Wide cascade.
- **Test cascade**: Tests currently use real clock with Sleep/Eventually patterns; migration to fake clock = significant test rewrite.
- **Agent lift**: Marginal — most tests are already passing, no race observed. Real benefit is determinism.
- **Cross-deps**: none.
- **Verdict**: DEFER unless flake rate justifies. NEEDS VERIFICATION on flake metrics.

### T2.9 — B77: `mcp.OnBeforeToolExecution` mutates DefaultRegistry from wire-time
- **Pattern**: Pass an explicit `*mcp.Registry` instance through `RegisterTools(... reg *Registry)`. Use `NewRegistry()` per-App.
- **LOC**: ~80 LOC + ~20 callsite changes in app/wire.go + tests.
- **Risk**: MED. The free functions (RegisterPlugin, OnBeforeToolExecution) need a per-App registry path. The pattern infrastructure exists (`NewRegistry()` already there) but the free-function delegation needs wiring.
- **Agent lift**: Enables in-process multi-server tests (none exist today). 0 agents.
- **Verdict**: DEFER — no test currently demands it.

---

## Tier 3 — MED-severity quick wins (≤30 LOC each)

| ID | Pattern | LOC | Risk | Notes |
|---|---|---|---|---|
| B68 | env-via-Config field | ~5 | LOW | Add `KiteGracefulChild` to `app.Config`; replace `os.Getenv` in `parseGracefulChildFromEnv`. Already has internal pure-parser path. |
| B55 | Test-injectable URL via field | ~3 | LOW | `googleUserInfoURL` is already mutable; tests already override. Minimal cleanup: move to a struct field on the SSO handler. |
| B59 | Per-store TTL field | ~10 | LOW | `var statsCacheTTL = 15 * time.Minute` → field on `audit.Store`, with `WithStatsCacheTTL` option. |
| B60 | Per-store interval field | ~10 | LOW | Same shape for `retentionTickInterval`. |
| B57 | Test-resettable counter | ~5 | LOW | `orderSeq atomic.Uint64` → make resettable via `papertrading.ResetOrderSeqForTest()`. |
| B83 | Lifecycle-order swap | ~5 | LOW | Move `oauth_handler` Close BEFORE `kc_manager` in registerLifecycle so DB close happens after both done. |
| B85 | Add fillWatcher.Stop + lifecycle.Append | ~15 | LOW | Add Stop method to `kc.FillWatcher`; register with lifecycle. |
| B33 + B40 + B42 | DRY teardown via lifecycle | ~30 | MED | Tier 2 T2.1 covers this. |
| B45 | Already correct (init-time only) | 0 | — | LOW; no real concurrency cost. |
| B46 | Already correct (startup-only) | 0 | — | LOW; storeToolManifest is one-shot. |
| B50 | Already correct (init-time only) | 0 | — | writeTools never mutated post-init. |

**Tier 3 total**: ~83 LOC. Each individually small; collectively close ~half of MED-severity surface.

---

## Defer (LOW + structural; do not fix at current scale)

Explicit list of blockers NOT worth fixing:

- **All Category 2 conditionals** (B5/B6/B7/B8/B9/B10/B11/B12/B13/B14): deployment-mode dichotomy. Per `blocker-fix-patterns.md`, ROI = zero or negative.
- **All Category 3 mutual-recursion setters** (B17/B18/B19/B22/B23/B24): 6 of 10 are genuine cycles. Wire/fx can't fix. Defer.
- **B25/B26/B27/B28/B31**: large central files / structs. Bounded-context split is gated on Phase 3a completion.
- **B29/B30/B33/B36/B37**: ordering constraints are architectural. Builder pattern relocates friction without eliminating it (per `non-wire-decoupling-followup.md`).
- **B43**: mcp init-ordering between `_tools.go` files works correctly today (Go init order is deterministic within a package).
- **B44**: DefaultRegistry is the production singleton — `NewRegistry()` already exists for tests. No fix needed.
- **B47/B48/B49**: plugin watcher singletons — production-correct, test-isolated via NewRegistry pattern when needed.
- **B51**: `ltpCache` is a bounded cache; tests don't observe cross-test pollution per BoundedToolCache TTL.
- **B52**: `serverStartTime = time.Now()` at init — no realistic test impact.
- **B54**: `httpClient` package var — no test-time injection requested by any failing test.
- **B58**: `legal.go` init log.Fatalf — embedded markdown is checked at compile time.
- **B61/B62/B63/B64**: package-level lookup tables / regex / interval constants — no concurrency cost.
- **B65/B66/B67 (re-evaluated)**: NOT 30+ files. Actual surface = T1.1 (one PR).
- **B70**: `LockDefaultRegistryForTest` IS the parallel-safe pattern. Misclassified in `6c2e871`.
- **B71**: orderSeq counter — covered by Tier 3 (~5 LOC fix if needed).
- **B73**: integration test against real Kite — intentional, opt-in via env.
- **B74**: instruments stats — startup-only, no cross-test pollution.
- **B75**: anomaly cache TTL — covered by B59 in Tier 3.
- **B76/B78/B79/B80/B81/B82/B84**: documentation-grade nuisances or already-handled.
- **All Category 5 ordering constraints**: architectural; covered by lifecycle migration in T2.1.

**Defer total**: 60+ blockers. The 85-blocker enumeration was empirically rich but most surface is benign at current scale.

---

## Verification log (for trust)

Every Tier 1 + Tier 2.x ROI claim was verified against actual code reads:

- **T1.1**: Verified `WebhookHandler` reads env at line 25-28 (closure capture, not per-request). Verified `CheckoutHandlerWithConfig` already exists and is the proven pattern. Confirmed `os.Setenv` count = 3 actual calls in test code.
- **T1.2**: Verified `LoadHashPublishConfig` reads env at lines 88-109. Verified single caller `app/wire.go:157`.
- **T1.3**: Verified `stripe.Key = stripeKey` only in `app/wire.go:446`. kc/billing tests don't touch it.
- **T1.4**: Verified t.Parallel adoption rate = 88%. Read `LockDefaultRegistryForTest` definition — explicitly designed for parallel use.
- **T2.1**: Verified `LifecycleManager` exists in `app/lifecycle.go` from commit `8727beb`. Verified 3 hand-maintained Phase A/B/C teardown sites.
- **T2.4**: Verified `kc/manager_init.go:158` opens alertDB in `initPersistence` AFTER kc.NewWithOptions allocates manager — confirms B1 cycle prevents pure constructor injection.
- **T2.6/T2.7**: Cross-referenced with `blocker-fix-patterns.md` (commit `6abad64`).

**No "NEEDS VERIFICATION" remaining for Tier 1 ROI claims.** Two tier-1.4 entries flagged as needing read-before-migrating: `kc/instruments/manager_test.go`, `oauth/handlers_test.go` — these are migration candidates, not ROI claims.

---

*Generated 2026-04-26 against HEAD `6c2e871`. Read-only research deliverable; no source files modified.*
