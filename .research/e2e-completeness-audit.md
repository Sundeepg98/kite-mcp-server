# E2E Completeness Audit — kite-mcp-server

**HEAD**: `1171bdf` (research(e2e): diagnose 2 remaining Playwright failures)
**Date**: 2026-05-02
**Scope**: All E2E layers (Playwright, Go integration, smoke, contract, conformance, OAuth, Telegram, paper, riskguard, MFA). Doc-only.

---

## TL;DR

**Empirical current E2E score: 78/100** (solo + pre-launch realistic ceiling ~85).

Codebase is quietly best-in-class for a solo Go MCP server: 8,743 test funcs across 417 files, 1.93 test:prod LOC ratio, race+mutation+DR-drill+benchmark CI gates, multi-OS matrix. The gaps are concentrated at the **wire-level** (Playwright suite is thin) and **canary/synthetic** (no scheduled in-prod probe).

**Top-3 critical-before-Submit additions** (each fits a 30-min slot):

1. **Fix the 2 broken Playwright specs** (`server-card`, `tool-surface`) per `playwright-2-remaining-diagnosis.md` (commit `1171bdf`). Currently red CI on master; Show-HN crowd will run the repo and notice. **30 min.**
2. **Add `tools/list` Go-side wire test against the running HTTP server** — the only HTTP integration test today is the broken Playwright one. Spawn `httptest.NewServer` wrapping `streamable.ServeHTTP`, do init→tools/list, assert hash. Catches mcp-go upgrade regressions. **45 min.**
3. **Wire the existing `scripts/smoke-test.sh` into a scheduled GitHub Action** (every 30 min on cron) that hits the deployed Fly.io URL. Today it runs only on manual operator command — no automatic canary. Email on red. **20 min.**

Everything else (k6 load tests, Telegram-bot E2E, paper-trade lifecycle E2E, dedicated MCP conformance, Codecov badge) is **post-launch nice-to-have**.

---

## Phase 1 — E2E Surface Inventory

| Layer | Location | Coverage state | "Good E2E" looks like |
|-------|----------|----------------|----------------------|
| **A. Playwright browser-level** | `tests/e2e/specs/*.spec.ts` (5 specs, 14 tests, 426 LOC) | **Thin + 2 broken.** Healthy: `healthz` (3 tests), `landing` (3), `oauth-redirect` (4). Broken: `server-card` (2), `tool-surface` (2 — see `1171bdf`). | 8-12 specs covering: critical user journeys (OAuth round-trip with sandbox app), widget rendering smoke, 1-2 dashboard SSO smokes. |
| **B. Go-side integration** | `app/integration_test.go` (390 LOC), `app/integration_kite_api_test.go` (build tag `integration`, 1 test), `mcp/admin_integration_test.go` (2 tests), `mcp/path2_integration_test.go` (3 tests), `kc/papertrading/engine_integration_test.go`, `kc/papertrading/riskguard_integration_test.go`, `kc/riskguard/guard_integration_test.go`, `mcp/e2e_roundtrip_test.go` (build tag `e2e`, stdio handshake). | **Strong.** Cross-package wiring proven: ENABLE_TRADING gating, admin tool chain, riskguard 8-check chain, paper engine roundtrip. | Add 1 HTTP-level integration test with `httptest.NewServer` doing the full streamable-HTTP handshake (currently absent — see Top-3 #2). |
| **C. Post-deploy smoke** | `scripts/smoke-test.sh` (313 LOC, 13 checks against Fly.io). | **Good content, no schedule.** Covers `/healthz`, OAuth metadata, landing IP, `/mcp` 401/405, `/oauth/authorize` 302→kite.zerodha.com, latency budget, tool-count floor, anomaly_cache. | Wire into cron-scheduled GH Action OR Fly.io scheduled Job → Telegram alert on red. (Top-3 #3.) |
| **D. API contract / JSON-RPC schema** | None as a versioned contract suite. `mcp/tool_surface_lock_test.go` (SHA256 over tool names) is the closest. ADR 0009 (`a6fbe38`) names JSON-RPC 2.0 as IPC contract but no per-tool input/output schema test. | **Partial.** Surface-set is locked; per-tool input/output JSON-schema is NOT pinned. A bad annotation drift on `place_order.inputSchema.properties.quantity` would not fail a test. | Add a "for each tool, marshal its inputSchema, hash it, compare to golden" lock — small (one Go test, ~80 LOC). |
| **E. Cross-broker** | `broker/zerodha/*_test.go` (multi-file, native_alert + retry + convert + factory + mock_sdk + client_mock). `broker/mock/client_test.go` is the test double. Single broker today. | **Adequate** for current state (Zerodha-only). No premature abstraction tests. | When second broker lands, parameterize the existing `broker.Client` interface tests across both. Not needed pre-launch. |
| **F. MCP protocol conformance** | None. We rely on `mark3labs/mcp-go` upstream conformance + our own `mcp/e2e_roundtrip_test.go` for stdio handshake. | **Acceptable risk.** No official MCP test harness exists yet (per `kite-launch-blockers-apr18.md`). Our `tool_surface_lock_test.go` + `e2e_roundtrip_test.go` are de-facto conformance. | When the spec ships an official conformance suite, wire it. Until then, the upstream library passes its own conformance — we inherit. |
| **G. OAuth flow E2E** | `oauth/*_test.go` (10 files, 200+ test funcs covering `Authorize`, `Token`, `Register`, MFA, JWT, Google SSO, callbacks). Plus Playwright `oauth-redirect.spec.ts` (4 wire-level tests). Plus smoke check 7-8. | **Strong.** Authorize 302 to Kite, token grant, refresh, JWT, PKCE, MFA enroll/verify, Google SSO admin path — all covered. Missing: full HTTP-roundtrip test (authorize → mocked-Kite-callback → token exchange → call /mcp tools/list with bearer). | One Go integration test using `httptest.NewServer` for both our server and a fake Kite IdP. ~120 LOC. Post-launch. |
| **H. Telegram bot E2E** | `kc/telegram/*_test.go` (10 files: `handler_trading_test.go` 13 tests, `commands_test.go` 76 tests, `handler_test.go`, `bot_edge_test.go`, `cleanup_test.go`, `disclaimer_test.go`, `handler_auth_test.go`, `handler_portfolio_test.go`, `plugin_commands_test.go`, `trading_fuzz_test.go`). 5,208 LOC test vs 1,640 LOC prod (3.18x). | **Strong unit, weak inline-keyboard.** Per-handler tests for `/buy`, `/sell`, `/quick`, `/setalert` confirmed via `executeConfirmedOrder` symbol presence. Inline-keyboard CONFIRM-button click flow appears tested via `handleSetAlert_*` style harnesses. Real bot-API roundtrip not tested (would need fake telegram-bot-api server). | Acceptable. Real-API E2E not needed for trading-bot logic. |
| **I. Paper trading E2E** | `kc/papertrading/engine_integration_test.go`, `kc/papertrading/riskguard_integration_test.go`, `kc/papertrading/engine_test.go`, plus 9 edge files. 6,892 LOC test vs 1,822 LOC prod (3.78x). | **Strong.** Engine + riskguard integration tests exist. Mock broker drives LTP. SQLite-backed store. Order-id gen, leak sentinel, FK constraints, MTM monitor — all covered. | None pre-launch. |
| **J. Riskguard E2E** | `kc/riskguard/guard_integration_test.go` (8-check full chain), 21 unit/edge files. 5,670 LOC test vs 3,265 LOC prod (1.74x). | **Strong.** Full chain integration tested. Property tests (rapid) for dedup. SBOM check, plugin discovery, OTR band, market hours, anomaly μ+3σ — all covered. | None pre-launch. |
| **K. MFA admin flow** | `kc/users/mfa_test.go` + `oauth/handlers_admin_mfa_test.go` (14 test funcs in latter). | **Strong.** Real `users.Store` + encryption key wired through HTTP test. TOTP enrollment + verify covered end-to-end. | None. |

**Build-tag-gated** (excluded from default `go test ./...`):
- `//go:build integration` → `app/integration_kite_api_test.go` (1 file, real Kite API instruments fetch)
- `//go:build e2e` → `mcp/e2e_roundtrip_test.go` (1 file, stdio binary roundtrip)

These run in CI via dedicated jobs (or are intended to). `playwright.yml` wires Playwright; `e2e_roundtrip_test.go` does not currently appear in `ci.yml`'s test commands — runs only when an operator passes `-tags=e2e`.

---

## Phase 2 — Untested User Journey Audit

| # | Journey | Coverage | Gap detail |
|---|---------|----------|-----------|
| 1 | Clone → docker compose up → OAuth → first tool call → success | **Partial.** Smoke covers `/healthz` + OAuth metadata; no journey assertion that "first tool call returns data". | No test boots the binary, performs full mcp-remote-style OAuth, then issues `get_holdings`. |
| 2 | Existing user OAuth re-auth → tool call | **Partial.** `oauth/middleware_test.go` covers expired-token → 401 path. No HTTP-roundtrip test through bearer→tools/list. |
| 3 | place_order → riskguard pass → success → audit emit → telegram notify | **Strong but split.** Each link tested separately (riskguard chain in `guard_integration_test.go`, audit emit in `audit/store_test.go`, telegram in `telegram/handler_trading_test.go`). No single test wires all four. | A "one happy-path execution chain" test would close this. |
| 4 | place_order → riskguard rejects → friendly error | **Strong.** `riskguard/guard_integration_test.go` covers all 8 reject paths. |
| 5 | Admin: MFA enroll → verify → access /admin/ops | **Strong.** `oauth/handlers_admin_mfa_test.go` covers enroll + verify; `kc/ops/ops_admin_test.go` covers admin gate. Not chained in one test. |
| 6 | Alert created → price condition → telegram fires | **Strong.** `kc/alerts/evaluator_test.go`, `kc/alerts/telegram_test.go`, `kc/alerts/briefing_test.go`. Worktree variants exist too. |
| 7 | Backtest SMA crossover on INFY → returns Sharpe | **Unknown** — the audit didn't surface a `mcp/backtest_tool_test.go` in the file list returned. Worth confirming before launch. |
| 8 | Paper buy → fill → close → P&L | **Strong.** `kc/papertrading/engine_integration_test.go` + `engine_edge_*_test.go`. |
| 9 | Server crashes mid-tool-call → restart → session recovers | **Partial.** `app/server_lifecycle_test.go` and `app/shutdown_test.go` (worktree shows `kc/eventsourcing/projection_test.go`) cover persistence. No "kill -9 mid-flight, restart, see session restored" test. |
| 10 | Litestream restore from R2 → data integrity | **Strong.** `scripts/dr-drill.sh` runs monthly via `dr-drill.yml` cron, restores from R2, asserts row count. Real backup chain validated. |

**Critical untested**: Journey #1 (cold-start onboarding, first-data fetch). All others have at least adequate component-level coverage.

---

## Phase 3 — Layer-Specific Coverage (LOC)

| Layer / Package | Prod LOC | Test LOC | Ratio | Comment |
|---|---|---|---|---|
| Repo total (Go) | 84,096 | 162,483 | **1.93** | Healthy |
| `app/` | 8,842 | 18,271 | **2.07** | Healthy |
| `mcp/` | 20,915 | 32,983 | **1.58** | Adequate |
| `oauth/` | 2,466 | 10,748 | **4.36** | Mature |
| `kc/audit/` | 3,644 | 5,519 | 1.51 | Adequate |
| `kc/riskguard/` | 3,265 | 5,670 | 1.74 | Healthy |
| `kc/papertrading/` | 1,822 | 6,892 | **3.78** | Mature |
| `kc/telegram/` | 1,640 | 5,208 | **3.18** | Mature |
| `kc/users/` | 1,102 | 2,298 | 2.09 | Healthy |
| `kc/alerts/` | 3,445 | 9,271 | 2.69 | Mature |
| `broker/zerodha/` | 1,423 | 4,128 | **2.90** | Mature |
| Playwright `tests/e2e/specs/` | n/a | 426 | n/a | **Thin** — 5 specs, 2 broken |
| `scripts/smoke-test.sh` | n/a | 313 | n/a | Adequate content, no schedule |

**Counts**: 8,743 unique Go test funcs, 18 fuzz funcs, 6 benchmark funcs, 14 Playwright tests.

**Lowest ratio**: `mcp/` at 1.58. `mcp/` has 80+ tools so more handlers per test is expected. Still healthy.

---

## Phase 4 — Hosted-Deploy Canary Analysis

`scripts/smoke-test.sh` (313 LOC) covers post-deploy verification. Its 13 checks are well-scoped: `/healthz`, OAuth metadata (RFC 8414 + RFC 8707 fields), landing-page IP whitelist, `/mcp` 401/405 (NOT 500), `/oauth/authorize` validation, `/oauth/authorize` 302→kite.zerodha.com, warm-latency budget (5 samples, max <500ms), Path 2 compliance copy, new-tools advert, tool-count floor, anomaly_cache component.

**Gaps for a launch-grade canary:**

| Want | Have | Gap |
|------|------|-----|
| Continuous synthetic monitoring (every 5-30 min) | Manual operator only | Wire smoke-test into `cron: '*/30 * * * *'` GH Action OR Fly.io scheduled job. **Top-3 #3.** |
| Per-tool-call canary (init → tools/list every 5 min) | `/mcp` 401/405 only | Won't matter pre-launch — tools/list is locked at unit level. Post-launch nice-to-have. |
| OAuth complete-login canary (synthetic full round-trip) | Authorize 302 only | High setup cost (need stable test creds + bypass MFA on test acct). Defer. |
| Litestream backup-freshness check | DR-drill monthly cron, not freshness | Add a `scripts/litestream-freshness.sh` that checks last R2 generation timestamp <24h. Easy 30-min add. Post-launch. |
| Cert expiry (Let's Encrypt / Fly TLS) | None | Fly.io auto-renews; not our concern unless we go custom domain. |

---

## Phase 5 — Test Infrastructure Quality

| Dimension | State |
|-----------|-------|
| **Flakiness** | Recently fixed (`a5a3d9a`). 2 currently broken Playwright specs are stale-test, not flaky. No race conditions reported in `test-race.yml`. |
| **`go test -race`** | Runs in dedicated `test-race.yml` workflow on every push/PR. Scope: `kc/audit/...`, `kc/riskguard/...`, `oauth/...`, `app/...`. `mcp/...` is best-effort (continue-on-error). |
| **Coverage measurement** | `go test -coverprofile=coverage.out -covermode=atomic` in `ci.yml` (line 34). Uploaded as artifact. **NO Codecov/Coveralls integration** — coverage trend is invisible to PR reviewers. |
| **Test-time budget** | `ci.yml` runs `-timeout 8m`; `test-race.yml` per-package 120s. Build-tag gates (`integration`, `e2e`) keep default suite fast. No sharding (single `go test ./...` invocation). |
| **CI matrix** | `ci.yml` matrix: `[ubuntu-latest, macos-latest, windows-latest]` × Go 1.25.x. Best-in-class for a solo project. |
| **Build-tag tests in CI?** | `e2e_roundtrip_test.go` (build tag `e2e`) is NOT in any workflow's `go test` invocation that I could find — it requires `-tags=e2e` and only `playwright.yml` boots the binary. Stdio E2E roundtrip therefore runs only under operator opt-in. |
| **Fuzz tests** | 18 fuzz funcs (`mcp/common_fuzz_test.go`, `mcp/ext_apps_fuzz_test.go`, `kc/telegram/trading_fuzz_test.go`, `kc/riskguard/dedup_property_test.go`, etc.). Run via `go test -fuzz=` ad-hoc — no scheduled fuzz workflow. |
| **Benchmarks** | 6 funcs gated through `kc/instruments`. `benchmark.yml` PR-gates regressions >10% (sec/op or allocs/op). Best-in-class. |
| **Mutation testing** | `mutation.yml` weekly cron on `kc/riskguard`, `kc/audit`, `oauth` via `gremlins`. Best-in-class. |
| **DR-drill** | Monthly cron via `dr-drill.yml`. Restores from R2, queries kite_tokens, alerts via Telegram. Best-in-class. |
| **Vuln/security scan** | `security.yml` runs `gosec` + `govulncheck` per push/PR. Plus `sbom.yml`, `security-scan.yml`, `v4-watchdog.yml`. Comprehensive. |

**Verdict**: test infrastructure is **already best-in-class** for a solo Go project. The gaps are at the wire level, not the unit/integration level.

---

## Phase 6 — Comparison to Best-in-Class

| Reference | Pattern | Our state | Adopt? |
|-----------|---------|-----------|--------|
| **HashiCorp Boundary** | `internal/tests/api/` — full-stack HTTP→DB tests via `httptest.NewServer` and dockertest for postgres. Subtests for each verb. | We use `httptest.NewServer` in `app/integration_test.go`. SQLite in-memory replaces the dockertest dance. Equivalent posture for a smaller project. | Already aligned. |
| **kubernetes/kubernetes** | `test/e2e/` runs against a real cluster; conformance tests are tagged `[Conformance]` for the CNCF certification program. | We have neither a conformance program (none exists for MCP yet) nor an in-cluster test harness. | Wait for MCP spec to ship a conformance suite. Today: not applicable. |
| **Stripe Go SDK** | VCR-style replay tests — record real Stripe API responses once, replay deterministically in CI. `stripe/stripe-go/v82/cassettes/`. | We use `httptest.NewServer` with hand-rolled stubs (`broker/zerodha/client_test.go`). Cassettes would catch shape drift but require a sandbox account. | **Defer to post-launch.** Setup cost (sandbox creds, cassette refresh process) > marginal value while we ship Path 2 read-only. |
| **mcp-go upstream (mark3labs)** | `server/streamable_http_test.go` covers session-id management, init handshake, malformed JSON. `client/transport/streamable_http_test.go` covers the client side. | We inherit upstream coverage by virtue of using v0.46.0. Our wrapper (`createStreamableHTTPServer`) has tests via `app/server_lifecycle_test.go`. | Already aligned. |

**Patterns to adopt** (in priority order):
1. **Codecov badge** + delta-comment-on-PR. We have `coverage.out` already; wiring Codecov is 5 min and visibly demonstrates rigor on the README. **Pre-launch nice-to-have.**
2. **One HTTP-roundtrip integration test for `/mcp`** (Top-3 #2). Equivalent to Boundary's `internal/tests/api/`. **Pre-launch.**
3. **Cassette-replay against Kite sandbox** post-launch (Stripe pattern). Defer.

---

## Phase 7 — E2E-100 Verdict + Ceiling

| Dimension | Score | Notes |
|-----------|-------|-------|
| Unit-test depth | 95/100 | 8,743 funcs, 1.93 ratio, mature packages 3-4x |
| Integration-test breadth | 80/100 | 7 integration test files; missing HTTP-roundtrip variant for /mcp |
| Wire-level (Playwright) | 50/100 | 5 specs, 2 broken, 14 tests total; `oauth-redirect`+`landing`+`healthz` are solid |
| Smoke / canary | 70/100 | Excellent script content, no schedule |
| Race / mutation | 95/100 | Both wired in CI |
| DR / backup | 95/100 | Monthly drill on real R2 |
| Coverage visibility | 60/100 | Profile generated but not surfaced to PRs |
| Multi-OS matrix | 100/100 | ubuntu/macos/windows |
| MCP protocol conformance | 70/100 | No official suite exists; our surface-lock + roundtrip stand in |
| Cross-broker | n/a | Single broker today |

**Weighted current**: ~78/100.

**Realistic solo + pre-launch ceiling**: ~85/100. Reaching 90+ requires:
- Dedicated load testing (k6/wrk + a synthetic-traffic dataset) — 8-16 hours setup
- Real Kite-sandbox cassette suite — needs sandbox dev app + maintenance
- Continuous OAuth-roundtrip canary — needs stable test creds

None of those are appropriate for a solo pre-launch posture. Ceiling at ~85.

**Gap to ceiling (78 → 85)** = 7 points = the 3 critical-before-Submit fixes below.

---

## Phase 8 — Top-10 ROI-Ranked Fixes (30-min slots)

Order = (gap-reduction × pre-launch-value) / dev-minutes.

| # | Fix | Slot | Gap closed | Pre/post |
|---|-----|------|-----------|----------|
| 1 | Fix Failure 1 in `server-card.spec.ts` — relax assertion to also accept `body.serverInfo?.name` | 5 min | Wire-level red CI cleared | **PRE** |
| 2 | Fix Failure 2 in `tool-surface.spec.ts` — full init→notifications/initialized→tools/list handshake | 30 min | Wire-level red CI cleared | **PRE** |
| 3 | Add scheduled GH Action that runs `scripts/smoke-test.sh` against fly.dev every 30 min, alerts on red | 20 min | Continuous canary | **PRE** |
| 4 | Add Go HTTP-roundtrip integration test using `httptest.NewServer` wrapping our streamable + init→tools/list, hash-verify | 45 min | Closes the only "no HTTP test for /mcp" gap | **PRE (light)** |
| 5 | Wire Codecov upload + README badge | 10 min | PR-visible coverage delta | **PRE (cosmetic)** |
| 6 | Add per-tool inputSchema hash lock (one Go test, ~80 LOC, hash all `inputSchema` JSON over sorted-key marshaling) | 30 min | Tool-shape regression catch | **POST** |
| 7 | Wire `e2e_roundtrip_test.go` (`-tags=e2e`) into `playwright.yml` (or a new workflow) so stdio handshake runs in CI, not just on operator opt-in | 15 min | Stdio path tested in CI | **POST** |
| 8 | Add `scripts/litestream-freshness.sh` (assert last R2 generation < 24h) + smoke-test.sh check | 25 min | Backup-staleness alarm | **POST** |
| 9 | Add full-chain happy-path test: place_order → riskguard → audit → telegram (single test wiring all four) | 45 min | Closes Journey #3 | **POST** |
| 10 | Add cassette-replay tests against kite.trade API using a recorded sandbox session | 4-8 hours | Real-API drift catch | **POST** |

---

## Phase 9 — Pre-Show-HN E2E Subset

**Critical-before-Submit** (Top-5 — total ~110 min, fits two batches):

1. Fix server-card.spec.ts (5 min)
2. Fix tool-surface.spec.ts (30 min)
3. Schedule smoke-test cron (20 min)
4. Add Go HTTP-roundtrip integration test (45 min)
5. Codecov badge (10 min)

These eliminate the visible CI red and add one canary that prevents another consent_log-style production silent break.

**Post-launch nice-to-have** (Top 6-10): per-tool inputSchema lock, e2e tag in CI, litestream-freshness, full execution-chain test, Kite-cassette suite. None block Show HN.

---

## Diminishing-returns flag

This is the 18th research dispatch in the session. The audit found:
- Test infra is genuinely strong (8,743 funcs, race+mutation+DR-drill+benchmark all wired)
- The handful of pre-launch gaps are all 30-min slot fixes
- No structural rewrites needed

**New findings that don't overlap with UX/UI/Repo-polish work in flight**:
- `e2e_roundtrip_test.go` (build tag `e2e`) is not invoked by ANY workflow's `go test` line — confirmed by checking all 12 yml files. Operator-opt-in only.
- `coverage.out` is uploaded as artifact but never surfaces to a badge or PR comment — single "wire Codecov" step would close that gap.
- No load-testing tool (k6/wrk/vegeta/locust) referenced anywhere in `go.sum`, `go.mod`, or `scripts/`.
- The `scripts/smoke-test.sh` is excellent content but has zero scheduled triggers — pure manual operator command today.

These four are the actionable deltas this audit surfaces beyond what other in-flight agents have covered.
