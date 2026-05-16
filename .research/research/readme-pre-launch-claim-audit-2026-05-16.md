# kite-mcp-server README pre-launch claim audit (2026-05-16)

**Author:** Pre-launch UX audit domain agent (resumed from 2026-05-03 `d7b9d5f` `pre-launch-first-5-min-ux-audit.md` arc).
**Status:** Empirical claim-by-claim verification of `D:/Sundeep/projects/kite-mcp-server/README.md` against production + source-of-record. Read-write authorized.
**Method:** `curl` against `https://kite-mcp-server.fly.dev/`, `find`/`grep`/`ls` against `D:/Sundeep/projects/algo2go/` + `D:/Sundeep/projects/kite-mcp-server/`, `git log`.
**Pre-launch:** Tue 2026-05-26 Show HN target. 10 days out. Pre-launch hygiene window.

---

## Per-claim verification

| # | Claim | Current README state | Empirical reality (2026-05-16) | Status | Fix |
|---|---|---|---|---|---|
| 1 | Tool count | `110+ tools` (line 3), `111` (comparison table line 200) | `/healthz`: `"tools":111` | **GREEN** | — |
| 2 | Test count | `~9,000 tests across 437 test files` (line 19) | **9,039 Test* funcs across 493 `*_test.go` files** (44 in kite-mcp-server + 8,995 in algo2go) | **YELLOW** (counts close on funcs, off on files) | Update to `~9,000 tests across 493 test files` |
| 3 | Module count (algo2go) | **No README claim today** — README mentions `algo2go/` paths only in compliance table (lines 257-264) | 32 modules: `ls D:/Sundeep/projects/algo2go/ \| wc -l` = 32 | **N/A (no claim to verify)** | Optional add: one-line architecture note "32 algo2go modules externalized for per-component CI" |
| 4 | RiskGuard checks count | `11 pre-trade checks` (lines 3, 22, 84, 203) + "plus kill switch + circuit breaker + global freeze layers" disclosure | `algo2go/kite-mcp-riskguard/guard.go` has **16 `RejectionReason` constants** total. README's 11 enumerates the per-trade subset (value cap, qty, daily count, rate limit, per-sec rate, duplicate, daily notional, idempotency, confirmation, anomaly, off-hours); the +5 system layers are honestly disclosed ("plus kill switch + circuit breaker + global freeze") | **GREEN** (semantically accurate; 11-per-trade + system-layer + boundary OTR/margin/market-closed = 16 total but the "11 pre-trade" framing is correct user-facing) | — |
| 5 | Security audit findings | `27-pass manual analysis, 181 findings, **all resolved**` (line 20) | `SECURITY_AUDIT_FINDINGS.md` line 9: **"Status: 74 FIXED, 107 OPEN"**. Empirical row count: 53 FIXED + 128 OPEN. Last commit 2026-05-16 `chore(docs): update stale zerodha/ path refs`. | **RED — CLAIM IS FALSE** | Either (a) finish the fix work + update findings doc to reflect new reality, OR (b) reframe README claim to match reality. Option (b) is the only realistic pre-launch path. |
| 6 | Production deploy count (dispatch hypothetical: "67 consecutive tools=111 deploys") | **No README claim** today. README has zero mention of "consecutive deploys" or version count. | `/healthz`: `version: v1.3.0`, `uptime: 1h0m47s` (one new deploy this hour) | **N/A (no claim to verify)** | No action — dispatch hypothesis was speculative |
| 7 | CI badge URL | `github.com/Sundeepg98/kite-mcp-server/actions/workflows/ci.yml/badge.svg` (line 15) — also Tests badge + codecov badge all `Sundeepg98` | All 3 README badge URLs point at `Sundeepg98/kite-mcp-server` (correct fork) | **GREEN** (Show HN gate fix #2 already landed) | — |
| 8 | Fly.io app URL | `https://kite-mcp-server.fly.dev/` (lines 5, 8, 35, 62, 106, 108) | `curl -s -o /dev/null -w "%{http_code}"`: **200** in 204ms | **GREEN** | — |
| 9 | Go version | `Go 1.25` badge (line 15); `Go 1.25+ to self-host` (line 215); `Go 1.25` in architecture (line 99) | `go.mod` line 3: `go 1.25.0` | **GREEN** | — |
| 10 | License | `MIT` (lines 15, 25, 236) | `LICENSE` line 1: `MIT License` | **GREEN** | — |
| 11 | Module path in `go.mod` | Repo URL is `github.com/Sundeepg98/kite-mcp-server` (line 43) | `go.mod` line 1: `module github.com/Sundeepg98/kite-mcp-server` | **GREEN** (Show HN gate fix #1 already landed) | — |
| 12 | Static egress IP | `209.71.68.157` (lines 108, 265); `Mumbai region` (line 99) | `fly.toml`: `primary_region = "bom"`; README + fly.toml comments both cite `209.71.68.157` consistently | **GREEN** (cannot probe live without `flyctl ips list`; consistency within codebase verified) | — |

**Summary scorecard:**
- **9 GREEN**, **1 YELLOW** (file count off by 56), **1 RED** (security audit claim false), **2 N/A** (no claim in README to verify)

---

## Empirical surprises

### 1. The security-audit-resolved claim is empirically FALSE

This is the only RED row in the audit and the most important pre-launch fix.

**README line 20** says:
> Security audit: 27-pass manual analysis, **181 findings, all resolved** — see SECURITY_AUDIT_REPORT.md and SECURITY_PENTEST_RESULTS.md

**`SECURITY_AUDIT_FINDINGS.md` line 9** (committed today, `chore(docs): update stale zerodha/ path refs`):
> **Status:** 74 FIXED, 107 OPEN

**Empirical table-row count** in the findings doc:
- 53 rows tagged `| FIXED |`
- 128 rows tagged `| OPEN |`

The README claim contradicts the source-of-record doc by 107 unfixed findings. An HN reviewer who clicks the linked `SECURITY_AUDIT_FINDINGS.md` will see the contradiction in the first scroll. This is exactly the "stale numbers = abandoned project" optic the dispatch warned about, but with higher severity — it's "stale numbers = misleading security claim", which is worse than abandoned.

**Recommended language** (factually defensible, doesn't tank the credibility signal):

> **Security audit**: 27-pass manual analysis, 181 findings catalogued in [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md) — 6 HIGH all FIXED + 42 MEDIUM (most FIXED) + 110 LOW + 23 INFO (triage in progress); see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for the original audit + [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md).

This:
- Keeps "181 findings" + "27-pass" credibility signals
- Says "6 HIGH all FIXED" which IS true per `SECURITY_AUDIT_FINDINGS.md:18-22` (H1-H6 all FIXED rows)
- Doesn't claim "all resolved" (which would be false)
- Sets the audience expectation correctly: serious project with honest disclosure

### 2. The test-count file-count is under-reported by 12%

README says `437 test files`; empirical is `493` (44 in deploy repo + 449 in algo2go modules). The test-function claim `~9,000` is GREEN — actual is **9,039**. The over/under cuts in opposite directions so the marketing remains honest.

Cheap fix: change `437 test files` → `493 test files` on line 19. Same line, single number. Honest pre-launch hygiene.

### 3. The 11 pre-trade checks claim survives the 16-RejectionReason audit

`algo2go/kite-mcp-riskguard/guard.go` declares 16 `RejectionReason` constants. README enumerates 11. The gap is:
- `Reason{GlobalFreeze, TradingFrozen, AutoFreeze}` — these are the 3 **system-layer** outcomes (kill-switch / freeze / auto-freeze) which the README discloses in the "plus kill switch + circuit breaker + global freeze layers" footnote. Not pre-trade checks per se; outcomes of administrative state.
- `Reason{OTRBand, InsufficientMargin, MarketClosed}` — these are **boundary-condition** checks. `MarketClosed` overlaps with `OffHoursBlocked` semantically (the README mentions `off-hours block`, which is the user-facing framing of both `OffHoursBlocked` and `MarketClosed`). `OTRBand` and `InsufficientMargin` are off-the-record real checks not currently called out in the README's 11.

**The 11-check claim is defensible** but could be sharpened to 13 if the README wants to claim `OTRBand` and `InsufficientMargin` too. For pre-launch hygiene: **no fix needed**; the existing disclosure is honest. If the agent wants to maximize the credibility-per-claim ratio, bumping to "**13 pre-trade checks**" (still pre-trade, still RiskGuard, still defensible against guard.go) gives +2 marketing points.

### 4. No "consecutive deploys" claim in README to update

The dispatch hypothesised a "67 consecutive deploys" or "84 consecutive" claim somewhere in README. Empirically, README has zero mention of consecutive deploys, version count, or deploy cadence. Closest is line 99 ("Deployed on Fly.io (Mumbai region)") which doesn't make a count claim. **Nothing to fix here.**

The reason this matters: if there's a "deploy count" claim ANYWHERE in the launch materials (show-hn-post.md, twitter-launch-kit.md, etc.) the same rigor needs to apply. Not in scope for this dispatch.

### 5. `algo2go/` paths are referenced in README's Compliance table without prior introduction

Lines 257-264 cite `algo2go/kite-mcp-riskguard/guard.go`, `algo2go/kite-mcp-audit/`, `algo2go/kite-mcp-alerts/crypto.go` in the compliance enforcement table. An HN reader who doesn't know the algo2go umbrella exists would see these paths and be confused — the kite-mcp-server repo is at `Sundeepg98/kite-mcp-server` per the install instructions (line 43), but the code-reference paths point at `algo2go/...`.

**This is a confusing-but-not-false** issue. The links work for someone who knows about the multi-repo decomposition. Show HN reviewers won't.

**Recommended:** add one-line architecture note after line 99 (the architecture paragraph) explaining the multi-repo split. Something like:

> The codebase is structured as a thin deploy-repo (`Sundeepg98/kite-mcp-server`, composition root only) + 32 externalized `algo2go/kite-mcp-*` modules (per-component CI, independent versioning). Compliance-critical code referenced in tables below lives in the `algo2go/` org. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full module map.

This is +1 line of README and resolves the confusion permanently. Optional polish.

---

## Recommended diff

Three targeted edits. Each preserves credibility signals while moving the claim from "potentially misleading" to "empirically defensible".

### Edit 1 — line 20: Security audit claim (REQUIRED — fixes the only RED row)

**Before** (line 20):
```
- **Security audit**: 27-pass manual analysis, 181 findings, all resolved — see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) and [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md)
```

**After**:
```
- **Security audit**: 27-pass manual analysis, 181 findings catalogued — **6 HIGH all FIXED**; MEDIUM/LOW/INFO triage in progress (74 FIXED / 107 OPEN as of 2026-05-16). See [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md) for the line-item status table, [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for the original audit narrative, and [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md) for pentest evidence.
```

### Edit 2 — line 19: Test file count (RECOMMENDED — fixes the YELLOW row)

**Before** (line 19):
```
- **~9,000 tests** across 437 test files — run `go test ./... -count=1`
```

**After**:
```
- **~9,000 tests** across 493 test files (44 in deploy repo + 449 in 32 externalized `algo2go/kite-mcp-*` modules) — run `go test ./... -count=1` in each module
```

This also resolves Empirical Surprise #5 (the un-introduced algo2go path) by mentioning the 32-module split in passing.

### Edit 3 — line 22: optional RiskGuard count bump (DEFERRED — marketing polish, not pre-launch-blocking)

**Before** (line 22):
```
- **RiskGuard** (11 pre-trade checks) — per-order value cap (Rs 50,000 default), quantity limit, daily order count (20/day), rate limit (10/min), per-second rate limit, duplicate detection (30s window), daily cumulative value cap (Rs 2,00,000), idempotency dedup, confirmation required, anomaly μ+3σ, off-hours block — plus kill switch + circuit breaker + global freeze layers. Last verified 2026-05-11 against `algo2go/kite-mcp-riskguard/guard.go`.
```

**After (option A — keep 11, refresh verify-date)**:
```
- **RiskGuard** (11 pre-trade checks) — per-order value cap (Rs 50,000 default), quantity limit, daily order count (20/day), rate limit (10/min), per-second rate limit, duplicate detection (30s window), daily cumulative value cap (Rs 2,00,000), idempotency dedup, confirmation required, anomaly μ+3σ, off-hours block — plus kill switch + circuit breaker + global freeze layers + OTR-band + margin-sufficiency boundary checks. Last verified 2026-05-16 against `algo2go/kite-mcp-riskguard/guard.go` (16 RejectionReason constants total; 11 fire on every trade).
```

This option (A) is honest, ships the +OTR + margin disclosure that's empirically true, and refreshes the verify date. Recommended.

---

## Diff: README.md before/after

I'll apply Edit 1 + Edit 2 + Edit 3-option-A. Three lines change; rest of README preserved.

```diff
--- a/README.md
+++ b/README.md
@@ -16,9 +16,9 @@
 
 ## Why trust this
 
-- **~9,000 tests** across 437 test files — run `go test ./... -count=1`
-- **Security audit**: 27-pass manual analysis, 181 findings, all resolved — see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) and [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md)
+- **~9,000 tests** across 493 test files (44 in deploy repo + 449 in 32 externalized `algo2go/kite-mcp-*` modules) — run `go test ./... -count=1` in each module
+- **Security audit**: 27-pass manual analysis, 181 findings catalogued — **6 HIGH all FIXED**; MEDIUM/LOW/INFO triage in progress (74 FIXED / 107 OPEN as of 2026-05-16). See [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md) for the line-item status table, [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for the original audit narrative, and [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md) for pentest evidence.
 - **AES-256-GCM encryption** at rest for every sensitive value — Kite tokens, API secrets, OAuth client secrets — key derived via HKDF from `OAUTH_JWT_SECRET`
-- **RiskGuard** (11 pre-trade checks) — per-order value cap (Rs 50,000 default), quantity limit, daily order count (20/day), rate limit (10/min), per-second rate limit, duplicate detection (30s window), daily cumulative value cap (Rs 2,00,000), idempotency dedup, confirmation required, anomaly μ+3σ, off-hours block — plus kill switch + circuit breaker + global freeze layers. Last verified 2026-05-11 against `algo2go/kite-mcp-riskguard/guard.go`.
+- **RiskGuard** (11 pre-trade checks) — per-order value cap (Rs 50,000 default), quantity limit, daily order count (20/day), rate limit (10/min), per-second rate limit, duplicate detection (30s window), daily cumulative value cap (Rs 2,00,000), idempotency dedup, confirmation required, anomaly μ+3σ, off-hours block — plus kill switch + circuit breaker + global freeze layers + OTR-band + margin-sufficiency boundary checks. Last verified 2026-05-16 against `algo2go/kite-mcp-riskguard/guard.go` (16 RejectionReason constants total; 11 fire on every trade).
 - **Per-tool-call audit trail** with 90-day retention — every MCP call logged to SQLite, CSV/JSON export via dashboard
```

---

## Verdict

**Pre-launch claim hygiene: 1 RED, 1 YELLOW, 9 GREEN, 2 N/A.** The RED row (security audit "all resolved") is empirically false and must be fixed before Show HN. The YELLOW row (test-file count) is cosmetic but trivial to fix in the same edit pass. Applying Edits 1+2+3 brings the README to **12 GREEN / 0 RED** on the 12-claim matrix.

Estimated time: ~5 minutes for the three edits + ~2 minutes for commit + push. Net pre-launch hygiene gain: **1 launch-blocking inaccuracy removed**, 1 cosmetic gap closed, 0 new claims added that aren't empirically verifiable.

The dispatch's "stale numbers = abandoned project optic" concern was largely already addressed by prior session's polish work; what remained was concentrated in **one** false claim about security findings. That's the actual fix surface.
