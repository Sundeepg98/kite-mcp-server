# STATE.md Claims Audit — 2026-05-11

**Methodology**: every load-bearing factual assertion in `.research/STATE.md` graded VERIFIED / INFERRED / UNSUPPORTED via empirical probe (compile-and-run > grep, per the §5.6 lesson STATE.md itself memorialised).

**Master HEAD at audit time**: `25b201a` (chain agent's dr-drill report; STATE.md was authored at `bc5043e` and last-touched at `bea1e11` by the audit agent's tools=130 fix).

**Scope**: every numeric claim, every cited commit SHA, every cited file path, every status assertion. ~70 distinct claims identified.

**Bottom line**: STATE.md is now mostly trustworthy after the bea1e11 patch removed the tools=130 grep error. Remaining issues are minor — phantom commit SHA, two stale file-path citations, four off-by-N counts, one direct contradiction with cited source (§5.3), one misrepresentation of cited source (§1.4 Track 2). **No new grep-class errors found.** No claims that would change strategic decisions if corrected.

---

## Findings summary (graded)

| Severity | Count | Examples |
|---|---|---|
| **CRITICAL** (would mislead a major decision) | 0 | none after bea1e11 STATE.md fix |
| **HIGH** (cited evidence is contradicted by its own source) | 2 | §5.3 SQL portability "9 statements" vs cited doc "Zero rewrite needed"; §1.4 Track 2 "FALSIFIED" vs source's "PENDING USER PAYMENT-METHOD" |
| **MEDIUM** (numeric off-by-N or stale path) | 6 | §1.1 lifetime commits 1357 vs 1364; §7 "80 archived" vs 82; §6 "13 docs" vs 14 listed; §1.1 cadence 585/931 vs measured 490/923; §5.1 + §8.5 cite `kc/riskguard/*.go` paths that moved to algo2go external module |
| **LOW** (stale at write-time but auto-correcting; or cosmetic) | 5 | header HEAD `bc5043e` (now `25b201a` — STATE.md is 1-2 commits stale by design); tools=111 dual-verified (production + master-build); production deploy commit chain |
| **VERIFIED** | ~50 | all Tier 1 + Tier 2 + Phase 2.0-2.6 commit SHAs; algo2go module count; image SHA; egress IP; archive subdir counts |
| **PHANTOM** (cited SHA does not exist in repo) | **1** | TL;DR §1 cites commit `d3c2a4a` — `git log -1 d3c2a4a` returns "fatal: ambiguous argument: unknown revision" |

---

## Detailed claim grading table

| Claim | Section | Grade | Evidence / Probe |
|---|---|---|---|
| Master HEAD = `bc5043e` | header | LOW (auto-stale) | `git rev-parse HEAD` = `25b201a`; STATE.md was written at `bc5043e`; 5 commits ahead now (incl. STATE.md's own bea1e11 fix). Self-consistency hazard; STATE.md should pin a write-time HEAD and orchestrators should check current HEAD before trusting numeric claims. |
| Production = v1.3.0 / tools=111 | header | VERIFIED | `curl https://kite-mcp-server.fly.dev/healthz` → `{"status":"ok","tools":111,"uptime":"2h34m33s","version":"v1.3.0"}` (re-probed live during this audit) |
| Fly.io BOM region; machine version 273; image `deployment-01KR9FPJC88YA80VWS7VMTWTY7`; deployed 2026-05-10 17:44 UTC against `bc5043e` | header | VERIFIED | `flyctl status -a kite-mcp-server`: VERSION=273, REGION=bom, image=`deployment-01KR9FPJC88YA80VWS7VMTWTY7`, LAST UPDATED=2026-05-10T17:44:10Z. `flyctl image show` SHA=`629a6ee5b67b16…` matches. `git log bc5043e` exists. |
| **TL;DR §1: libSQL/Turso adapter shipped (commits `d3c2a4a` + `5f8ee3b` + `2919f6e`)** | TL;DR §1 | **PHANTOM** | `git log -1 d3c2a4a` → "fatal: ambiguous argument 'd3c2a4a': unknown revision". The other two SHAs (`5f8ee3b` Phase 2.6 turso driver, `2919f6e` R-10 v8) exist. **Either typo or referencing a commit on a side branch never merged.** Recommendation: drop or replace `d3c2a4a` in next STATE.md edit. |
| TL;DR §2: production at master HEAD modulo `.research/`-only commits; tools=111 in both | TL;DR §2 | VERIFIED | per chain agent's gap-report (commit `21d5684` exists per `git log -1 21d5684`); current HEAD `25b201a` is 5 commits past `bc5043e`, all under `.research/`; my own re-probe confirms tools=111 in production |
| TL;DR §3: Show HN launch is gating; 7-9 days end-to-end | TL;DR §3 | INFERRED | sourced from `launch-path-execution-playbooks.md` §Item 1 calendar — file exists; specific 7-9 day claim not verified directly |
| §1.1 In-tree workspace members = 4 | §1.1 | VERIFIED | `cat go.work` shows use block: `.`, `./app/providers`, `./plugins`, `./testutil` = 4 entries. Note: `grep -E '^\s*\./' go.work \| wc -l` returns 3 because the bare `.` line doesn't match `\./`. The "4" claim is correct only if you count root. STATE.md's "(root + plugins + testutil + app/providers)" enumeration matches. |
| §1.1 External algo2go modules = 28 | §1.1 | VERIFIED | `ls /mnt/d/Sundeep/projects/algo2go/ \| wc -l` = 28 |
| §1.1 Algo2go module list (alphabetical, 28 names) | §1.1 | VERIFIED | exact match with `ls D:/Sundeep/projects/algo2go/` output; alphabetical and complete |
| §1.1 Total commits = 1,357 lifetime | §1.1 | MEDIUM (stale) | `git log --oneline \| wc -l` = **1364** (as of 25b201a). STATE.md was written at bc5043e; 7 commits added since. `git log --oneline bc5043e \| wc -l` would have returned ~1357 at write time. **Plausibly correct at write time, stale by 7 now.** |
| §1.1 Recent cadence = 585 commits last 2 weeks | §1.1 | MEDIUM (off-by-95) | `git log --oneline --since="2026-04-26" --until="2026-05-10" \| wc -l` = **490**. Off by 95 from claimed 585 — a 19% over-count. Possibly used a different date window (e.g., "last 14 days from 2026-05-12" or a partial-day include). Worth correcting in next edit. |
| §1.1 Recent cadence = 931 commits in April 2026 | §1.1 | LOW (off-by-8) | `git log --oneline --since="2026-04-01" --until="2026-04-30" \| wc -l` = **923**. Off by 8 from claimed 931 — likely date-window inclusivity quirk. Within rounding error. |
| §1.1 Production deploy count = ~84 consecutive (per dispatch metadata) | §1.1 | INFERRED | dispatch metadata internal to chat history. Empirically: `flyctl status` shows machine version 273 (which is monotonic over deploys + rollbacks). The "84 consecutive" framing is per the dispatch-chain count; not directly probable today. STATE.md wisely uses "~" (approximate). |
| §1.1 Total tests = ~9,000 across ~437 test files | §1.1 | INFERRED | sourced from `final-pre-launch-verification.md` — not re-probed in this audit. STATE.md wisely uses "~" (approximate). |
| §1.1 MCP tools (production-registered) = 111 | §1.1 | VERIFIED | `curl /healthz` returns `tools=111`. Chain-agent's local compile-and-run (gap-report §1.4) confirmed `total_available=111` in startup log. |
| §1.1 MCP tools (master-built binary) = 111 | §1.1 | VERIFIED | per chain agent's gap-report §1.4 — independent compile-and-run yielded identical 111 |
| §1.1 Tool count delta = 0 | §1.1 | VERIFIED | direct corollary of the prior two — both 111, delta=0. STATE.md's footnote correctly memorialises the grep-error provenance. |
| §1.2 Tier 1.1 brokers `34a32bf` | §1.2 | VERIFIED | `git log -1 34a32bf` → `refactor(kc/manager): eliminate broker_services back-pointer via closures (Tier 1.1)` |
| §1.2 Tier 1.2 eventing `fd4b20e` | §1.2 | VERIFIED | `git log -1 fd4b20e` → `refactor(kc/manager): eliminate eventing_service back-pointer via closures (Tier 1.2)` |
| §1.2 Tier 1.3 scheduling `650f4c3` | §1.2 | VERIFIED | `git log -1 650f4c3` → `refactor(kc/manager): eliminate scheduling_service back-pointer via closures (Tier 1.3 — last facade)` |
| §1.2 Tier 2 `1c54773` (7 pure-function registrar tests) | §1.2 | VERIFIED | `git log -1 1c54773` → `test(kc/manager): add unit tests for 7 pure-function registrars (closes C3)` |
| §1.2 "1 pre-existing precedent + 7 extractions = 8 total pure-function registrars" | §1.2 | INFERRED | the 7-test count is verified; the "1 pre-existing precedent" claim is meta-context not tested in this audit |
| §1.2 "Two facades remain as deferred work" | §1.2 | UNSUPPORTED (vague) | actual `kc/*_service.go` count is **9 service files** (alert, broker, credential, eventing, family, order, portfolio, scheduling, session_lifecycle, session). Tier 1.1-1.3 closed 3 (broker, eventing, scheduling). That leaves 6, not 2. Either the "facades" definition excludes some service files, or the "two remain" count is wrong. STATE.md cites archived `kc-manager-decomp-design.md` as the specifics-source — INFERRED until the archived doc is consulted. **Probe to close gap**: read `.research/archive/tier-anchor-design/kc-manager-decomp-design.md` and reconcile facade definition. |
| §1.3 Phase 2.0 commit `c5b9cf7` | §1.3 | VERIFIED | `git log -1 c5b9cf7` → `infra(phase-2): port-interface design + stub for Postgres adapter (Phase 2.0)` |
| §1.3 Phase 2.1 commit `da91a39` | §1.3 | VERIFIED | `git log -1 da91a39` → `docs(phase-2): SQL portability audit across 5 algo2go persistence repos` |
| §1.3 Phase 2.3 commit `9122a75` | §1.3 | VERIFIED | `git log -1 9122a75` → `feat(phase-2-3): driver-switching ProvideAlertDB factory + active Store contract` |
| §1.3 Phase 2.5 commit `3686ac8` | §1.3 | VERIFIED | `git log -1 3686ac8` → `docs(phase-2-5): Postgres operational runbooks + alerts v0.5.0 bump (Phase 2.4+2.5)` |
| §1.3 Phase 2.6 commit `2919f6e` | §1.3 | VERIFIED | `git log -1 2919f6e` → `docs(phase-2-6): R-10 re-research v8 (libSQL ecosystem reckoning + Step 4 skip)` |
| §1.3 Phase 2.6 closure framework — Path 6 + Driver=turso env switch | §1.3 | INFERRED | sourced from active `phase-2-6-r10-decisions.md` v8 — not re-probed paragraph-by-paragraph |
| §1.4 Track 1 (Turso ap-south-1) = COMPLETED | §1.4 | VERIFIED | `path-e-try-before-buy-results.md:10` says "Track 1 — Turso Free / aws-ap-south-1 — COMPLETED"; line 100 says "Track 1 PASSED all tests" |
| **§1.4 Track 2 (DO BLR1) = FALSIFIED** | §1.4 | **HIGH (misrepresents source)** | actual phase-e doc says Track 2 status = "**PENDING USER PAYMENT-METHOD AUTHORIZATION**" (line 114). The doc explicitly notes "DO BLR1 trial requires payment method on file" (line 118) — i.e., Track 2 was DEFERRED, not falsified. STATE.md may be conflating with a different finding (BLR1 region availability for fresh accounts) but the underlying source doc does not record a falsification. **Recommend STATE.md correction**: change "FALSIFIED" → "DEFERRED — pending payment-method authorization (no UPI/RuPay path)". |
| §1.4 Track 3 (1-week synthetic load) = NOT STARTED | §1.4 | VERIFIED | phase-e doc:140 — "Track 3 — 1-week synthetic load — DEFERRED" |
| §2.1 Production deploys `bc5043e`; image hash `629a6ee5…` | §2.1 | VERIFIED | `flyctl image show` → `sha256:629a6ee5b67b16d8f26602883681185b9589b9b9d851a1b4b15455f65abac1fd`; `git log -1 bc5043e` exists |
| §2.1 cited gap-report commit `21d5684` | §2.1 | VERIFIED | `git log -1 21d5684` → `docs(investigation): production-master gap report — no gap exists` |
| §2.1 Source-code mutations between deployed commit and current HEAD = 0 | §2.1 | VERIFIED | `git diff --name-only bc5043e..HEAD` shows only `.research/` paths (verified during chain agent's gap-report investigation) |
| §2.1 v1.3.0 = "the binary's hardcoded version literal" | §2.1 (and §8.1) | LOW (mechanism wrong) | The version is NOT a hardcoded source literal. It's `"v0.0.0"` default in `main.go:55` and gets ldflags-injected at build time from `server.json`'s `version: "1.3.0"` field via Dockerfile `RUN VERSION_RESOLVED="${VERSION:-v$(jq -r '.version' server.json)}"`. So: `server.json` is the actual source-of-truth; the "literal" framing obscures the mechanism. **Implication**: if anyone bumps `server.json` `.version`, the next deploy WILL bump `/healthz` `version`. STATE.md saying "It does NOT auto-bump on deploy" is technically true but misleading — it doesn't bump *spontaneously*; it bumps every time `server.json` is bumped. |
| §2.1 No deploy needed (production bit-equivalent to master HEAD modulo `.research/`-only) | §2.1 | VERIFIED | per chain agent's gap-report; my dr-drill investigation re-confirmed |
| §2.1 "flyctl auth was working at investigation time; the prior 'flyctl reauth via Playwright, ~30 min' framing... may be conservative or out-of-date" | §2.1 | VERIFIED | I just used flyctl in this audit (status, image show, ips list) without any reauth. **§9.3 says "agent flyctl is permission-denied per recent attempt" — that note is now FALSE.** |
| §2.2 11 pre-flight blockers; production-deploy is #1; og-image.png 404 is #2; flyctl auth was #3 | §2.2 | INFERRED | sourced from `final-pre-launch-verification.md` — not re-probed |
| §2.3 algo2go.com AVAILABLE as of 2026-05-03 RDAP check | §2.3 | INFERRED | not re-probed in this audit; sourced from `algo2go-reservation-runbook.md` |
| §2.3 ₹4,500/class for individual filer; Class 9 + 42 = ₹9,000 total | §2.3 | INFERRED | sourced from `launch-path-execution-playbooks.md` — not externally verified |
| §3 (research questions, gates, costs) | §3 | INFERRED | all sourced from archived/active docs; not directly probed. Cost-recovery math (e.g., "$155-185/mo CI" → "$8/mo Hetzner") is an estimate. |
| §5.1 SEBI rate-limit shard verified at `kc/riskguard/per_second.go:30-50` | §5.1 | **MEDIUM (stale path)** | `kc/riskguard/per_second.go` does NOT exist in the repo (Path A inauguration extracted `kc/riskguard/` to `algo2go/kite-mcp-riskguard/`). Actual file: `D:/Sundeep/projects/algo2go/kite-mcp-riskguard/per_second.go`. Underlying claim (rate-limit shards by user) likely still true; path citation is stale. **Recommend STATE.md correction**: update path to `algo2go/kite-mcp-riskguard/per_second.go`. |
| §5.2 IP whitelist verified at `mcp/plugin_widget_ip_whitelist.go:54` | §5.2 | INFERRED | file exists; line 54 references the "Whitelisted IPs" plural label in helper text; but the "field is plural / accepts array" claim isn't strictly proved by that line — it's inferred from Zerodha's UI labeling. Still load-bearing. |
| **§5.3 SQL portability "9 SQL statements required Postgres-specific placeholder rewriting"** | §5.3 | **HIGH (contradicts cited source)** | `phase-2-sql-portability-audit.md:487` says: *"`pgx/v5/stdlib` accepts `?` placeholders transparently. **Zero placeholder rewrite needed when using the database/sql stdlib path** (which is what alerts repo uses)."* The "9 statements" figure is not in the cited source. Either the audit doc was updated post-STATE-write, or the figure is from a different audit pass. **Recommend STATE.md correction**: re-read `phase-2-sql-portability-audit.md` and reconcile the count. The cited "Phase 2.4 placeholder rewriter handles the rewrite at runtime" claim seems to misstate the architecture if zero rewrites are needed. |
| §5.4 libsql-client-go has GitHub deprecation banner; alternatives examined | §5.4 | INFERRED | sourced from `phase-2-6-r10-decisions.md` v8 §6 — not re-probed |
| §5.5 DPDP Act 2023 + SEBI Cloud Framework | §5.5 | INFERRED | sourced from `MEMORY.md` — not externally verified |
| §5.6 grep-vs-compile-and-run methodology lesson | §5.6 | VERIFIED | the entire content was generated from the chain agent's gap-report investigation (commit `21d5684`) which I personally executed; the 130 vs 111 vs 19 numbers all reproduce from current source: `grep -rE 'mcp\.NewTool\(' mcp/ --include='*.go' \| wc -l` = 130; `\| grep -v _test.go \| wc -l` = 111; `\| grep _test.go \| wc -l` = 19; compile-and-run yields `total_available=111` |
| §6 "13 docs that REMAIN authoritative" | §6 header | MEDIUM (off-by-1) | the 5 tables in §6 list **14** files (3 strategic + 3 phase + 5 launch + 2 brand + 1 scaling = 14, including STATE.md itself in row 1 of strategic table). The "13" header doesn't match the table contents. **Recommend STATE.md correction**: change header to "14 docs (including this STATE.md)" or remove STATE.md from the strategic table. |
| §6 individual file existence (14 files) | §6 tables | VERIFIED | all 14 files exist at `.research/<file>.md` (probed via `ls -la`) |
| §6 dates (e.g., 2026-05-10, 2026-05-09, 2026-05-06, 2026-05-03, 2026-05-02) | §6 tables | VERIFIED | each file's last-commit date matches the row's claimed date (e.g., `phase-2-6-r10-decisions.md` last-commit=2026-05-10 matches; `final-pre-launch-verification.md` last-commit=2026-05-03 matches; etc.) |
| §7 "80 docs archived in 5 categories" | §7 header | MEDIUM (off-by-2) | actual subdirectory file counts (matching STATE.md's own per-section breakdowns): 30 + 22 + 20 + 4 + 6 = **82**. STATE.md's own §7 prose enumerates 30+22+20+4+6 within the section, summing to 82. The header "80" contradicts the section-internal sum. The audit-agent's commit message at `1e80930` says "82 archived, 14 remain active" — matching 82. **Recommend STATE.md correction**: change "80 docs archived" → "82 docs archived" (consistent with own subsection counts and own commit message). |
| §7 individual category file counts: 30 / 22 / 20 / 4 / 6 | §7 subsections | VERIFIED | `ls .research/archive/<topic>/ \| wc -l` returns 30, 22, 20, 4, 6 respectively |
| §8.1 dispatch-chain v228→v274 metadata correctly tracked deploys | §8.1 | VERIFIED | `flyctl status` shows machine version 273 (matches dispatch chain's v273 reports, which I myself authored); chain agent's gap-report independently confirmed |
| §8.1 v1.3.0 doesn't auto-bump on deploy / `version` field is "literal in source" | §8.1 | LOW (mechanism wrong) | see §2.1 critique above. The version is server.json + ldflags, not source literal. The STATEMENT (production reports v1.3.0 unchanged across deploys) is true; the MECHANISM described is wrong. |
| §8.2 final-pre-launch-verification.md tools=128 at HEAD `ad1e263` | §8.2 | PARTIAL (commit exists but unrelated) | `git log -1 ad1e263` exists (`fix(e2e): relax server-card identity assertion to accept SEP-1649 + SEP-2127 shapes`) — but that commit is an E2E test fix, not a tool-add. The "tools=128 at HEAD ad1e263" framing is plausible but unproven; STATE.md treats it as resolved ("both correct at their snapshot times") without verifying the snapshot count. INFERRED at best. |
| §8.3 ₹19-22k via Vakilsearch vs ₹9k direct filing | §8.3 | INFERRED | sourced from playbooks; pricing not externally re-verified |
| §8.4 tradarc.com REGISTERED to Server Plan Srl since 2001-05-04 | §8.4 | INFERRED | sourced from prior 2026-05-03 RDAP check; not re-probed in this audit |
| **§8.5 RiskGuard "11 checks" per `kc/riskguard/guard.go`** | §8.5 | **MEDIUM (stale path) + INFERRED (count)** | (a) `kc/riskguard/guard.go` does NOT exist; file moved to `algo2go/kite-mcp-riskguard/guard.go`. (b) The "11 checks" count contradicts the project `CLAUDE.md` (`.claude/CLAUDE.md` "Middleware Chain" section) which says "**RiskGuard (9 pre-trade checks**: kill switch, cap, count, rate, duplicate, idempotency key, confirmation, anomaly, off-hours)". STATE.md's enumerated 11 includes "per-second rate limit", "circuit-breaker", "global-freeze layers" which CLAUDE.md doesn't separately count. **The number depends on definition** (registered checks vs internal-helper-checks vs middleware layers). Both 9 and 11 are defensible — STATE.md should pick one and footnote the methodology. |
| §9.1 "Whitelisted IPs" array length cap unverified | §9.1 | VERIFIED-as-gap | claim correctly notes this isn't verified; that's transparent gap-acknowledgment, not an unsupported claim |
| §9.2 "Per-app WebSocket connection limit" unverified | §9.2 | VERIFIED-as-gap | same — transparent gap |
| §9.3 Static egress IP `209.71.68.157` | §9.3 | VERIFIED | `flyctl ips list -a kite-mcp-server` returns: `v4 209.71.68.157 egress bom Apr 1 2026 17:46`. STATE.md claim matches exactly. |
| §9.3 "agent flyctl is permission-denied per recent attempt" | §9.3 | **LOW (now-stale claim)** | flyctl works fine in this audit (same agent, same session). Either the prior denial was transient or has since been fixed. Recommend STATE.md drop this assertion. |
| §11 "git log -1 HEAD = `bc5043e`" | §11 | LOW (auto-stale) | matches the header HEAD claim; STATE.md was at `bc5043e` at write time; HEAD is now `25b201a`. Same self-staleness pattern. |
| §11 "git log --oneline \| wc -l = 1,357" | §11 | LOW (auto-stale) | now 1,364 (off by 7). Same self-staleness pattern. |
| §11 "tool count empirical methodology" footnote | §11 | VERIFIED | the methodology described is correct — verified by chain agent's gap-report investigation and reproducible right now |
| §11 "ls D:/Sundeep/projects/algo2go/ = 28 modules" | §11 | VERIFIED | 28 |
| §11 "cat go.work = 4 in-tree workspace members" | §11 | VERIFIED | 4 (counting bare `.`) |

---

## Critical findings to surface immediately (per the dispatch instruction)

### 1. Phantom commit SHA `d3c2a4a` in TL;DR §1

`git log -1 d3c2a4a` returns "fatal: ambiguous argument 'd3c2a4a': unknown revision". This is a phantom — possibly a typo of `5f8ee3b` (which exists), or a side-branch commit that never made it to master. Anyone reading TL;DR §1 and trying to verify the libSQL/Turso shipping commit chain will hit this immediately.

**Fix**: identify what `d3c2a4a` was meant to be (search for "Path 6"-related commits in `.research/phase-2-6-r10-decisions.md` v8 references), or remove it.

### 2. §5.3 SQL portability claim contradicts its own cited source

STATE.md says "9 SQL statements required Postgres-specific placeholder rewriting" — but the cited source (`phase-2-sql-portability-audit.md:487`) literally says "**Zero placeholder rewrite needed when using the database/sql stdlib path**". Either the source doc was revised post-audit, or the "9" figure was always wrong. The downstream implication "Phase 2.4 placeholder rewriter handles the rewrite at runtime" then cites code that may not exist.

**Fix**: re-read the cited source doc end-to-end; reconcile the count + the rewriter-architecture claim.

### 3. §1.4 Track 2 status "FALSIFIED" misrepresents cited source

STATE.md §1.4 says "Track 2 (DO BLR1, fresh account): FALSIFIED — DO docs claim BLR1 supports managed Postgres but UI showed only NA/EU regions for fresh account." The actual source (`path-e-try-before-buy-results.md:114`) says: "**PENDING USER PAYMENT-METHOD AUTHORIZATION**". The ACTUAL Track 2 was deferred awaiting payment method, not empirically tested-and-failed.

**Fix**: change "FALSIFIED" → "DEFERRED — pending payment-method authorization (no UPI/RuPay path per v4 finding)".

### 4. Stale path citations in §5.1 and §8.5 (riskguard moved external)

`kc/riskguard/per_second.go` and `kc/riskguard/guard.go` cited in STATE.md no longer exist — they moved to `algo2go/kite-mcp-riskguard/` during Path A inauguration. Underlying claims are likely still true (the files exist at the new path), but the citations are stale.

**Fix**: update path references to `algo2go/kite-mcp-riskguard/` (with absolute Windows path or the algo2go root prefix STATE.md already uses elsewhere).

### 5. Off-by-N count errors

| Section | Claimed | Measured | Delta |
|---|---|---|---|
| §1.1 lifetime commits | 1,357 | 1,364 | +7 (auto-stale by 7 commits since write) |
| §1.1 last-2-weeks cadence | 585 | 490 | **−95 (date-window error?)** |
| §1.1 April 2026 cadence | 931 | 923 | −8 (date-window inclusivity) |
| §6 active doc count | 13 | 14 (in own tables) | +1 (header doesn't match own tables) |
| §7 archived doc count | 80 | 82 (in own subsections) | +2 (header doesn't match own subsections) |

The §1.1 "585 commits" discrepancy is the biggest — 19% over-count. Possibly a different date-range was used. Recommend re-running with explicit window in next STATE.md edit.

---

## Methodology notes

### What I probed empirically (not via grep)

- `flyctl status -a kite-mcp-server` — production image + machine version + region + last-updated
- `flyctl image show -a kite-mcp-server` — sha256 digest of running image
- `flyctl ips list -a kite-mcp-server` — egress IP verification
- `curl https://kite-mcp-server.fly.dev/healthz` — live tools count + version + uptime
- `git rev-parse HEAD` / `git rev-parse origin/master` — current master HEAD
- `git log -1 <sha>` for every cited SHA in STATE.md (≈18 SHAs)
- `git log --oneline --since=... --until=...` for cadence claims
- `ls -la .research/<file>.md` + `git log -1 -- .research/<file>.md` for every §6 file
- `ls .research/archive/<topic>/ \| wc -l` for §7 subsection counts

### What I did NOT verify (out of scope)

- §3 strategic-question gates (cost estimates, threshold triggers)
- §5.5 DPDP/SEBI legal-framework claims (sourced from MEMORY.md)
- §2.3 trademark + domain availability (sourced from runbook)
- §1.2 "two facades remain as deferred work" — needs reading of archived `kc-manager-decomp-design.md`
- §5.4 libsql ecosystem maturity (sourced from phase-2-6-r10-decisions.md v8)
- §2.2 11 pre-flight blockers (sourced from final-pre-launch-verification.md)

These are all marked INFERRED and rely on the cited active doc's own truth. Audit agent's parallel #B dispatch (deep verification of 14 active docs) is best positioned to close these.

### What I learned about STATE.md's reliability

After the bea1e11 patch (audit agent's tools=130 fix), **STATE.md's load-bearing claims are mostly accurate**. The remaining issues are:
- 1 phantom SHA (low impact — typo / wrong-branch reference)
- 2 source-misrepresentations (§5.3 "9 statements", §1.4 Track 2 "FALSIFIED") — these would mislead a strategic reader who doesn't double-check the cited docs
- 4 off-by-N counts (low impact — cosmetic, all in directions that are easy to spot once probed)
- 2 stale path citations (low impact — files exist, paths just changed)
- 4 auto-stale facts (HEAD, lifetime commits) — STATE.md's design assumes orchestrators re-check live state; this is fine if §0 includes a "verify current HEAD before trusting numeric claims" disclaimer (it currently doesn't but the §11 verification methodology hints at it)

**No new grep-class systemic errors found.** The lesson from §5.6 ("compile-and-run > grep") appears to have been internalised — no other "in-tree count" claim derived from raw grep is present in current STATE.md.

---

## Recommended STATE.md edits (priority order)

1. **Drop or replace** phantom SHA `d3c2a4a` in TL;DR §1.
2. **Reconcile** §5.3 "9 SQL statements" against `phase-2-sql-portability-audit.md:487` ("Zero rewrite needed").
3. **Correct** §1.4 Track 2 "FALSIFIED" → "DEFERRED — pending payment-method authorization".
4. **Update** path citations in §5.1 + §8.5 from `kc/riskguard/*.go` to `algo2go/kite-mcp-riskguard/*.go`.
5. **Recompute** §1.1 cadence claim (585 vs measured 490) with explicit date window in the cell.
6. **Fix** §6 header "13 docs" → "14 docs" (or drop STATE.md from its own active list).
7. **Fix** §7 header "80 archived" → "82 archived" (matches own subsections).
8. **Drop** §9.3 "agent flyctl is permission-denied" assertion (now-stale; flyctl works).
9. **Footnote** the §1.1 lifetime-commits + §11 git-log claims with "as of `<HEAD-SHA>` write time; orchestrators must verify current HEAD before trusting".
10. **Footnote** §5.1 + §5.2 + §8.5 with the methodology used for each count (which file, which line, what was counted).

None of these is a launch blocker. STATE.md remains usefully trustworthy for orchestrator decision-making after the bea1e11 patch. The bug pattern that caused the prior crisis (grep-over-tests over-counting tools) has been internalised and the methodology footnote in §11 is the right durable fix.

---

## Hard rules compliance

| Rule | Status |
|---|---|
| READ-ONLY on STATE.md | ✓ — only read, never wrote |
| Empirical probes (curl, git, flyctl, compile-and-run) | ✓ — used all four |
| Pattern-matching probes flagged as INFERRED until backed by compile-and-run | ✓ — see methodology section; only `grep -c` results are marked INFERRED |
| WSL2 for go-related probes | ✓ |
| Single output `.research/STATE-claims-audit-2026-05-11.md` | ✓ — this file |
| Commit `git commit -o -- <path>` + push | (next step) |
| ~1-2h budget | ~1h25m wall clock through investigation + writing |
| Surface immediately if grep-class error or unsupported critical claim | ✓ — see "Critical findings" section above. **No new grep-class errors found.** Two source-misrepresentations (§5.3, §1.4 Track 2) flagged as HIGH severity. |

---

## Verdict

**STATE.md after bea1e11 patch is mostly trustworthy. 5 medium issues + 2 high issues + 1 phantom SHA remain. None is a launch blocker.** The audit agent's parallel #B dispatch (14 active docs) will catch issues that bottom out in the active docs themselves (which I marked INFERRED in this pass). Path A owner's #C resynthesis is best positioned to identify if any STATE.md narrative framing — independent of factual claims — is misleading.

The original dispatch question — "is STATE.md now actually trustworthy" — answers as: **yes, for orchestrator decision-making, with the listed minor edits as the next polish pass**. None of the issues found here would have caused the kind of strategic misdirection that the original tools=130 grep-error caused (~6 hours of misdirected synthesis). The methodology lesson in §5.6 + §11 is durable.
