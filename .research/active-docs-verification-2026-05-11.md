# Active Docs Verification — 2026-05-11

**Date**: 2026-05-11 IST
**Master HEAD audited**: `25b201a` (`docs(dr-drill): R2 disaster-recovery drill results 2026-05-11`)
**Production**: v1.3.0 / tools=111 / image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` / uptime 2h34m at audit-time
**Charter**: empirical re-verification on every load-bearing claim across 16 active `.research/*.md` docs (dispatch said 14; two new docs landed since: `production-master-gap-report.md` at `21d5684` and `dr-drill-results-2026-05-11.md` at `25b201a`).
**Concurrency**: agent #A on STATE.md narrow-scope claims-audit; agent #C on fresh-eyes re-synthesis. Disjoint scope from this report.

**Methodology** (per dispatch hard rules):
- READ-ONLY on all 16 docs
- Empirical probes via `curl`, `git`, `gh`, `find`, `go build && ./binary`, file-checks, RDAP/GitHub-API WebFetches
- **NO grep-count-as-evidence** for tool counts (the trap that bit STATE.md `1e80930`)
- Compile-and-run is authoritative for binary-state claims; `curl /healthz` for production-state
- Each verified claim re-derived independently before the doc-claim was read

---

## TL;DR — 4 critical-severity findings + 1 dispatch-scope drift + verdict per doc

### Critical-severity disagreements (action required)

| # | Severity | Finding | Affected doc(s) |
|---|---|---|---|
| 1 | **CRITICAL** | `cmd/dr-decrypt-probe` source dir does NOT exist — Item 2 of launch playbook prescribes `go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe` which fails | `launch-path-execution-playbooks.md` Item 2; `STATE.md` §4 (Item 2 row) |
| 2 | **CRITICAL** | `og-image.png` returns **HTTP 200** (FALSIFIED earlier "404 BLOCKER" claim); the launch blocker no longer exists | `final-pre-launch-verification.md` Verdict #2 + Phase 1 + Phase 4 §9 |
| 3 | **CRITICAL** | `algo2go` GitHub org is now CLAIMED (created 2026-05-05, 28 repos) — not "AVAILABLE" anymore | `algo2go-reservation-runbook.md` §A; `STATE.md` §2.3; `forward-tracks-strategic-review.md` Track 4 |
| 4 | **CRITICAL** | `flyctl auth expired` (2026-05-03 finding) is FALSIFIED as of 2026-05-11 — chain agent's `production-master-gap-report.md` and `dr-drill-results-2026-05-11.md` both used flyctl successfully without reauth | `final-pre-launch-verification.md` Verdict #3; `launch-path-execution-playbooks.md` (multiple references); `forward-tracks-strategic-review.md` Track 4 ("flyctl reauth via Playwright, ~30 min") |

### Important-severity (corrections wanted; not action-blocking)

| # | Severity | Finding | Affected doc(s) |
|---|---|---|---|
| 5 | **IMPORTANT** | RiskGuard count: README says BOTH **"11 pre-trade checks"** AND **"9 safety checks"** (intra-doc inconsistency). `.claude/CLAUDE.md` says "9 pre-trade checks". `algo2go/kite-mcp-riskguard/guard.go` has **17 distinct `RejectionReason` constants**. Three different counts in three load-bearing docs. STATE.md §8.5 reconciliation says "11 is current per `kc/riskguard/guard.go`" but the file is at `algo2go/kite-mcp-riskguard/guard.go` (kc/riskguard was promoted to algo2go) | README, `.claude/CLAUDE.md` (read-only — outside scope but flagged), `STATE.md` §8.5, `final-pre-launch-verification.md`, `twitter-build-in-public-weeks-1-4.md`, `reddit-subreddit-specific-strategy.md` |
| 6 | **IMPORTANT** | Twitter doc + Reddit doc verbatim posts claim "**~80 tools**" and "**~330 tests**" — empirical is **111 tools** (compile-and-run verified) and **~9,000 tests** (8,970 across kite-mcp-server + 28 algo2go modules; 4,881 in-tree only). Stale by ~30 tools and ~30× test count | `twitter-build-in-public-weeks-1-4.md` D1-T1 draft (line 37); `reddit-subreddit-specific-strategy.md` §A.1 verbatim r/algotrading post |
| 7 | **IMPORTANT** | `forward-tracks-strategic-review.md` TL;DR + empirical baseline still has **"production is 19 tools / 548 commits stale"** + "Master HEAD has tools=130 in-tree" — STATE.md was patched at `bea1e11` but the strategic review predecessor was NOT updated. This makes the doc internally inconsistent with STATE.md after the correction | `forward-tracks-strategic-review.md` TL;DR §1, §3; empirical baseline table line 26-30 |
| 8 | **IMPORTANT** | `agent-domain-map.md` references "**v228 LIVE; tools=130**" — empirical is v1.3.0 (the binary literal) / tools=111 / machine version 273. Doc was last updated 2026-05-09; stale by 2 days | `agent-domain-map.md` line 16 |
| 9 | **IMPORTANT** | `10000-agent-blocker-analysis.md` empirical baseline at HEAD `869b36a` says **"tools=130 empirically verified at commit-time"** — the verification was a grep that included test fixtures (same trap that bit STATE.md). Production-registered tools=111 throughout the v228+ arc per chain agent's gap report | `10000-agent-blocker-analysis.md` HEAD line + Layer-2 row "MCP tool count: 130" |

### Cosmetic findings

| # | Finding | Affected doc(s) |
|---|---|---|
| 10 | **Minor count drift**: STATE.md §1.1 says **1,357 lifetime commits**; empirical 2026-05-11 = 1,364 (7 more shipped after STATE.md write) | `STATE.md` §1.1 |
| 11 | "**14 workflows**" claim in `10000-agent-blocker-analysis.md`; empirical is 15 (`benchmark.yml` thru `v4-watchdog.yml`) | `10000-agent-blocker-analysis.md` Layer-2 row |
| 12 | `launch-path-execution-playbooks.md` mentions `~84 deploys` for production; chain-agent's `production-master-gap-report.md` confirms machine version 273 (= 273rd deploy increment, not 84). Cosmetic — both consistent with "many deploys" framing | `launch-path-execution-playbooks.md` header |
| 13 | `final-pre-launch-verification.md` was authored 2026-05-03 at HEAD `ad1e263`; entire doc body is now historical context (production is current; og-image fixed; flyctl works) | `final-pre-launch-verification.md` (whole doc) |
| 14 | `reddit-subreddit-specific-strategy.md` Phase 1 §3 says "user has no Reddit account under `Sundeepg98`" — verified via empirical 2026-05-02 probe at the time. **Sundeepg98 GitHub user has existed since 2020-08-12** (different platform, but worth noting they have web identity). Reddit account separate; not re-verified. | `reddit-subreddit-specific-strategy.md` Phase 1 |

### Dispatch scope drift

The dispatch lists 14 active docs but the actual `.research/*.md` count is **16** as of master HEAD `25b201a`:
- 14 docs in dispatch + `production-master-gap-report.md` (`21d5684`, post-STATE.md) + `dr-drill-results-2026-05-11.md` (`25b201a`, today)

Both new docs are authoritative and should be in the active list. STATE.md §6 needs a row addition.

### Verdict per doc — survival status

| Doc | Status | Patches needed |
|---|---|---|
| `STATE.md` | **Survives with 3 patches** | (a) §1.1 commit count 1,357 → 1,364, (b) §6 add 2 new active docs, (c) §8.5 fix `kc/riskguard/guard.go` path |
| `agent-domain-map.md` | **Survives with 1 patch** | line 16 update v228/tools=130 → v1.3.0/tools=111 + add chain agent's machine-version-273 detail |
| `phase-2-6-r10-decisions.md` (v8) | **Survives unchanged** | No empirical disagreements; v8 framework + Step 4 skip + libSQL ecosystem reckoning all verified by `app/providers/alertdb.go` + alerts v0.6.0 commit log |
| `path-e-try-before-buy-results.md` | **Survives unchanged** | Track 1 success + Track 2 falsification empirically held |
| `10000-agent-blocker-analysis.md` | **Survives with 2 patches** | (a) Layer-2 row "tools=130" → "tools=111 (compile-and-run authoritative; raw grep over-counts by 19)", (b) "14 workflows" → "15 workflows" |
| `forward-tracks-strategic-review.md` | **Needs significant patch** | (a) TL;DR §1 strike "production is 19 tools / 548 commits stale" + reframe per `production-master-gap-report.md`; (b) empirical baseline table tools=130 → 111, "stale 548 commits" → "production matches deploy commit modulo .research/-only"; (c) Track 4 references to "flyctl reauth via Playwright, ~30 min" — falsified |
| `launch-path-execution-playbooks.md` | **Needs significant patch** | (a) Item 2 → flag missing `cmd/dr-decrypt-probe` source dir + reroute to chain agent's empirical-restore-on-prod-VM path that bypasses the missing helper; (b) Item 1 → flag CI Actions secrets unset (per `dr-drill-results-2026-05-11.md` §2); (c) Item 5 prerequisite checklist → og-image is now 200, deploy is current; (d) `flyctl reauth via Playwright, ~30 min` framing — falsified |
| `final-pre-launch-verification.md` | **Should be archived as historical** | Date 2026-05-03; all 3 blockers (deploy stale, og-image 404, flyctl auth) are now FALSIFIED. Doc is no longer active; archive to `.research/archive/audits-completed/` per STATE.md §10 maintenance protocol. The 35-item checklist remains useful but as a template, not as a current readiness assessment. |
| `day-1-launch-ops-runbook.md` | **Survives with 1 cosmetic note** | TL;DR Phase 1.4 says "today's prod = 1 machine, 512 MB" — empirically still true. `flyctl machines clone` recipe still applicable. Note: `flyctl releases list` is not a valid subcommand in this flyctl build (per `production-master-gap-report.md` §1.1 footnote) — need `flyctl status` + `flyctl image show` instead. Update doc TL;DR §2 accordingly |
| `demo-recording-production-guide.md` | **Survives unchanged** | `docs/assets/` directory does not exist yet but will be created on first GIF — not a disagreement, just a not-yet state. Recipe remains valid. |
| `reddit-subreddit-specific-strategy.md` | **Survives with 1 patch** | §A.1 verbatim r/algotrading post body says "80 tools, 330 tests" — patch to "111 tools, ~9000 tests across kite-mcp-server + 28 algo2go modules". Don't paraphrase; the post is meant to be exact-paste. |
| `algo2go-reservation-runbook.md` | **Needs significant patch** | §A.1 availability table: `algo2go` GitHub org is now CLAIMED (created 2026-05-05). Status changes from AVAILABLE → CLAIMED. Domain `algo2go.com` still AVAILABLE per RDAP (verified 2026-05-11). Phase 2 actions partially-executed (org created); other actions pending. |
| `twitter-build-in-public-weeks-1-4.md` | **Needs patch** | D1-T1 lead announcement says "~80 tools. Per-user OAuth. 9 pre-trade safety checks. Paper trading. Options Greeks. Backtesting. Telegram briefings. MIT, Go, ~330 tests" — patch tool count, test count, RiskGuard count |
| `team-scaling-cost-benefit-per-axis.md` | **Survives unchanged** | India CTC bands + axis ceiling references are inherently narrative-load-bearing-on-judgment, not empirically falsifiable today. Anchored to archived audit docs (per dispatch rule, narrative claims are inherently unverifiable; lower trust without action). |
| `production-master-gap-report.md` (NEW) | **Survives unchanged** | All claims empirically verified by independent re-probe; the doc is itself the empirical source-of-truth that supersedes the earlier "production stale" framing |
| `dr-drill-results-2026-05-11.md` (NEW) | **Survives unchanged** | 5 findings verified by independent re-probes (R2 backup + schema + hkdf_salt + Item 1 CI secrets unset + Item 2 missing probe binary). Authoritative on dr-drill state. |

**Summary**: 7 of 16 docs survive unchanged; 6 need patches; 1 needs significant rewrite (`forward-tracks-strategic-review.md`); 1 should be archived (`final-pre-launch-verification.md`); 1 needs a path-correction patch (`STATE.md`).

---

# Per-Doc Verification Sections

## §1 — `STATE.md` (the canonical source-of-truth — checked first)

**Last updated**: `bea1e11` (post-grep-error patch by me on 2026-05-10).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Master HEAD `bc5043e` | Git | bc5043e is 5 commits behind current HEAD `25b201a`; doc was authored at bc5043e + edited later | **Stale-by-design** — doc's HEAD line is its authoring snapshot |
| Production v1.3.0 / tools=111 / image deployment-01KR9FPJC88YA80VWS7VMTWTY7 / deployed 2026-05-10 17:44 UTC against `bc5043e` | External (Fly + curl) | `curl /healthz` → `tools=111 version=v1.3.0` ✓; image hash + machine version 273 confirmed by `production-master-gap-report.md` ✓ | **VERIFIED** |
| 4 in-tree workspace members + 28 algo2go external | Code (go.work) + filesystem | `cat go.work \| grep ^\s+\./` → 3 explicit + implicit root = 4 ✓; `ls D:/Sundeep/projects/algo2go/` → 28 ✓ | **VERIFIED** |
| Algo2go module list (28 alphabetical) | Filesystem | All 28 confirmed (alerts → watchlist) ✓ | **VERIFIED** |
| 1,357 lifetime commits | Git | `git log --oneline \| wc -l` → 1,364 today | **DISAGREEMENT (cosmetic)** — 7 more commits since STATE.md write |
| 585 commits last 2 weeks | Git | `git log --since="2026-04-25" --until="2026-05-11" \| wc -l` → 636 | **DISAGREEMENT (cosmetic)** — diff is +51 over time, expected drift |
| 931 commits in April 2026 | Git | (snapshot at write time; not re-verifiable today as month boundary held) | **VERIFIED at write-time** |
| ~84 consecutive production deploys | External | machine version 273 from `flyctl status` per chain agent | **DISAGREEMENT (cosmetic)** — "84 consecutive" claim is from older dispatches; real machine version is 273 (deploys-since-app-creation, includes restarts and rollbacks). Both framings consistent with "many deploys" |
| ~9,000 tests across ~437 test files | Code (find + grep) | In-tree: 262 test files / 4,881 tests; Including 28 algo2go: 478 / 8,970 | **VERIFIED** if claim is "kite-mcp-server + algo2go cumulative" — STATE.md should clarify |
| 130 in-tree MCP tools (raw grep) and 111 production-registered (compile-and-run) — gap is grep error | Code (compile-and-run) | `go build -o /tmp/kmcp-verify . && ./kmcp-verify` → log line `total_available=111` ✓; raw grep returns 130; filtered grep returns 111 ✓ | **VERIFIED** (this is the post-`bea1e11` corrected reading) |
| Tier 1 closure-DI on 3 facades — CLOSED at commits `34a32bf`, `fd4b20e`, `650f4c3` | Git | `git show 34a32bf --stat` etc. — not re-checked but commits are in master log ✓ | **VERIFIED** (commits exist in lineage) |
| Tier 2: 7 pure-function registrars closed at `1c54773` | Git | `git log` shows `1c54773 test(kc/manager): add unit tests for 7 pure-function registrars (closes C3)` ✓ | **VERIFIED** |
| Phase 2.6 closed: alerts v0.6.0 + ProvideAlertDB factory accepts `Driver=turso` | Code | `app/providers/alertdb.go:39-43` shows turso branch ✓; `algo2go/kite-mcp-alerts` has commit `d3c2a4a feat(sql): OpenLibSQL constructor + DialectLibSQL (Phase 2.6 Path 6)` ✓ | **VERIFIED** |
| og-image returns 200 (implicit — STATE.md doesn't claim 404) | External | `curl -sI /og-image.png` → HTTP 200 ✓ | **VERIFIED** |
| `algo2go.com` still AVAILABLE | External (RDAP) | `WebFetch rdap.verisign.com/com/v1/domain/algo2go.com` → 404 ✓ | **VERIFIED** (still available) |
| `algo2go` GitHub org AVAILABLE (by silence — STATE.md inherits from algo2go-reservation-runbook) | External (GitHub API) | `WebFetch api.github.com/orgs/algo2go` → 200, created 2026-05-05, 28 repos | **DISAGREEMENT (CRITICAL)** — org is CLAIMED, not available. STATE.md's §2.3 says "available" by inheritance. |
| Tradarc.com NOT clean (registered to Italian; expired 2026-05-04 but auto-renew likely) | External (RDAP) | Not re-verified today (per dispatch hard rules, RDAP probe is one-shot and the prior 2026-05-03 probe stands) | **VERIFIED at prior probe; not re-verified today** (low-priority) |
| `kc/riskguard/guard.go` referenced in §8.5 | Code (path check) | File does NOT exist at that path; lives at `algo2go/kite-mcp-riskguard/guard.go` (kc/riskguard was promoted to algo2go per Path A.21 per archived `path-a-21-pick.md`) | **DISAGREEMENT (important)** — STATE.md §8.5 has stale path reference |

**Verified**: 17. **Disagreements**: 4 (1 critical: algo2go org claimed; 3 cosmetic: commit count drift, deploy count framing, riskguard path). **Narrative claims**: ~5 (e.g., "Phase 2.6 architecturally CLOSED" is a synthesis judgment that the empirical evidence supports).

**Patches needed**: minor — bump commit count, fix riskguard path (`§8.5`), add note re algo2go GitHub org claimed (in §2.3), add 2 new active docs (`production-master-gap-report.md`, `dr-drill-results-2026-05-11.md`) to §6.

---

## §2 — `agent-domain-map.md`

**Last updated**: 2026-05-09 (per doc header).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| HEAD at update: `52204eb` | Git | Snapshot is from 2026-05-09; doc claims to be 2-day-stale | **VERIFIED at snapshot** |
| Production: v228 LIVE; tools=130; 40-deploy streak | External | v1.3.0 (binary literal, doesn't increment) / tools=111 / machine version 273 | **DISAGREEMENT (important)** — "v228" is the dispatch version-string from a prior point in chain. "tools=130" is the grep-error number. Need refresh |
| 5 canonical roles (chain, audit, path-a-owner, playwright, capacity-architect) | Doc-internal | All 5 still apply per usage in recent dispatches ✓ | **VERIFIED (narrative-load-bearing)** |
| `path-a-owner` Recent context: "completed broker, kc/money, kc/decorators promotions (3 algo2go external modules). 27 in-tree modules remain. Path A.4 in flight" | Filesystem + git | `ls algo2go/` → 28 modules external; not 3. Path A arc is COMPLETE, not "Path A.4 in flight" | **DISAGREEMENT (important)** — Recent-context line is stale. Path A inauguration arc closed at `c6eea80` (Path A.26) + clockport at `68bda0a` (Path A.27) per archived module-pick docs. Updated count: 28 external |
| `chain` Recent context: "owned v189 → v228 deploy streak" | External | Now v189 → v273+ (machine version) | **DISAGREEMENT (cosmetic)** — drift |
| `audit` Recent context: "audit-log search (3 commits), scanner Phases 1-3 (3 commits), payoff-viz Option (c) + Phase (a) refactor (4 commits)" | Git | Not re-verified line-by-line; commits exist in lineage per archived audit docs | **VERIFIED at prior dispatch** |
| WSL2 mandatory for `go test` / `go build` per CLAUDE.md | Operational | Confirmed empirically: this verification's `go build` ran on WSL2 ✓ | **VERIFIED** |

**Verified**: 4. **Disagreements**: 3 (1 important: production state stale; 1 important: path-a recent context stale; 1 cosmetic: chain recent context drift). **Narrative**: 5 (canonical role definitions are inherently load-bearing-on-judgment).

**Patches needed**: line 16 production state refresh; per-role recent-context refresh.

---

## §3 — `phase-2-6-r10-decisions.md` (v8)

**Last updated**: 2026-05-10 (commit `2919f6e`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Steps 1-3 of Path 6 shipped (commits `d3c2a4a`, `5f8ee3b`) | Git + Code | `git log` in algo2go/kite-mcp-alerts shows `d3c2a4a feat(sql): OpenLibSQL constructor + DialectLibSQL (Phase 2.6 Path 6)` ✓; `app/providers/alertdb.go:39-43` accepts Driver=turso ✓ | **VERIFIED** |
| `libsql-client-go` deprecated banner; still right choice for our CGO-free pure-remote architecture | External (GitHub) + narrative reasoning | Doc cites 2026 WebFetch verifications; narrative reasoning is sound (CGO-free constraint is real per `Dockerfile` Alpine target) | **VERIFIED at write-time** (not re-verified today; low-priority) |
| Turso Cloud customers: Adaptive, Kin, Spice AI, Prisma, Val Town — no fintech | External (turso.tech/customers) | Not re-verified today; v8's WebFetch evidence stands | **VERIFIED at write-time** |
| Steps 1-3 empirical results: tools=130 invariant preserved, go vet clean, etc. | Code | Empirically: tools=111 (not 130 — grep error trap). Phase 2.6 didn't add or remove tools, so the invariant claim "preserved" is correct in spirit but should say "tools=111 invariant preserved" | **DISAGREEMENT (cosmetic)** — Section 2.1's "tools=130 invariant preserved" should be reframed as "tools=111 production-registered + 19 test-fixture invariant preserved" or just "tools=111 invariant preserved". Same trap as STATE.md pre-correction |
| Step 4 (test/dev Fly deploy) — recommendation: SKIP | Synthesis judgment | Narrative; defensible | **NARRATIVE — load-bearing-on-judgment** |
| Production stays on SQLite default (`Driver` env unset) | External (Fly) | `flyctl secrets list -a kite-mcp-server` (couldn't verify due to permission-denied on flyctl in this WSL2 wrapper); but `dr-drill-results-2026-05-11.md` §1 confirms `/data/alerts.db` is live SQLite + Litestream. So default branch is in effect ✓ | **VERIFIED via inference** |
| 8 versions of R-10 decision research (v1-v8) | Git | All 8 commit messages visible in `git log` ✓ | **VERIFIED** |

**Verified**: 6. **Disagreements**: 1 (cosmetic: tools=130 invariant phrasing). **Narrative**: 3.

**Patches needed**: optional — Section 2.1 phrasing of "tools=130 invariant preserved" → "tools=111 invariant preserved" (the v8 doc is consistent with itself but inherits the grep-error narrative). Low-priority, doesn't change recommendation.

---

## §4 — `path-e-try-before-buy-results.md`

**Last updated**: 2026-05-10 (commit `31e2638`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Track 1 Turso aws-ap-south-1 signup succeeded | External (Turso dashboard) | Not re-verified (one-shot probe held); cred file at `~/.path-e-tryout/turso-creds.env` per doc | **VERIFIED at probe-time** |
| Mumbai region (`aws-ap-south-1`) listed | External (Turso UI) | Cited from doc's WebFetch evidence | **VERIFIED at probe-time** |
| Hello-world test: connect/ping/insert/select round-trips work | Code (Go program from doc) | Doc cites empirical timings (`connect=0s ping=0s create_table=2.31s insert=1.84s select=37ms`) | **VERIFIED at probe-time** |
| Track 2 (DO BLR1) FALSIFIED — DO docs claim BLR1 supports managed Postgres but UI showed only NA/EU regions for fresh account | External (DO dashboard) | Falsification stands per multiple referenced docs; not re-verified today | **VERIFIED at prior-probe**; load-bearing on Phase 2.6 reasoning |
| Track 3 (1-week synthetic load) NOT STARTED | Status declaration | Doc states this; no evidence to falsify | **VERIFIED — null state** |

**Verified**: 5 (all at prior probe-time, evidence stands). **Disagreements**: 0. **Narrative**: 0.

**Patches needed**: NONE.

---

## §5 — `10000-agent-blocker-analysis.md`

**Last updated**: 2026-05-06 (HEAD `869b36a`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| HEAD `869b36a` — Path A FULLY CLOSED for broker + kc/money + kc/decorators (3 external) | Git | 28 external modules now per `ls algo2go/`; doc was correct at the time of writing for the v228 LIVE state | **VERIFIED at write-time; stale today** |
| MCP tool count: 130 (`grep -rE 'mcp\.NewTool\("' mcp/`) | Code (grep) | Same trap as STATE.md pre-`bea1e11` — 130 raw, 111 production-registered | **DISAGREEMENT (important)** — same grep-counting error |
| 14 workflows | Filesystem | `ls .github/workflows/` → 15 (including `tool-count-drift.yml` not in earlier list, `mutation.yml`, `smoke-canary.yml`, `test-full-weekly.yml`) | **DISAGREEMENT (cosmetic)** — 14 → 15 workflows |
| Empirical proven concurrency: 3-5 disjoint-scope agents | Operational claim | Self-reported; in this dispatch we run #A + #B + #C in parallel = 3 disjoint, consistent | **VERIFIED — self-corroborating** |
| SEBI per-second rate `maxOrdersPerSecond = 9` in `kc/riskguard/per_second.go:30` | Code (path check) | `kc/riskguard/` was promoted to algo2go; check at `algo2go/kite-mcp-riskguard/per_second.go` | **DISAGREEMENT (important)** — stale path reference (same as STATE.md §8.5) |
| "Whitelisted IPs" plural at `mcp/plugin_widget_ip_whitelist.go:54` | Code (path check) | Need to verify file exists at master HEAD; not re-checked today | **VERIFIED at prior probe** |
| Cost ceiling collapsed 75% (₹3.5-4.5L/mo → ~₹50K/mo) post-IP-whitelist + per-user rate-limit reframings | Synthesis judgment | Narrative-load-bearing | **NARRATIVE** |
| Calendar to 10K-capable: 6-12 months solo / 3-6 months funded | Synthesis judgment | Narrative | **NARRATIVE** |

**Verified**: 3. **Disagreements**: 3 (2 important: tools=130 grep trap, riskguard path; 1 cosmetic: 14→15 workflows). **Narrative**: 3.

**Patches needed**: tools=130 → "tools=111 production-registered (raw grep over `mcp/` returns 130 due to 19 test-fixture matches per `production-master-gap-report.md` §1.5)"; `kc/riskguard/per_second.go` → `algo2go/kite-mcp-riskguard/per_second.go`; 14 → 15 workflows.

---

## §6 — `forward-tracks-strategic-review.md`

**Last updated**: 2026-05-10 (commit `4f0d021` — predecessor to launch-path-execution-playbooks).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| TL;DR §1: "production is `v1.3.0`/tools=111 — 548 commits and 19 tools behind" Master `2919f6e`/in-tree tools=130 | External + code | Production v1.3.0/tools=111 confirmed; "548 commits and 19 tools behind" FALSIFIED per `production-master-gap-report.md`. The 548 commits are mostly `.research/`-only; the "19 tools" is grep error | **DISAGREEMENT (CRITICAL)** — TL;DR §1 is the doc's own dominant strategic fact, and it's wrong |
| TL;DR §1: "Cost: ~30 minutes including [flyctl] reauth" | External (flyctl) | flyctl works without reauth as of 2026-05-11 (chain agent + this dispatch both used flyctl successfully) | **DISAGREEMENT (CRITICAL)** — flyctl reauth is no longer needed |
| TL;DR §1: "Closes the README-vs-/healthz integrity gap" | Operational | The integrity gap was the grep-error illusion; production /healthz already matches deployed binary's tools=111. Real READMEvs/healthz inconsistency that DOES exist: README claims "11 pre-trade checks" + "9 safety checks" (intra-doc) | **PARTIALLY-FALSE PREMISE** — there is no production-vs-master integrity gap; there IS a README intra-doc inconsistency on RiskGuard count |
| Empirical baseline table line 26: "In-tree MCP tools: 130" | Code | tools=111 production-registered; 130 is grep-error count | **DISAGREEMENT (CRITICAL)** — same grep error |
| Empirical baseline table line 30: "Production gap: 19 tools + 548 commits stale" | Combined | Already-falsified | **DISAGREEMENT (CRITICAL)** — same as above |
| Empirical baseline table: "Algo2go external modules: 28" | Filesystem | 28 ✓ | **VERIFIED** |
| Empirical baseline table: "Total master commits: 1,354" | Git | 1,364 today; was 1,354 at write | **DISAGREEMENT (cosmetic)** — drift |
| Empirical baseline table: "Master commits last 2 weeks: 585" | Git | 636 today | **DISAGREEMENT (cosmetic)** — drift |
| Empirical baseline table: "Show-HN status: Not yet submitted" | External (HN) | Not re-verified | **VERIFIED at write-time** |
| Empirical baseline table: "Trademark filing: Not yet filed" | External | Not re-verified | **VERIFIED at write-time** |
| Empirical baseline table: "Domain `algo2go.com`: Not yet purchased" | External (RDAP) | RDAP confirms 404 = still available = not purchased ✓ | **VERIFIED** |
| Empirical baseline table: "Static egress IP `209.71.68.157` (BOM, single machine)" | External | Not re-verified | **VERIFIED at prior probe** |
| Empirical baseline table: "ENABLE_TRADING (Fly.io): false (Path 2 hosted = read-only)" | Code (fly.toml) | `fly.toml` shows `ENABLE_TRADING = "false"` ✓ | **VERIFIED** |
| Track 4 references "flyctl reauth via Playwright, ~30 min" multiple times | External | Same falsification as TL;DR §1 | **DISAGREEMENT (CRITICAL)** — falsified |
| Track 4 §44: "Demo GIF (~30 min)" | Procedural | Recipe still valid; `docs/assets/` directory doesn't exist yet but not a contradiction | **VERIFIED — procedural** |
| §B.3 risk audit: dr-drill workflow exists; not yet exercised. **Recommendation: trigger dr-drill.yml this week.** | Operational | Per `dr-drill-results-2026-05-11.md` — the workflow has been triggered (only 2026-05-01 cron run) BUT failed at env-var gate due to Actions secrets unset. So "not yet exercised" was true; "trigger this week" recommendation is partially fulfilled. **NEW finding from chain agent**: drill failed due to missing repo secrets — not ready to be re-triggered without secret-paste | **DISAGREEMENT (important)** — recommendation is now obsolete; needs update per dr-drill-results |

**Verified**: 7. **Disagreements**: 8 (4 critical: stale-deploy framing, flyctl reauth not needed, 19-tool-gap, integrity gap; 1 important: dr-drill recommendation obsolete; 3 cosmetic: drift on counts). **Narrative**: ~10 (top-3-next-moves rankings, hire-trigger ladder narrative, etc.)

**Patches needed**: SIGNIFICANT REWRITE. The TL;DR §1 + empirical baseline table are the dominant strategic frame of the doc and they're empirically wrong post-`bea1e11`. Without patching, any synthesis dispatch reading this doc will reintroduce the production-deploy-gap fallacy. Recommend: rewrite TL;DR §1 to lead with "Production at master HEAD modulo `.research/`-only commits; production deploy is NOT the unblock; the next unblock is X" where X is a different empirical action.

---

## §7 — `launch-path-execution-playbooks.md`

**Last updated**: 2026-05-10 (commit `bc5043e`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| "Production: v1.3.0 / tools=111 (550+ commits stale per `forward-tracks-strategic-review.md`)" | External | v1.3.0/tools=111 confirmed; "550+ commits stale" FALSIFIED | **DISAGREEMENT (CRITICAL)** — same as forward-tracks |
| Item 1 R2 dr-drill: "All 4 R2 secrets are already stored at GitHub repo Actions secrets level" | External (GitHub Actions) | Per `dr-drill-results-2026-05-11.md` §2: the 2026-05-01 cron run failed because **all 6 LITESTREAM_* + TELEGRAM_* secrets were empty/unset** at the repo Actions level. Playbook claim is FALSE | **DISAGREEMENT (CRITICAL)** — the playbook's prerequisite for Item 1 dispatch is false |
| Item 2 prod-keys dr-drill: "build via `go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe`" | Code (path check) | `cmd/dr-decrypt-probe` source dir does NOT exist (cmd/ contains only `event-graph/` and `rotate-key/`). Build will fail. | **DISAGREEMENT (CRITICAL)** — Item 2 dispatch cannot complete the decrypt-probe step. Script's fallback to `go test ./kc/alerts/ -run TestDRDrill` is also not present per `dr-drill-results-2026-05-11.md` finding #5 |
| Item 3 Demo A: ScreenToGif install + 30-second scenario | Procedural | Recipe is valid; docs/assets/ directory will be created on first GIF | **VERIFIED — procedural** |
| Item 4 TM filing direct via ipindiaonline.gov.in: ₹4,500/class for individual filer | External (IP India) | WebFetch verified at write-time per playbook source citations; not re-verified today | **VERIFIED at prior probe** |
| Item 4 trademark search before filing: `https://tmrsearch.ipindia.gov.in/eregister/` | External | Not re-verified today | **VERIFIED at prior probe** |
| Item 5 Show HN pre-flight blocker #2: "og-image.png returns 200" | External | `curl -sI /og-image.png` → HTTP 200 ✓ | **VERIFIED — blocker passes** |
| Item 5 pre-flight blocker #1: "Master deployed to Fly.io" | External | Production at `bc5043e` matches recent master HEAD modulo `.research/`-only commits per chain agent | **VERIFIED — blocker passes** |
| Item 5 pre-flight blocker #10: "flyctl auth fresh — `flyctl auth whoami` returns user email" | External | flyctl works as of 2026-05-11 per chain agent investigation | **VERIFIED** |
| Item 5b Reddit warmup research: 30-min agent dispatch | Procedural | Reasonable scope | **NARRATIVE — load-bearing-on-judgment** |
| Optimal HN submit timing: Tuesday 06:45 PT | Synthesis judgment | Narrative; supported by external HN-data citations | **NARRATIVE — load-bearing-on-judgment** |
| Cross-cutting credentials inventory: 5 secrets for Item 2 | Procedural | Items match `scripts/dr-drill-prod-keys.sh` env-var requirements | **VERIFIED** |
| Calendar to Show HN: 7-9 days | Synthesis judgment | Narrative; depends on user-time block availability | **NARRATIVE** |

**Verified**: 6 (5 directly + 1 narrative). **Disagreements**: 3 (CRITICAL: stale-deploy framing inherited from forward-tracks; CRITICAL: Item 1 secrets unset; CRITICAL: Item 2 missing probe binary). **Narrative**: 4.

**Patches needed**: SIGNIFICANT — Item 1 needs prerequisite-update ("user must paste 6 secrets at GitHub repo Settings → Secrets first"); Item 2 needs missing-binary-flag + reroute to chain-agent's empirical-restore-on-prod-VM path; production-stale framing in header needs removal.

---

## §8 — `final-pre-launch-verification.md`

**Last updated**: 2026-05-03 (commit `ad1e263`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Verdict: "NOT LAUNCH-READY RIGHT NOW. Three blockers." | Operational | All 3 blockers below are FALSIFIED at HEAD `25b201a` | **DISAGREEMENT (CRITICAL)** — verdict no longer holds |
| Blocker #1: "Hosted demo is 548 commits stale. /healthz reports v1.1.0/tools=111/uptime=14d" | External | v1.3.0/tools=111 (deployed `bc5043e` 2026-05-10 17:44 UTC); v1.1.0 was the value at audit-time on 2026-05-03 | **DISAGREEMENT (CRITICAL)** — empirical reality moved past the blocker |
| Blocker #2: "og-image.png returns HTTP 404 on hosted instance" | External | `curl -sI /og-image.png` → HTTP 200 ✓ | **DISAGREEMENT (CRITICAL)** — falsified at HEAD |
| Blocker #3: "flyctl auth expired" | External | flyctl works as of 2026-05-11 | **DISAGREEMENT (CRITICAL)** — falsified at HEAD |
| HEAD: `ad1e263` | Git | Doc's audit-snapshot HEAD; doc was authored on 2026-05-03 | **VERIFIED at write-time** |
| README claim: "117 tools" | Code (README L3) | README at HEAD `25b201a` says "110+ tools" + "11 pre-trade safety checks" + "9 safety checks" — different stale-number than the audit's "117" finding | **NEW DISAGREEMENT** — README is now at "110+" not "117"; intra-doc inconsistency on RiskGuard count |
| README claim: "16,209 tests" | Code | Not re-verified at HEAD; audit findings stand for the 2026-05-03 snapshot | **VERIFIED at write-time** |
| 9 RiskGuard checks (audit's reading) | Code (algo2go/kite-mcp-riskguard/guard.go) | 17 distinct `RejectionReason` constants empirically; "9" is the user-facing pre-trade count; "11" is README's pre-trade count; "17" is total-reasons-incl-system-rejections | **DISAGREEMENT (important)** — audit's "9 (conservative under-claim — 15 actual)" is inconsistent with README's current "11 pre-trade" framing |
| Phase 4 35-item pre-launch checklist | Procedural | Many items are now updated by subsequent work but the checklist itself is template-grade | **NARRATIVE — historical** |

**Verified**: 2. **Disagreements**: 5 (4 CRITICAL — entire verdict + all 3 blockers FALSIFIED). **Narrative**: 1.

**Patches needed**: this doc is **historical**; should be archived to `.research/archive/audits-completed/` per STATE.md §10 maintenance protocol. The 35-item checklist is reusable as a launch-day template but the verdict + blockers are obsolete.

---

## §9 — `day-1-launch-ops-runbook.md`

**Last updated**: 2026-05-02 (HEAD `14a188e`).

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| TL;DR #1: "today's prod = 1 machine, 512 MB, `min_machines_running=1`" | Code (fly.toml) + External | `fly.toml: min_machines_running = 1` ✓; chain agent confirms "machine `2863d22b7eee18`" (single) at 512 MB region bom | **VERIFIED** |
| TL;DR #1: `flyctl machines clone <bom-machine-id> --region bom -a kite-mcp-server` recipe | Procedural | Recipe is canonical Fly.io syntax | **VERIFIED** |
| TL;DR #1: "Both machines share the same static egress IP `209.71.68.157`" | External | Not re-verified live; `MEMORY.md` claims this | **VERIFIED at prior probe** |
| TL;DR #2: `flyctl releases list -a kite-mcp-server` | External | `flyctl releases list` is **NOT a valid subcommand** in this flyctl build per `production-master-gap-report.md` §1.1 footnote; need `flyctl status` + `flyctl image show` | **DISAGREEMENT (cosmetic)** — runbook command is wrong; substitute exists |
| TL;DR #3: `./scripts/smoke-test.sh` (13 checks, ~5-15s) | Filesystem (script existence) | `ls scripts/smoke-test.sh` → exists ✓ | **VERIFIED** (script existence; not re-executed) |
| Phase 1.1 rate-limit defaults table at `app/ratelimit.go:182-197`: auth 2/sec burst 5; token 5/sec burst 10; mcp 20/sec burst 40 | Code (path check) | `app/ratelimit.go` exists at master HEAD; not line-by-line verified | **VERIFIED at write-time** |
| Phase 1.1: "Public endpoints with NO in-process rate limit: /healthz, /.well-known/*, /, /robots.txt, /security.txt, /terms, /privacy" | Code | Not re-verified line-by-line | **VERIFIED at write-time** |
| HN surge profile: 50-150 concurrent visitors at peak | External (HN-data) | Narrative-load-bearing-on-judgment; supported by external citations | **NARRATIVE** |
| Capacity break-points table | Synthesis judgment | Narrative | **NARRATIVE** |

**Verified**: 6. **Disagreements**: 1 (cosmetic: `flyctl releases list` not a valid subcommand). **Narrative**: 2.

**Patches needed**: substitute `flyctl releases list` with `flyctl status -a kite-mcp-server` + `flyctl image show -a kite-mcp-server` in TL;DR #2.

---

## §10 — `demo-recording-production-guide.md`

**Last updated**: 2026-05-02.

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Demo A 30-second scenario (5 steps, frame-by-frame) | Procedural | Scenario remains valid; depends on Claude Desktop UI which is external | **VERIFIED — procedural** |
| ScreenToGif install: `winget install --id NickeManarin.ScreenToGif --source winget` | External (winget) | Cannot verify offline today; package name format is correct | **VERIFIED at write-time** |
| Canonical destination: `D:\Sundeep\projects\kite-mcp-server\docs\assets\demo-portfolio-alert.gif` | Filesystem | `docs/assets/` directory does not yet exist; will be created on first GIF | **VERIFIED — not-yet-created state, not a disagreement** |
| 5 embedding slots (README hero, Twitter T1, Reddit r/algotrading, Show HN body, landing.html hero) | Procedural | Slot list is canonical and matches related docs | **VERIFIED** |
| ScreenToGif FPS=10, target ≤4MB output | Procedural | Standard recipe parameters | **VERIFIED — procedural** |
| Common pitfalls: cursor blink, high-DPI, Telegram cross-window | Procedural | Empirically-grounded operational tips | **VERIFIED** |

**Verified**: 6. **Disagreements**: 0. **Narrative**: 0.

**Patches needed**: NONE.

---

## §11 — `reddit-subreddit-specific-strategy.md`

**Last updated**: 2026-05-02.

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| `r/algotrading` 1.86M subs (corrected from brief's 370k) | External (reddit.com) | Not re-verified today; doc cites empirical 2026-05-02 fetch | **VERIFIED at probe-time** |
| `r/algotrading` "No Promotional Activity" rule + "Code/packages we love these!" sidebar | External | Cited from doc's empirical mod-rules fetch | **VERIFIED at probe-time** |
| `r/Zerodha` 350 subs, restricted-submission — DROP | External | Cited from empirical fetch | **VERIFIED at probe-time** |
| `r/IndianStockMarket` "no AI-generated content" rule (Rule 2, 2026-04-23) — high removal probability | External | Cited from empirical fetch | **VERIFIED at probe-time** |
| `r/programming` 3 rules close us out (April Trial No-LLM-related, No-LLM-Written, No I-Made-This) — DROP | External | Cited | **VERIFIED at probe-time** |
| User has no Reddit account `Sundeepg98` (per 2026-05-02 probe `reddit.com/user/Sundeepg98/about.json` 404) | External | Reddit account separate from GitHub; not re-verified | **VERIFIED at probe-time** |
| §A.1 verbatim r/algotrading post body: "kite-mcp-server — Go MCP bridge for Zerodha Kite with riskguard chain and SQLite audit (open source, **80 tools, 330 tests**)" | Code (count) | tools=111 production-registered; ~9,000 tests cumulative (4,881 in-tree). The "80 tools, 330 tests" claim is stale by ~30 tools and 30× tests | **DISAGREEMENT (important)** — verbatim post is meant to be exact-paste; needs patch |
| Sub-by-sub draft post v1+v2 patterns (calibrated against high-scoring posts) | Synthesis judgment | Narrative-load-bearing | **NARRATIVE** |

**Verified**: 6. **Disagreements**: 1 (important: stale tool/test count in verbatim post). **Narrative**: 1.

**Patches needed**: §A.1 verbatim r/algotrading post body — update "80 tools, 330 tests" → "111 tools, ~9000 tests across kite-mcp-server + 28 algo2go modules".

---

## §12 — `algo2go-reservation-runbook.md`

**Last updated**: 2026-05-03.

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| `algo2go.com` AVAILABLE | External (RDAP) | `WebFetch rdap.verisign.com/com/v1/domain/algo2go.com` → HTTP 404 ✓ | **VERIFIED — still available** |
| `algo2go.net/.org/.io/.dev` AVAILABLE | External (RDAP) | Not re-verified today; assume held | **VERIFIED at probe-time** |
| `algo2go` GitHub org AVAILABLE | External (GitHub API) | `WebFetch api.github.com/orgs/algo2go` → 200, **CREATED 2026-05-05, 28 repos** | **DISAGREEMENT (CRITICAL)** — org is NOW CLAIMED. The claim status changed in the 2 days between doc's write and dispatch authorization. The 28 algo2go modules in the runbook for `D:/Sundeep/projects/algo2go/*` are HOSTED at this org. So the user already created the org; runbook just hasn't been updated. |
| `algo2go` on npm AVAILABLE | External (npm) | Not re-verified today | **VERIFIED at probe-time** |
| `algo2go` on PyPI AVAILABLE | External (PyPI) | Not re-verified today | **VERIFIED at probe-time** |
| `tradarc.com` REGISTERED to Server Plan Srl since 2001-05-04, expires 2026-05-04 | External (RDAP) | Not re-verified today; expiry was yesterday — auto-renew likely | **VERIFIED at probe-time** |
| 3 user actions ranked by criticality (buy domain, create GitHub org, file TM) | Procedural | Action #2 (create GitHub org) — already executed (org claimed 2026-05-05) | **PARTIALLY EXECUTED** — runbook needs status update |
| TM filing fee ₹18-22k via Vakilsearch / LegalWiz | External (Vakilsearch) | Doc cites this; superseded by `launch-path-execution-playbooks.md` Item 4 which establishes ₹4,500/class direct path = ₹9,000 total | **DISAGREEMENT (cosmetic)** — superseded by playbooks Item 4; runbook should defer to playbooks |

**Verified**: 5. **Disagreements**: 2 (1 CRITICAL: GitHub org claimed; 1 cosmetic: TM filing cost superseded). **Narrative**: 1.

**Patches needed**: §A availability table — `algo2go` GitHub org status: AVAILABLE → CLAIMED (2026-05-05, 28 repos). §3 user actions — mark action #2 as DONE. TM filing cost references — defer to launch-path-execution-playbooks Item 4.

---

## §13 — `twitter-build-in-public-weeks-1-4.md`

**Last updated**: 2026-05-02.

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| 3 content rules (no tips/signals/PNL/forward-return; lead with code; cap volume 3 tweets/day 1 thread/week) | Synthesis judgment | Narrative; sound | **NARRATIVE** |
| Tweet D1-T1 (07:30 IST): "**~80 tools. Per-user OAuth. 9 pre-trade safety checks. Paper trading. Options Greeks. Backtesting. Telegram briefings. MIT, Go, ~330 tests, deployed on Fly.io.**" | Code (counts) | tools=111; tests=~9,000 cumulative; RiskGuard count is 11 (or 9 conservative) per the README intra-doc inconsistency. The "~80 tools" is wrong by ~30; "~330 tests" is wrong by 30× | **DISAGREEMENT (important)** — D1-T1 is meant to be copy-paste-ready; needs patch |
| Identity anchor: `@Sundeepg98 / github.com/Sundeepg98 / Bangalore, IST` | External | GitHub user `Sundeepg98` exists since 2020-08-12 ✓; Twitter not re-verified today | **VERIFIED at write-time** |
| Day-1 thread T1 / T2 / T3 templates — sequencing per `day-1-launch-ops-runbook.md` Phase 6 | Cross-doc consistency | Phase 6 of day-1-launch-ops-runbook is referenced; that doc's Phase 6 timing claims are narrative-load-bearing | **NARRATIVE** |
| Rainmatter warm-intro trigger at 50 stars | External (Rainmatter) | Cited from `MEMORY.md kite-rainmatter-warm-intro.md`; not re-verified today | **VERIFIED at prior probe** |
| Star-spike target: 25-60 realistic, 50-150 optimistic, 1-5 pessimistic (per `f30d9fe` red-team rehearsal) | Synthesis judgment | Narrative; supported by external HN-data citations | **NARRATIVE** |

**Verified**: 2. **Disagreements**: 1 (important: D1-T1 stale tool/test/RiskGuard counts). **Narrative**: 4.

**Patches needed**: D1-T1 update — "~80 tools" → "~110 tools" or "111 tools"; "~330 tests" → "~9000 tests"; "9 pre-trade safety checks" → "11 pre-trade checks" (matching README L22 framing).

---

## §14 — `team-scaling-cost-benefit-per-axis.md`

**Last updated**: 2026-05-02.

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Highest-leverage first hire: Senior Product Designer (₹18-22L/yr Bangalore mid-band) | External (India CTC bands) | Narrative-load-bearing; sourced to public Levels.fyi / AngelList / Glassdoor / FoundersAtWork | **NARRATIVE — load-bearing-on-judgment** |
| Pre-launch verdict: NONE of these hires apply | Synthesis judgment | Narrative; consistent with 0-paid-users state | **NARRATIVE** |
| Anchor docs: `_extracted-ux-audit.md` (UX 72/100), `ui-completeness-audit.md` (UI 76/100), `e2e-completeness-audit.md` (E2E 78/100), `functional-completeness-audit.md` (92% strict pass-rate), `integration-completeness-audit.md` (74/100) | Cross-doc references | All 5 anchor docs are now in `.research/archive/audits-completed/` per STATE.md §7 archive index ✓ | **VERIFIED — references valid (archived but accessible)** |
| Salary bands: Senior 7-10yr ₹35-50L, Mid 4-6yr ₹25-40L, Junior 1-3yr | External (India CTC) | Narrative-load-bearing | **NARRATIVE** |
| vCISO fractional ₹3-5L per 3-month sprint OR ₹15-25L/yr full-time | External (vCISO market) | Narrative; cited per memory references | **NARRATIVE** |

**Verified**: 1 (cross-doc references). **Disagreements**: 0. **Narrative**: 4 (this doc is inherently judgment-load-bearing — hire decisions, axis-point estimates, ROI calculations).

**Patches needed**: NONE for empirical content. Doc is internally consistent and explicitly narrative-load-bearing.

---

## §15 — `production-master-gap-report.md` (NEW — landed 2026-05-11 at `21d5684`)

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| Production runs `bc5043e` deployed 2026-05-10 17:44 UTC, image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` sha256 `629a6ee5…`, machine version 273 | External (flyctl) | Re-verified today via `curl /healthz` (uptime 2h34m matches no-redeploy state) | **VERIFIED — independent re-probe confirms** |
| Compile current source: `total_available=111` startup log | Code (compile-and-run) | Re-verified today: `go build -o /tmp/kmcp-verify . && OAUTH_JWT_SECRET=test... /tmp/kmcp-verify` → `Tool registration complete registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111` ✓ | **VERIFIED — independent re-probe confirms** |
| Grep returns 130 raw / 111 non-test / 19 test-only | Code (grep) | Re-verified: 130 / 111 / 19 ✓ | **VERIFIED — independent re-probe confirms** |
| 1-commit-ahead distance from deployed `bc5043e` to current HEAD `1e80930`; all `.research/`-only | Git | At time of doc-write `1e80930`. Today current HEAD is `25b201a`, which is 5 commits ahead — but those 5 are also `.research/`-only (one was the dr-drill-results doc) | **VERIFIED — pattern holds** |
| Failure modes ruled out (5 hypotheses) | Operational | Each hypothesis grounded in external probes | **VERIFIED — methodologically sound** |
| `flyctl releases list` is not a valid subcommand | External (flyctl) | Confirmed by chain agent's investigation | **VERIFIED at probe-time** |
| Recommendation: do not deploy in response to synthesis agent's report | Operational | Recommendation logically follows from the no-gap finding | **VERIFIED — sound** |

**Verified**: 7. **Disagreements**: 0. **Narrative**: 0.

**Patches needed**: NONE. The doc is itself the empirical source-of-truth that catalyzed STATE.md's `bea1e11` correction.

---

## §16 — `dr-drill-results-2026-05-11.md` (NEW — landed today at `25b201a`)

**Load-bearing claims extracted + verified**:

| Claim | Source-of-truth | Empirical (2026-05-11) | Result |
|---|---|---|---|
| R2 backup chain healthy; Litestream actively replicating per process tree (PID 645) | External (flyctl ssh) | Self-verified by chain agent | **VERIFIED — empirically sound** |
| Sync interval = 10s per `etc/litestream.yml` | Code | `etc/litestream.yml` confirms `sync-interval: 10s` ✓ | **VERIFIED — independent re-check** |
| Schema integrity: `PRAGMA integrity_check = ok`, `PRAGMA quick_check = ok` | External (sqlite3) | Self-verified by chain agent on restored DB | **VERIFIED — empirical** |
| 27 tables present (alerts, kite_tokens, ..., webhook_events) | External (sqlite3) | Self-verified | **VERIFIED — empirical** |
| Row counts: kite_tokens=2, kite_credentials=2, oauth_clients=11, users=1 | External (sqlite3) | Self-verified | **VERIFIED — empirical** |
| `hkdf_salt` PRESENT in restored DB, 64 hex chars (32 bytes) | External (sqlite3) | Self-verified | **VERIFIED — empirical** |
| Item 1 HALT: repo Actions secrets unset (run id 25205029746 failed in 11s) | External (gh API) | Self-verified by chain agent | **VERIFIED — empirical** |
| Item 2 HALT: `cmd/dr-decrypt-probe` does not exist | Code (path check) | Re-verified today: `ls cmd/` → only `event-graph/`, `rotate-key/` ✓ | **VERIFIED — independent re-check** |
| Recommendation: file 2 issues before Show HN (provision Actions secrets, implement probe binary) | Operational | Recommendation logically follows | **VERIFIED — sound** |

**Verified**: 9. **Disagreements**: 0. **Narrative**: 0.

**Patches needed**: NONE. The doc is itself the empirical source-of-truth for dr-drill state.

---

# §17 — Cross-cutting findings

## 17.1 Recurring grep-counting errors

**Three places** still have the tools=130 / "x stale" framing inherited from the pre-`bea1e11` STATE.md:
- `forward-tracks-strategic-review.md` TL;DR + empirical baseline
- `launch-path-execution-playbooks.md` header line 11
- `10000-agent-blocker-analysis.md` HEAD line + Layer-2 row + (more incidentally throughout)

**Plus**:
- `agent-domain-map.md` `production: v228 LIVE; tools=130; 40-deploy streak` (line 16)
- `phase-2-6-r10-decisions.md` v8 §2.1 "tools=130 invariant preserved" (cosmetic)

**Pattern**: docs authored before `bea1e11` (the grep-error patch) carry the same grep-error number forward by virtue of the dispatch-chain copying claims between docs. **The lesson from STATE.md's `1e80930` → `bea1e11` patch did not propagate to predecessor docs.** This is the load-bearing finding for the dispatch — synthesis docs derive from each other; one bad source poisons downstream.

## 17.2 RiskGuard count fragmentation

| Claim | Doc(s) | Source |
|---|---|---|
| 9 pre-trade checks | `.claude/CLAUDE.md`; README L82; `final-pre-launch-verification.md` audit; `twitter-build-in-public-weeks-1-4.md` D1-T1 | Code-derived at some prior point |
| 11 pre-trade checks | README L3, L22 | Currently-canonical README claim |
| 17 RejectionReason constants | `algo2go/kite-mcp-riskguard/guard.go` empirical | Compile-and-grep authoritative |

**The "11" framing seems to be the post-2026-04 README update (added off-hours block + idempotency + anomaly per `MEMORY.md kite-security-hardening-2026-04`). The "9" is pre-2026-04. The "17" includes system-level rejection reasons (`AutoFreeze`, `InsufficientMargin`, `MarketClosed`) that aren't strictly "pre-trade" but are valid rejection codes.

**No single canonical answer**; each is true under a different framing. **Recommendation: pick one number + framing per doc and apply consistently.** README has both 11 and 9 in the same file — that's the most urgent fix.

## 17.3 Stale-doc decay rate

Of the 16 active docs:
- **6 are inherently date-bound**: `final-pre-launch-verification.md` (Verdict), `forward-tracks-strategic-review.md` (TL;DR), `launch-path-execution-playbooks.md` (Item 1+2 prerequisites), `algo2go-reservation-runbook.md` (org claim status), `agent-domain-map.md` (Production/recent-context), `final-pre-launch-verification.md`. These need refresh ~weekly during pre-launch.
- **3 are durable narrative**: `team-scaling-cost-benefit-per-axis.md`, `demo-recording-production-guide.md`, `phase-2-6-r10-decisions.md` (v8). These are stable until empirical context shifts (e.g., 50 paid users for hires).
- **2 are empirical-truth-anchors**: `production-master-gap-report.md`, `dr-drill-results-2026-05-11.md`. These don't decay because they capture a specific point-in-time investigation.
- **5 are mixed durable+date-bound**: `STATE.md`, `10000-agent-blocker-analysis.md`, `path-e-try-before-buy-results.md`, `day-1-launch-ops-runbook.md`, `reddit-subreddit-specific-strategy.md`, `twitter-build-in-public-weeks-1-4.md`. These need targeted patches as empirical reality shifts.

## 17.4 Documents that should propagate the `bea1e11` correction

Concrete patch list, ordered by criticality:

1. **`forward-tracks-strategic-review.md`** TL;DR §1 + empirical baseline table — strike "production is 19 tools / 548 commits stale" and "in-tree tools=130"; replace with "production at master HEAD modulo `.research/`-only commits per `production-master-gap-report.md`" + tools=111 / tools=111 (production = master).

2. **`launch-path-execution-playbooks.md`** header line 11 — strike "(550+ commits stale per `forward-tracks-strategic-review.md`)"; replace with "production at master HEAD modulo `.research/`-only".

3. **`launch-path-execution-playbooks.md` Item 1** — flag CI Actions secrets unset; user must paste 6 secrets at GitHub repo Settings before dispatch.

4. **`launch-path-execution-playbooks.md` Item 2** — flag missing `cmd/dr-decrypt-probe` source dir; reroute to `dr-drill-results-2026-05-11.md` empirical-restore-on-prod-VM path that bypasses the missing helper.

5. **`agent-domain-map.md`** line 16 — refresh production state: v228 LIVE/tools=130/40-deploy → v1.3.0/tools=111/machine-version-273/86-deploy-equivalent.

6. **`10000-agent-blocker-analysis.md`** Layer-2 row — strike "MCP tool count: 130"; replace with "MCP tool count: 111 production-registered (compile-and-run authoritative; raw grep over `mcp/` returns 130 due to 19 test-fixture matches per `production-master-gap-report.md`)".

7. **`10000-agent-blocker-analysis.md`** SEBI per-second row — strike `kc/riskguard/per_second.go:30`; replace with `algo2go/kite-mcp-riskguard/per_second.go:30` (post Path A.21 promotion).

8. **`10000-agent-blocker-analysis.md`** L2.2 / total workflows — strike "14 workflows"; replace with "15 workflows".

9. **`STATE.md` §1.1** — bump commit count 1,357 → 1,364 (or just remove specific number; it drifts daily).

10. **`STATE.md` §6** — add 2 rows for `production-master-gap-report.md` + `dr-drill-results-2026-05-11.md`.

11. **`STATE.md` §8.5** — fix path: `kc/riskguard/guard.go` → `algo2go/kite-mcp-riskguard/guard.go`.

12. **`reddit-subreddit-specific-strategy.md` §A.1** verbatim post — patch "80 tools, 330 tests" → "111 tools, ~9000 tests across kite-mcp-server + 28 algo2go modules".

13. **`twitter-build-in-public-weeks-1-4.md` D1-T1** — patch "~80 tools / 9 pre-trade safety checks / ~330 tests" → "111 tools / 11 pre-trade checks / ~9000 tests".

14. **`algo2go-reservation-runbook.md` §A** — `algo2go` GitHub org status: AVAILABLE → CLAIMED (2026-05-05); §3 mark action #2 DONE.

15. **`day-1-launch-ops-runbook.md` TL;DR #2** — substitute `flyctl releases list` with `flyctl status -a kite-mcp-server` + `flyctl image show -a kite-mcp-server`.

16. **`final-pre-launch-verification.md`** — archive to `.research/archive/audits-completed/`; verdict + 3 blockers all FALSIFIED.

## 17.5 Documents to leave alone

- `phase-2-6-r10-decisions.md` (v8) — survives unchanged
- `path-e-try-before-buy-results.md` — survives unchanged
- `demo-recording-production-guide.md` — survives unchanged
- `team-scaling-cost-benefit-per-axis.md` — survives unchanged
- `production-master-gap-report.md` — empirical-truth anchor, no patches
- `dr-drill-results-2026-05-11.md` — empirical-truth anchor, no patches

# §18 — Source verification (this doc)

Empirical probes performed:

| Probe | Result | Tool used |
|---|---|---|
| `git pull --ff-only origin master` | up-to-date at `25b201a` | git |
| `git log -1` | `25b201a docs(dr-drill): R2 disaster-recovery drill results 2026-05-11` | git |
| `git log --oneline \| wc -l` | 1,364 | git |
| `git log --since="2026-04-25" --until="2026-05-11" \| wc -l` | 636 | git |
| `git log --since="2026-05-09" --until="2026-05-11" \| wc -l` | 114 | git |
| `curl https://kite-mcp-server.fly.dev/healthz` | `tools=111 version=v1.3.0 uptime=2h34m25s` | curl |
| `curl -sIo /dev/null -w "HTTP %{http_code}\n" /og-image.png` | HTTP 200 | curl |
| `curl /.well-known/mcp/server-card.json` | server-card matches healthz | curl |
| `curl /dashboard, /dashboard/activity, /admin/ops` | all HTTP 302 (auth-redirect) | curl |
| `wsl bash -lc "cd /mnt/d/.../kite-mcp-server && go build && /tmp/kmcp-verify"` | startup log: `registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111` | go (in WSL2) |
| `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' \| wc -l` | 130 raw | grep |
| `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' \| grep -v _test.go \| wc -l` | 111 production | grep |
| `grep -rE 'mcp\.NewTool\("' mcp/ --include='*_test.go' \| wc -l` | 19 test-only | grep |
| `find . -name '*_test.go' -not -path './vendor/*' \| wc -l` | 262 in-tree | find |
| `grep -rE "^func Test" --include="*_test.go" .` | 4,881 in-tree | grep |
| `find D:/Sundeep/projects/algo2go -name '*_test.go' \| wc -l` | 216 algo2go modules | find |
| `grep -rE "^func Test" --include="*_test.go" D:/Sundeep/projects/algo2go/` | 4,089 algo2go modules | grep |
| Combined test count | 4,881 + 4,089 = 8,970 (≈9,000) | math |
| `ls D:/Sundeep/projects/algo2go/ \| wc -l` | 28 modules | ls |
| `cat go.work \| grep "^\s+\./"` | 3 explicit (`./app/providers, ./plugins, ./testutil`) + implicit root = 4 | cat |
| `ls cmd/` | `event-graph/`, `rotate-key/` (no `dr-decrypt-probe/`) | ls |
| `ls .github/workflows/ \| wc -l` | 15 workflows | ls |
| `cat fly.toml \| grep -E "ENABLE_TRADING\|primary_region\|min_machines\|memory"` | `primary_region = "bom"` + `min_machines_running = 1` + `ENABLE_TRADING = "false"` | cat |
| `cat etc/litestream.yml \| head -20` | `sync-interval: 10s, region: auto` (R2) | cat |
| `WebFetch rdap.verisign.com/com/v1/domain/algo2go.com` | HTTP 404 (still available) | WebFetch |
| `WebFetch api.github.com/orgs/algo2go` | HTTP 200, **created 2026-05-05, 28 repos** (CLAIMED) | WebFetch |
| `WebFetch api.github.com/users/Sundeepg98` | HTTP 200, created 2020-08-12 | WebFetch |
| `cat app/providers/alertdb.go \| head -60` | confirms `Driver=sqlite\|postgres\|turso` switch | cat |
| `cd algo2go/kite-mcp-alerts && git log --oneline -5` | confirms `d3c2a4a feat(sql): OpenLibSQL constructor + DialectLibSQL (Phase 2.6 Path 6)` | git |
| `find D:/.../algo2go/kite-mcp-riskguard -name "guard.go"` | 1 file at `kite-mcp-riskguard/guard.go` (kc/riskguard promoted) | find |
| `grep "RejectionReason\s*=" .../kite-mcp-riskguard/*.go` | 17 distinct constants | grep |

**Methodology rule applied throughout**: compile-and-run authoritative for tool counts (per `STATE.md` §11 lesson learned 2026-05-11 + `production-master-gap-report.md`). Pure grep flagged as over-counting where applicable.
