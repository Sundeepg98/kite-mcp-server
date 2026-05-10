# STATE.md — Canonical Research Source-of-Truth

**Date**: 2026-05-10
**Master HEAD**: `bc5043e` (`docs(launch-playbooks): per-item execution playbooks for #42-46 cluster`)
**Production**: v1.3.0 / tools=111 (Fly.io BOM region; uptime measured 9-10min at audit-time)
**Charter**: this is THE doc the orchestrator reads first. Everything else in `.research/` is supporting reference; archive is historical.

---

## How to use this doc

- **First-time orientation**: read this top-to-bottom, then dive into `.research/<active-file>.md` only when STATE references it.
- **Returning to a session**: re-read TL;DR + Active Decisions sections. Cross-check production state via `curl https://kite-mcp-server.fly.dev/healthz`.
- **Before dispatching new agent work**: confirm the dispatch domain matches an entry in §Active Cross-References. If not, this doc is missing the work; update STATE first.
- **When a reference doc becomes stale**: `git mv` it to `.research/archive/<topic>/` and update §Active Cross-References + §Archive Index.

---

## TL;DR — three things to know

1. **Phase 2.6 architecturally CLOSED.** libSQL/Turso adapter shipped (commits `d3c2a4a` + `5f8ee3b` + `2919f6e`). `ProvideAlertDB` factory accepts `Driver=sqlite|postgres|turso` via env switch. Production stays on SQLite default (`Driver` env unset). Authoritative doc: `phase-2-6-r10-decisions.md` (v8). All Phase 2.0-2.5 design docs archived.

2. **Production is 19 tools / ~550 commits stale of master.** Master HEAD `bc5043e` has tools=130 in-tree; production is v1.3.0/tools=111. **Closing this gap is the #1 highest-leverage move**, identified in `forward-tracks-strategic-review.md`. The blockers are administrative (flyctl reauth via Playwright, ~30 min), not technical.

3. **Show HN launch is the gating distribution event.** `launch-path-execution-playbooks.md` provides per-item execution recipes for #43 (R2 dr-drill), #44 (Demo GIF), #42 (Algo2Go TM filing), #45 (Reddit warmup), #46 (Show HN submit). End-to-end calendar: 7-9 days from production-deploy. **Hard prerequisite: production deploy must happen FIRST.**

---

## §1 — Architectural state at HEAD `bc5043e`

### 1.1 Repository structure

| Layer | State | Source-of-truth |
|---|---|---|
| **In-tree workspace members** | **4** (root + plugins + testutil + app/providers) | `go.work:1-90` |
| **External algo2go modules** | **28** | `D:/Sundeep/projects/algo2go/*` |
| **Algo2go module list (alphabetical)** | alerts, aop, audit, billing, broker, clockport, cqrs, decorators, domain, eventsourcing, i18n, instruments, isttz, legaldocs, logger, money, oauth, papertrading, registry, riskguard, scheduler, sectors, telegram, templates, ticker, usecases, users, watchlist | `ls D:/Sundeep/projects/algo2go/` |
| **Total commits** | 1,357 lifetime | `git log --oneline | wc -l` |
| **Recent cadence** | 585 commits last 2 weeks; 931 commits in April 2026 alone | `git log --since` |
| **Production deploy count** | ~84 consecutive (per dispatch metadata; empirically verifiable via `flyctl releases list`) | `flyctl` (auth-gated) |
| **Total tests** | ~9,000 across ~437 test files | per `final-pre-launch-verification.md` |
| **MCP tools (in-tree)** | **130** | `grep -rE 'mcp\.NewTool\("' mcp/` |
| **MCP tools (production)** | **111** | `curl /healthz` |
| **Tool count delta** | +19 tools in master not yet deployed | comparison |

### 1.2 Tier 1 + Tier 2 in-tree refactor state

**Tier 1 (closure-DI on facades) — CLOSED**:
- Tier 1.1 brokers (commit `34a32bf`) — `m *Manager` → 8 closure pairs
- Tier 1.2 eventing (commit `fd4b20e`) — `m *Manager` → 16 closure pairs (handles 8-use-case Wave-D propagation)
- Tier 1.3 scheduling (commit `650f4c3`) — `m *Manager` → 4 closure pairs

**Tier 2 (pure-function command registrar extractions) — CLOSED**:
- Per `1c54773 test(kc/manager): add unit tests for 7 pure-function registrars`, 7 registrars now pure-function (Path A owner closed C3)
- 1 pre-existing precedent + 7 extractions = 8 total pure-function registrars

**Two facades remain as deferred work** (acceptable; per `agent-domain-map.md`):
- (specifics in archived `kc-manager-decomp-design.md`)

### 1.3 Phase 2.x persistence layer state

| Phase | Goal | Status | Source |
|---|---|---|---|
| 2.0 | Port-interface stub for Postgres adapter | Closed (in-tree at `c5b9cf7`) | archived `phase-2-postgres-adapter-design.md` |
| 2.1 | SQL portability audit across 5 algo2go persistence repos | Closed (commit `da91a39`) | archived `phase-2-sql-portability-audit.md` |
| 2.2 | OpenPostgresDB constructor + alerts v0.5.0 bump | Closed | archived `phase-2-5-postgres-runbooks.md` |
| 2.3 | Driver-switching ProvideAlertDB factory | Closed (commit `9122a75`) | (in-tree) |
| 2.4 | Postgres placeholder rewriter + round-trip tests | Closed | archived `phase-2-5-postgres-runbooks.md` |
| 2.5 | Operational runbooks for Postgres canary | Closed (commit `3686ac8`) | archived `phase-2-5-postgres-runbooks.md` |
| **2.6** | **libSQL/Turso adapter — 8 versions of R-10 decision research** | **CLOSED at v8** (commit `2919f6e`) | **active**: `phase-2-6-r10-decisions.md` |

**Phase 2.6 closure framework** (per active `phase-2-6-r10-decisions.md` v8):
- Path 6 adopted: libSQL/Turso adapter via `OpenLibSQL` constructor in algo2go/kite-mcp-alerts v0.6.0
- `Driver=turso` env switch wired in `ProvideAlertDB` factory (commit `5f8ee3b`)
- Production stays on SQLite (`Driver` unset → default branch)
- Step 4 (test/dev Fly deploy) SKIPPED — defensible engineering, deferable to flip-time
- libsql-client-go has GitHub deprecation banner BUT is the right choice for our CGO-free pure-remote architecture (alternatives `go-libsql` requires CGO; `tursogo` is BETA + wrong architecture)

### 1.4 Phase E try-before-buy results (still load-bearing)

Per active `path-e-try-before-buy-results.md`:
- **Track 1 (Turso aws-ap-south-1)**: COMPLETED — hello-world round-trip succeeded, fed into Phase 2.6 v6 + v8 decisions
- **Track 2 (DO BLR1, fresh account)**: FALSIFIED — DO docs claim BLR1 supports managed Postgres but UI showed only NA/EU regions for fresh account. Reframed Path 2 in v7 doc as "DO BLR1 not viable for new operator accounts." This empirical finding is **still load-bearing**: any future "should we use DO Postgres BLR1?" decision must re-verify the account-specific availability.
- **Track 3 (1-week synthetic load)**: NOT STARTED — was scoped as optional follow-up if Phase 2.6 picked Path 6 over Path 1

---

## §2 — Distribution + launch state

### 2.1 Production deploy gap (THE blocker)

| Field | Master HEAD | Production | Gap |
|---|---|---|---|
| Version | (untagged, post v1.3.0) | v1.3.0 | ~commits behind |
| Tools | 130 | 111 | +19 not deployed |
| Tests | ~9,000 | (snapshot at v1.3.0 deploy) | sprint-deltas not deployed |
| Commits behind | n/a | ~550+ | mostly Tier 1+2 + Phase 2.x decomposition + cleanup chains |

**Cause**: flyctl auth expires periodically; user has not run `flyctl deploy -a kite-mcp-server` since v1.3.0 cut.
**Mitigation**: re-auth via Playwright per `MEMORY.md` ("flyctl PATH issue — use full path; re-login via Playwright browser automation"). Then `flyctl deploy --remote-only`. ~30 min total.

### 2.2 Show HN launch readiness

Per active `final-pre-launch-verification.md` (the Verdict carries to today + master HEAD):
- 11 pre-flight blockers enumerated
- Production-deploy is blocker #1
- og-image.png 404 on production is blocker #2 (same fix as #1)
- flyctl auth was blocker #3 (still expires periodically)

Per active `launch-path-execution-playbooks.md` §Item 5:
- Optimal title: `Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards`
- Optimal timing: Tuesday 06:45 PT (= 19:15 IST)
- HN convention: URL submission with EMPTY Text field; body posted as FIRST COMMENT
- 4 agent halts at submit time (pre-flight blockers, body review, pre-stage decision, final submit click)

### 2.3 Algo2Go brand reservation state

Per active `algo2go-reservation-runbook.md`:
- `algo2go.com` AVAILABLE as of 2026-05-03 RDAP check
- `algo2go` GitHub org AVAILABLE
- `algo2go` on npm + PyPI AVAILABLE
- TM filing direct via ipindiaonline.gov.in: ₹4,500/class for individual filer
- Class 9 (software) + Class 42 (SaaS) = ₹9,000 total
- Trade-off: Vakilsearch / LegalWiz path is ₹19-22k (₹10-13k savings via direct)
- Backup name `tradarc.com` is **NOT clean** (registered to Italian registrant since 2001-05-04; expired 2026-05-04 but most domains auto-renew — don't gamble)

Per active `launch-path-execution-playbooks.md` §Item 4:
- 5 user halts: scope confirm → IPIndia login → form review → PAN upload → DSC-or-affidavit → payment
- ~50-75 min agent + 15-30 min user time
- Recommendation: defer ₹9k filing until post-Show-HN validation

---

## §3 — Active research questions (gated, no execution yet)

### 3.1 Phase 3 multi-cell architecture

**Status**: trigger has NOT fired (need ≥100 sustained concurrent users; we are at 0 paid).
**Smallest first step**: `flyctl machines clone <bom-id> --region bom -a kite-mcp-server`. Single command, ~60-90s, ~₹30/day. Same static egress IP. Validates 2-cell architecture + serves dual-purpose with HN-surge prep.
**Cost ceiling progression**: 2 cells ~₹1-2k/mo → 5 cells ~₹2.5-5k/mo → 10 cells ~₹5-10k/mo → 100 cells ~₹50k-1L/mo.
**Reference**: archived `10000-agent-blocker-analysis.md` Layer 2 (kept in `.research/` root for cross-link) + `forward-tracks-strategic-review.md` Track 1.

### 3.2 Phase 1.4 self-hosted CI runners

**Status**: trigger has fired (free-tier exhausted at 1,170 commits/mo cadence) but **the cheap mitigation is already in `ci.yml`** (macOS dropped, `concurrency: cancel-in-progress`). Remaining work: full self-hosted Hetzner crossover.
**Smallest first step**: provision Hetzner CPX21 ubuntu-22.04 VM (~$8/mo). Self-hosted runner registration + 1-week soak validation + cutover.
**Cost recovery**: GitHub-hosted ~$155-185/mo at 1,170 commits cadence; Hetzner ~$8/mo. Net positive ~$140-175/mo savings.
**Recommendation**: defer until after Show-HN validation. Speculative engineering deserves cheap CI; don't optimize speculation cost without paid signal.
**Reference**: archived `architecture-scale-paths-A-B-C.md` Path A.

### 3.3 NSE empanelment prep

**Status**: trigger has NOT fired (need 50 paid subs; we are at 0).
**Cheapest pre-work that can happen now**: email `kiteconnect@zerodha.com` with 3 questions per `MEMORY.md feedback_cheapest_compliance_action.md`. Cost ₹0. Establishes paper trail before monetization.
**Pre-Pvt-Ltd-formation halt**: do NOT spend ₹70k-1.2L (Pvt Ltd + lawyer + business account) until Show-HN validates project-fit.
**Reference**: archived `10000-agent-blocker-analysis.md` Layer 1.

---

## §4 — Active decision points (today's dispatch authorization)

Per active `launch-path-execution-playbooks.md`:

| Item | Status | User decision needed |
|---|---|---|
| **#43 R2 dr-drill (basic)** | Awaiting dispatch authorization | YES — small (~15min agent, $0) |
| **#43-prod R2 dr-drill (HKDF chain)** | Awaiting dispatch authorization | YES — requires 5-secret paste; user must use WSL2 terminal directly accessed by agent process |
| **#44 Demo A GIF** | USER-execute task | YES — ~30-60 min user time block |
| **#42 Algo2Go TM filing** | Awaiting dispatch authorization | YES — ~₹9k cost, 5 user halts |
| **#45 Reddit warmup research** | Can dispatch in parallel | YES — research-only, 30min agent |
| **#46 Show HN submit** | Cannot dispatch yet (blocked on master deploy + Items 1+3+5b) | DEFERRED until prerequisites |

**Critical sequencing**: master deploy → Items 1+3+5b → Item 5. ~7-9 days end-to-end.

---

## §5 — Key empirical findings (still load-bearing across multiple decisions)

### 5.1 SEBI rate limit reframing (2026-05-06)

**Original framing**: "SEBI 10/sec is per-operator; multi-Kite-app sharding required for 10K-agent capacity."
**Empirical correction**: SEBI 10/sec is **per (user's-own-Kite-app, user)**. Each user authenticates via THEIR own Kite developer app per BYO-developer-app architecture. **No multi-app sharding needed.** Capacity scales naturally per-user.
**Verified at**: `kc/riskguard/per_second.go:30-50` (already shards rate-limit by user).
**Implication**: 10K-agent cost ceiling collapsed 75% (₹3.5-4.5L/mo → ~₹50K/mo founder-only).

### 5.2 IP whitelist reframing (2026-05-06)

**Original framing**: "SEBI per-user IP whitelist mandate forces multi-cell to require Kite-console scraping or SEBI relaxation petition."
**Empirical correction**: Kite developer console field is "Whitelisted IPs" (PLURAL — accepts an array). User adds N cell IPs to ONE field of ONE Kite app.
**Verified at**: `mcp/plugin_widget_ip_whitelist.go:54`.
**Implication**: multi-cell distribution is ~1 week wizard UI engineering, not regulatory work.

### 5.3 Phase 2 SQL portability audit (2026-05-09)

**Finding**: across 5 algo2go persistence repos (`kite-mcp-alerts`, `kite-mcp-audit`, `kite-mcp-billing`, `kite-mcp-watchlist`, plus host), only **9 SQL statements** required Postgres-specific placeholder rewriting (`?` → `$1` etc). Phase 2.4 placeholder rewriter handles the rewrite at runtime. **Migration surface is small.**
**Implication**: Phase 2.x portability is engineering-tractable; not a 6-month project.
**Reference**: archived `phase-2-sql-portability-audit.md`.

### 5.4 libSQL ecosystem maturity caveats (2026-05-10)

**Finding**: `tursodatabase/libsql-client-go` has GitHub deprecation banner. Investigation showed it's the right choice for CGO-free pure-remote architecture. Alternatives:
- `go-libsql` — requires CGO, breaks our Alpine deploy
- `tursogo` — BETA quality, wrong architecture (per-process not per-app)
**Implication**: ecosystem maturity caveats are NOT a blocker for Phase 2.6; they're documented in v8 doc as "ship-and-never-flip-yet defensive optionality."
**Reference**: active `phase-2-6-r10-decisions.md` v8 §6.

### 5.5 DPDP Act 2023 + SEBI Cloud Framework

**Finding** (per `MEMORY.md kite-landmines.md`):
- DPDP Act 2023: cross-border negative-list model; below SDF threshold cross-border permitted
- SEBI Cloud Framework Circular SEBI/HO/ITD/ITD_VAPT/P/CIR/2023/033 (March 6, 2023): REs narrow definition; algo vendors are AGENTS not REs per Dec 2024 framework
**Implication**: our Path 2 hosted (read-only) + self-host trading architecture stays in safe-harbor below 50 paid subs. Above 50 paid subs: NSE empanelment + DPDP Data Fiduciary registration.

### 5.6 Production deploy gap (since 2026-05-03)

**Finding** (per `final-pre-launch-verification.md` + verified live 2026-05-10): production is v1.3.0/tools=111 against master HEAD's tools=130. ~550 commits behind. **Same finding has held across 7+ days of new dispatches.** Master keeps moving; production keeps standing still.
**Implication**: every strategic recommendation that depends on "what production looks like" is operating against a 7-day-stale baseline. **Closing this gap unblocks the next 6 months of strategic direction.**

---

## §6 — Active cross-references (the 13 docs that REMAIN authoritative)

Listed by domain. Each entry has a 1-line role description.

### Strategic / state docs (3)

| File | Role | Date |
|---|---|---|
| **`STATE.md`** (this) | Canonical source-of-truth — read first | 2026-05-10 |
| **`forward-tracks-strategic-review.md`** | 5-track survey + risk audit + top-5-next-moves ranking | 2026-05-10 |
| **`agent-domain-map.md`** | Live agent → domain mapping for orchestrator routing | 2026-05-09 |

### Phase / architectural state (3)

| File | Role | Date |
|---|---|---|
| **`phase-2-6-r10-decisions.md`** (v8) | Phase 2.6 closure framework + libSQL ecosystem reckoning + Step 4 skip rationale | 2026-05-10 |
| **`path-e-try-before-buy-results.md`** | Track 1 (Turso) success + Track 2 (DO BLR1) falsification — empirical evidence still load-bearing | 2026-05-10 |
| **`10000-agent-blocker-analysis.md`** | Capacity plan reference (Phase 1.4 / Phase 3 / NSE empanelment specs); SEBI rate-limit and IP-whitelist reframings | 2026-05-06 |

### Launch execution (5)

| File | Role | Date |
|---|---|---|
| **`launch-path-execution-playbooks.md`** | Per-item execution recipes for #42-#46 cluster (most recent; supersedes prior) | 2026-05-10 |
| **`final-pre-launch-verification.md`** | 11 pre-flight blockers + 35-item checklist (still load-bearing — production gap not closed) | 2026-05-03 |
| **`day-1-launch-ops-runbook.md`** | Show-HN day operations: pre-stage `flyctl machines clone`, comment triage, incident response | 2026-05-02 |
| **`demo-recording-production-guide.md`** | Demo A 30-second recipe + ScreenToGif + 5 embed slots | 2026-05-02 |
| **`reddit-subreddit-specific-strategy.md`** | Per-sub rules + verbatim r/algotrading post draft + 6-day warmup cadence | 2026-05-02 |

### Brand + content (2)

| File | Role | Date |
|---|---|---|
| **`algo2go-reservation-runbook.md`** | Domain + GitHub org + TM filing — per-action criticality ranking | 2026-05-03 |
| **`twitter-build-in-public-weeks-1-4.md`** | 4-week post-launch Twitter cadence + Day-1 thread template | 2026-05-02 |

### Scaling reference (1)

| File | Role | Date |
|---|---|---|
| **`team-scaling-cost-benefit-per-axis.md`** | Hire-trigger ladder (vCISO → Senior PD → Senior Architect → Founding Director) + India CTC bands | 2026-05-02 |

---

## §7 — Archive index

All archived docs preserved at `.research/archive/<topic>/` via `git mv` (history preserved). 80 docs archived in 5 categories.

### `.research/archive/path-a-modules/` (30 files)

Path A inauguration arc — all 28 algo2go modules promoted (broker through clockport). Each `path-a-N-pick.md` documents the candidate selection + dep-graph audit + LOC/test counts at the time of promotion. Consult only for git archaeology / reproducing a specific module's promotion mechanics.
- `path-a-4-pick.md` through `path-a-27-clockport-pick.md`
- `path-a-8-halt.md` (kc/billing 5+ internal dep cluster halt) + `path-a-8-prime-pick.md` (kc/templates as alt-2)
- `path-a-future-candidates.md`, `path-a-next-target.md`, `path-a-non-kc-track-survey.md`
- `broker-promotion-runbook.md` (template runbook for the pattern)
- `path-b-stop-rule-finding.md` (kc/money transitive dep blocker)

### `.research/archive/tier-anchor-design/` (22 files)

Tier 1+2+3+4 leaf extractions + Anchors 1-6 PR design + B-Full execution runbook + zero-monolith roadmap + 1000-agent capacity plan. All work either shipped (24/24 modules extracted; 3 facade closure-DI; 8 pure-function registrars) OR superseded by `phase-2-6-r10-decisions.md` v8 closure framework.
- `kc-manager-decomp-design.md`, `tier-2-command-registrar-extractions-design.md`, `tier-5-and-anchor-6-pre-stage.md`, `testutil-clock-port-split-design.md`
- `anchor-redesign-plan.md` + 5 anchor-specific PR design docs
- `b-full-20-agent-reframe.md`, `b-full-execution-runbook.md`, `b-full-pr-shapes.md`
- `multi-repo-execute-or-defer.md`, `multi-repo-cliff-reevaluation.md`
- `100-pct-decomposition-strategy.md`, `abc-100pct-complete-paths.md`
- `architecture-scale-ceiling.md`, `architecture-scale-paths-A-B-C.md`, `port-adapter-framework-design.md`, `zero-monolith-roadmap.md`, `1000-agent-capacity-plan.md`

### `.research/archive/audits-completed/` (20 files)

Point-in-time completeness audits + scorecards + path-to-100 docs. Findings are baked into code; numbers are stale; no longer drive action.
- `e2e-completeness-audit.md`, `e2e-100pct-coverage-matrix-v187.md`
- `feature-completeness-audit.md`, `frontend-completeness-audit.md`, `frontend-completeness-audit-v2.md`
- `functional-completeness-audit.md`, `functional-postsprint-revalidation.md`
- `integration-completeness-audit.md`, `integration-postsprint-revalidation.md`
- `ui-completeness-audit.md`, `ui-ux-competitor-benchmark.md`, `ux-completeness-audit.md`, `ux-ui-postsprint-revalidation.md`, `_extracted-ux-audit.md`
- `github-repo-polish-audit.md`, `redundancy-audit.md`, `session-quality-reaudit.md`
- `path-to-100.md`, `path-to-100-final.md`, `residual-literal-100-engineering-path.md`

### `.research/archive/phase-2-completed/` (4 files)

Phase 2.0 through 2.5 design + audit + runbooks. All shipped. Phase 2.6 closure framework supersedes (active in `phase-2-6-r10-decisions.md` v8).
- `phase-2-pick.md`, `phase-2-postgres-adapter-design.md`, `phase-2-sql-portability-audit.md`, `phase-2-5-postgres-runbooks.md`

### `.research/archive/session-scratch/` (6 files)

One-off investigations + diagnostic findings + retired plans.
- `observation-gate-analysis.md` (24h gate falsification — empirical, completed)
- `playwright-2-remaining-diagnosis.md` (E2E fixes shipped)
- `rollback-target.md` (v180 snapshot — production has moved on)
- `revive-family-answers.md` (usecase revival — work landed)
- `test-count-worktree-investigation.md` (worktree pollution — resolved)
- `fresh-forward-plan.md` (2026-04-12 plan — superseded by forward-tracks-strategic-review)

---

## §8 — Conflicts surfaced + resolutions

### 8.1 "v272 LIVE / 84th deploy" vs empirical "v1.3.0 / tools=111"

**Source of conflict**: dispatch metadata across 3+ recent dispatches claims v272 / 84th deploy / tools=130 in production.
**Empirical reality**: `curl https://kite-mcp-server.fly.dev/healthz` returns `{"status":"ok","tools":111,"uptime":"9m32s","version":"v1.3.0"}` (verified 2026-05-10).
**Resolution**: **empirical reality wins**. Production is stale. Dispatch metadata appears to confuse "in-tree state at master HEAD" (which is tools=130) with "deployed state on Fly.io" (which is tools=111). STATE.md, the playbooks, and the strategic review use empirical numbers.
**Action**: production deploy is recommendation #1 in `forward-tracks-strategic-review.md`.

### 8.2 "v8 doc said tools=130; final-pre-launch-verification said tools=128"

**Source of conflict**: `final-pre-launch-verification.md` claims master has 122 unique / 128 NewTool() at HEAD `ad1e263` (older). `phase-2-6-r10-decisions.md` v8 + grep at HEAD `2919f6e` claims tools=130.
**Resolution**: tool count grows over time as new tools land. tools=130 is current at HEAD `bc5043e`. tools=128 was current at HEAD `ad1e263`. **Both correct at their snapshot times.** STATE.md uses tools=130 for in-tree current.

### 8.3 "₹19-22k TM filing cost" vs "₹9k direct filing"

**Source of conflict**: `algo2go-reservation-runbook.md` quotes ₹19-22k via Vakilsearch / LegalWiz / Mytrademarkguide. `MEMORY.md kite-algo2go-rename.md` similar.
**Resolution per `launch-path-execution-playbooks.md` Item 4**: direct filing via ipindiaonline.gov.in is ₹4,500/class for individual filer. Class 9 + Class 42 = ₹9,000. The ₹10-13k delta is service fees from Vakilsearch et al. **Direct path is recommended default.**

### 8.4 "Tradarc.com is documented backup" vs "Tradarc.com is not clean"

**Source of conflict**: `MEMORY.md kite-algo2go-rename.md` claims `tradarc.com` is documented backup if Algo2Go gets contested.
**Empirical correction (2026-05-03)**: `tradarc.com` is REGISTERED to Server Plan Srl since 2001-05-04, expired 2026-05-04 but most domains auto-renew. **Don't gamble.**
**Resolution**: drop Tradarc as a documented backup. If user needs a backup name, fresh research required.

### 8.5 "11 RiskGuard checks" vs "9 RiskGuard checks" vs "8 RiskGuard checks"

**Source of conflict**: `docs/show-hn-post.md` claims 11 checks. `MEMORY.md` claims 9. Older docs claim 8.
**Resolution**: **11 is current** per `kc/riskguard/guard.go` — kill-switch, order-value cap ₹50k, qty limit, daily order count 20/day, rate-limit, per-second rate limit, duplicate-within-30s, daily ₹2L notional, idempotency dedup, anomaly μ+3σ, off-hours block + circuit-breaker + global-freeze layers. The "9" memory note pre-dates the idempotency + anomaly + off-hours additions per `kite-security-hardening-2026-04`.

---

## §9 — Identified gaps (claims not verified anywhere; user-side verification needed)

### 9.1 "Whitelisted IPs" field array length cap

**Claim**: per `10000-agent-blocker-analysis.md` L1.2, the Kite developer console "Whitelisted IPs" field is plural (accepts array).
**Verified**: yes (`mcp/plugin_widget_ip_whitelist.go:54`).
**NOT verified**: array length cap. Likely ≥10 per typical cloud pattern; >50 would need Zerodha conversation.
**Action**: at 5-cell threshold, user must verify with Zerodha. **Not a blocker today.**

### 9.2 "Per-app WebSocket connection limit"

**Claim**: per `10000-agent-blocker-analysis.md` L3.4, ticker WS scaling presumes per-cell WS pool with one connection per (cell, user-app) pair.
**NOT verified**: Kite's per-app WS connection cap. Could be 1 (per-app singleton) or N (parallel).
**Action**: at 5-cell threshold, user must verify with Kite docs. **Not a blocker today.**

### 9.3 "Static egress IP `209.71.68.157`"

**Claim**: per `MEMORY.md` and `final-pre-launch-verification.md`, current static egress IP is `209.71.68.157` (Fly.io BOM region).
**NOT verified live**: requires `flyctl ips list -a kite-mcp-server` (auth-gated; agent flyctl is permission-denied per recent attempt).
**Action**: user runs `flyctl ips list` post-deploy to confirm. If IP changed: user updates Kite developer console whitelist + `docs/show-hn-post.md` body claim before launch.

### 9.4 "OAuth JWT secret rotation"

**Claim**: per `MEMORY.md`, monthly rotation of `OAUTH_JWT_SECRET` is good hygiene.
**NOT verified**: actual rotation cadence. The `dr-drill-prod-keys.sh` script's purpose is partly to validate rotation hasn't lost the encryption salt.
**Action**: user runs Item 2 (HKDF dr-drill) periodically. If exit code 6 (decrypt fail): rotation broke the encryption chain; investigate.

### 9.5 "Kite Connect ₹500/mo per app"

**Claim**: per `MEMORY.md`, Kite Connect price reduced from ₹2000 to ₹500/mo mid-2025. One active user session per app.
**NOT verified live**: pricing or active-session-cap status today (not since memory was updated).
**Action**: orchestrator confirms with user before any pricing-relevant strategic call (e.g., "should we cap free tier at 1 user-app?").

### 9.6 "Kite Connect daily token expiry ~6 AM IST"

**Claim**: per `MEMORY.md`, Kite access token expires ~6 AM IST daily; smart token expiry detection runs.
**NOT verified live**: the exact behavior under SEBI Apr 2026 framework changes.
**Action**: orchestrator monitors for `MEMORY.md kite-sebi-otr-feb-2026` or later updates. **Not a blocker today.**

---

## §10 — Maintenance protocol

### When to update STATE.md

1. **After any structural commit** that changes (a) module count, (b) tool count, (c) production deploy, (d) phase closure, (e) major decision: update §1 + §2 + relevant §3-§5 sections.
2. **After archiving any new docs**: update §6 (active list) + §7 (archive index).
3. **After resolving any conflict surfaced in §8**: cross out the entry with the date of resolution.
4. **When a §9 gap is empirically resolved**: move the entry to §5 (key findings) and note the verification date.

### When NOT to update STATE.md

- Don't update for transient findings that aren't load-bearing across decisions.
- Don't update after every commit; daily-summary cadence is fine.
- Don't update for archived-doc reads (consult-only operations).

### Archive a doc

```bash
# from D:/Sundeep/projects/kite-mcp-server
git mv .research/<file>.md .research/archive/<topic>/<file>.md
# Update STATE.md §6 (remove from active list) + §7 (add to archive index)
git add .research/STATE.md
git commit -m "docs(research): archive <file> + STATE.md update" \
    -o -- .research/STATE.md ".research/archive/<topic>/<file>.md" \
          .research/<file>.md
git push
```

---

## §11 — Source verification (this doc)

Every load-bearing claim above is cross-referenced to:
- Active `.research/*.md` files (12 docs + STATE.md = 13)
- Live empirical probes:
  - `git log -1` HEAD = `bc5043e`
  - `git log --oneline | wc -l` = 1,357 lifetime commits
  - `curl /healthz` = v1.3.0/tools=111 (2026-05-10)
  - `grep -rE 'mcp\.NewTool\(' mcp/` = 130 in-tree
  - `ls D:/Sundeep/projects/algo2go/` = 28 modules
  - `cat go.work` = 4 in-tree workspace members
- `MEMORY.md` (user's auto-memory; orchestrator-scoped)
- Archived `.research/archive/<topic>/*.md` (historical reference; do not consult by default)

**This doc supersedes ad-hoc orientation reads.** When in doubt, re-read STATE.md first; consult archived docs only when a specific claim needs deeper grounding.
