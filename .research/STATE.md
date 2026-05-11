# STATE.md — Canonical Research Source-of-Truth

**Date**: 2026-05-10
**Master HEAD**: `bc5043e` (`docs(launch-playbooks): per-item execution playbooks for #42-46 cluster`)
**Production**: v1.3.0 / tools=111 (Fly.io BOM region; machine version 273, image `deployment-01KR9FPJC88YA80VWS7VMTWTY7`, deployed 2026-05-10 17:44 UTC against commit `bc5043e`)
**Charter**: this is THE doc the orchestrator reads first. Everything else in `.research/` is supporting reference; archive is historical.

---

## How to use this doc

- **First-time orientation**: read this top-to-bottom, then dive into `.research/<active-file>.md` only when STATE references it.
- **Returning to a session**: re-read TL;DR + Active Decisions sections. Cross-check production state via `curl https://kite-mcp-server.fly.dev/healthz`.
- **Before dispatching new agent work**: confirm the dispatch domain matches an entry in §Active Cross-References. If not, this doc is missing the work; update STATE first.
- **When a reference doc becomes stale**: `git mv` it to `.research/archive/<topic>/` and update §Active Cross-References + §Archive Index.

---

## TL;DR — three things to know

1. **Phase 2.6 architecturally CLOSED.** libSQL/Turso adapter shipped: `algo2go/kite-mcp-alerts d3c2a4a feat(sql): OpenLibSQL constructor + DialectLibSQL (Phase 2.6 Path 6)` (external repo) + `kite-mcp-server 5f8ee3b` (driver factory wiring) + `kite-mcp-server 2919f6e` (R-10 v8 closure doc). `ProvideAlertDB` factory accepts `Driver=sqlite|postgres|turso` via env switch. Production stays on SQLite default (`Driver` env unset). Authoritative doc: `phase-2-6-r10-decisions.md` (v8). All Phase 2.0-2.5 design docs archived.

2. **Production is at master HEAD modulo `.research/`-only commits.** Production runs image `deployment-01KR9FPJC88YA80VWS7VMTWTY7` built from commit `bc5043e`; current master `21d5684` is 1-2 commits ahead but those commits are `.research/`-only (excluded from Docker build context). **No deploy needed.** Tool count: production reports `tools=111`; master-built binary registers `total_available=111` (verified by chain agent compiling + running locally — see `production-master-gap-report.md`). The earlier "19 tools / ~550 commits stale" framing was a measurement artefact: a `grep mcp.NewTool(` over `mcp/` returned 130 because it included 19 test-fixture calls in `*_test.go` files; filtering with `grep -v _test.go` yields 111. **No gap exists.**

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
| **MCP tools (production-registered)** | **111** | `curl /healthz` AND chain-agent's local `go build` + run: startup log says `registered=93 gated_trading=18 total_available=111` |
| **MCP tools (master-built binary)** | **111** | identical to production — verified by compiling current master HEAD locally (per `production-master-gap-report.md` §1.4) |
| **Tool count delta** | **0** — no gap exists | the prior "+19 in-tree tools not deployed" claim was a grep error: `grep -rE 'mcp\.NewTool\("' mcp/` includes 19 calls in `_test.go` fixture files. **Footnote for future synthesis**: when counting tools, MUST filter `--include='*.go' \| grep -v _test.go` OR (preferred) compile-and-run the binary to read the `total_available=N` startup log line. Pure grep over `mcp/` over-counts by ~19 test-fixture lines. |

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
- **Track 2 (DO BLR1, fresh account)**: PAYMENT-METHOD-GATED — DO docs claim BLR1 supports managed Postgres but UI showed only NA/EU regions for fresh accounts (no card on file). Reframed Path 2 in v7 doc as "DO BLR1 reachability is payment-method-gated for new operator accounts." Per the source `path-e-try-before-buy-results.md`: the empirical observation was UI-level (regions hidden until payment authorization), NOT that BLR1 is unavailable. This finding is **still load-bearing**: any future "should we use DO Postgres BLR1?" decision must re-verify with a payment-method-authorized account.
- **Track 3 (1-week synthetic load)**: NOT STARTED — was scoped as optional follow-up if Phase 2.6 picked Path 6 over Path 1

---

## §2 — Distribution + launch state

### 2.1 Production deploy state (NO gap — corrected 2026-05-11)

**Empirical truth** (per chain agent's investigation at `.research/decisions/production-master-gap-report.md`, commit `21d5684`):

| Field | Master HEAD | Production | Status |
|---|---|---|---|
| Deploy commit | (production runs `bc5043e`) | `bc5043e` (verified via image hash `629a6ee5…` = `deployment-01KR9FPJC88YA80VWS7VMTWTY7`) | **production matches deploy commit** |
| Master HEAD ↔ deployed-image distance | 1-2 commits ahead | n/a | **all `.research/`-only** (excluded from Docker build context) |
| Source-code mutations between deployed commit and current HEAD | **0** | n/a | bit-equivalent build |
| Version | v1.3.0 (the binary's hardcoded version literal) | v1.3.0 | matches |
| Tools (production-registered) | 111 | 111 | **matches** |
| Tools (master-built binary, verified by chain agent) | 111 | 111 | **matches** |
| Machine version on Fly | n/a | 273 | matches dispatch chain v273 reports |

**Conclusion**: there is no deploy backlog. Earlier sections of STATE.md and `forward-tracks-strategic-review.md` claimed "production is 19 tools / ~550 commits stale" — that claim originated in a grep that included `_test.go` fixtures (130 raw matches; 19 in test files; 111 production-registered). The chain agent compiled the current master HEAD locally and the binary registers exactly `total_available=111` — identical to production. **The dispatch-chain metadata (v228 → v274) was tracking real deploys correctly; only STATE.md's source-counting was wrong.**

**No `flyctl deploy` needed.** A doc-only deploy of the `.research/`-cleanup commits would produce a bit-equivalent image (cf. v263–v272 doc-only sub-arc that all shared image sha256). flyctl auth was working at investigation time; the prior "flyctl reauth via Playwright, ~30 min" framing in `launch-path-execution-playbooks.md` may be conservative or out-of-date.

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
**Verified at**: `algo2go/kite-mcp-riskguard/per_second.go:30-50` (post Path A.21 promotion — was `kc/riskguard/per_second.go` pre-promotion; already shards rate-limit by user).
**Implication**: 10K-agent cost ceiling collapsed 75% (₹3.5-4.5L/mo → ~₹50K/mo founder-only).

### 5.2 IP whitelist reframing (2026-05-06)

**Original framing**: "SEBI per-user IP whitelist mandate forces multi-cell to require Kite-console scraping or SEBI relaxation petition."
**Empirical correction**: Kite developer console field is "Whitelisted IPs" (PLURAL — accepts an array). User adds N cell IPs to ONE field of ONE Kite app.
**Verified at**: `mcp/plugin_widget_ip_whitelist.go:54`.
**Implication**: multi-cell distribution is ~1 week wizard UI engineering, not regulatory work.

### 5.3 Phase 2 SQL portability audit (2026-05-09)

**Finding** (corrected 2026-05-11 against archived source `phase-2-sql-portability-audit.md:482-493`): **`pgx/v5/stdlib` accepts `?` placeholders transparently — ZERO placeholder rewrite needed for the database/sql stdlib path** (which is what alerts repo uses). The prior STATE.md framing of "9 SQL statements required Postgres-specific placeholder rewriting" contradicted the cited source; the "9 statements" figure refers to total parametrized SQL statements in the migration surface, NOT how many need rewriting. Phase 2.4 placeholder rewriter (`alerts/db_queries.go`) exists as a defensive layer for non-stdlib paths but is not invoked under the stdlib-default flow.
**Implication**: Phase 2.x portability is engineering-tractable; not a 6-month project. Effective rewrite-cost = 0 statements under default wiring.
**Reference**: archived `phase-2-sql-portability-audit.md` §"Critical finding".

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

### 5.6 Source-counting methodology — compile-and-run > grep-and-count (2026-05-11)

**Finding** (per chain agent's `production-master-gap-report.md`, commit `21d5684`): a naive `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go'` over-counts the registered tool count by exactly 19 because 19 of the matches are inside `_test.go` files (test fixtures, not production-registered). The correct empirical methodology is one of:

1. **Compile-and-run** the binary and read the `Tool registration complete registered=N excluded=N gated_trading=N total_available=N` startup log line. This is the source-of-truth — `/healthz` returns the same `total_available` count via `len(mcp.GetAllTools())` at `app/http.go:619`.
2. **Filter the grep**: `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -v _test.go`. Acceptable as a quick check but not authoritative.

**Implication beyond tool count**: any "in-tree count" claim derived from `grep` over `*.go` files in mixed code+test directories is suspect. **Future synthesis MUST footnote the counting method** when reporting any code-grep number. The flawed STATE.md "tools=130 in-tree" claim caused 4 consecutive synthesis dispatches to recommend "production deploy is the #1 unblock" against a non-existent gap. Cost: ~6 hours of misdirected research synthesis. The lesson is durable — applies to any grep-derived metric (test counts, tool counts, riskguard checks, etc.).

**The earlier "production deploy gap is THE blocker" finding (held in this slot through 2026-05-03 → 2026-05-10) is FALSIFIED.** No gap existed. The dispatch-chain reports of v228 → v274 deploys were real; production bit-equivalent to master HEAD modulo `.research/`-only commits.

---

## §6 — Active cross-references (the 13 docs that REMAIN authoritative)

Listed by domain. Each entry has a 1-line role description.

**Structural note (2026-05-11)**: `.research/` was split into subdirs to make doc-class explicit (per `.research/maintenance-strategy/value-framework.md` Class A-G + 3-tier model + corpus-maintenance synthesis at `.research/CORPUS-MAINTENANCE-STRATEGY.md`):

- `.research/` (root) = **active Tier 1 Live** (STATE.md, INDEX.md, agent-domain-map.md) + **Class C/F synthesis still mid-flight** (forward-tracks, launch-path, 10000-agent, runbooks)
- `.research/decisions/` (5 files) = **Class B Decision Records** — write-once captures of WHY a path was chosen; never edited in-place; newer-version supersedes
- `.research/audits/<YYYY-MM-DD>/` (7 files at `2026-05-11/`) = **Class G Ephemera** — point-in-time verification reports; auto-archive after 30 days OR after newer audit-cycle of same scope
- `.research/maintenance-strategy/` (4 files) = corpus-governance docs (value-framework, maintenance-model, doc-classification, CORPUS-MAINTENANCE-STRATEGY)
- `.research/archive/<topic>/` = historical reference (preserved for git archaeology only)

### Strategic / state docs (4)

| File | Role | Date |
|---|---|---|
| **`STATE.md`** (this) | Canonical source-of-truth — read first | 2026-05-11 |
| **`INDEX.md`** | Question-keyed lookup table across 7 corpus locations | 2026-05-11 |
| **`forward-tracks-strategic-review.md`** | 5-track survey + risk audit + top-5-next-moves ranking | 2026-05-10 |
| **`agent-domain-map.md`** | Live agent → domain mapping for orchestrator routing | 2026-05-09 |

### Phase / architectural state — root + decisions/ (3 active)

| File | Role | Date |
|---|---|---|
| **`decisions/phase-2-6-r10-decisions.md`** (v8) | Phase 2.6 closure framework + libSQL ecosystem reckoning + Step 4 skip rationale | 2026-05-10 |
| **`decisions/path-e-try-before-buy-results.md`** | Track 1 (Turso) success + Track 2 (DO BLR1) falsification — empirical evidence still load-bearing | 2026-05-10 |
| **`10000-agent-blocker-analysis.md`** | Capacity plan reference (Phase 1.4 / Phase 3 / NSE empanelment specs); SEBI rate-limit and IP-whitelist reframings | 2026-05-06 |

### Decision records — `decisions/` subdir (Class B, write-once)

| File | Role | Date |
|---|---|---|
| **`decisions/phase-2-6-r10-decisions.md`** | v8 closure for libSQL/Turso adoption (also listed in Phase/architectural above) | 2026-05-10 |
| **`decisions/path-e-try-before-buy-results.md`** | Try-before-buy results for Turso vs DO BLR1 (also listed above) | 2026-05-10 |
| **`decisions/production-master-gap-report.md`** | Chain agent's investigation falsifying the "production stale" framing | 2026-05-11 |
| **`decisions/dr-drill-results-2026-05-11.md`** | R2 disaster-recovery drill state + decrypt-probe gap finding | 2026-05-11 |
| **`decisions/rotate-key-runbook-2026-05-11.md`** | `OAUTH_JWT_SECRET` rotation procedure | 2026-05-11 |

### Launch execution (4) — `final-pre-launch-verification.md` archived at `a772e9c` per §10 protocol

| File | Role | Date |
|---|---|---|
| **`launch-path-execution-playbooks.md`** | Per-item execution recipes for #42-#46 cluster (most recent; supersedes prior) | 2026-05-10 |
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

### Corpus maintenance — `maintenance-strategy/` subdir (2026-05-11 dispatch)

| File | Role | Date |
|---|---|---|
| **`CORPUS-MAINTENANCE-STRATEGY.md`** | Canonical synthesis of value-framework + maintenance-model + doc-classification | 2026-05-11 |
| **`maintenance-strategy/value-framework.md`** | Abstract criteria — 7 doc classes (A-G) + 3 tiers + 5 long-term-value principles | 2026-05-11 |
| **`maintenance-strategy/maintenance-model.md`** | Ownership + automation model — stewards per doc-class + frontmatter conventions | 2026-05-11 |
| **`maintenance-strategy/doc-classification.md`** | Per-doc verdicts across the 280-doc corpus | 2026-05-11 |

### Today's audits — `audits/2026-05-11/` (Class G Ephemera; SOON-TO-ARCHIVE)

7 verification reports produced 2026-05-11. Their verdicts are baked into `maintenance-strategy/doc-classification.md`. Per framework §3.G: auto-archive to `archive/audits-completed/` after 30 days OR newer audit-cycle of same scope.

- `audits/2026-05-11/active-docs-verification-2026-05-11.md`
- `audits/2026-05-11/memory-files-verification-2026-05-11.md`
- `audits/2026-05-11/repo-docs-verification-2026-05-11.md`
- `audits/2026-05-11/STATE-claims-audit-2026-05-11.md`
- `audits/2026-05-11/STATE-fresh-eyes-diff-2026-05-11.md`
- `audits/2026-05-11/STATE-v2-fresh-eyes.md`
- `audits/2026-05-11/research-batch-2026-05-11.md`

---

## §7 — Archive index

**Three categories of historical-reference subdirs (2026-05-11 structural split)**:

1. **`.research/archive/<topic>/`** — historical reference; preserved for git archaeology only. 5 sub-categories below; 80+ docs total.
2. **`.research/audits/<YYYY-MM-DD>/`** — Class G Ephemera (point-in-time verification reports). Active until 30-day auto-archive. Current: `audits/2026-05-11/` with 7 reports.
3. **`.research/decisions/`** — Class B Decision Records. Write-once; newer-version supersedes; never edited in-place. Current: 5 decision records.

`audits/` rolls into `archive/audits-completed/` after 30 days OR after a newer audit-cycle of the same scope. `decisions/` stays indefinitely (audit trail).

### `.research/decisions/` (5 active decision records)

- `phase-2-6-r10-decisions.md` (v8) — Phase 2.6 closure; libSQL/Turso adoption + Step 4 skip
- `path-e-try-before-buy-results.md` — Try-before-buy empirical (Turso ✓; DO BLR1 payment-method-gated)
- `production-master-gap-report.md` — Chain agent's "no gap exists" investigation
- `dr-drill-results-2026-05-11.md` — R2 disaster-recovery drill + decrypt-probe gap finding
- `rotate-key-runbook-2026-05-11.md` — `OAUTH_JWT_SECRET` rotation procedure

### `.research/audits/2026-05-11/` (7 files — current cycle)

- `active-docs-verification-2026-05-11.md` (16/20 active docs verified)
- `memory-files-verification-2026-05-11.md` (76 memory files audited)
- `repo-docs-verification-2026-05-11.md` (22/124 repo docs deep-read)
- `STATE-claims-audit-2026-05-11.md` (claim-by-claim grading of STATE.md)
- `STATE-fresh-eyes-diff-2026-05-11.md` (independent re-synthesis diff)
- `STATE-v2-fresh-eyes.md` (fresh-eyes STATE re-synthesis)
- `research-batch-2026-05-11.md` (14-question synthesis batch)

### `.research/archive/<topic>/` — historical reference (80+ docs, 5 sub-categories below)

All archived docs preserved via `git mv` (history preserved).

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

### 8.1 "v272 LIVE / 84th deploy" vs empirical "v1.3.0 / tools=111" — REVISED 2026-05-11

**Original framing (now corrected)**: dispatch metadata across 3+ dispatches claimed v272 / 84th deploy / tools=130 in production. STATE.md initially read this as "dispatch metadata wrong; production is stale."

**Corrected framing** (per chain agent's `production-master-gap-report.md`, commit `21d5684`):
- The dispatch-chain metadata was **CORRECT all along**. v228 → v274 deploys really happened; `flyctl status` confirms machine version 273, image hash `629a6ee5…`, deployed 2026-05-10 17:44 UTC against commit `bc5043e`.
- The binary's hardcoded `version` field is `v1.3.0` (a literal in source). It does NOT auto-bump on deploy. So `/healthz` reporting `version=v1.3.0` does NOT mean the binary is from the v1.3.0 deploy era — the v1.3.0 string is just the binary's internal version constant which has not been incremented in source.
- Production tools=111 = master-built tools=111. No gap.

**Resolution**: STATE.md's earlier "production is stale" framing was wrong because it conflated (a) the `version` field literal in `/healthz` (which doesn't change deploy-to-deploy) with (b) actual deploy state (which v228 → v274 dispatch metadata correctly tracked).

**Updated action**: no deploy needed. The "production deploy is recommendation #1" call in `forward-tracks-strategic-review.md` is FALSIFIED. Surface this back to the strategic-review doc + playbook in next synthesis pass.

### 8.6 "tools=130 in-tree" vs empirical "tools=111 in master-built binary" — NEW 2026-05-11

**Source of conflict**: STATE.md §1.1 (initial commit `1e80930`) claimed `MCP tools (in-tree): 130` based on `grep -rE 'mcp\.NewTool\("' mcp/` returning 130 hits. The same grep was used as a foundational "production-master gap" indicator across 4 synthesis dispatches.

**Empirical reality** (per chain agent at HEAD `21d5684`):
- `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go'` → 130 hits (raw)
- `grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -v _test.go` → 111 hits (production-registered)
- `grep -rE 'mcp\.NewTool\("' mcp/ --include='*_test.go' | wc -l` → 19 hits (test fixtures)
- 111 + 19 = 130 (the raw grep figure)
- Compile current master HEAD: `go build -o /tmp/kmcp-test . && /tmp/kmcp-test` → startup log: `Tool registration complete registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111`

**Resolution**: **compile-and-run > grep-and-count.** The grep was counting test-fixture `mcp.NewTool(...)` calls inside `_test.go` files which are never registered in production. The 19-test-fixture count happened to exactly match the apparent "tool gap" (130 - 111 = 19) — pure coincidence.

**Methodology fix**: the Source verification §11 of this doc now mandates compile-and-run as the authoritative tool-count method. Pure grep is documented as over-counting. Future agents must footnote the counting method.

**Cost of the error**: ~6 hours of synthesis dispatches recommending "production deploy is the #1 unblock" against a non-existent gap. Resolved by chain agent's 10-minute compile-and-run investigation.

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
**Resolution**: **11 is current** per `algo2go/kite-mcp-riskguard/guard.go` (post Path A.21 promotion — was `kc/riskguard/guard.go` pre-promotion) — order-value cap ₹50k, qty limit, daily order count 20/day, rate-limit, per-second rate limit, duplicate-within-30s, daily ₹2L notional, idempotency dedup, confirmation required, anomaly μ+3σ, off-hours block — plus kill-switch + circuit-breaker + global-freeze + auto-freeze + OTR-band + insufficient-margin + market-closed system-rejection layers (17 `RejectionReason` constants total; 11 user-facing pre-trade). The "9" memory note pre-dates the idempotency + anomaly + off-hours additions per `kite-security-hardening-2026-04`.

### 8.7 Dr-drill launch blockers (NEW 2026-05-11)

**Source**: `dr-drill-results-2026-05-11.md` findings #4 + #5 + `research-batch-2026-05-11.md` §C + §D.

**Two operational gaps block playbook Items #1 + #2** (per `launch-path-execution-playbooks.md`):

1. **GitHub repo Actions secrets unset** — the 2026-05-01 monthly cron run (id `25205029746`) failed in 11s at the env-var gate. All 6 secrets (`LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_BUCKET`, `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_DR_CHAT_ID`) inject as empty strings. **Item #1 cannot dispatch until provisioned.** Provision script: `research-batch-2026-05-11.md` §D (six `gh secret set` commands, idempotent).

2. **`cmd/dr-decrypt-probe` source dir does not exist** — `ls cmd/` returns only `event-graph/` + `rotate-key/`. The script `scripts/dr-drill-prod-keys.sh:147-166` references `/tmp/dr-decrypt-probe` binary; script's fallback path mentions `go test ./kc/alerts/ -run TestDRDrill` (synthetic test analog) which DOES exist at `algo2go/kite-mcp-alerts/dr_drill_prod_keys_test.go` as `TestDRDrill_ProductionKeyChain_Synthetic` + `TestDRDrill_WrongSecret_FailsLoudly`. Spec for the missing binary at `research-batch-2026-05-11.md` §C (~1.5h Go implementation, 8-phase logic, exit codes 0/2/5/6).

**Neither blocker is "production is broken"** — Litestream replication to R2 is healthy, salt is preserved, structural restore byte-identical per `dr-drill-results-2026-05-11.md` §1.2. Both are "we have not empirically proven the encrypted-column round-trip end-to-end" gaps.

**Resolution path**: dispatch implements `cmd/dr-decrypt-probe` per §C spec → user pastes 6 secrets via §D script → CI green on next monthly cron OR manual workflow_dispatch trigger.

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

### Structural division (2026-05-11)

`.research/` now has 4 distinct subdirs for 4 distinct doc lifecycles. **Each new research doc must land in the right subdir on creation, not get re-classified later.** Per `.research/maintenance-strategy/value-framework.md` §3:

| Subdir | Lifecycle | Class | When to write here |
|---|---|---|---|
| `.research/` (root) | Active Live + active synthesis | A (Canonical State) + F (Synthesis mid-flight) | Singletons (STATE, INDEX, agent-domain-map); active synthesis docs being iterated on |
| `.research/decisions/` | Write-once; never edited | B (Decision Records) | Capturing WHY a path was chosen + alternatives + falsifications. New version = new file (e.g., `r10-v9-decisions.md`); old stays. |
| `.research/audits/<YYYY-MM-DD>/` | Write-once; auto-archive after 30 days | G (Ephemera — verification reports) | Point-in-time audits (verification reports, claims-audits, fresh-eyes diffs). Filename includes date for visible decay-by-design. |
| `.research/maintenance-strategy/` | Quasi-singleton; supersede-only | A + F (corpus-governance) | Value-framework, maintenance-model, doc-classification. Pair with `CORPUS-MAINTENANCE-STRATEGY.md` at `.research/` root as canonical synthesis. |
| `.research/archive/<topic>/` | Historical reference; never delete | (any class after lifecycle ended) | Anything that ran its course (audits-completed, path-a-modules, tier-anchor-design, phase-2-completed, session-scratch). |

### When to update STATE.md

1. **After any structural commit** that changes (a) module count, (b) tool count, (c) production deploy, (d) phase closure, (e) major decision: update §1 + §2 + relevant §3-§5 sections.
2. **After archiving any new docs**: update §6 (active list) + §7 (archive index).
3. **After resolving any conflict surfaced in §8**: cross out the entry with the date of resolution.
4. **When a §9 gap is empirically resolved**: move the entry to §5 (key findings) and note the verification date.
5. **After any `git mv` between subdirs** (active ↔ decisions/ ↔ audits/ ↔ archive/): update §6 and §7 references in the same commit; patch any cross-references in active docs.

### When NOT to update STATE.md

- Don't update for transient findings that aren't load-bearing across decisions.
- Don't update after every commit; daily-summary cadence is fine.
- Don't update for archived-doc reads (consult-only operations).

### Archive a doc (and migrate between subdirs)

```bash
# from D:/Sundeep/projects/kite-mcp-server

# === Variant 1: a written-once decision record goes to decisions/ subdir ===
git mv .research/<file>.md .research/decisions/<file>.md

# === Variant 2: a point-in-time audit/verification report goes to audits/<date>/ subdir ===
mkdir -p .research/audits/<YYYY-MM-DD>
git mv .research/<file>.md .research/audits/<YYYY-MM-DD>/<file>.md

# === Variant 3: a fully-completed doc goes to archive/<topic>/ ===
git mv .research/<file>.md .research/archive/<topic>/<file>.md

# In every variant:
# 1. Update STATE.md §6 (remove from active list) + §7 (add to relevant subdir)
# 2. Update INDEX.md cross-references (sed-rename any .research/<file>.md references)
# 3. Patch any active synthesis docs that referenced the moved file
git add .research/STATE.md .research/INDEX.md <other-modified-active-docs>
git commit -m "docs(research): migrate <file> to <new-location> + cross-ref patches" \
    -o -- .research/STATE.md .research/INDEX.md ".research/<new-location>/<file>.md" \
          .research/<file>.md <other-modified-active-docs>
git push
```

---

## §11 — Source verification (this doc)

Every load-bearing claim above is cross-referenced to:
- Active `.research/*.md` files (12 docs + STATE.md = 13)
- Live empirical probes:
  - `git log -1` HEAD = `bc5043e`
  - `git log --oneline | wc -l` = 1,357 lifetime commits
  - `curl /healthz` = v1.3.0/tools=111 (2026-05-10, re-verified 2026-05-11 = same)
  - **Tool count empirical methodology** (lesson learned 2026-05-11; see §5.6 + §8.6): authoritative count comes from compile-and-run, NOT grep. Method 1: `go build -o /tmp/kmcp-test . && OAUTH_JWT_SECRET=… ALERT_DB_PATH=… /tmp/kmcp-test` and read the `total_available=N` startup log line. Method 2: `curl /healthz | jq .tools` (production runtime). Method 3 (NOT authoritative — over-counts): `grep -rE 'mcp\.NewTool\(' mcp/`. The grep over `mcp/` over-counts by ~19 because it includes test-fixture `mcp.NewTool(...)` calls in `_test.go` files which are never registered in production. Always footnote the method when reporting any code-grep number.
  - `ls D:/Sundeep/projects/algo2go/` = 28 modules
  - `cat go.work` = 4 in-tree workspace members
- `MEMORY.md` (user's auto-memory; orchestrator-scoped)
- Archived `.research/archive/<topic>/*.md` (historical reference; do not consult by default)

**This doc supersedes ad-hoc orientation reads.** When in doubt, re-read STATE.md first; consult archived docs only when a specific claim needs deeper grounding.
