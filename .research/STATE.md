# STATE.md — Canonical Research Source-of-Truth
<!-- Refreshed 2026-05-16 -->

**Date**: 2026-05-16 (refreshed after Sprint 0 merge + Phase 1 kc/ extraction LIVE; 21 commits past prior `6e72014` baseline)
**Master HEAD**: `449aff1` (`chore(go.mod): bump bootstrap to v0.2.1 (Phase 1 kc/ extraction)`)
**Production**: v1.3.0 / tools=111 (Fly.io BOM region; machine version 275, **66 consecutive deploys with tools=111 invariant** through today; healthz live-verified 2026-05-16)
**Production-vs-master gap**: Phase 1 extraction (kc/+app/metrics/+tools-common/) shipped to bootstrap repo via Sprint 0 PR #1 merge (`3f57acf`) + cleanup (`46d15ae`). Bootstrap `v0.2.0` was burned by GOPROXY immutability incident (see `feedback_goproxy_immutability` memory rule); forward-only fix is `v0.2.1` consumed at master HEAD `449aff1`. Production runs the prior image (tools=111 unchanged); next deploy is doc/refactor-only — no functional gap.
**Charter**: this is THE doc the orchestrator reads first. Everything else in `.research/` is supporting reference; archive is historical.

---

## How to use this doc

- **First-time orientation**: read this top-to-bottom, then dive into `.research/<active-file>.md` only when STATE references it.
- **Returning to a session**: re-read TL;DR + Active Decisions sections. Cross-check production state via `curl https://kite-mcp-server.fly.dev/healthz`.
- **Before dispatching new agent work**: confirm the dispatch domain matches an entry in §Active Cross-References. If not, this doc is missing the work; update STATE first.
- **When a reference doc becomes stale**: `git mv` it to `.research/archive/<topic>/` and update §Active Cross-References + §Archive Index.

---

## TL;DR — three things to know

1. **Sprint 0 MERGED + Phase 1 kc/ extraction LIVE.** Sprint 0 PR #1 merged at `3f57acf` (bootstrap composition root relocated to `algo2go/kite-mcp-bootstrap`); orphan-test cleanup at `46d15ae`. Phase 1 cutover landed in bootstrap at `b33912e` (canary-deletion of in-tree `kc/`), with `algo2go/kite-mcp-kc v0.1.0` (then `v0.1.1` after internal/util/ reorg) consumed via bootstrap `v0.2.1`. Also LIVE: `algo2go/kite-mcp-metrics v0.1.0` + `algo2go/kite-mcp-tools-common v0.1.0`. **Total algo2go module count: 32** (28 domain + bootstrap + kc + metrics + tools-common; verified `ls D:/Sundeep/projects/algo2go/` 2026-05-16).

2. **Production stays at tools=111 — invariant across 66 consecutive deploys.** Production reports `tools=111` (live-verified 2026-05-16 via `curl /healthz`). The tool-registration invariant has held across ~84 → 275 machine-version deploys (per dispatch chain metadata; 66 consecutive holds across the structural decomposition arc). Phase 1 extraction is a structural refactor — no tool-surface change. The earlier "19 tools / ~550 commits stale" framing was a measurement artefact (grep over `*_test.go` fixtures over-counted by 19; see §5.6 + §8.6). **No functional deploy gap exists.**

3. **Show HN launch is the gating distribution event.** `launch-path-execution-playbooks.md` provides per-item execution recipes for #43 (R2 dr-drill), #44 (Demo GIF), #42 (Algo2Go TM filing), #45 (Reddit warmup), #46 (Show HN submit). End-to-end calendar: 7-9 days from production-deploy. **Hard prerequisite: production deploy must happen FIRST.**

---

## §1 — Architectural state at HEAD `449aff1`

### 1.1 Repository structure

| Layer | State | Source-of-truth |
|---|---|---|
| **In-tree workspace members (kite-mcp-server master)** | **1** (root only — Sprint 0 + Phase 1 collapsed it from 4) | `go.work` post-`3f57acf` (verified 2026-05-16) |
| **External algo2go modules** | **32 total** (28 domain + bootstrap + kc + metrics + tools-common) | `ls D:/Sundeep/projects/algo2go/` (verified 2026-05-16) |
| **Algo2go module list (alphabetical)** | alerts, aop, audit, billing, **bootstrap** (Sprint 0), broker, clockport, cqrs, decorators, domain, eventsourcing, i18n, instruments, isttz, **kc** (Phase 1 LIVE 2026-05-16), legaldocs, logger, **metrics** (Phase 1 LIVE 2026-05-16), money, oauth, papertrading, registry, riskguard, scheduler, sectors, telegram, templates, ticker, **tools-common** (Phase 1 LIVE 2026-05-16), usecases, users, watchlist | `ls D:/Sundeep/projects/algo2go/` (verified 2026-05-16) |
| **algo2go modules consumed by production (master)** | **31 of 32** — `kite-mcp-aop` is promoted but ORPHANED (`go mod why` says "main module does not need package") | `go list -m all` empirical probe (verified 2026-05-16) |
| **Sprint 0 bootstrap-relocation status** | **MERGED via PR #1 at `3f57acf`** (2026-05-16 17:32 IST). Orphan-test cleanup at `46d15ae`. Bootstrap repo `algo2go/kite-mcp-bootstrap` at v0.2.1 (forward-only after the v0.2.0 GOPROXY-immutability burn — see `feedback_goproxy_immutability` memory rule) | `git log` + `git tag` (verified 2026-05-16) |
| **Phase 1 kc/ extraction status** | **LIVE in bootstrap at `b33912e`** (canary deletion of in-tree `kc/`; `algo2go/kite-mcp-kc v0.1.0` is canonical; bumped to `v0.1.1` at `3def64c` for internal/util/ reorg). `kite-mcp-server` master consumes via bootstrap `v0.2.1` at `449aff1` | `git log` + bootstrap go.mod (verified 2026-05-16) |
| **In-tree non-test LOC on master** | **~178 LOC** (41-line `main.go` + 137-line `go.mod`) — irreducible deploy thin-shell post Sprint 0 + Phase 1 | `wc -l main.go go.mod` (verified 2026-05-16) |
| **Total commits** | 1,418 lifetime (21 commits past prior STATE baseline at `6e72014` from earlier today; Sprint 0 + Phase 1 + GOPROXY-immutability fix + research docs) | `git log --oneline \| wc -l` (verified 2026-05-16) |
| **Production deploy count** | **66 consecutive deploys with tools=111 invariant** at v275 (today); empirically verifiable via `flyctl releases list` | `flyctl` (auth-gated) |
| **Total tests** | ~9,000 across ~437 test files (in-tree count now ~zero; tests live in algo2go/* modules + bootstrap) | per `final-pre-launch-verification.md` |
| **MCP tools (production-registered)** | **111** | `curl /healthz` 2026-05-16 returned `{"status":"ok","tools":111,"uptime":"29m36s","version":"v1.3.0"}` |
| **MCP tools (master-built binary)** | **111** | identical to production — invariant has held for 66 consecutive deploys |
| **Tool count delta** | **0** — no gap exists | the prior "+19 in-tree tools not deployed" claim was a grep error: `grep -rE 'mcp\.NewTool\("' mcp/` includes 19 calls in `_test.go` fixture files. **Footnote for future synthesis**: when counting tools, MUST filter `--include='*.go' \| grep -v _test.go` OR (preferred) compile-and-run the binary to read the `total_available=N` startup log line. Pure grep over `mcp/` over-counts by ~19 test-fixture lines. |
| **Dependency-state ladder (code we own under algo2go)** | Today (master `449aff1` post Sprint 0 + Phase 1): **~99.8% in algo2go**, ~0.2% (178 LOC deploy thin-shell) → Post-org-transfer: **literal 100%** all repos under algo2go org | `algo2go-dependency-state-2026-05-11.md` + `path-to-100-percent-algo2go-2026-05-11.md` (claims revised by Sprint 0 + Phase 1; verified 2026-05-16) |

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

### 2.1 Production deploy state (NO gap — Phase 1 LIVE, tools=111 invariant holds)

**Empirical truth** (verified 2026-05-16 via `curl https://kite-mcp-server.fly.dev/healthz`):

| Field | Master HEAD `449aff1` | Production | Status |
|---|---|---|---|
| Tools (production-registered) | 111 (invariant) | **111** | **matches; 66 consecutive deploys** |
| Version | v1.3.0 (the binary's hardcoded version literal) | v1.3.0 | matches |
| Machine version on Fly | n/a | **275** | dispatch chain ~84 → 275 |
| Source state (post Sprint 0 + Phase 1) | in-tree thin shell (~178 LOC) | image built from prior commit (Sprint 0 + Phase 1 not yet redeployed) | **no functional gap; structural refactor only** |

**Conclusion**: there is no functional deploy backlog. Sprint 0 (composition root relocated to bootstrap) and Phase 1 (kc/+metrics/+tools-common/ extracted to algo2go modules) shipped today as structural refactors with tools=111 invariant preserved. Production runs the prior image with identical tool surface. Earlier sections of STATE.md and `forward-tracks-strategic-review.md` claimed "production is 19 tools / ~550 commits stale" — that claim was a measurement artefact (130 raw grep matches; 19 in test files; 111 production-registered). The tool-count invariant has held across the full structural decomposition arc.

**No `flyctl deploy` needed for code surface.** The Phase 1 cutover preserved bit-equivalent tool registration; a redeploy would not change the user-facing surface. flyctl auth was working at investigation time; the prior "flyctl reauth via Playwright, ~30 min" framing in `launch-path-execution-playbooks.md` may be conservative or out-of-date.

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
- `algo2go` GitHub org **CREATED 2026-05-05** (**32 public repos** as of 2026-05-16: 28 domain modules + bootstrap + kc + metrics + tools-common after Phase 1 extraction)
- `algo2go` on npm + PyPI AVAILABLE
- TM filing direct via ipindiaonline.gov.in: ₹4,500/class for individual filer
- Class 9 (software) + Class 42 (SaaS) = ₹9,000 total
- Trade-off: Vakilsearch / LegalWiz path is ₹19-22k (₹10-13k savings via direct)
- Backup name `tradarc.com` is **NOT clean** (registered to Italian registrant since 2001-05-04; expired 2026-05-04 but most domains auto-renew — don't gamble)

### 2.4 Path to literal 100% algo2go — staged work (refreshed 2026-05-16)

Per active `path-to-100-percent-algo2go-2026-05-11.md` (claim values updated by Sprint 0 + Phase 1 merging today):
- **Today (post Sprint 0 + Phase 1 LIVE)**: **~99.8% of code we own is under `algo2go/*`** (just ~178 LOC of deploy thin-shell remains in `Sundeepg98/kite-mcp-server`: 41-line main.go + 137-line go.mod)
- **30-second user action to close the gap**: `gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer -F new_owner=algo2go`
- **Empirically verified Fly impact**: ZERO — `flyctl status` shows `Owner=personal` (Fly org), `Image=kite-mcp-server:deployment-...` (built+pushed locally, not pulled from GitHub URL). `fly.toml` has zero GitHub URL refs.
- **Empirically verified mcp-remote impact**: ZERO — cache keyed by Fly URL (`kite-mcp-server.fly.dev/mcp`), unchanged by GitHub transfer.
- **Empirically verified GitHub Actions secrets state**: empty (zero secrets configured today; nothing to preserve through transfer)
- **MCP Registry name gotcha**: `io.github.Sundeepg98/kite-mcp-server` v1.2.0 active, isLatest=true, publishedAt 2026-04-19. Registry primary-key `name` is permanently locked; only `repository.url` is mutable via next-version publish. **Resolution**: accept legacy name (Path 5.3.a in source doc); update `repository.url` post-transfer (Item 1 of earlier batch already did this in source server.json at `6e72014`).
- **Deploy-prep work landed today**: Item 1 (`6e72014`) patched 8 hard-coded `Sundeepg98/kite-mcp-server` URL references — including the CRITICAL `dr-drill.yml` + `dr-drill-prod-keys.yml` `if: github.repository ==` hard checks that would have silently skipped post-transfer.

### 2.5 Sprint 0 bootstrap-relocation state — **MERGED 2026-05-16**

Per Sprint 0 PR #1 merge commit `3f57acf` + audit dispatches at `ec8f640` (preservation audit) + `5167a11` (mergeability audit) + cleanup at `46d15ae`:
- **PR #1 MERGED**: `Sundeepg98/kite-mcp-server` PR #1 (`bootstrap-relocation` → `master`) merged at `3f57acf` on 2026-05-16 17:32 IST
- 516 .go files moved from kite-mcp-server in-tree (kc/+app/+mcp/+plugins/+testutil/) to `algo2go/kite-mcp-bootstrap`
- 373 import lines bulk-rewritten (`github.com/zerodha/kite-mcp-server/*` → `github.com/algo2go/kite-mcp-bootstrap/*`)
- Orphan-test cleanup post-merge at `46d15ae` (removed 6 integration tests that depended on now-extracted in-tree packages)
- All 4 prior workspace members (root + app/providers + plugins + testutil) compile clean on bootstrap repo
- `go test ./...` exit 0 across all 18 bootstrap packages (~67s wall-clock)
- Bonus quality fixes shipped: SA1012 nil-context fix in `bootstrap_test.go`, timezone-sensitive test correctness in `app/app_test.go` (3 cases), `go mod tidy` direct/indirect classification
- Pre-merge preservation audit (`sprint-0-preservation-audit.md` @ `ec8f640`) + mergeability audit (`sprint-0-pr-mergeability-audit.md` @ `5167a11`) confirmed zero data loss; 167+ ad-hoc shell scripts pre-archived at `0b44ca8` to `.research/scripts-archive-2026-05-16/`

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

### 5.7 209.71.68.157 egress-IP claim is STALE (2026-05-11 falsification)

**Finding** (per `egress-ip-stale-sweep-2026-05-11.md`, commit `7559133`): the `209.71.68.157` IP value cited across multiple docs (server.json `deployment.egressIp`, README, scripts/smoke-test.sh check #5, etc.) was historically the bom-region static egress IP but is no longer accurate. The actual current egress IPs (from `flyctl ips list -a kite-mcp-server`) are: an IPv6 + shared `66.241.125.151`. **No patch needed for code** — server.json's `deployment.egressIp` is a metadata-only field consumed by no production code path; the value is informational. The "stale-sweep" research falsified the premise that an active fix was required.

**Implication**: any future SEBI-mandate-IP-whitelist discussion must re-probe `flyctl ips list -a kite-mcp-server` for the current value, NOT cite the docs-embedded `209.71.68.157`. The IP is empirically a moving target that flyctl assigns; docs should reference how to query it, not embed a literal.

### 5.8 Dependency-state ladder (refreshed 2026-05-16 — code we own vs algo2go)

**Finding** (per `algo2go-dependency-state-2026-05-11.md` + `path-to-100-percent-algo2go-2026-05-11.md`; revised by today's Sprint 0 merge + Phase 1 kc/ extraction):

| State | Code in algo2go | Code in kite-mcp-server in-tree | Verdict |
|---|---|---|---|
| Prior (master `6e72014`, 2026-05-11 morning) | 46% (46,405 LOC across 28 algo2go modules) | 54% (54,504 LOC in kc/+app/+mcp/+plugins/+testutil/) | NOT fully algo2go |
| **Today (master `449aff1`, post Sprint 0 + Phase 1 LIVE)** | **~99.8%** (~100,000 LOC across **32 modules** — 28 domain + bootstrap + kc + metrics + tools-common) | **~0.2% (~178 LOC** deploy thin-shell: main.go 41 + go.mod 137) | NEARLY YES |
| Post-org-transfer (`Sundeepg98 → algo2go`) | ~99.8% | ~0.2% | YES (every repo under algo2go org) |
| Post-decomposition (kc.Manager dissolved further into algo2go modules) | ~99.8% | ~0.2% (irreducible deploy floor) | FULL YES |

**Empirical methodology** (verified 2026-05-16): `ls D:/Sundeep/projects/algo2go/` = 32 modules; `wc -l main.go go.mod` = 178 LOC in-tree; `cat go.work` = root-only workspace; `curl /healthz` = tools=111. NOT inherited from prior synthesis.

**Critical asterisk**: the MCP Registry name `io.github.Sundeepg98/kite-mcp-server` is permanently locked (registry primary-key immutability rule). Even post-transfer, the registry entry retains the legacy name; only `repository.url` updates. Cosmetic only — doesn't affect functionality.

### 5.9 Option B refactor (Manager accessor drain) — **4 of 8 done; 4 remain** (refreshed 2026-05-16)

**Finding** (per `option-b-expose-properties-2026-05-11.md`, commit `2b57212`; progress updated 2026-05-16): Anchor 6 PRs 6.1-6.14 already drained 7 accessor methods via the exact "expose unexported field + delete getter" pattern (commits `5514fa3`, `629413b`, `e4f31ff`, `5e98596`, `4d6c69d`, `8b282ff`, `62599d7`). Continuing the pattern, **4 of the 8 remaining accessors are now drained**: SessionManager, ManagedSessionSvc, SessionSigner all drained; UpdateSessionSignerExpiry removed entirely. Tool count invariant at 111; no rollback events. **Only 2 of 5 originally-planned PRs remain**: B3 (MCPServer) + B5 (CommandBus/QueryBus capstone). Recommendation: GO FULL Option B (continue).

**Empirical call-site counts** (live grep on bootstrap HEAD `f4e2215`): CommandBus 77 non-test, QueryBus 74, SessionManager (DRAINED), ManagedSessionSvc (DRAINED), SessionSigner (DRAINED), MCPServer 14, UpdateSessionSignerExpiry (REMOVED), SetMCPServer 1. 87% of remaining accessor traffic is CommandBus/QueryBus alone (capstone PR B5).

### 5.10 DDD score — ~85% (refreshed 2026-05-16; up from 75%)

**Finding** (per today's audit findings; supersedes prior `path-to-100-final.md` 75% score): the Domain-Driven Design score has materially improved to **~85%** as of 2026-05-16. Order, Position, Session, and Alert aggregates are all **rich domain entities** now — no longer anemic. The prior 75% figure (from `archive/audits-completed/path-to-100-final.md`) predated several rounds of behavior-attraction work that landed in `algo2go/kite-mcp-domain` + `algo2go/kite-mcp-usecases` modules.

**Methodology**: per-aggregate evaluation — anemic (only fields + getters) → rich (fields + invariants + behavior). Today: 4 of the 4 load-bearing aggregates passed the rich-entity bar. The remaining ~15% gap is concentrated in (a) value-object extraction completeness across the broker port surface, (b) repository-pattern purity for the legacy alerts SQL layer (Phase 2.6 closure does not require it).

**Implication**: the "75% DDD" framing in stale planning docs should NOT drive new prioritization. DDD path is now in maintenance mode; the next refactor priority is Path Y substantive decomposition (per `decomposition-blockers-comprehensive-2026-05-11.md`).

---

## §6 — Active cross-references (the 13 docs that REMAIN authoritative)

Listed by domain. Each entry has a 1-line role description.

**Structural note (refreshed 2026-05-16)**: `.research/` was split into subdirs to make doc-class explicit (per `.research/maintenance-strategy/value-framework.md` Class A-G + 3-tier model + corpus-maintenance synthesis at `.research/CORPUS-MAINTENANCE-STRATEGY.md`):

- `.research/` (root) = **active Tier 1 Live** (STATE.md, INDEX.md, agent-domain-map.md) + **Class C/F synthesis still mid-flight** (forward-tracks, launch-path, 10000-agent, runbooks, plus 3 new Sprint 0 docs landed today)
- `.research/decisions/` (5 files) = **Class B Decision Records** — write-once captures of WHY a path was chosen; never edited in-place; newer-version supersedes
- `.research/audits/<YYYY-MM-DD>/` (7 files at `2026-05-11/`) = **Class G Ephemera** — point-in-time verification reports; auto-archive after 30 days OR after newer audit-cycle of same scope
- `.research/research/` (**NEW** as of 2026-05-11; **26 files** as of 2026-05-16 — `dead-code-utilization-analysis-2026-05-11.md` added) = **Class C/F research dispatches** — topic-keyed analyses (decomposition blockers, dependency-state, GitHub transfer mechanics, end-state architecture, god-object inventory, etc.). Each file is single-author, single-topic, dated. See §6.3 below.
- `.research/maintenance-strategy/` (4 files) = corpus-governance docs (value-framework, maintenance-model, doc-classification, CORPUS-MAINTENANCE-STRATEGY)
- `.research/scripts-archive-2026-05-16/` (**NEW 2026-05-16**; 202 archived shell scripts) = pre-Sprint-0 preservation; all ad-hoc dispatch/build/test scripts moved here at commit `0b44ca8` to clean the tree before PR #1 merge. Preserve for git archaeology; do not consult by default.
- `.research/archive/<topic>/` = historical reference (preserved for git archaeology only)

### 6.3 `.research/research/` corpus — 26 dispatches (refreshed 2026-05-16)

Topic-keyed research outputs from the 2026-05-11 multi-agent dispatch arc + 2026-05-16 follow-ups. All dated `2026-05-11` (synthesis day) or `2026-05-16` (Sprint 0 day). Listed alphabetically:

| File | Topic | Authoritative for | Date |
|---|---|---|---|
| `algo2go-dependency-state-2026-05-11.md` | Empirical % code-we-own vs algo2go | "Are we fully on algo2go?" question + 46%/99.3%/100% ladder | 2026-05-11 |
| `algo2go-umbrella-rebrand-strategy-2026-05-11.md` | Brand/market positioning angle | algo2go umbrella vs single-product framing | 2026-05-11 |
| `architecture-integration-audit-2026-05-11.md` | 7 cross-module flows audit; ALL GREEN | Integration test gap inventory | 2026-05-11 |
| `cloudflare-bitwarden-install-plan-2026-05-11.md` | Cloudflare Code Mode + Bitwarden MCP install plan | MCP ecosystem expansion roadmap | 2026-05-11 |
| `day-1-launch-ops-2026-05-11.md` | Show-HN day operations refresh | Day-1 runbook (fly MCP + dr-decrypt-probe + H1 deltas) | 2026-05-11 |
| `dead-code-utilization-analysis-2026-05-11.md` | Dead-code WHY analysis + HOW to utilize | Dead-code inventory + utilization decisions | 2026-05-11 (added 2026-05-16) |
| `decomposition-blockers-comprehensive-2026-05-11.md` | 10 categories of decomposition blockers; 145-288h Tier-1+2 estimate | Path Y substantive decomposition roadmap | 2026-05-11 |
| `e2e-ui-completeness-audit-2026-05-11.md` | 12/12 Playwright specs pass against prod v1.3.0 | E2E UI coverage state | 2026-05-11 |
| `egress-ip-stale-sweep-2026-05-11.md` | 209.71.68.157 premise FALSIFIED | No patch needed for IP-in-docs; query flyctl instead | 2026-05-11 |
| `end-state-architecture-2026-05-11.md` | Meta-synthesis of Path A + Audit + Chain reports | Where the codebase is converging | 2026-05-11 |
| `floss-fund-rainmatter-readiness-2026-05-11.md` | FLOSS/fund + Rainmatter readiness check | Funding pathway readiness | 2026-05-11 |
| `flyctl-friction-and-playwright-capabilities.md` | flyctl friction inventory + Playwright MCP capabilities | Tooling state | 2026-05-11 |
| `github-transfer-bootstrap-2026-05-11.md` | GitHub transfer mechanics + bootstrap module design | Sprint 0 design spec | 2026-05-11 |
| `god-object-inventory-2026-05-11.md` | 10-step decomposition roadmap; Manager 63-fields → ≤10 | Path Y per-slice work items | 2026-05-11 |
| `gtm-launch-sequence-2026-05-11.md` | GTM launch sequence refresh against 58dc369 baseline | Pre-launch sequence | 2026-05-11 |
| `launch-readiness-verdict-2026-05-11.md` | CONDITIONAL GO verdict | Launch-readiness gate | 2026-05-11 |
| `mcp-ecosystem-audit-2026-05-11.md` | MCP ecosystem audit + prioritized install/build queue (Track 3) | MCP ecosystem state | 2026-05-11 |
| `option-b-expose-properties-2026-05-11.md` | Option B refactor design — expose unexported Manager fields | Manager accessor drain plan (5 PRs, 6-9h) | 2026-05-11 |
| `path-to-100-percent-algo2go-2026-05-11.md` | Residual analysis + transfer mechanics for literal 100% algo2go | Path-to-100%-algo2go playbook | 2026-05-11 |
| `playwright-empirical-drill-2026-05-11.md` | storageState/TOTP/sudo-mode confirmed | Playwright MCP confirmation | 2026-05-11 |
| `pre-launch-ux-audit-2026-05-11.md` | First-5-min UX audit refresh | UX state pre-launch | 2026-05-11 |
| `sebi-shared-vs-dedicated-ip-2026-05-11.md` | SEBI April 2026 mandate deep-dive | Shared vs dedicated IPv4 analysis | 2026-05-11 |
| `showhn-redteam-2026-05-11.md` | Show HN re-red-team — 30 archetypes + CRITICAL leaked-secrets finding | Show HN attack-surface inventory | 2026-05-11 |
| `test-coverage-audit-2026-05-11.md` | 32 modules empirically measured | Test coverage state | 2026-05-11 |
| `twitter-build-in-public-finalized-2026-05-11.md` | Weeks 1-4 finalized — supersedes 2026-05-02 plan | Twitter cadence plan | 2026-05-11 |
| `zerodha-compliance-email-2026-05-11.md` | Refresh draft + AT-T-1h send-timing recommendation | Compliance comms timing | 2026-05-11 |

### Strategic / state docs (4)

| File | Role | Date |
|---|---|---|
| **`STATE.md`** (this) | Canonical source-of-truth — read first | 2026-05-16 |
| **`INDEX.md`** | Question-keyed lookup table across 7 corpus locations | 2026-05-11 |
| **`forward-tracks-strategic-review.md`** | 5-track survey + risk audit + top-5-next-moves ranking | 2026-05-10 |
| **`agent-domain-map.md`** | Live agent → domain mapping for orchestrator routing | 2026-05-09 |

### Sprint 0 + bootstrap decomposition (3 NEW root docs landed 2026-05-16)

| File | Role | Commit | Date |
|---|---|---|---|
| **`sprint-0-preservation-audit.md`** | Comprehensive what-could-be-lost analysis pre-merge | `ec8f640` | 2026-05-16 |
| **`sprint-0-pr-mergeability-audit.md`** | Empirical trial-merge mergeability audit | `5167a11` | 2026-05-16 |
| **`bootstrap-decomp-strategy.md`** | Bootstrap decomposition strategy REV 2 (Path A reconciliation) | `280ae67` | 2026-05-16 |

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
- Active `.research/*.md` files (16 docs + STATE.md = 17 after today's additions)
- Live empirical probes (verified 2026-05-16):
  - `git log -1` HEAD = `449aff1` (`chore(go.mod): bump bootstrap to v0.2.1`)
  - `git log --oneline | wc -l` = 1,418 lifetime commits
  - `curl https://kite-mcp-server.fly.dev/healthz` returned `{"status":"ok","tools":111,"uptime":"29m36s","version":"v1.3.0"}` (2026-05-16)
  - **Tool count empirical methodology** (lesson learned 2026-05-11; see §5.6 + §8.6): authoritative count comes from compile-and-run, NOT grep. Method 1: `go build -o /tmp/kmcp-test . && OAUTH_JWT_SECRET=… ALERT_DB_PATH=… /tmp/kmcp-test` and read the `total_available=N` startup log line. Method 2: `curl /healthz | jq .tools` (production runtime). Method 3 (NOT authoritative — over-counts): `grep -rE 'mcp\.NewTool\(' mcp/`. The grep over `mcp/` over-counts by ~19 because it includes test-fixture `mcp.NewTool(...)` calls in `_test.go` files which are never registered in production. Always footnote the method when reporting any code-grep number.
  - `ls D:/Sundeep/projects/algo2go/` = **32 modules** (28 domain + bootstrap + kc + metrics + tools-common)
  - `cat go.work` = root-only workspace (post Sprint 0)
  - `wc -l main.go go.mod` = 178 LOC in-tree deploy thin-shell
- `MEMORY.md` (user's auto-memory; orchestrator-scoped) — see also `feedback_goproxy_immutability` (new rule landed 2026-05-16 from the bootstrap v0.2.0 → v0.2.1 incident)
- Archived `.research/archive/<topic>/*.md` (historical reference; do not consult by default)

**This doc supersedes ad-hoc orientation reads.** When in doubt, re-read STATE.md first; consult archived docs only when a specific claim needs deeper grounding.
