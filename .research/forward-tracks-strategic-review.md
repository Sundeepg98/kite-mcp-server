# Forward-Tracks Survey + Strategic Review

**Date**: 2026-05-10
**HEAD audited**: `2919f6e` (`docs(phase-2-6): R-10 re-research v8 (libSQL ecosystem reckoning + Step 4 skip)`)
**Charter**: research-only synthesis. Doc-only. NO code changes. Decision aid for "what to do next given everything that's been built."
**Predecessor docs (anchors)**: `10000-agent-blocker-analysis.md`, `architecture-scale-paths-A-B-C.md`, `algo2go-reservation-runbook.md`, `day-1-launch-ops-runbook.md`, `final-pre-launch-verification.md`, `demo-recording-production-guide.md`, `team-scaling-cost-benefit-per-axis.md`, `phase-2-6-r10-decisions.md` (v8).
**Concurrency note**: Path A owner is in flight on session-quality re-audit (option 2 from the same surface). This doc is option 1+3 — disjoint scope, no overlap.

---

## TL;DR — three calibrated assertions

**CORRECTION 2026-05-11**: This doc was written 2026-05-10 at HEAD `2919f6e` claiming "production is 548 commits stale; in-tree tools=130; 19-tool gap; need flyctl reauth + deploy." **All four claims are FALSIFIED per `production-master-gap-report.md` (chain agent's empirical investigation, commit `21d5684`).** Empirical reality: production at master HEAD modulo `.research/`-only commits; tools=111 = master-built = production-registered (the "130" was a grep error that included 19 `_test.go` fixtures); flyctl auth works without reauth (chain agent + verification dispatch both used flyctl successfully). **The "production deploy is the #1 unblock" framing throughout this doc is no longer load-bearing.** The actual gating cluster is launch ops (TM filing, demo GIF, Reddit warmup, dr-drill secrets, missing `cmd/dr-decrypt-probe`) per `dr-drill-results-2026-05-11.md` + `research-batch-2026-05-11.md`. Original TL;DR §1 text below retained for traceability but read as historical.

1. **[FALSIFIED — see CORRECTION above]** ~~The single most important thing we are NOT doing right now is shipping a production deploy.~~ Master is `2919f6e`/in-tree tools=130; production is `v1.3.0`/tools=111 — **548 commits and 19 tools behind**. `final-pre-launch-verification.md` already flagged this: hosted demo is 14d-uptime stale. Every other forward-track investment compounds against a deploy that is already unblocked once flyctl auth is refreshed. **Cost: ~30 minutes including reauth. Impact: closes the README-vs-/healthz integrity gap that any HN/Reddit visitor will spot in 10 seconds.**

2. **Phase 3 multi-cell, Phase 1.4 self-hosted runners, NSE empanelment prep — none of these has its trigger fired.** All three are correctly-scoped at "do nothing yet": Phase 3 trigger is sustained 100+ concurrent users (we are at 0 paid); Phase 1.4 trigger is GitHub free-tier exhaust at N=50+ pushes/month (we hit this in early May at 585 commits/2wk — **trigger has fired but the cheap one-line fix is already in `ci.yml`**); NSE empanelment trigger is 50 paid subs (we are at 0). **Action: do small, cheap pre-positioning steps for Phase 1.4 only; defer Phase 3 and NSE empanelment until their triggers fire.**

3. **The launch path #42-46 is the highest-leverage cluster of work this week.** Trademark filing (~₹19-23k, 30 min user-time), R2 dr-drill (~15 min), demo GIF (~30 min), Reddit warmup (6 days), Show HN window (Tue/Wed PT). **All five are individually small; together they unlock the only credibility-validated distribution funnel we have.** Until a Show-HN attempt happens, we have no empirical signal on whether the project is interesting to anyone outside our own toolchain. The 1354-commit / 28-module / tools=130 codebase has been built without external feedback. **Get external feedback before building more.**

---

## Empirical baseline at HEAD `2919f6e`

| Dimension | State | Source |
|---|---|---|
| Master HEAD | `2919f6e` | `git log -1` |
| In-tree MCP tools | **130** (51 files in `mcp/`) | `grep -rE 'mcp\.NewTool\("' mcp/` count |
| Production version | **v1.3.0** | `curl /healthz` |
| Production tools | **111** (deployed snapshot) | `curl /healthz` |
| Production uptime | 3m33s at audit-time (just-restarted) | `curl /healthz` |
| **Production gap** | **0 tools, 0 source commits** (production at master HEAD modulo .research/-only commits per `production-master-gap-report.md` §1.4 — both production and master-built binary register tools=111; the "548 commits / 19 tools" framing above is the grep-error narrative FALSIFIED 2026-05-11) | per chain agent's compile-and-run probe + machine version 273 image hash chain |
| Algo2go external modules | **28** (alerts/aop/audit/billing/broker/clockport/cqrs/decorators/domain/eventsourcing/i18n/instruments/isttz/legaldocs/logger/money/oauth/papertrading/registry/riskguard/scheduler/sectors/telegram/templates/ticker/usecases/users/watchlist) | `ls D:/Sundeep/projects/algo2go/` |
| Total master commits | **1,354** lifetime | `git log --oneline | wc -l` |
| Master commits last 2 weeks | **585** | `git log --since` |
| Master commits Apr 2026 | **931** | `git log --since/--until` |
| Paid users | **0** | `MEMORY.md` (no billing rows) |
| Show-HN status | **Not yet submitted** | `final-pre-launch-verification.md`: blockers exist |
| Trademark filing | **Not yet filed** | `algo2go-reservation-runbook.md` Phase 2 not executed |
| Domain `algo2go.com` | **Not yet purchased** (still available per 2026-05-03 RDAP) | `algo2go-reservation-runbook.md` |
| Static egress IP | `209.71.68.157` (BOM, single machine) | `MEMORY.md` |
| `ENABLE_TRADING` (Fly.io) | `false` (Path 2 hosted = read-only) | `fly.toml` |

**The "stale production" framing is the dominant strategic fact.** Everything below assumes that gap closes (~30 min of work) before any other forward-track action.

---

# Part A — Forward-Track Survey

## Track 1 — Phase 3 multi-cell architecture

### What it is

Horizontal scaling beyond the current single-Fly.io-machine deployment. Each "cell" = independent Fly app with its own SQLite + per-cell egress IP. Routing layer shards users by `hash(user_email) mod N_cells` (per `architecture-scale-paths-A-B-C.md` and `10000-agent-blocker-analysis.md` L2.3 + L1.4).

### Has the trigger fired?

**No.** Phase 3 trigger from `10000-agent-blocker-analysis.md` L2.3: "sustained 100+ concurrent users." Empirical state: 0 paid users, ~0 sustained concurrent (production was just-restarted, 3m33s uptime at audit-time = no traffic worth retaining sessions for).

### Smallest first step (when trigger fires)

`flyctl machines clone <bom-machine-id> --region bom -a kite-mcp-server` — one command, ~60-90s cold-start, ~₹30/day for the second machine. **Same static egress IP** (Fly.io single-app machines share the egress IP), so SEBI Apr-2026 IP-whitelist is unaffected at the 2-cell level. This is the architecture-validation step: prove the binary tolerates running side-by-side with shared SQLite via Litestream replication.

This step **already appears in `day-1-launch-ops-runbook.md` Phase 1.4** as the "horizontal scale recommended pre-launch" action. Same command serves both purposes (capacity for HN surge AND Phase 3 architecture-validation). Doing this once before Show-HN is a cheap dual-purpose dry-run.

### Cost ceiling

Per `10000-agent-blocker-analysis.md` L5.2 (revised post-IP-whitelist correction):

| Cells | Approx. monthly cost | Approx. capacity (concurrent users) |
|---|---|---|
| 2 | ~₹1-2k/mo (₹500-1k/cell × 2) | ~1,000-2,000 |
| 5 | ~₹2.5-5k/mo | ~5,000 |
| 10 | ~₹5-10k/mo | ~10,000 |
| 100 | ~₹50k-1L/mo | ~100,000 |

**At 0 paid users**: cost is purely operational overhead. ROI **strongly negative** until ≥50 sustained concurrent users.

### Per-cell static IP — post-DO-BLR1 falsification

Path 2 of `path-e-try-before-buy-results.md` falsified DO BLR1 reachability for fresh accounts. Implication: per-cell static IP options are narrower than initially scoped. Current options ranked:

1. **Fly.io single-app multi-machine** (recommended for cells 2-5): ALL machines in `bom` region share the app's static egress IP. **Single SEBI whitelist entry covers all cells.** Validated empirically per `MEMORY.md`.
2. **Fly.io multi-app cells** (for cells 5-100): each Fly app has its own egress IP. User must paste N IPs into the "Whitelisted IPs" field of their Kite developer console. Plural-field architecture confirmed at `mcp/plugin_widget_ip_whitelist.go:54`.
3. **Hetzner / Linode / AWS Mumbai region**: static IP options exist but require DNS/routing/secret-replication engineering. ~2-4 weeks engineering. **Defer until Fly.io options exhaust.**

### Recommendation

**Do not invest in Phase 3 yet.** Pre-position the 2-cell Fly clone command in `day-1-launch-ops-runbook.md` (already documented). Architecturally-validated by virtue of the existing per-user session affinity in `kc/oauth/middleware.go`. Net forward-track work: **0 hours.**

---

## Track 2 — Phase 1.4 self-hosted CI runners

### What it is

Replace GitHub-hosted CI runners (Linux $0.008/min, Windows $0.016/min, macOS $0.08/min) with self-hosted runners on cheap cloud VMs (Hetzner CPX21 ~$8/mo, Fly.io machine ~$10/mo). Per `architecture-scale-paths-A-B-C.md` Path A.

### Has the trigger fired?

**Partially.** GitHub free tier is 2,000 Linux-runner-min/month. Empirical commit cadence: 585 commits last 2 weeks = ~1,170/month projected. At ~5 min/commit per workflow × 8 workflows triggered per push: well past free-tier exhaust.

**The cheap mitigation is already in `ci.yml`** (per the head I read: `concurrency: cancel-in-progress: true` + macOS dropped from matrix). This is `architecture-scale-paths-A-B-C.md` Path A item 1+2 already shipped. The −65% cost step is done. **Remaining work is the self-hosted-runner crossover** — only worth doing if monthly CI cost crosses ~$50/month sustained.

### Cost (current)

Empirical at 1,170 commits/mo cadence, post-macOS-drop:
- ubuntu-latest × 5 min × 1,170 = $46.80/mo
- windows-latest × 5 min × 1,170 = $93.60/mo
- + race-tests / sbom / security / playwright (each ubuntu-only) ~$15-30/mo
- **Total: ~$155-185/mo current GitHub-hosted spend** (at 1,170 commits cadence)

Self-hosted Hetzner CPX21 = $8/mo. Crossover happens past ~$10/mo GitHub spend (already crossed). **Empirical ROI: positive ~$140-175/mo savings.**

### Smallest first step

Per `architecture-scale-paths-A-B-C.md` Path A:

1. **Provision one Hetzner CPX21 ubuntu-22.04 VM** (~5 min, $8/mo). Self-hosted runner registration token via GitHub repo settings → Actions → Runners → New self-hosted runner.
2. **Update `ci.yml` matrix** to include `self-hosted-linux` alongside `ubuntu-latest` initially (validates that self-hosted gives identical results before switching). ~30 min.
3. **Cut over** to self-hosted-only after 1 week stability validation. ~5 min config edit.

**Total user time: ~6 hours (mostly waiting for Hetzner provisioning + 1 week soak validation). Total cost: $8/mo recurring + $0 one-time.**

### Risks

- Self-hosted Linux runners on cheap VMs are slower per-job (CPX21 = 2 vCPU vs GitHub-hosted 4 vCPU). **Per-PR latency increases ~30-50%.**
- Self-hosted runners are vulnerable to malicious code injection (any PR that runs `make build` runs arbitrary code on the runner). For a public repo, **only safe if the runner is ephemeral** (restart between jobs) AND on a network with no production secrets reachable.
- Windows-latest cannot be cheaply self-hosted on Linux VMs — would need a Windows VM (~$15-30/mo on Azure or AWS Mumbai). **Recommendation: keep `windows-latest` on GitHub-hosted; self-host only Linux.**

### Recommendation

**Do this only after Show-HN signal validates the project is worth investing in.** At zero-paid-user state, the $155-185/mo CI cost is itself the cost of doing this volume of speculative engineering. Cutting it without validation just makes the speculation cheaper. **Pre-position Hetzner research; don't commit infra until paid signal.**

If user disagrees and wants the cost-savings now: 6 hours of work, $8/mo recurring, ~$150/mo savings. Net positive immediately. The "don't invest until validation" framing is conservative — both calls are defensible.

---

## Track 3 — NSE empanelment prep

### What it is

NSE algo-vendor empanelment per Apr-2026 framework + per `MEMORY.md kite-cost-estimates.md`. Required at 50+ paid subs (Z-Connect threshold per `MEMORY.md kite-mrr-reality.md`). Cost: ₹4-8L (legal counsel + filing + capital lock-in). Calendar: 3-6 months from filing to certification.

### Has the trigger fired?

**No.** Trigger: 50 paid subs. Empirical: 0 paid users.

### Pre-work that can happen now (legitimately)

Per `MEMORY.md kite-fintech-lawyers.md` (Spice Route Legal ₹15-35k consult, Finsec Law similar):

1. **Schedule a ~1-hour ₹15-35k pre-consultation** with Spice Route or Finsec Law to scope the empanelment process for our specific architecture (BYO-developer-app, Path 2 read-only on hosted, full trading on self-host). Output: a written estimate of timeline + cost-breakdown + filing checklist. **Cost: ~₹15-35k. Calendar: 1-2 weeks scheduling.**
2. **Form Pvt Ltd entity** (per `team-scaling-cost-benefit-per-axis.md` Axis A). Cost: ~₹55-85k including DSC, DIN, MoA/AoA, name reservation, certification. Calendar: 4-6 weeks via Vakilsearch / LegalWiz / IndiaFilings. **Required for empanelment** — NSE doesn't empanel sole proprietorships for this kind of work.
3. **Open INR business account** at HDFC / ICICI / Kotak post-Pvt-Ltd. Required for empanelment capital deposit + ongoing fee payments. Calendar: 1-2 weeks post-Pvt-Ltd.

### When to actually do this

Per `MEMORY.md kite-mrr-reality.md`: "₹15-25k MRR @ 12mo; empanelment only after 50 paid subs."

Conservative trigger: **30 paid subs** (gives 6-month buffer for the 3-6 month empanelment process before hitting the regulatory cliff at 50). Per `10000-agent-blocker-analysis.md` L1.3.

### Smallest first step

**Email `kiteconnect@zerodha.com` with 3 questions** (per `MEMORY.md feedback_cheapest_compliance_action.md`):

1. Does our architecture (BYO-developer-app, per-user OAuth, paid SaaS pricing) require NSE empanelment, or does the Kite Apps marketplace structure handle this?
2. At what user count does Zerodha's compliance team flag the operator for SEBI/NSE escalation?
3. Is there a precedent path for OSS algo tools below the empanelment threshold?

**Cost: ₹0. Calendar: 1 email, response in 2-5 business days.** Establishes paper trail before any monetization. **This is the cheapest forward-track action in the entire survey.**

### Recommendation

**Do the email this week.** Defer Pvt Ltd formation + lawyer pre-consult + business account until after Show-HN validation (saves ~₹70k-1.2L of compliance setup cost from being wasted on a project that doesn't get external interest).

---

## Track 4 — User-manual launch path #42-46

This is the cluster the dispatch identified as the most operational right now. Each of the 5 sub-items has been documented in detail elsewhere; this section consolidates them into one decision view.

### #42: Algo2go trademark filing (₹19-23k, ~30 min user time)

Per `algo2go-reservation-runbook.md` Phase 2 actions ranked by criticality. Actions and order:

1. **Buy `algo2go.com` at Namecheap** (5 min, ~₹1k/yr) — domain squatter risk is highest here.
2. **Create `algo2go` GitHub org** (2 min, free) — protects against name collision.
3. **File TM Class 36 + 42 via Vakilsearch / LegalWiz** (30 min online, ~₹18-22k) — locks legal escape route from Zerodha C&D.
4. **Squat npm/PyPI/X handles** (~30 min total).

**Critical correction from `algo2go-reservation-runbook.md`**: Tradarc backup name is **NOT clean** — registered to Server Plan Srl since 2001-05-04, expired 2026-05-04 but most domains auto-renew. Don't waste TM filing fee on Tradarc.

**Recommendation**: actions 1-2 this week regardless (~₹1k cost, 7 min user time, locks brand reservation). Defer action 3 (TM filing) until after Show-HN validates project name is worth filing for. The filing date establishes priority but also commits ₹19-22k to a brand that may or may not survive launch.

### #43: R2 dr-drill (~15 min)

Per `MEMORY.md` Litestream + R2 backup architecture: SQLite WAL → R2 bucket `kite-mcp-backup`. The DR drill validates restore-from-backup actually works.

`.github/workflows/dr-drill.yml` exists in the repo per the workflow listing. The drill is automated. **Smallest first step**: trigger the workflow manually via `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server`. Read the output. Verify restore time < 5 min and zero data loss. **Cost: ~15 min user time. Recurring: ~$0/mo (R2 free tier covers our scale).**

### #44: Demo GIF (~30 min)

Per `demo-recording-production-guide.md` "Demo A — minimum viable single-GIF demo":

- ScreenToGif (free, signed, OS-native): `winget install ScreenToGif`
- 30-second scenario: Show portfolio → set alert → Telegram notification visible
- **Paper-trading mode ON** before recording (no real Kite data)
- Output target ≤4MB GIF
- Embed locations: README hero, Twitter Day-1 thread T1, Reddit r/algotrading post body, Show HN body, landing.html

**This is the highest impact-per-minute action in the launch prep cluster.** All five distribution channels reward video/GIF posts ~3-5× text-only. Without it, Show HN body is text-only and Reddit r/algotrading post will be text-only.

### #45: Reddit warmup (~6 days, ~30 min/day passive)

Per `reddit-subreddit-specific-strategy.md`:

- User has no Reddit account under `Sundeepg98` — verified 404 at `reddit.com/user/Sundeepg98/about.json`.
- New accounts (≤30 days, ≤50 karma) are auto-shadowbanned in r/algotrading + many big subs.
- **Day 0 cannot be a Reddit launch.**

Smallest first step: **create `u/Sundeepg98` Reddit account this week (15 min). Lurk + comment helpfully on 5-10 unrelated threads in r/algotrading + r/golang + r/SideProject over 7 days to accumulate 30-50 comment karma.** Without this, Day-1 +12h Reddit posts get auto-shadowbanned.

### #46: Show HN window (Tue/Wed PT)

Per `day-1-launch-ops-runbook.md` Phase 1.3 + `gtm-launch-sequence.md`:

- **Optimal window**: Tuesday or Wednesday 06:30-08:30 PT (= 19:00-20:30 IST evening)
- Pre-stage second `bom` machine 10 min before submission (`flyctl machines clone`)
- Capture last-known-good Fly.io release ID + Docker image tag in scratch file before submit
- Run `./scripts/smoke-test.sh` (13 checks); all green required
- Verify Litestream WAL freshness (mtime within 60s of business hours)
- Submit; do NOT respond to comments for first 15 min
- First 90-min triage workflow per Phase 2 of `day-1-launch-ops-runbook.md`

**Blocker per `final-pre-launch-verification.md`**: hosted demo is 14d-uptime stale. **Must deploy first.** Then must wait for `dr-drill.yml` + `playwright.yml` to be green at deployed commit. Then submit.

### Sequencing recommendation for the launch-path cluster

| Day | Action | Time | Cost |
|---|---|---|---|
| **Today** | ~~Refresh flyctl auth + deploy to Fly.io (closes the 548-commit gap)~~ — FALSIFIED 2026-05-11; no deploy needed (production = master modulo .research/-only); see `production-master-gap-report.md` §1.4 + `STATE.md` §2.1 | 0 min | $0 |
| **Today** | Trigger `dr-drill.yml` via `gh workflow run` (action #43) | ~15 min | $0 |
| **Today** | Buy `algo2go.com` + create `algo2go` GitHub org (action #42 partial) | ~10 min | ₹1k |
| **Today** | Create `u/Sundeepg98` Reddit account (action #45 setup) | ~15 min | $0 |
| **Day +1** | Record Demo A GIF (action #44) | ~30-60 min | $0 |
| **Day +1 to +6** | Reddit lurk/comment for karma (action #45 warmup, passive) | ~30 min/day | $0 |
| **Day +7** | Final pre-launch checks: smoke-test green, dr-drill green, healthz tools=111, og-image 200 (already HTTP 200 verified 2026-05-11) | ~30 min | $0 |
| **Day +7 (Tue/Wed PT)** | Show HN submission (action #46) + Twitter D1-T1 + Reddit r/algotrading post | ~3 hours active triage | $0 |
| **Day +30** | Star count check; if ≥50 stars → Rainmatter warm-intro trigger (per `kite-rainmatter-warm-intro.md`) | ~1 hour | $0 |
| **Day +90** | TM filing review: only file if Show HN delivered ≥25 stars + ≥5 paid trial conversions (action #42 final) | 30 min online | ₹18-22k |

**Total user time before Show HN**: ~3-4 hours of active work + 6 days of ~30min/day passive Reddit warmup.
**Total cost before Show HN**: ~₹1k.
**Key insight**: ~₹0 of the ~₹19-23k TM filing cost is needed before Show HN launch. The TM is a post-validation expense.

---

## Track 5 — Other tracks (not in dispatch)

### 5.1 — Mobile-responsive dashboard (~1 week)

`/dashboard` is desktop-optimized per `MEMORY.md kite-dashboard-design.md`. Mobile (Indian retail trader primary device) renders functionally but UX is poor. ~1 week engineering for responsive Tailwind cleanup. **Trigger**: ≥10 paid users AND ≥50% mobile sessions (verifiable via Cloudflare analytics post-Cloudflare-front).

### 5.2 — Pattern-based alerts (~3 days)

Beyond price/percentage alerts, add chart-pattern detection: support/resistance breaks, double-top/bottom, volume-spike-with-direction. Already partially scoped at `mcp/alerts/projection_tool.go` and `volume_spike_tool.go`. Wires into Telegram briefings. ~3 days engineering. **Trigger**: ≥5 paid users provide direct request OR alert-tool usage analytics show >50% of alerts are repeat-tier ones.

### 5.3 — Multi-broker support (~3-6 weeks)

Currently Kite-only. Adding Upstox / Dhan / 5paisa requires the broker port abstraction (already exists at `D:/Sundeep/projects/algo2go/kite-mcp-broker`) to gain 2-3 more adapter implementations. **Engineering time**: ~3-6 weeks per adapter (each broker has its own OAuth quirks + symbol formats + rate limits). **Trigger**: paid users on different brokers (verifiable via post-launch demand signals) OR ≥3 incoming GitHub issues "please support X."

### 5.4 — Cloudflare front for unauthenticated edge (~2-3 days)

Per `day-1-launch-ops-runbook.md` Phase 1.3 risk-table: **`/.well-known/oauth-authorization-server` discovery has no in-process rate limit**. Naive crawler / Twitter-card preview farm could DDoS for free. Cloudflare in front fixes this + adds free DDoS protection + free SSL + analytics. ~2-3 days engineering (Cloudflare proxy DNS + Fly.io trust-Cloudflare-IP setup + cache rules). **Trigger**: any incident OR pre-Show-HN as conservative posture (recommended).

### 5.5 — Stripe / Razorpay billing integration (~1 week)

Currently no payment integration; "billing" tier-gating is via env flag only. To accept paid subscribers, need Razorpay (preferred for India) integration. ~1 week engineering. **Trigger**: ≥3 paid-trial requests post-Show-HN.

### 5.6 — Embedded demo on landing page (~1 day)

Per `MEMORY.md kite-templates`: `landing.html` exists. Embedding the demo GIF inline above-fold (vs requiring user to install Claude Desktop + OAuth) raises conversion ~3-5×. ~1 day engineering. **Trigger**: same as #44 (demo GIF recording) — ship together.

### 5.7 — `kite-mcp-internal` private fork sync hygiene (~ongoing)

`MEMORY.md` notes `.research` was moved to private repo `Sundeepg98/kite-mcp-internal`. Public `.research/` has 80+ files at this writing — drift between public and private. Decision: either (a) move all `.research/*` back to private, OR (b) accept public `.research/` as research-history-as-evidence (HN crowd may interpret this positively as transparent process). **Recommendation**: option (b) until public-vs-private hygiene becomes a launch-day complaint; revisit then.

---

# Part B — Strategic Review

## B.1 — Where does the project stand empirically

### Quantitative state

- **Codebase**: 1,354 lifetime commits (1,364+ at 2026-05-11 re-verify). **111 MCP tools** (production-registered via compile-and-run; "130 in-tree" was a grep error including 19 test fixtures). 28 algo2go external modules. **~8,500 tests cumulative** (4,697 in-tree + 3,760 across 28 algo2go modules per research-batch §I). Production at v1.3.0 / tools=111 — **MATCHES master-built binary** per `production-master-gap-report.md`; the ".0 tools / 0 source commits stale" reality is the operative empirical state (post-2026-05-11 correction).
- **Architecture**: Clean Architecture + CQRS + 9 RiskGuard checks + AES-256-GCM encryption + Litestream → R2 backup + per-user OAuth. Phase 2.6 (libSQL/Turso adapter) closed at `2919f6e`.
- **Distribution**: Zero. No Show HN submission yet. No Reddit posts. No Twitter (handle exists, build-in-public not started). No domain owned. No trademark filed.
- **Monetization**: Zero. No payment integration. ENABLE_TRADING=false on Fly.io (Path 2 read-only). Free tier of 50 paid subs target per `kite-mrr-reality.md` is 50 trial→paid conversions away.
- **SEBI/regulatory posture**: Per `MEMORY.md kite-landmines.md` + Apr-2026 SEBI framework: algo vendor classification = "agent" (not RE), below ATS/empanelment thresholds. Path 2 hosted = read-only. Self-hosted = full trading via personal-use safe-harbor. Defensible.
- **Calendar burn**: ~12 months of ~daily commits per the 1,354-commit / Apr-2026 → 2026-05-10 timeline. ~70% of those commits in the last 60 days (931 in April + 585 in last 2 weeks of survey window).

### Qualitative state

- **The codebase is over-built for its current external traction.** 111 tools / 28 external modules / 11 RiskGuard pre-trade checks (17 RejectionReason constants) / AES-256-GCM encryption / Litestream backups / DR drills / Path 2 compliance — every dimension has been hardened beyond the needs of 0 paid users. This is the "diminishing returns past ~10 research agents — transition to execution" pattern flagged in `MEMORY.md feedback_research_diminishing_returns.md`. Same pattern now applies to engineering: diminishing returns past tools=111, transition to distribution.
- **Architecture ceiling has been hit at the current effort level.** Per `team-scaling-cost-benefit-per-axis.md`: solo + agent-fleet ceiling on Architecture is ~95.69; the next +47 nominal points are gated by external auditor sign-off (SOC 2, ISO 27001, SEBI CSCRF, NIST CSF) — none of which can ship without an external customer + funded runway.
- **The single highest-leverage gap is empirical-feedback-from-strangers.** Every other team-config / tooling / decoupling / capacity decision has been made on internal reasoning. **No external user has ever stress-tested it.** Show HN + Reddit + Twitter is the cheapest way to break this.

### What's been built that's actually unique vs. competitors

Per `MEMORY.md kite-competitors-corrected.md` + `kite-zerodha-no-marketplace.md`:

- **vs official `mcp.kite.trade`**: official has 22 tools (read-only + GTT), free, no developer app needed. Ours has 130 tools, full trading on self-host, RiskGuard, Telegram alerts, paper trading, options Greeks, backtesting, multi-user with persistent OAuth. **Differentiator: order placement + RiskGuards + Telegram + multi-user**.
- **vs `aranjan/kite-mcp` on punkpeye Finance** (Python, 14 tools, TOTP, local-only): ours is hosted, OAuth (not TOTP), 130 tools (not 14), production-deployed, Fly.io BOM region. **Differentiator: 9× tool count + hosted auth + production hardening.**
- **vs Multibagg / Streak** (closed-source SaaS, anti-MCP): ours is open-source MCP-native. **Differentiator: not even competing — different category.**

**The unique value is real and verifiable. The marketing has not been done.**

---

## B.2 — Highest-leverage next move (top 3-5 ranked)

Calibrated against (user-facing value × probability-of-impact) ÷ (effort + cost).

### #1 — ~~Deploy current master to Fly.io (~30 min, $0)~~ — **FALSIFIED 2026-05-11**

**Updated**: this was the #1 highest-leverage move per the 2026-05-10 framing. Per `production-master-gap-report.md`: there is no deploy backlog. Production runs `bc5043e`; master HEAD is 1-2 commits ahead but those are `.research/`-only (excluded from Docker build context). The "README claims tools=130 / production shows tools=111" was a grep error (README L198 was the only `117/130` claim; patched to `111` at commit `b4fdaf7`). No deploy needed. The replacement #1 is **publish demo GIF + execute launch path** (Tasks #44 + #46 from `launch-path-execution-playbooks.md`) — see #2/#3 below for re-ranked priorities.

### #2 — Demo GIF recording (~30-60 min, $0)

User-facing value: **enables visual posts on Twitter/Reddit/HN**, raises engagement 3-5× per `demo-recording-production-guide.md`.
Probability of impact: **~80%** — depends on quality of recording, but lower-bound is "decent first attempt."
Effort: ~30-60 min including 2 retakes.
Risk: minimal (paper-trading-mode prevents leak; `winget install ScreenToGif` is signed).
Reversibility: full (just don't ship it if it looks bad).

### #3 — Email `kiteconnect@zerodha.com` with 3 compliance questions (~10 min, ₹0)

User-facing value: **establishes paper trail BEFORE monetization**, answers a critical regulatory question, costs nothing.
Probability of impact: **~70%** — depends on whether Zerodha responds (they usually do within 2-5 business days for serious sender addresses).
Effort: ~10 min to draft + send.
Risk: minimal — worst case is silence or "consult a lawyer."
Reversibility: N/A (an email can't be unsent, but the questions are anodyne).

### #4 — Buy `algo2go.com` + create `algo2go` GitHub org (~10 min, ₹1k)

User-facing value: **locks brand reservation**. Domain squatter risk is real (algo2go.com was still available at 2026-05-03 RDAP check).
Probability of impact: **100% reservation** (purchase is guaranteed to succeed at ₹1k).
Effort: ~10 min.
Risk: ~₹1k/yr forever if we never use it.
Reversibility: yes (let it lapse; cost is sunk ₹1k).

### #5 — Reddit account creation + 6-day warmup (~15 min today + 30 min/day for 6 days, $0)

User-facing value: **unlocks Reddit r/algotrading as a launch channel.** Without it, Day-1 +12h posts auto-shadowban.
Probability of impact: **~85%** — depends on consistency of warmup commenting; mostly a function of user discipline.
Effort: ~15 min today + ~3 hours total over 6 days.
Risk: minimal (Reddit account is free; downside is just time).
Reversibility: full (account can be deleted; no data attached yet).

### What is NOT in the top 5

- **Phase 3 multi-cell scaling**: trigger has not fired. Doing it now is investing infra cost on speculation.
- **NSE empanelment Pvt Ltd formation**: trigger has not fired. Doing it now is committing ₹70k-1.2L on a project that hasn't been validated externally.
- **Self-hosted CI runners**: cost-savings are real (~$150/mo) but should follow Show-HN validation; don't need to do it pre-launch.
- **More algo2go module extractions**: 28 modules already external per Path A inauguration COMPLETE (post 2026-05-10 per `memory/session_2026-05-10_path-a-complete.md`). tools=111 production-registered matches master-built; no "build more before deploying" gap exists.
- **TM filing**: ₹19-22k pre-validation expense. Wait until Show-HN delivers ≥25 stars + paid-trial signal.
- **More research docs**: `feedback_research_diminishing_returns.md` is real. We have 80+ research docs in `.research/`. Adding more is procrastination.

---

## B.3 — Risk audit

### Production failure modes (current, single-machine deployment)

1. **Fly.io BOM region outage**: probability ~0.5%/year per Fly.io status history. Impact: full outage 30-90 min. Mitigation: Litestream → R2 means data survives; restart on alternate region needs DNS swap (~5-15 min) + new IP whitelist (breaks user OAuth until re-whitelisted).
2. **OOM kill on 512MB machine**: probability ~5-10%/month under any sustained load. Impact: 30s-5min restart, audit-write loss bounded by buffered async writer (already in place). Mitigation: `flyctl scale memory 1024` (~$5/mo extra; documented in `day-1-launch-ops-runbook.md`).
3. **SQLite WAL corruption**: probability ~0.01%/year. Impact: data loss bounded by Litestream replication interval (10s). Mitigation: DR drill workflow exists; not yet exercised. **Recommendation: trigger dr-drill.yml this week.**
4. **flyctl auth expiry mid-incident**: empirical (`final-pre-launch-verification.md` Verdict #3 already hit this). Impact: cannot deploy or rollback without re-auth (~15 min via Playwright). Mitigation: re-auth weekly OR before any planned deploy.

### Regulatory failure modes

1. **SEBI rule change tightening algo vendor obligations**: probability ~10-20%/year per Apr 2026 framework iteration cadence. Impact: variable (could require empanelment at lower threshold; could ban current architecture). Mitigation: monitor SEBI gazette + `kite-sebi-otr-feb-2026` style updates; engage Spice Route Legal if material.
2. **Kite API change (rate limit, auth flow, deprecation)**: probability ~5-10%/year per Zerodha ToS history. Impact: variable; usually 30-90 day deprecation window. Mitigation: passive monitoring; per-user-OAuth architecture is naturally adaptable to flow changes.
3. **DPDP Act 2023 enforcement uptick**: probability ~30%/year (Act passed but enforcement was light Y1; Y2-3 likely steps up). Impact: requires Data Fiduciary registration + DPO designation at ~₹50k-1L legal cost. Mitigation: per `MEMORY.md kite-landmines.md`, register at 50 paid subs.
4. **Zerodha unilateral C&D**: probability ~5%/year per `MEMORY.md kite-landmines.md` analysis. Impact: forced rename + repository takedown notice. Mitigation: TM filing for Algo2Go (Class 36+42) establishes priority.
5. **NSE/INVG/69255 enforcement at 50+ paid subs without empanelment**: probability ~50%/year if we cross the threshold without filing. Impact: trading-disable order on the operator's Kite app. Mitigation: empanelment process trigger at 30 paid subs.

### Tech-debt at first 10 paid users

1. **No payment integration**: blocks revenue capture day-1. Mitigation: Razorpay integration (~1 week) at first paid-trial request.
2. **Single Fly.io machine**: 50-150 concurrent visitors HN-surge tested but not production-load tested. Mitigation: pre-stage second `bom` machine per `day-1-launch-ops-runbook.md`.
3. **Public `.research/` directory**: 80+ files of internal strategy + costs + competitive analysis visible. Mitigation: continue accepting (transparency framing) OR move to private (re-evaluate post-Show-HN).
4. **No mobile-responsive dashboard**: Indian retail primary device is mobile. Mitigation: `~1 week` Tailwind cleanup at first paid user complaint.
5. **`/.well-known/oauth-authorization-server` not rate-limited**: free DDoS surface. Mitigation: Cloudflare front (~2-3 days) before any sustained traffic.
6. **OAuth JWT expiry 24h (MCP) / 7d (dashboard)**: per `MEMORY.md` Mar-2026 verification. Adequate but could be tightened to 4h MCP for higher-security tier (per Stripe/Plaid norms). Mitigation: not urgent.
7. **No SOC 2 / ISO 27001 / SEBI CSCRF audits**: external auditor sign-off bucket per `team-scaling-cost-benefit-per-axis.md`. Mitigation: blocked until Pvt Ltd + funded runway; this is intentionally deferred.

### Catastrophic-but-low-probability failure modes

1. **Compromised commit lands on master + auto-deploys**: probability ~0.1%/year (single committer; no MFA on git push). Impact: arbitrary Kite API access via deployed binary, regulatory fallout. Mitigation: PR-only-to-master + signed commits + CodeRabbit pre-review.
2. **Litestream replication silently broken + SQLite corruption**: compound probability ~0.005%/year. Impact: total data loss for non-replicated period (~10s + corruption window). Mitigation: dr-drill.yml + monitoring alerts on WAL freshness.
3. **OAuth JWT secret leak via flytctl logs**: probability ~0.5% per flyctl log dump. Impact: forge MCP tokens; access any user's Kite session. Mitigation: rotate OAUTH_JWT_SECRET monthly + alert on flyctl secret-list anomaly.

---

## B.4 — Resourcing reality check

### Current resourcing

- **1 user (orchestrator)**, ~6h-budget agent dispatches.
- **N agents (sub-team)** — 1M context each, durable across sessions.
- **0 hires**, 0 contractors, 0 external counsel engaged.
- **₹0 burn** (free tier of Fly.io / GitHub / Cloudflare R2; ₹500/mo Kite Connect app).

### Parallel-agent compression analysis

Per `feedback_decoupling_denominator.md`: decoupling investments should be evaluated against **multi-agent parallel-dev velocity**, not user-MRR.

**Empirical compression observed at HEAD `2919f6e`**: 585 commits last 2 weeks via team-config + 5-15 disjoint-scope agents. At a baseline single-developer pace of ~5-10 commits/day = 70-140/2wk, this is **4-8× compression**. **The agent-fleet has paid for the decoupling investments already** (28 algo2go modules + Tier 1+2 + Phase 2.x sequence).

**Where compression breaks down**:

1. **Decisions requiring user judgment** — TM-filing yes/no, lawyer engagement yes/no, monetization-pricing — agents can research but cannot decide. Bottleneck = orchestrator round-trip latency. **Mitigation**: `MEMORY.md feedback_chain_dispatches_when_mapped.md` (chain through pre-mapped sequences without intermediate confirmation).
2. **Decisions requiring external response** — kiteconnect@zerodha.com email reply, SEBI enforcement signal, paid-trial conversion — agents cannot accelerate these. Bottleneck = real-world latency.
3. **Distribution channel actions** — Reddit warmup, Twitter posts, HN submission — agents cannot post on user's behalf without credentials + identity. Bottleneck = user calendar time.

### What needs human time vs. agent time (next 30 days)

| Action | Human time | Agent time |
|---|---|---|
| ~~Deploy to Fly.io~~ — FALSIFIED 2026-05-11; production already at master modulo .research/-only | 0 min | 0 |
| Trigger dr-drill.yml | ~5 min (gh workflow run + read output) | ~5 min |
| Buy domain + create GitHub org | ~10 min | 0 |
| Email kiteconnect@zerodha.com | ~10 min | ~5 min draft |
| Record Demo GIF | ~30-60 min | 0 |
| Reddit warmup (6 days passive) | ~3 hours total | 0 |
| Show HN submission + first 90-min triage | ~3 hours (active) | 0 |
| Twitter D1-T1 post + replies | ~1 hour (active) | 0 |
| Reddit r/algotrading post | ~30 min | 0 |
| **Total before launch** | **~9-12 hours of focused user-time** | **<1 hour agent-time** |

**Implication**: the bottleneck for the next 30 days is **user calendar time**, not agent capacity. The agent fleet is over-provisioned for the next-30-days workload.

### When does the next hire / contractor make sense?

Per `team-scaling-cost-benefit-per-axis.md` TL;DR: **NONE of the hires apply pre-launch.**

Trigger-based hire roadmap:

| Trigger | First hire | Cost |
|---|---|---|
| ≥100 paying users (₹10-25k MRR) | Senior Product Designer | ₹18-22L/yr |
| First enterprise customer + SOC 2 demand | vCISO (fractional) | ₹3-5L per 3-mo sprint |
| Codebase crosses 150k LOC OR 4+ engineer team | Senior Architect | ₹35-50L/yr |
| Pvt Ltd formation (50+ paid OR fundraise) | Founding Director (co-founder, equity-only) | ₹0 cash + 5-15% equity |

**At 0 paid users, all four triggers are far. Stay solo + agent-fleet for the next 30 days.**

---

## Closing recommendation

**Do five things this week. In order.**

1. ~~Deploy master to Fly.io~~ — FALSIFIED 2026-05-11 per `production-master-gap-report.md`. Production at master HEAD modulo `.research/`-only commits; tools=111 in both production and master-built binary. Replacement step #1: **Provision GitHub Actions secrets for dr-drill** per `research-batch-2026-05-11.md` §D (6 `gh secret set` commands). **~5 min once secrets in hand.**
2. Trigger `dr-drill.yml` workflow. Read output. **15 min.**
3. Buy `algo2go.com` + create `algo2go` GitHub org. **10 min, ₹1k.**
4. Email `kiteconnect@zerodha.com` with 3 compliance questions. **10 min.**
5. Create `u/Sundeepg98` Reddit account. Begin warmup commenting in r/algotrading + r/golang. **15 min today + 30 min/day for 6 days.**

Then record Demo GIF (Day +1), continue Reddit warmup (Day +2 to +6), and submit to Show HN on Tue/Wed PT of week +1 per `day-1-launch-ops-runbook.md`.

**Defer everything else.** Phase 3 multi-cell, self-hosted CI runners, NSE empanelment formation, more module extractions, more research docs — all wait for Show-HN signal.

**The single highest-leverage decision is to stop building and start shipping.** The codebase has been ready for ~2 weeks per `final-pre-launch-verification.md`. The blockers are administrative (flyctl reauth, deploy, smoke-test, demo GIF), not technical. **Solving administrative blockers gates the next 6 months of strategic direction.**

---

## Sources of evidence (all under HEAD `2919f6e`)

- `.research/10000-agent-blocker-analysis.md` — Phase 3 multi-cell + Phase 1.4 CI runners + L1.3 NSE empanelment + L5.2 cost ceiling
- `.research/architecture-scale-paths-A-B-C.md` — Path A CI scaling specifics
- `.research/algo2go-reservation-runbook.md` — TM/domain/handle availability + ₹19-23k filing breakdown
- `.research/day-1-launch-ops-runbook.md` — Show HN day operations + flyctl machines clone command
- `.research/final-pre-launch-verification.md` — production-staleness empirical + 35-item checklist
- `.research/demo-recording-production-guide.md` — Demo A 30-second recipe + ScreenToGif winget
- `.research/team-scaling-cost-benefit-per-axis.md` — hire-trigger ladder + India CTC bands
- `.research/decisions/phase-2-6-r10-decisions.md` (v8) — Phase 2.6 closure reference
- `.research/reddit-subreddit-specific-strategy.md` — Reddit warmup + per-subreddit fit
- `.research/twitter-build-in-public-weeks-1-4.md` — Twitter cadence post-launch
- `MEMORY.md` — `kite-mrr-reality.md`, `kite-cost-estimates.md`, `kite-fintech-lawyers.md`, `kite-landmines.md`, `kite-rainmatter-warm-intro.md`, `feedback_research_diminishing_returns.md`, `feedback_decoupling_denominator.md`, `feedback_cheapest_compliance_action.md`
- Live verification: `git log -1`, `curl /healthz`, `curl /.well-known/mcp/server-card.json`, `grep mcp.NewTool mcp/`, `ls D:/Sundeep/projects/algo2go/`
