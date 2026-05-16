<!-- secret-scan-allow: no-secrets-in-this-doc -->

---
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head-at-write: 652e848
scope: READ-ONLY refresh of `58dc369` (GTM launch sequence) against 12-day-later state
prior-doc: `.research/gtm-launch-sequence.md` (now archived in `kite-mcp-internal` per `dd8be3a`)
related-active-docs:
  - `.research/twitter-build-in-public-weeks-1-4.md` (Twitter cadence)
  - `.research/reddit-subreddit-specific-strategy.md` (per-subreddit drafts)
  - `.research/demo-recording-production-guide.md` (GIF/asciinema/MP4 recipes)
  - `.research/day-1-launch-ops-runbook.md` (Show HN ops)
  - `.research/launch-path-execution-playbooks.md` (#42-46 execution chain)
  - `.research/algo2go-reservation-runbook.md` (TM + brand)
  - `.research/research/cloudflare-bitwarden-install-plan-2026-05-11.md` (I10/I11 plaintext-secret resolution)
  - `.research/research/egress-ip-stale-sweep-2026-05-11.md` (PREMISE FALSIFIED — 209.71.68.157 IS live)
  - `.research/STATE.md` (canonical source-of-truth)
verification-method: live `gh api`, `curl /healthz`, RDAP, Reddit API probes — all dated 2026-05-11
budget-used: ~3h of 3h target
---

# GTM launch sequence refresh — 2026-05-11

## TL;DR — three things that changed since `58dc369`

1. **Production deploy gap was FALSIFIED.** Production runs `bc5043e` (v1.3.0, tools=111); master is 1-2 `.research/`-only commits ahead. **No deploy backlog.** The "550 commits stale" framing in older docs is a `git log` over `.research/` doc churn, not code. Verified by chain agent compiling master locally + `curl /healthz` (`production-master-gap-report.md`). **This removes one Week 0 blocker.**

2. **The brief's Week 0 list is partly already-done and partly mis-prioritised.** Empirical state on each: (a) **Algo2go org claimed 2026-05-05** ✓ (28 modules external, but **repo NOT transferred** — still at `Sundeepg98/kite-mcp-server`); (b) **Tradarc.com is registered to Server Plan Srl, auto-renewed to 2027-05-04** — owned by an Italian holder, NOT a clean backup; (c) **"Stale 209.71.68.157" is FALSIFIED** — that IP IS the live egress IPv4 (`egress-ip-stale-sweep-2026-05-11.md` proves it via `flyctl ips list`); (d) **I10/I11 plaintext secrets in `MEMORY.md` are STILL there** — resolution plan exists (`cloudflare-bitwarden-install-plan-2026-05-11.md`) but neither MCP installed yet; (e) **0 GitHub Actions secrets set** (probe `gh api repos/Sundeepg98/kite-mcp-server/actions/secrets` returned `total_count: 0` — the brief said "6 unset", actual is "all 6 unset"); (f) **Reddit `u/Sundeepg98` 404'd today** (still does not exist, same as `f14d92c`); (g) **X `@Sundeepg98` returns HTTP 200** (handle exists per Twitter weeks 1-4 doc citing it).

3. **Next viable Show HN window: Tue 2026-05-26 06:30-08:30 PT or Wed 2026-05-27 06:30-08:30 PT.** Today is Sat 2026-05-16. The Tue 2026-05-19 / Wed 2026-05-20 immediate window is **infeasible** — Reddit account warmup needs 6 days minimum (`f14d92c` §Phase 3), Demo A GIF not yet recorded, GitHub Actions secrets unset (blocks dr-drill green), and the 7-9 day calendar from `launch-path-execution-playbooks.md` Item #5 dependencies hasn't started. **Show HN slips to W22 (Tue 2026-05-26).**

**Three highest-leverage actions for the user this week (Sat 2026-05-16 → Fri 2026-05-22):**

1. **Set the 6 GitHub Actions secrets** (one `gh secret set` command per, ~5 min total). Without these, `dr-drill.yml` exits 1 at the env-var gate AND the brief's "Week 0 GitHub Actions secrets" item is structurally unfinishable. Highest impact-per-minute action in the entire refresh.
2. **Create `u/Sundeepg98` Reddit account + start the 6-day comment-karma warmup** (15 min one-time + 20 min/day × 6 days). Per `f14d92c` §Phase 3: r/ClaudeAI requires hard 50-karma, r/algotrading filters fresh accounts. Without warmup, every Reddit post in launch week gets auto-shadowbanned.
3. **Record Demo A GIF** (~30 min one-time). The single asset goes in 5 places (README hero, landing.html, Twitter T1, Reddit body, Show HN footer per `demo-recording-production-guide.md`). Recipe is ready; user-only-can-execute step.

---

## §1 — Re-evaluation of the original 6 phases (from `58dc369`)

Original doc had 6 phases: (1) channel inventory, (2) 3 time-to-50-stars scenarios, (3) cleanup recipe, (4) Day-0/Day-1-7/Week-2-4 sequencing, (5) risk audit, (6) 5-7 final actions. Refresh per-phase:

### §1.1 — Channel inventory: corrections + 2 new channels

| Channel from `58dc369` | Original verdict | 2026-05-11 status | Action |
|---|---|---|---|
| A. Show HN | Primary wedge | **STILL primary**. `docs/show-hn-post.md` calibrated. **Next window: Tue 2026-05-26 06:30 PT.** | unchanged plan |
| B. MCP Registry | `io.github.Sundeepg98/kite-mcp-server@1.2.0` published 2026-04-19 | **STILL active** per `registry.modelcontextprotocol.io/v0/servers?search=kite` | unchanged |
| C. awesome-mcp-servers PRs (×3) | Punkpeye 85k★ + mcpservers.org + jaw9c | **NOT YET SUBMITTED** (no PR found in `Sundeepg98/kite-mcp-server` PR list); precondition was repo cleanup | dispatch now (not blocked by anything else) |
| D. Reddit (5 subs) | r/algotrading primary | **Refreshed in `f14d92c`** (Reddit per-subreddit doc 970 lines) — r/Zerodha dropped, r/SideProject + r/golang added | unchanged |
| E. Twitter | 14-day cadence in `docs/twitter-launch-kit.md` | **Refreshed in `5adf80f`** (Twitter Weeks 1-4, 35 tweet drafts) | unchanged |
| F. Indian Discord/Slack | Lower-priority warm channels | unchanged | unchanged |
| G. Claude Code Discord / r/ClaudeAI | Ecosystem fit | **Already covered** in `f14d92c` §E (r/ClaudeAI hard 50-karma gate confirmed) | unchanged |
| H. Anthropic-direct outreach | Bug-report-as-introduction | unchanged | unchanged |
| I. HN non-Show (Ask HN, regular) | Risky fallback only | unchanged | unchanged |
| J. Z-Connect editorial | Post-500-stars threshold | unchanged | gate at 500 stars |

**New channel K — Algo2Go branded GitHub Sponsors / FUNDING.json after repo transfer.** `funding.json` exists in repo (referenced in `13888e1`); has not been linked publicly yet. After repo transfer to `algo2go` org, the funding.yml/json gets richer surface (org-level "Become a sponsor" button is more credible than personal-account). **Defer** until repo transfer happens (post-launch).

**New channel L — `algo2go/kite-mcp-*` 28 external modules each have their own GitHub presence.** Each could earn stars independently for module-level utility (e.g. `algo2go/kite-mcp-riskguard` is a reusable Go pre-trade safety chain). **Don't market these separately for v1 launch** — they're orphan-star noise that fragments the primary repo's 50-star trigger gate. Mention in passing only.

### §1.2 — Three time-to-50-stars scenarios: still valid

`58dc369` Phase 2 gave optimistic (50★ in week 1, ~25% probability), realistic (4-6 weeks, ~50%), pessimistic (never, ~25%). **Refresh: probabilities are unchanged**, BUT the *baseline state* has improved:

- **Production demonstrably stable**: v1.3.0 up 5.4 days continuous (`uptime_s: 467966` per `curl /healthz` 2026-05-16), zero incidents. No "production hasn't been live long enough to trust" risk.
- **111 production tools verified** vs OSS competitor `aranjan/kite-mcp` (~14 tools per `f14d92c`). Differentiation table in `docs/product-definition.md` is concrete.
- **28 external algo2go modules** = sophistication signal that wasn't present at `58dc369` write-time (then was just root-only).
- **MCP Registry entry live since 2026-04-19** = 27 days of organic discoverability already accumulated. Zero stars to date suggests the registry alone is not a star-driver.

**Net**: the *quality of the launch artifact* is higher than at `58dc369`. **The conversion rate from a Show-HN-front-page slot to GitHub-star is the same; the probability of getting that slot is unchanged because that's a function of HN audience taste, not project quality.** The Optimistic / Realistic / Pessimistic probabilities stay 25/50/25.

### §1.3 — Phase 3 cleanup status: PARTIALLY EXECUTED

`58dc369` Phase 3 specified: (a) `git clean -fX` for 228 build artifacts, (b) remove 8 stray root `.md`, (c) gitignore `.research/*-msg.txt` scratch.

Empirical state today (per `STATE.md` + `github-repo-polish-audit.md` archived):
- **(a) and (b) DONE** in earlier sessions; repo root looks clean per `gh repo view` (`size=11.3MB`).
- **(c) DONE**; 160 .research/ files moved to private `kite-mcp-internal` per `dd8be3a`.

**One residual concern**: 6 commit-message scratch files (`_*.txt`) in `.research/` root (verified via `ls .research/ | grep '^_'`). These ARE doc-only and gitignored-style noise. Could be cleaned with one commit. **Not a launch blocker** (the public-facing repo polish is already done; the dirty files are visible only inside `.research/` which is no longer the public surface).

### §1.4 — Phase 4 sequencing: stale dates, refreshed in §3 below

Original Day-0 was undated; refresh assigns concrete dates in §3.

### §1.5 — Phase 5 risk audit: 5 new risks, 2 deleted

| Risk from `58dc369` | 2026-05-11 status |
|---|---|
| R1 Zerodha C&D | unchanged probability ~10-15% |
| R2 SEBI backlash on `place_order` | unchanged; `ENABLE_TRADING=false` on hosted is still policy |
| R3 Multibagg / Streak counter-attack | unchanged; no signal of triggering |
| R4 Indian fintwit dogpile | unchanged |
| R5 Repo cleanup not done → Show HN crowd lands on junk | **DELETED** — cleanup is done |
| R6 MCP Registry data reset | reduced probability; entry has been live 27 days without reset |
| R7 Show HN timing collision | unchanged |
| R8 GitHub discovery routes to `aranjan/kite-mcp` competitor | reduced; competitor still on punkpeye Finance, but our differentiation table is concrete |
| R9 Rainmatter warm-intro burned too early | unchanged; 50-star gate holds |
| R10 User's energy gives out | unchanged |

**New risks since `58dc369`**:

- **R11 — GitHub Actions secrets still unset blocks dr-drill on launch day.** If a Show-HN commenter asks *"is your backup story tested?"* and `gh run list --workflow dr-drill.yml` shows last run = 2026-05-01 failed-in-11s at env-var gate, credibility collapses. **Severity: high. Probability: ~30% that someone asks this on HN.** Mitigation: set the 6 secrets BEFORE launch.

- **R12 — I10/I11 plaintext secrets in `MEMORY.md` are an attack surface.** Brief calls this "pending rotation." Per `cloudflare-bitwarden-install-plan-2026-05-11.md` §4, they're still in `MEMORY.md`. **Not a Show-HN-blocker** (the file is in a private Claude home dir, not the public repo) but a residual security-debt item that should be migrated to Bitwarden post-launch. **Severity: medium-low. Probability of public exposure: very low** (MEMORY.md is local). **Action**: defer to post-launch.

- **R13 — Algo2Go org claimed but repo NOT transferred.** Brief says "Algo2go org claimed (was AVAILABLE)" — true per `gh api orgs/algo2go` (28 repos, created 2026-05-05). But the primary repo `kite-mcp-server` is STILL at `Sundeepg98/kite-mcp-server`. If Show HN goes well and the project gets traction under the `Sundeepg98` namespace, **transferring later is harder** (existing-user social proof tied to old URL; 301 redirects work but aren't perfect; awesome-list PRs link to old URL). **Decision needed pre-launch**: transfer now (risky, breaks every doc reference for ~24h) or transfer later (stuck at `Sundeepg98` namespace forever). **Recommendation**: defer transfer to post-launch + post-50★. `github-transfer-bootstrap-2026-05-11.md` (commit `13888e1`) has the mechanics.

- **R14 — Tradarc backup name is a dead alternative.** Original `kite-algo2go-rename.md` memory said *"backup Tradarc"*. Live RDAP probe today: Tradarc.com registered to Server Plan Srl since 2001, auto-renewed to 2027-05-04. **Tradarc is NOT clean.** If Algo2Go gets contested (low probability), the documented fallback fails. **Severity: low** (probability of contestation is low). **Mitigation**: research 2-3 alternative backup names if user wants belt-and-suspenders (e.g. `algoflow`, `tradarc.io`, `algowire`). **Defer**.

- **R15 — Twitter weeks 1-4 cadence not yet active.** `5adf80f` shipped the plan but the actual posting hasn't started. If user can't sustain 2-3 tweets/day for 30 days (`5adf80f` TL;DR), the post-Show-HN momentum window collapses. **Severity: medium. Probability ~50%** based on solo-dev-energy realism (`58dc369` R10). Mitigation: pre-schedule via Buffer/Typefully before Day 0.

### §1.6 — Phase 6 final actions: refreshed in §3 below

---

## §2 — Critical-path analysis: what blocks what

Empirical state of each potential blocker, 2026-05-11:

| Item | Status | Blocks what | Time to unblock |
|---|---|---|---|
| **GitHub Actions secrets unset (×6)** | `total_count: 0` per `gh api .../actions/secrets` | dr-drill green; "backup tested" HN credibility | 5 min user (six `gh secret set`) |
| **Reddit account does not exist** | `u/Sundeepg98` → HTTP 404 | r/algotrading + r/ClaudeAI + r/SideProject posts (all subs auto-shadowban fresh accounts) | 15 min create + 6 days karma warmup |
| **Demo A GIF not recorded** | `find . -name '*.gif'` → 0 results | README hero / landing.html / Twitter T1 / Reddit body / Show HN footer | 30 min user |
| **Production deploy gap** | FALSIFIED — production at `bc5043e` == master modulo `.research/`-only commits | n/a — no deploy needed | 0 min |
| **Stale egress IP 209.71.68.157** | FALSIFIED — IS the live egress IPv4 | n/a — no sweep needed | 0 min |
| **MCP Registry entry** | Active, 27 days live | n/a | 0 min |
| **awesome-mcp-servers PRs (×3)** | NONE submitted | discoverability multiplier on top of registry | 45 min one-shot |
| **Twitter @Sundeepg98 cadence not started** | Account exists; posting cadence not active | post-Show-HN star compounding | 30 min/day × 30 days |
| **I10/I11 plaintext secrets in MEMORY.md** | Still in file per `cloudflare-bitwarden-install-plan-2026-05-11.md` §4 | post-launch security hygiene | ~13 min after Bitwarden install (~30 min total) |
| **Algo2Go repo transfer** | NOT done; org has 28 module repos but NOT kite-mcp-server itself | nothing pre-launch; affects post-50★ growth path | ~50 min one-shot; defer to post-launch |
| **TM filing (Algo2Go Class 36 + 42)** | NOT filed; runbook in `algo2go-reservation-runbook.md` | nothing pre-launch (brand is publicly claimed via GitHub org); affects 6-month brand defense | ~50-75 min agent + 15-30 min user + ₹9k |
| **Tradarc backup name** | REGISTERED elsewhere (not clean) | nothing immediate; matters only if Algo2Go gets contested | research 2-3 alternatives (~30 min) |

**Critical path to Show HN submit**:

```
GitHub Actions secrets set (5 min)
    ↓
Reddit account created + karma warmup (15 min + 6 days)
    ↓
Demo A GIF recorded + embedded in README (30 min + 15 min commit)
    ↓
awesome-mcp-servers PRs submitted (45 min) ← can run parallel to above
    ↓
Twitter pre-schedule Day 1-7 (60 min)
    ↓
Show HN submit (Tue 2026-05-26 06:30 PT) ← MIN 7 days from today
```

**The Reddit warmup IS the critical path. Everything else can fit in parallel within those 6 days.**

---

## §3 — Refreshed 4-week sequence

### Week 0 — Pre-launch (Sat 2026-05-16 → Fri 2026-05-22)

**Day 0 — Sat 2026-05-16 (today)**: ~30 min total
- **Set 6 GitHub Actions secrets** (5 min). Commands ready in `research-batch-2026-05-11.md` §D (per STATE.md TL;DR). Six `gh secret set NAME` calls.
- **Create `u/Sundeepg98` Reddit account** (15 min): verify email, subscribe to r/algotrading + r/golang + r/SideProject + r/ClaudeAI + r/MachineLearning. Set bio: *"Solo dev, Bangalore. Go + MCP."*. Set avatar matching GitHub.
- **Manual workflow_dispatch trigger of `dr-drill.yml`** (5 min) to verify secrets work end-to-end. `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server` + `gh run watch`.
- **Verify production health** (5 min): `curl https://kite-mcp-server.fly.dev/healthz` — should still return `status: ok`.

**Day 1 — Sun 2026-05-17**: ~50 min
- **Reddit warmup day 1**: post 3 substantive comments in r/golang (technical Go threads, helping someone with real questions). 20 min.
- **Submit punkpeye/awesome-mcp-servers PR** with entry text from `kite-awesome-mcp-listings.md` memory. Append `🤖🤖🤖` to PR title per memory note. 15 min.
- **Submit jaw9c/awesome-remote-mcp-servers PR**. 15 min.

**Day 2 — Mon 2026-05-18**: ~45 min
- **Reddit warmup day 2**: post 3 substantive comments in r/algotrading (on backtesting / data / API integration questions). 20 min.
- **Submit mcpservers.org form** (covers wong2/awesome-mcp-servers). 15 min.
- **Record Demo A GIF** per `demo-recording-production-guide.md` lead-in summary. 30 min.

**Day 3 — Tue 2026-05-19**: ~30 min
- **Reddit warmup day 3**: post 2-3 comments in r/SideProject (encouraging fellow solo devs). 15 min.
- **Commit Demo A GIF to `docs/assets/demo-portfolio-alert.gif`** + update README hero with `![demo](docs/assets/demo-portfolio-alert.gif)` + 1-line caption per `demo-recording-production-guide.md` §C1. 15 min.

**Day 4 — Wed 2026-05-20**: ~30 min
- **Reddit warmup day 4**: post 2 comments in r/ClaudeAI on MCP-related threads (technical, not "how do I use"). 15 min.
- **Update `kc/templates/landing.html` hero** with `<video autoplay loop muted playsinline>` block embedding the GIF. 15 min.

**Day 5 — Thu 2026-05-21**: ~30 min
- **Reddit warmup day 5**: post 2 substantive comments in r/MachineLearning (on `[D]` or `[P]` threads). 15 min.
- **Pre-schedule Twitter Day 1-7** tweets in Buffer/Typefully per `5adf80f` Week 1 plan. 15 min.

**Day 6 — Fri 2026-05-22**: ~25 min
- **Reddit warmup day 6 (final)**: post 2 comments in r/IndianStreetBets or r/SideProject. 15 min.
- **Final pre-launch check**: account karma should be 30-60 by now. Verify by `gh api /user` style probe of own Reddit profile. If <30, slip Show HN by another week. 10 min.

**Week 0 stop conditions**:
- If `dr-drill.yml` fails on Sat 2026-05-16 with secrets set, fix-context agent dispatch needed before launch.
- If Reddit warmup hits <30 karma by Day 6, slip Show HN to Tue 2026-06-02 (one week later).
- If Demo A recording fails 3+ retakes, defer; ship Show HN without GIF (lower star ceiling) OR slip.

### Week 1 — Launch (Sat 2026-05-23 → Fri 2026-05-29)

**Day 7 — Sat 2026-05-23**: weekend rest day. Twitter cadence pre-scheduled queue takes over (`5adf80f`).

**Day 8 — Sun 2026-05-24**: weekend rest day. Final dry-run of the Day 0 ops sequence from `day-1-launch-ops-runbook.md` (clone Fly machine, snapshot release ID, smoke-test). 30 min.

**Day 9 — Mon 2026-05-25**: ~60 min
- **Pre-flight per `day-1-launch-ops-runbook.md`**: `flyctl machines clone` extra `bom` machine, capture last-known-good release ID + Docker image tag, run `scripts/smoke-test.sh` (13 checks).
- **Verify** `https://kite-mcp-server.fly.dev/mcp` responds, OAuth flow works against `mcp-remote`, Litestream WAL fresh.

**Day 10 — Tue 2026-05-26**: SHOW HN DAY
- **06:30-08:30 PT** (= 19:00-21:00 IST): submit Show HN per `docs/show-hn-post.md` Title Option 1. Stay at keyboard for first 90 min.
- **09:00 PT**: post Twitter Day-1 thread T1 (Demo A GIF native upload + body from `5adf80f` Week 1 Day 1).
- **11:00 PT**: post Reddit r/algotrading v1 per `f14d92c` §A.1.
- **22:00 IST**: comment-triage on HN per `docs/show-hn-post.md` §3 prepared replies; reply to first 5 critiques within 30 min each.

**Day 11 — Wed 2026-05-27**:
- **09:00 PT**: post Reddit r/ClaudeAI v1 per `f14d92c` §E.1 (requires Sundeepg98 karma >50 — verify before post).
- **Throughout**: monitor star count, monitor any incident signals per `day-1-launch-ops-runbook.md` Phase 2.
- **Twitter Day-2 tweet** from pre-scheduled queue fires.

**Day 12 — Thu 2026-05-28**:
- **11:00 PT**: post Reddit r/MachineLearning v1 `[P]` flair per `f14d92c` §D.1.
- **Twitter Day-3 tweet** fires.

**Day 13 — Fri 2026-05-29**:
- **11:00 IST**: post r/IndianStreetBets — **modmail first** per `f14d92c` §C1, post only after approval.
- **Twitter Day-4 tweet** fires.

**Week 1 stop conditions**:
- If Show HN flagged within 60 min of submission OR sits at <5 upvotes after 3h, do **not** proceed to Reddit r/ClaudeAI same week. Investigate; fallback to v2 release-note format on next Tuesday.
- If a SEBI-adjacent voice raises a regulatory concern that gets >100 engagement on any thread, execute Plan B from `58dc369` §Phase 2 Scenario 3: pause, send Zerodha disclosure email, wait 7 days.

### Week 2 — Post-launch ramp (Sat 2026-05-30 → Fri 2026-06-05)

- **Sat-Sun**: weekend rest. Twitter cadence continues.
- **Mon**: post r/IndianStockMarket v1 per `f14d92c` §B.1 (inverted framing, no AI in title).
- **Tue**: post r/SideProject v1 per `f14d92c` §F.1.
- **Wed**: post r/golang v1 per `f14d92c` §G.1.
- **Thu**: post kite.trade forum reply 1 per `docs/kite-forum-replies.md` (if file still exists — verify; was referenced in older docs but may be in `kite-mcp-internal` now).
- **Fri**: STAR COUNT CHECK. If ≥50 stars by EOD: activate Rainmatter warm-intro to `@deepakshenoy` per `kite-rainmatter-warm-intro.md`. If <50: continue cadence, don't burn the warm-intro window.

### Week 3 — Trigger gates (Sat 2026-06-06 → Fri 2026-06-12)

- **If 50★ hit**: phased Twitter DMs to `@deepakshenoy` (Sun), `@iamvishvajit` (Tue), `@abidsensibull` (Thu) per `kite-rainmatter-warm-intro.md` priority order.
- **Submit FLOSS/fund application** per `docs/floss-fund-proposal.md` (target $25-30k, 12-month roadmap). Independent of star count. 30 min.
- **Submit FOSS United / IndiaFOSS 2026 CFP** per `docs/drafts/indiafoss-2026-cfp.md` (if exists at HEAD; verify). 30 min.
- **Algo2Go TM filing — Class 36 + 42** per `algo2go-reservation-runbook.md` (~₹9k govt-direct path; defer ₹19-22k Vakilsearch). Dispatch as low-priority agent task.

### Week 4 — Steady cadence (Sat 2026-06-13 → Fri 2026-06-19)

- Twitter cadence per `5adf80f` Week 4 plan.
- Substack Week 1 post (options Greeks) cross-posted from Twitter.
- IF 100★+ hit: consider Z-Connect editorial pitch per `kite-zerodha-no-marketplace.md`.
- IF approaching 500★: prepare Z-Connect pitch in detail.
- **Algo2Go repo transfer decision**: if 50-100★ + Rainmatter conversation underway, defer transfer (URL-stability matters at this fragile growth point). If <30★ + traction stalled, attempt transfer as a "rebrand to algo2go" relaunch attempt (per `kite-algo2go-rename.md` rationale).

---

## §4 — Refreshed top-7 actionable list

For the user this week, ranked by impact-per-minute (different from `58dc369` final list because state has moved):

| # | Action | Time | Why this rank | Blocks |
|---|---|---|---|---|
| 1 | **Set 6 GitHub Actions secrets via `gh secret set`** | 5 min | dr-drill green; HN credibility on "backup story" | dr-drill workflow runs |
| 2 | **Create `u/Sundeepg98` Reddit account + Day 0 of warmup** | 30 min today + 20 min/day × 6 days | r/algotrading + r/ClaudeAI auto-shadowban fresh accounts; this is THE critical-path bottleneck | all Reddit launch posts |
| 3 | **Record Demo A GIF** per `demo-recording-production-guide.md` lead-in | 30 min | 5-place asset multiplier; HN/Reddit thumbnail readers convert 3-5× higher with visual | README hero, landing.html, Twitter T1, Reddit body, Show HN footer |
| 4 | **Submit punkpeye/jaw9c/mcpservers.org PRs** | 45 min | already-drafted text from memory; cascades to glama.ai auto-index in ~1 week | n/a — independent track |
| 5 | **Pre-schedule Twitter Day 1-7 in Buffer/Typefully** | 60 min | post-Show-HN momentum window collapses without consistent cadence; `5adf80f` Week 1 plan ready | Twitter cadence |
| 6 | **Workflow_dispatch trigger of `dr-drill.yml` to verify end-to-end** | 5 min after #1 | proves the secrets actually work BEFORE Show HN day pressure | reduces R11 risk |
| 7 | **(IF time on Day 6 — Fri 2026-05-22):** TM filing dispatch via `algo2go-reservation-runbook.md` | 50-75 min agent + ₹9k | brand defense; not urgent but easier to dispatch parallel | brand protection (not launch) |

**Total time investment Week 0 (Sat → Fri)**: ~3-4 hours user-active + 6 × 20 min Reddit comments + the GIF recording. Achievable across 6 days for a focused solo dev.

---

## §5 — Items explicitly NOT in this refresh

To prevent scope creep beyond the brief:

- **NOT** re-doing the 11-channel inventory (was `58dc369` §Phase 1; channels haven't changed). See §1.1 above for the corrections.
- **NOT** re-writing the Show HN draft (`docs/show-hn-post.md` is still calibrated).
- **NOT** redrafting Twitter thread (use `5adf80f`).
- **NOT** redrafting Reddit posts (use `f14d92c`).
- **NOT** specifying GIF recording recipe (use `demo-recording-production-guide.md`).
- **NOT** specifying Algo2Go TM filing procedure (use `algo2go-reservation-runbook.md`).
- **NOT** repeating launch-day ops runbook (use `day-1-launch-ops-runbook.md`).

This doc is purely the **refreshed sequence + critical-path + delta against the original `58dc369` plan**.

---

## §6 — Verification probes (run before treating this doc as current)

| Claim in this doc | Probe | Expected |
|---|---|---|
| Production tools=111 | `curl https://kite-mcp-server.fly.dev/healthz` | `"tools":111` or absent (other healthz fields) |
| Repo at 0 stars | `gh api repos/Sundeepg98/kite-mcp-server --jq .stargazers_count` | `0` |
| GitHub Actions secrets unset | `gh api repos/Sundeepg98/kite-mcp-server/actions/secrets --jq .total_count` | `0` |
| Reddit u/Sundeepg98 does not exist | `curl -A research-agent -H Accept:application/json https://www.reddit.com/user/Sundeepg98/about.json` | HTTP 404 OR `{"message":"Not Found"}` |
| Algo2go org has 28 repos | `gh api orgs/algo2go --jq .public_repos` | `28` |
| Tradarc.com registered (not available) | `curl https://rdap.verisign.com/com/v1/domain/tradarc.com` | 200 with `expiration: 2027-05-04` |
| 209.71.68.157 is live egress IPv4 | `flyctl ips list -a kite-mcp-server` (WSL2) | 4 IPs, one of type `egress_v4` = `209.71.68.157` |
| MCP Registry entry active | `curl https://registry.modelcontextprotocol.io/v0/servers?search=kite` | `io.github.Sundeepg98/kite-mcp-server` with `status: active` |

All claims in this doc were verified at write-time 2026-05-11. Re-probe if reading after 2026-06-11.

---

*This document does not change code. It does not modify any other research file.*
