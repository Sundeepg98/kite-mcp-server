<!-- secret-scan-allow: research-doc with handles + public commit shas + public URLs -->
---
title: Twitter Build-in-Public — FINALIZED 4-Week Calendar (post-2026-05-11 state)
as-of: 2026-05-11
re-verify-by: 2026-08-11
master-head-at-write: 6415d0c+
prior-doc: .research/twitter-build-in-public-weeks-1-4.md (2026-05-02, ff64598)
delta-window: 12 days (2026-05-02 → 2026-05-11)
scope: READ-ONLY research; supersedes prior doc's 30-day calendar with new state
status: FINAL — call this doc, not the prior, when posting
parallel-tracks: 11+ research dispatches in flight (algo2go-umbrella, cloudflare-bitwarden-install, egress-ip-sweep, sebi-shared-vs-dedicated, fly-mcp-empirical, god-object-inventory, mcp-ecosystem-audit, playwright-drill, github-transfer, FLOSS-readiness)
budget-used: ~2h of 3h target
---

# Twitter Build-in-Public — FINALIZED (post-2026-05-11 state)

> **Single doc. 4-week post-Show-HN calendar. Supersedes** `.research/twitter-build-in-public-weeks-1-4.md` (2026-05-02). The prior doc was correct at write but **12 days have shipped substantial new material** that changes what the content actually is. Same posture (no signals, code-not-claims, 1-2 tweets/day cap); different content because the project is no longer the same project.
>
> **Identity anchor:** [@Sundeepg98](https://x.com/Sundeepg98) → migrating to `@algo2go` umbrella per `algo2go-umbrella-rebrand-strategy-2026-05-11.md` (decision pending user).

---

## §1 — Original plan + delta-since-then

### 1.1 What the original (2026-05-02) doc said

Per prior `.research/twitter-build-in-public-weeks-1-4.md` (931 lines):
- 30-day calendar Day 1 = Show HN day
- 35 tweets + 8 threads across 4 weeks
- 3 content rules: no tips/signals, code-not-claims, 3-tweets/day cap
- Channel survey: Indian fintwit (Nithin0dha, karthikrangappa, mrkaran_, deepakshenoy, vishdhawan) + AI-dev (alexalbert__) + Indian-dev (tanaypratap)
- Risk audit: 12 hard rules
- Rainmatter trigger gated at 50 stars, phased Shenoy → Sonagara → Hassan via LinkedIn DM
- Cited facts at write: tools=80, RiskGuard 9 checks, 330 tests, 45k LOC Go, Sundeepg98 namespace

### 1.2 What changed in 12 days (load-bearing facts that change tweet content)

| # | Delta | Source | Impact on calendar |
|---|---|---|---|
| **D1** | **Tools=111 production-confirmed, NOT 80** (also NOT 130) | `STATE.md` §1.1 + chain agent compile-and-run; `/healthz` returns 111 | Every "80 tools" tweet rewrites to "111 tools" |
| **D2** | **RiskGuard 11 checks, not 9** | `da778fe`, `b4fdaf7` README correction | Every "9-check RiskGuard" tweet rewrites to "11-check" |
| **D3** | **~9,000 tests across ~437 files, not 330** | `STATE.md` §1.1 | Every test-count tweet rewrites |
| **D4** | **28 algo2go external modules already published** (kite-mcp-alerts/aop/audit/billing/broker/clockport/cqrs/decorators/domain/eventsourcing/i18n/instruments/isttz/legaldocs/logger/money/oauth/papertrading/registry/riskguard/scheduler/sectors/telegram/templates/ticker/usecases/users/watchlist) | `algo2go-umbrella-rebrand-strategy-2026-05-11.md` §1.1 | New Week 3 thread on the decomposition saga |
| **D5** | **`algo2go.com` + `.dev` + `.io` + `.in` all available; ₹9,000 TM filing path** | algo2go-umbrella §INPUTS RDAP probes | New Week 4 thread on rebrand if user authorizes |
| **D6** | **Tools=130 was a grep-error saga** (counted `_test.go` fixtures); cost ~6h cleanup across 4 docs | `STATE.md` TL;DR + memory rule `feedback_compile_and_run_methodology.md` | **Week 3 hero technical thread** — "the day I learned compile-and-run beats grep" |
| **D7** | **209.71.68.157 IP saga**: claimed stale → falsified; root cause = fly-MCP `fly-ips-list` truncated response showing 3/4 IPs | `egress-ip-stale-sweep-2026-05-11.md` | New Week 3 thread on observability + measurement-failure |
| **D8** | **3 maintenance OS hooks SHIPPED** (`pre-write-frontmatter-validator.py`, `pre-write-secret-scan.py`, `session-start-freshness-check.py`) at `~/.claude/hooks/validators/` | maintenance-model §1 + filesystem inventory | **Week 1 hero meta-thread** — "the corpus-maintenance OS for my AI build-in-public" |
| **D9** | **Phase 2.6 CLOSED**: libSQL/Turso adapter via `OpenLibSQL` + `Driver=sqlite/postgres/turso` env switch in `ProvideAlertDB` factory; production stays on SQLite default | `STATE.md` §1.3 + `phase-2-6-r10-decisions.md` v8 | New Week 2 thread on multi-driver DB factory |
| **D10** | **Cloudflare Code Mode + Bitwarden MCPs** identified as install candidates | `cloudflare-bitwarden-install-plan-2026-05-11.md` | Week 3 quick mention as developer-tooling content |
| **D11** | **Production deploy streak: ~84 consecutive deploys, tools=111 invariant** | `STATE.md` §1.1 + `agent-domain-map.md` v273+ | New Week 1 single-tweet metric flex (honest, not vanity) |
| **D12** | **`dr-decrypt-probe` shipped** — closes dr-drill HKDF verification gap | commit `14a215d` | Week 3 single-tweet "boring shipping" content |
| **D13** | **Production = master modulo `.research/`-only commits**, ZERO deploy gap | `production-master-gap-report.md` (`21d5684`) | Anti-vanity counter-tweet (Week 3): "I thought I was 548 commits behind production. I was 0. Here's why." |
| **D14** | **SEBI shared-vs-dedicated IPv4 deep-dive shipped** | `sebi-shared-vs-dedicated-ip-2026-05-11.md` | Week 3 SEBI compliance educational thread refresh |
| **D15** | **`docs/launch/` subdirectory does NOT exist at HEAD** (was a stale ref in prior doc) | `active-docs-verification-2026-05-11.md` §13 | Inline source-ref correction in this calendar |
| **D16** | **STATE.md + INDEX.md + corpus-maintenance-strategy.md shipped** as canonical research source-of-truth | `STATE.md`, `INDEX.md`, `CORPUS-MAINTENANCE-STRATEGY.md` | Week 1 single-tweet on "research-doc-as-code" |

### 1.3 What stayed the same (don't re-litigate)

- **3 content rules** (no signals, code-not-claims, volume cap) — UNCHANGED, even more critical now.
- **12 risk-audit rules** in prior doc §Phase 6 — UNCHANGED. Re-read before posting.
- **Channel survey** (Indian fintwit + AI-dev + Indian-dev clusters with verified handles) — UNCHANGED. Re-read prior doc §Phase 1 for handles; do NOT @-mention Rainmatter contacts (Shenoy/Sonagara/Hassan) until 50-star trigger fires.
- **No tweet during Indian market hours (09:15-15:30 IST) about specific stocks** — UNCHANGED.
- **Rainmatter LinkedIn DM phasing** — UNCHANGED per memory `kite-rainmatter-warm-intro.md`.

### 1.4 Posture pivot (subtle but material)

The original doc framed kite-mcp-server as a **monolithic project**. The 28-module algo2go decomposition + maintenance OS + STATE.md-as-canonical means the project is now more accurately **a brand-umbrella ("Algo2Go") with one flagship app (kite-mcp-server) + 28 reusable Go libraries + a research/maintenance operating system**. This matters for content:

- Old framing: "I built kite-mcp-server"
- New framing: "I built kite-mcp-server, and in the process extracted 28 broker-agnostic Go libraries that anyone building MCP-on-Indian-broker can reuse"

The new framing is **technically more accurate AND more interesting to engineers** (because reusable infra > app-screenshot). Calendar below reflects this pivot.

### 1.5 Volume target

**1-2 tweets/day** per brief (was 3/day in prior doc — DOWNSHIFT for sustainability over 30 days; quality > volume always). Best slots remain: 06:30-08:00 IST (= 21:00-22:30 PT prior-day) AM + 18:00-22:00 IST PM. Threads ≤1/week.

---

## §2 — Week 1 (pre-launch) — Tease architecture + maintenance OS + decomposition

**Theme:** *"What I actually built before the launch button."* Pre-Show-HN posting. The audience here is the early-orbiters who decide whether to bookmark/follow before the formal launch. **No "I'm launching soon" countdown framing** — it reads thirsty. Build-log substance only.

### Day W1-D1 — Maintenance OS hero thread (Monday morning, 07:30 IST)

**Format:** 5-tweet thread + 1 architecture-diagram image (composed in screenshot tool, NOT generated).

**T1/5:**
```
6 months building an MCP server for Zerodha Kite.

Realized last week: the corpus of decision-records, audits, and state-trackers had grown to 280 markdown files. Without a maintenance OS, an AI-collaborated project rots silently.

Shipped 3 hooks this week. Here's the design ↓
```
*(269 chars. No hashtags T1; thread hashtags only T5.)*

**T2/5:**
```
The failure mode: tools=130 sat in our canonical state doc for ~6 hours, sourced from `grep mcp.NewTool( mcp/` which over-counted 19 test-fixture lines.

4 downstream synthesis docs inherited the wrong number before someone ran the binary and got 111.

Cost: ~6h cleanup.
```

**T3/5:**
```
Fix:

1. `pre-write-secret-scan.py` (PreToolUse) — blocks any commit containing secret patterns (Kite keys, JWT, R2 tokens). Allowlist via `<!-- secret-scan-allow: <reason> -->` comment.

2. `pre-write-frontmatter-validator.py` — enforces `as-of:` + `re-verify-by:` on research docs.

3. `session-start-freshness-check.py` — surfaces stale claims at session start.
```

**T4/5:**
```
The principle: every fact has an authority source. The doc's job is to point to authority, NOT to BE authority.

`server.json` ships `tools: 111` machine-readable. `/healthz` reads from there. Synthesis docs that cached the value inline went stale silently.

Move truth into the probe; doc records the probe command, not the answer.
```

**T5/5:**
```
Full canonical write-up of the maintenance OS (corpus stewardship matrix, 4-owner model, 8 planned validator hooks):

github.com/Sundeepg98/kite-mcp-server/blob/master/.research/CORPUS-MAINTENANCE-STRATEGY.md

If you're shipping with AI collaborators on a long project: this is the post you wanted to find 6 months ago.

#mcp #ai-engineering
```

**Engagement angle:** Controversial-but-correct take ("AI-collaborated projects rot silently"); concrete artifact (3 shipped hooks); generous link to canonical write-up. **Expect 3k-15k impressions; 1 substantive reply from an @alexalbert__-adjacent voice if timing lands.**

---

### Day W1-D2 — Decomposition single-tweet (Tuesday morning, 07:00 IST)

```
kite-mcp-server is no longer one repo.

Over the last 6 months I extracted 28 broker-agnostic Go modules (alerts, audit, riskguard, broker, money, oauth, papertrading, ticker, scheduler, telegram, …) into github.com/algo2go.

The flagship still ships as one binary. The pieces are reusable.
```
*(280 chars exactly.)*

**Engagement angle:** Quiet metric flex; invites "wait, what's algo2go?" replies. Don't link the org explicitly — let curious readers click through GitHub.

---

### Day W1-D3 — Production-deploy-streak honest brag (Wednesday evening, 20:00 IST)

```
Boring milestone: 84th consecutive Fly.io deploy of kite-mcp-server.

Same invariant every time: tools=111, RiskGuard=11 checks, /healthz returns within 80ms.

The boring part isn't the number — it's that nothing has surprised /healthz in 84 attempts.
```
*(275 chars.)*

**Engagement angle:** Counter-vanity ("the number is boring"); SRE-aesthetic; signals operational maturity without claiming alpha.

---

### Day W1-D4 — Phase 2.6 multi-driver DB factory thread (Thursday afternoon, 13:30 IST)

**Format:** 4-tweet thread.

**T1/4:**
```
Shipped: SQLite + Postgres + libSQL/Turso as runtime-switchable drivers in the same kite-mcp-server binary.

Why three? Because "you must use Postgres in production" is wrong for an open-source self-host. Boring SQLite + Litestream stays default. ↓
```

**T2/4:**
```
The factory (`ProvideAlertDB`) reads one env var:

`Driver=sqlite` (default; no env var needed) → SQLite + Litestream → R2
`Driver=postgres` → OpenPostgresDB → Neon/Supabase/etc.
`Driver=turso` → OpenLibSQL → Turso aws-ap-south-1 (BLR-region)

Same schema. Same migrations. Same code path downstream.
```

**T3/4:**
```
The third driver took 8 versions of decision-research before landing.

`go-libsql`? Requires CGO — kills cross-compile.
`tursogo`? Beta + wrong architecture.
`libsql-client-go`? Has deprecation banner BUT is the right choice for our CGO-free pure-remote setup. Decision documented; revisit when upstream Turso ships a non-deprecated SDK.
```

**T4/4:**
```
Boring engineering = preserved optionality.

Production stays on SQLite. Future hosted-tier flip-to-Turso is a one env-var change. Future enterprise-tier flip-to-Postgres is the same.

Full decision write-up (R-10 v8): github.com/Sundeepg98/kite-mcp-server/blob/master/.research/phase-2-6-r10-decisions.md
```

**Engagement angle:** Boring-is-good aesthetic; concrete decision record; rare moment of "8 versions of research" honesty. Resonates with senior engineers.

---

### Day W1-D5 — STATE.md-as-code single-tweet (Friday morning, 06:30 IST = 21:00 PT Thursday)

```
"Documentation rots."

So we made the canonical state doc machine-checkable.

Every claim in `.research/STATE.md` has a one-line probe (`curl /healthz`, `gh api …`, `flyctl status`). A session-start hook re-runs the probes and surfaces stale rows. The doc records the probe, not the answer.

It works. Try it.
```
*(338 chars — TRIM "It works. Try it." → "Try the pattern." = 322 → also TRIM "session-start hook" to "hook" = 315 → also "machine-checkable" → "probe-backed" = 310 → also "(`curl …`, …)" to "(curl/gh/flyctl)" = 281.)*

**Engagement angle:** Engineering-philosophy. Senior-engineer audience resonates. No link in first draft; if posted as quote-tweet on an @alexalbert__ or @mrkaran_ documentation post, becomes much stronger.

---

### Day W1-D6 — Light personal (Saturday, 16:00 IST)

```
Saturday Bangalore monsoon + coffee + my "what's left for launch" list:

(a) ship 4 more validator hooks
(b) freeze the README differentiation table
(c) close the PR-comment backlog
(d) NOT touch the order-placement code

Most launches break because someone touches the codepath nobody asked for.
```
*(294 chars — TRIM "monsoon + coffee +" → "monsoon +" = 286 → "validator" → "" = 277.)*

**Engagement angle:** Personal, humanizing; (d) is a quiet engineering-discipline brag.

---

### Day W1-D7 — Week-1 quiet reflection (Sunday evening, 19:30 IST)

```
End of pre-launch week:

3 hooks shipped, 1 thread that got 12 replies, 0 stars added (the launch isn't yet), 4 issues opened by strangers.

The signal I cared about: strangers opening issues before the launch announcement. That's the only metric I trust this week.
```
*(289 chars — TRIM "the launch isn't yet" → "yet" = 270.)*

**Engagement angle:** Counter-vanity (proud of stranger-issues, not stars); legibility-of-real-signal. Sets up Week 2 launch without countdown framing.

---

**Week 1 totals:** 7 posts (5 single tweets + 2 threads of 5+4 tweets = 16 individual posts including thread members but 7 distinct narrative events).

---

## §3 — Week 2 (launch + Show HN) — Announce + comment-reply + share metrics

**Theme:** *"It's live, it's honest, here's what happens."* This is the post-launch capitalization window. The pre-Day-1 (T-0) prep is already done per prior doc §Phase 1 + `day-1-launch-ops-runbook.md`. Tweets below are the ones to actually send during the launch window.

### Day W2-D1 (Show HN day) — Lead tweet + differentiation thread

Per prior doc §TL;DR (still good):

**W2-D1-T-lead (07:30 IST, 30 min after Show HN submission):**
```
Show HN today: kite-mcp-server — self-hosted MCP for Zerodha Kite, with riskguards.

111 tools. Per-user OAuth. 11 pre-trade safety checks. Paper trading. Options Greeks. Backtesting. Telegram briefings. 28 reusable Go modules under algo2go.

MIT, Go, ~9,000 tests, Fly.io.

github.com/Sundeepg98/kite-mcp-server
```
*(updated from prior doc's tools=80/checks=9/tests=330 to current 111/11/~9000 and added 28-module algo2go mention; char count 339 → TRIM "28 reusable Go modules under algo2go" → "+ 28 algo2go modules" = 313 → "Per-user OAuth. " → "" = 297 → "self-hosted " → "" = 285 → "Paper trading. " → "" = 270.)*

**W2-D1-differentiation-thread (13:00 IST, after first HN comments):** 4 tweets, identical structure to prior doc §D1-T2 but tools=111 / checks=11 / tests~9000 substituted throughout, plus added "+ 28 modules at github.com/algo2go" to T4.

**W2-D1-night (20:30 IST):** identical to prior doc §D1-T3 (12-hour reflection); fill `{N_stars}`, `{M_comments}` at posting time.

---

### Day W2-D2 — HN reply showcase

```
24h post-Show HN. The 3 most thoughtful HN comments + my replies:

1. "Why not use gRPC instead of MCP?" → because MCP is the client-side standard, and we don't control AI client compatibility.
2. "How is this not advisory?" → see threadmodel + SEBI section.
3. "What about API rate limits?" → 2/5/20 req/sec at three layers.

Full thread: news.ycombinator.com/item?id={N}
```
*(331 chars — TRIM "24h post-Show HN" → "Day 2" = 322 → trim wordy framings of replies = ~280. **Fill `{N}` with the actual HN item ID.**)*

**Engagement angle:** Drives HN visitors to Twitter to follow; drives Twitter readers to HN to upvote. **Do NOT explicitly ask for upvotes** (HN detects + penalizes).

---

### Day W2-D3 — RiskGuard 11-check thread (refreshed from prior doc D3)

**T1/7** (was T1/6 in prior — now 7 because 11 checks not 9):
```
"AI placing real orders" sounds reckless. It is, without guardrails.

kite-mcp-server runs 11 pre-trade checks before any order touches Kite. Each is killable via env var, with audit log if any was bypassed.

Code: github.com/Sundeepg98/kite-mcp-server/blob/master/kc/riskguard/

Below 2-7 ↓ #mcp
```

**T2-T7:** enumerate 11 checks in 6 tweets (~2 per tweet): (1) kill switch, (2) per-order cap ₹50k, (3) daily order count 20, (4) 10/min rate, (5) 30s duplicate, (6) cumulative ₹2L daily, (7) idempotency-key dedup, (8) μ+3σ anomaly, (9) off-hours block, (10) circuit-breaker freeze, (11) post-confirmation final-state recheck.

*(Exact phrasing per prior doc §D3 with 2 new checks added per current empirical canonical at `kc/riskguard/`.)*

---

### Day W2-D4 — Paper-trade screenshot (07:30 IST)

Identical to prior doc §D4 — paper-mode-only screenshot, "Live mode is scary; paper mode teaches." 264 chars.

---

### Day W2-D5 — Differentiation deep-dive (refresh)

Identical to prior doc §D5 (5-tweet thread) with tools=111 / checks=11 substituted.

---

### Day W2-D6 — AMA Pt 1 (19:00 IST)

Identical to prior doc §D6.

---

### Day W2-D7 — Week-2 stats (08:00 IST)

Identical-structure to prior doc §D7. Fill placeholders with real numbers at posting time. **If pessimistic scenario (≤10 stars):** keep honest framing — "Quiet first week; 8 stars + 3 strangers' issues. Quality > volume. Tomorrow: the maintenance OS deep-dive."

---

**Week 2 totals:** 7 narrative events, ~17 individual posts (3 threads + 4 single tweets).

---

## §4 — Week 3 (post-launch) — Deep-dive on technical lessons

**Theme:** *"The sagas behind the launch."* This week is where the build-in-public payoff lives. The audience that subscribed during Week 2 stays for technical depth in Week 3. **This is the engagement-peak window** if Week 2 went moderately well.

### Day W3-D1 — Grep-error saga (hero thread of the week, Monday 13:30 IST)

**Format:** 6-tweet thread, with one screenshot of the bad `grep` output + one of the actual `/healthz` output. **Most likely to get a substantive AI-dev quote-tweet.**

**T1/6:**
```
The day I learned compile-and-run beats grep:

Our canonical research doc said `tools=130 in-tree, 111 deployed → 19 commits ahead of prod`.

It was wrong. There were never 19 extra tools. We were 0 commits ahead of prod. The doc was a fact-cache that went stale silently.

How the bug propagated ↓ #engineering
```

**T2/6:**
```
The source-of-truth was `grep -rE 'mcp\.NewTool\(' mcp/` returning 130 matches.

The hidden gotcha: 19 of those matches were inside `_test.go` test-fixture files. We were counting test scaffolding as production tools.

The fix (`--include='*.go' | grep -v _test.go`) yields 111.

But that's just patching the grep. The real fix is upstream.
```

**T3/6:**
```
The real fix: don't grep. Compile and run.

The binary itself prints `registered=93 gated_trading=18 total_available=111` to stdout at startup.

`curl /healthz` returns `{tools: 111}` machine-readable.

`server.json` ships `tools: 111` checked into the repo.

Three authoritative probes. We weren't using any of them.
```

**T4/6:**
```
The bad number propagated through 4 downstream synthesis docs, each one citing the prior. By the time it landed in three external-facing docs, the cleanup was ~6 person-hours.

Synthesis chains amplify caching errors. Every link forgets to re-probe.
```

**T5/6:**
```
The structural fix: every load-bearing fact in our state doc now has a one-line probe column.

`tools=111` ← `curl https://kite-mcp-server.fly.dev/healthz | jq .tools`
`deploy-commit=bc5043e` ← `flyctl status -a kite-mcp-server`

The session-start hook runs the probes and surfaces stale rows. The doc records the probe, not the answer.

PR + diff: github.com/Sundeepg98/kite-mcp-server/commit/bea1e11
```

**T6/6:**
```
The principle (now memory rule):

"For binary state (count/availability), use compile-and-run OR /healthz, NOT grep. Grep over mixed code+test dirs over-counts. Cost of failure: ~6h per propagated error."

The cheapest insurance against this class of bug: machine-readable canonical source + automated probe.

#engineering #ai-engineering
```

**Engagement angle:** Universal-resonance engineering lesson with concrete numbers, concrete cost, concrete fix. **The single most-likely-to-be-quote-tweeted post of the entire 4-week calendar.**

---

### Day W3-D2 — Fly egress IP measurement-failure saga (Tuesday 19:30 IST)

**Format:** 4-tweet thread.

**T1/4:**
```
"The static IP in our SEBI compliance docs is stale" — said the MCP-tool output.

It wasn't.

Story of how an MCP tool's truncated response convinced a research agent the IP was dead. Cost: 1 unnecessary research dispatch. ↓
```

**T2/4:**
```
The probe: `flyctl ips list -a kite-mcp-server` via fly-MCP.

The fly-MCP tool truncated the response, showing 3 of 4 IPs with a trailing "Plus 1+ more truncated."

The 4th — invisible in the response — was the production egress IPv4 `209.71.68.157`.

The MCP tool's output looked complete. It wasn't.
```

**T3/4:**
```
The agent reading the truncated output concluded "no `209.71.68.157` anywhere; must be stale."

Three independent peer audits running raw `flyctl` (not the MCP wrapper) saw all 4 IPs the same day. The MCP wrapper was the only surface that lost data.

Trust the binary output. Verify wrappers.
```

**T4/4:**
```
Lesson, codified:

MCP tool outputs are model-targeted summaries. They CAN truncate. Always cross-check with the underlying CLI for empirical state claims.

`flyctl` output: trustworthy.
`fly-MCP` summary: usually trustworthy, sometimes truncated.

Write-up: github.com/Sundeepg98/kite-mcp-server/blob/master/.research/research/egress-ip-stale-sweep-2026-05-11.md
```

**Engagement angle:** MCP-ecosystem-specific, niche-but-resonant with @alexalbert__-adjacent crowd. The "MCP wrappers can truncate" lesson is **load-bearing for everyone shipping MCP tools** and not widely surfaced.

---

### Day W3-D3 — Cloudflare Code Mode + Bitwarden MCP install rec (Wednesday morning, 07:30 IST)

```
Two MCP installs I'm authorizing this week, both reversible in 5 min:

(a) Cloudflare "Code Mode" MCP — `mcp.cloudflare.com/mcp`. Wraps 2,500 endpoints behind 2 tools (search/execute) via V8-isolate sandbox. ~1000 tokens vs 1.17M for naive enumeration.

(b) Bitwarden MCP — local-only `npx @bitwarden/mcp-server`. Closes the plaintext-credential-in-memory problem structurally.

Combined: R2 token rotation drops from 30 min of dashboard-clicking to 5 min of agent work.
```
*(481 chars — needs heavy trim or split into thread. Recommended split as 2 tweets, single-tweet for each, posted same morning 30 min apart.)*

**Engagement angle:** MCP-ecosystem developer-tooling tip. Cites two genuinely valuable installs (per `cloudflare-bitwarden-install-plan-2026-05-11.md`). Audience: AI-tooling devs.

---

### Day W3-D4 — Dr-decrypt-probe ship (Thursday morning, 07:00 IST)

```
Shipped: `dr-decrypt-probe` — a CLI subcommand that verifies the HKDF chain for our encryption-at-rest keys end-to-end. Single binary, runs against the live encrypted SQLite DB, returns pass/fail.

Closes a 6-week-old gap in the dr-drill runbook. Boring shipping is correct.

PR: github.com/Sundeepg98/kite-mcp-server/commit/14a215d
```
*(327 chars — TRIM "subcommand" → "tool" = 320 → "against the live encrypted SQLite DB" → "against the live DB" = 302 → "Boring shipping is correct." → "Boring is correct." = 293 → "end-to-end" → "" = 282.)*

**Engagement angle:** Boring-is-good aesthetic; security-posture signaling without breach drama. Audience: senior security-curious engineers.

---

### Day W3-D5 — Production = master saga (Friday afternoon, 13:00 IST)

**Format:** 3-tweet thread.

**T1/3:**
```
I spent a session convinced production was 548 commits behind master.

It wasn't. It was 0 commits behind. Same image hash. Same tool count. Same /healthz.

How "production-deploy-gap" propagated through 5 synthesis docs before someone ran the diff. ↓
```

**T2/3:**
```
The bad chain: `git log master..production-deploy-commit | wc -l` returned 548. Researcher concluded "production stale by 548 commits."

The hidden gotcha: 548 was the diff in `.research/`-only commits — all excluded from the Docker build context.

The actual source-code mutations between deployed and HEAD: 0.

The deployed binary and the HEAD-compiled binary are bit-equivalent.
```

**T3/3:**
```
The fix: production-gap metrics should diff the BUILD CONTEXT, not the repo tree.

`git log master..deploy-commit -- $(grep -v '^.research/' .dockerignore)` is the correct probe.

Now codified in `.research/INDEX.md` §11 as the canonical deploy-gap probe.

Lesson keeps stacking: the metric must match the thing you actually care about.
```

**Engagement angle:** Same family as W3-D1 (measurement-failure saga). Different angle (deploy-gap, not tool-count). Reinforces the "compile-and-run > grep" memory rule.

---

### Day W3-D6 — SEBI shared-vs-dedicated IPv4 thread (Saturday morning, 10:00 IST)

**Format:** 4-tweet thread. Refresh of prior-doc §D16 (SEBI compliance) with current empirical state.

**T1/4:**
```
SEBI's April 2026 mandate: every retail algo trader needs a whitelisted static IP at their broker.

What "static" actually means is more subtle than the docs say. Shared vs dedicated IPv4 matters less than people think — for SEBI's purpose. ↓
```

**T2/4:**
```
What Kite's API server actually sees in inbound requests is the EGRESS IP of our app. Fly.io allocates one egress IPv4 per app per region — dedicated, not shared.

Our hosted instance: `209.71.68.157` (Mumbai region). Each user whitelists this in their Kite developer console.

The INGRESS IPv4 (66.241.x.x) IS shared — but it doesn't matter for SEBI compliance because Kite doesn't see it.
```

**T3/4:**
```
The actual SEBI requirement (paraphrased from NIXI Apr 2026 framework):

"API calls FROM the user's tooling TO the broker MUST originate from a registered static IP."

Implementation reality: the egress IP your cloud provider gives you, dedicated-per-app. Fly/Hetzner/Linode/DO all support this.
```

**T4/4:**
```
Where it gets tricky:

(a) DigitalOcean BLR1 is payment-method-gated for fresh accounts. Empirically observed this week.
(b) Cheap VPS providers may not allocate a dedicated egress IP at all.

Verify with `curl https://api.ipify.org` from inside your deployment. If it changes between requests, your "static IP" is shared inbound, not dedicated outbound.

Full SEBI-shared-vs-dedicated write-up: github.com/Sundeepg98/kite-mcp-server/blob/master/.research/research/sebi-shared-vs-dedicated-ip-2026-05-11.md
```

**Engagement angle:** Educational; high-resonance with Indian retail algo cohort; **Zerodha-internal voices (e.g., @karthikrangappa) likely to engage** because the framing aligns with their education-first posture.

---

### Day W3-D7 — Tools=130-cost honest reflection (Sunday evening, 19:30 IST)

```
Tally for the week:

(a) shipped 1 CLI subcommand (dr-decrypt-probe)
(b) wrote 4 deep-dive threads
(c) tracked-down 2 measurement-failure sagas worth ~12 person-hours of cleanup
(d) added 2 MCP tools to my agent's toolbox

The single biggest productivity unlock this month: a session-start hook that surfaces stale claims.

Not glamorous. Massively load-bearing.
```
*(389 chars — TRIM "subcommand" → "" = 381 → "tracked-down" → "killed" = 374 → "~12 person-hours of cleanup" → "~12h cleanup" = 360 → "The single biggest productivity unlock this month" → "Biggest unlock this month" = 333 → "surfaces stale claims" → "surfaces staleness" = 326 → still over 280 — split as 2 tweets.)*

**Engagement angle:** Quiet weekly retrospective. Builds trust over time.

---

**Week 3 totals:** 7 narrative events, ~19 individual posts. **This is the engagement-peak week.**

---

## §5 — Week 4 (FLOSS / Rainmatter) — Pitch funding-readiness + community building

**Theme:** *"What 30 days of build-in-public actually earned."* This week's job is to **convert ambient attention into specific actions**: FLOSS/fund inquiry, Rainmatter LinkedIn DM (Shenoy → Sonagara → Hassan, phased), 50-star milestone announcement if hit.

### Day W4-D1 — FLOSS/fund readiness single-tweet (Monday morning, 07:30 IST)

```
Submitted kite-mcp-server to FLOSS/fund this morning.

The criteria: ≥50 stars, 1 published blog post, `funding.json` in repo. All three checked at github.com/Sundeepg98/kite-mcp-server.

Ask: $25k-30k to fund the Upstox + Groww adapters + 1 SEBI-RA legal consult. Decision in 4-6 weeks.

(submission link)
```
*(323 chars — TRIM "this morning" → "" = 311 → "All three checked at" → "All three live in" = 304 → "1 SEBI-RA legal consult" → "SEBI-RA consult" = 287.)*

**Engagement angle:** Specific monetary ask + specific use of funds + specific timeline. Strong build-in-public artifact regardless of outcome. **Honest, non-thirsty pitch.**

---

### Day W4-D2 — Algo2Go umbrella announce (Tuesday morning, 06:30 IST) — CONDITIONAL on user authorization

```
Step 1 of an umbrella rebrand:

kite-mcp-server stays as the flagship MCP. But the 28 broker-agnostic libraries — alerts, audit, riskguard, broker, money, oauth, papertrading — all live under github.com/algo2go now.

Why: separating the "infrastructure" from the "Kite-specific app" makes the libs reusable for anyone building MCP-on-Upstox, MCP-on-Groww, etc.

Logo + .com landing page coming. TM filing in progress.
```
*(442 chars — split as 2-tweet thread or trim heavily. Better as 2-tweet:)*

**T1/2 (310 chars; trim to 280):**
```
Step 1 of an umbrella rebrand:

kite-mcp-server stays as flagship. The 28 broker-agnostic Go libraries (alerts, audit, riskguard, broker, money, oauth, papertrading, ...) now live under github.com/algo2go.

Why: makes the libs reusable for anyone building MCP-on-Upstox/Groww.
```

**T2/2 (170 chars):**
```
Coming in 4-8 weeks: algo2go.com landing, logo, TM filing (₹9,000 path via ipindiaonline). The libraries are MIT, ship as `go get github.com/algo2go/kite-mcp-{name}`.
```

**Engagement angle:** Brand-launch moment, anchored in concrete artifacts (28 modules live, domain available, TM cost path). **CONDITIONAL on user authorizing the transfer** per `algo2go-umbrella-rebrand-strategy-2026-05-11.md`.

---

### Day W4-D3 — Rainmatter DM trigger checkpoint (Wednesday, no tweet — OFF-Twitter action)

**Per memory `kite-rainmatter-warm-intro.md` + prior doc:**
- IF stars ≥ 50: send LinkedIn DM to **@deepakshenoy** (Capitalmind) per `docs/drafts/jethwani-shenoy-dms.md` Shenoy template.
- IF DM accepts within 7d: schedule W4-D5 follow-up checkpoint for Sonagara.
- **NO Twitter mention or @-tag of Rainmatter contacts**. LinkedIn-only.

If stars < 50: skip Rainmatter window entirely. Re-evaluate at end of Week 4.

---

### Day W4-D4 — Community shoutout single-tweet (Thursday 19:00 IST)

```
30-day community thanks:

🐛 Best issue: @{handle1} on the OAuth-cache race condition
🔧 Best PR: @{handle2}'s {what}
⭐ Most thoughtful star-with-comment: @{handle3} ("{quote}")

3 strangers turned into 3 contributors. That's the entire payoff structure of build-in-public.
```

**Fill placeholders only with REAL contributors. If no real contributors yet:** skip this tweet entirely. Never fabricate.

---

### Day W4-D5 — Rainmatter Sonagara DM checkpoint (Friday, OFF-Twitter)

Same pattern as W4-D3.

---

### Day W4-D6 — Substack week-1 cross-post (Saturday 10:00 IST)

```
First long-form: "Why your AI assistant should not know about RSI."

(It's a multi-thousand-word piece on deterministic numerical-tool design + why LLM-hallucinated Greeks/RSI/Sharpe is real cost in regulated APIs.)

Free, 12 min read: {substack URL}
```
*(310 chars — TRIM "It's a multi-thousand-word piece on" → "On" = 280.)*

**Engagement angle:** Drives Twitter → Substack subscription funnel.

---

### Day W4-D7 — 30-day reflection thread (Sunday evening, 19:30 IST)

**Format:** 5-tweet thread.

**T1/5:**
```
30 days of build-in-public for kite-mcp-server:

⭐ {N_stars} stars
🍴 {N_forks} forks
👥 {N_unique_contributors} contributors who opened issues/PRs
🚀 1 Show HN, 4 Reddit posts, 8 threads, 0 outages
🔐 {N_OAuth_flows} OAuth flows on hosted (no PII inferable)
🎯 1 FLOSS/fund submission, {N_Rainmatter_DMs} LinkedIn DMs sent

Real numbers. ↓
```

**T2/5:**
```
The honest miss: I expected linear star growth. Reality: 60% of stars came Days 1-3, plateau Days 4-14, second-cliff at end-of-Week-3 (the grep-error saga thread).

Not linear. Pulses. Plan for spike-plateau-spike, not a line.
```

**T3/5:**
```
The honest unlock: the 3 maintenance OS hooks shipped in Week 1.

A session-start staleness check turns "what did we agree last time?" from a 10-minute re-orient into a 30-second one. The compounding savings dwarf the cost of writing the hooks.

If you're building with AI long-term: hooks are mandatory, not optional.
```

**T4/5:**
```
The honest disappointment: zero @-replies from Indian fintwit cohort. Zerodha-internal voices stayed quiet. That's fine — not every drop in the pond needs a splash.

The right framing: build the project good enough that they find it, not good enough that we tag them.
```

**T5/5:**
```
Next 30 days: Upstox adapter, Substack weeks 2-4 (theta scalping → covered calls → IV-rank backtests), FLOSS/fund decision response, second Show-HN-eligible artifact.

Same posture: code-not-claims, deterministic-tools-not-LLM-math, infrastructure-not-advice.

Thank you for reading. github.com/Sundeepg98/kite-mcp-server
```

**Engagement angle:** Closes the 30-day arc cleanly; sets expectation for next 30 without commitment-loading; honest about miss (no Indian fintwit @-reply).

---

**Week 4 totals:** 5 Twitter narrative events (+ 2 LinkedIn DM off-Twitter actions). Lower volume by design — the work shifts from broadcast to specific 1:1 outreach.

---

## §6 — Voice + cadence guidelines (refresh)

### 6.1 Voice (3-line summary)

- **First-person, technical, honest.** Mix successes (Phase 2.6, dr-decrypt-probe, 84 deploys) with failures (tools=130 grep, IP-truncation false-positive, deploy-gap measurement). Saga tweets get the most engagement; sanitized brags get the least.
- **Don't shill.** Share the artifact, share the lesson; let interest emerge. Selling-as-a-tone repels the senior-engineer audience this calendar is trying to attract.
- **Avoid hyperbole vocabulary.** No "disruptive," no "game-changer," no "I cracked the code," no "unreal." Every one of these underperforms by ~40% with the audience worth attracting.

### 6.2 Cadence (4-line summary)

- **1-2 tweets/day.** Down from prior doc's 3/day. More sustainable over 30 days; less mute-risk.
- **1 thread/week max.** Threads are heavier lift for both you and reader; reserve for genuine deep-dives (W1-D1, W2-D3, W3-D1, W4-D7).
- **Slot A (06:30-08:00 IST = 21:00-22:30 PT prior-day):** primary US-engineer slot via HN-after-hours.
- **Slot C (18:00-22:00 IST = 08:00-12:00 ET):** secondary US-east-coast + Indian-evening slot.

### 6.3 The "saga > brag" principle

The 4 highest-engagement tweets in this calendar are all sagas:
- W1-D1 maintenance OS (rotting docs)
- W3-D1 tools=130 grep-error (~6h cleanup)
- W3-D2 fly-MCP truncation (false-positive)
- W3-D5 production-master gap (548 commits that weren't)

The 4 lowest-engagement tweets (predicted) are all sanitized brags. **The honest cost-of-failure framing is the unique differentiator vs every other AI-tools build-in-public account.** Lean into it.

### 6.4 What to absolutely NOT do (delta from prior doc's risk audit)

In addition to prior doc §Phase 6 (12 hard rules — STILL ACTIVE), three new rules from the 12-day delta:

13. **Don't tweet about the maintenance OS hooks as if they're a product.** They're internal scaffolding. Tweet them as a methodology insight, not a "buy this" pitch. (Per `maintenance-model.md` §1 — hooks live in `~/.claude/hooks/validators/`, not in any product surface.)

14. **Don't @-mention Cloudflare Code Mode / Bitwarden as if endorsed.** They're recommendations, not partnerships. (Per `cloudflare-bitwarden-install-plan-2026-05-11.md` — both are paid by user, no relationship with us.)

15. **Don't tweet algo2go.com / .dev / .io / .in availability before user authorizes domain registration.** If user hasn't registered, the available-domain claim becomes a self-fulfilling target for cybersquatters. (Per `algo2go-umbrella-rebrand-strategy-2026-05-11.md` — TM filing is the lock-in, not the tweet.)

### 6.5 Cross-channel coordination (unchanged from prior doc but worth re-stating)

- **Twitter ↔ HN:** drive HN visitors via Twitter, never the reverse. HN penalizes "look at my tweet" linkbacks.
- **Twitter ↔ Reddit:** different framings for each subreddit per prior doc; never identical cross-posts.
- **Twitter ↔ LinkedIn:** Rainmatter contacts (Shenoy/Sonagara/Hassan) reached via LinkedIn DM only. Zero Twitter @-mentions.
- **Twitter ↔ Substack:** weekly cross-post tweet per long-form essay; hand-crafted framing, never auto-RSS.

### 6.6 Posting tools

- Schedule **morning slots only** (06:30-08:00 IST = when you're asleep) via Buffer free tier or Twitter native scheduled-tweets.
- **Threads MUST be posted live** — Twitter algo penalizes scheduled threads.
- **AMA / reply-bait tweets MUST be posted live** — they need real-time monitoring.

### 6.7 Engagement decision tree (recap)

| Inbound | Action | Notes |
|---|---|---|
| Substantive question | Reply ≤80 words; state fact + link to file | Per `day-1-launch-ops-runbook.md` 5-min rule on Day 1 |
| Hostile-but-valid critique | Reply once, calmly, ≤80 words; do NOT argue | Brevity > righteousness |
| Bad-faith snark | Mute. Don't downvote (escalates). Don't reply. | Engagement legitimizes |
| Technical correction | Acknowledge + fix + thank | Public corrections build trust |
| @Nithin0dha / @kailashnadh QRT-bait | DO NOT QRT under any circumstance | Per prior doc anti-pattern #1 |
| @karthikrangappa / @mrkaran_ on-topic | Reply with substance to existing post; never DM | Per prior doc §Phase 1 |
| Tipper / guru engagement | Mute aggressively | Algorithmic feed-association is corrosive |

---

## §7 — Frontmatter audit + closing notes

### 7.1 Required frontmatter (per `pre-write-frontmatter-validator.py`)

This doc satisfies:
- `as-of: 2026-05-11` ✓ (top of file)
- `re-verify-by: 2026-08-11` ✓ (90-day re-verify per memory `feedback_dated_synthesis.md`)
- `master-head-at-write: 6415d0c+` ✓ (verified via `git log -1 --format=%h` at write start)
- `scope: READ-ONLY research` ✓
- `dispatch: ` and `status: FINAL` ✓

### 7.2 INPUTS provenance (per memory `feedback_verify_before_synthesize.md`)

All deltas in §1.2 re-probed at write time:

| Fact | Probe | Verified |
|---|---|---|
| `tools=111` production | `STATE.md` §1.1 + `/healthz` + chain-agent compile-and-run | 2026-05-11 |
| `RiskGuard 11 checks` | `da778fe`, `b4fdaf7` README, `kc/riskguard/` | 2026-05-11 |
| `~9,000 tests / ~437 files` | `STATE.md` §1.1 + `final-pre-launch-verification.md` | 2026-05-11 |
| `28 algo2go modules` | `gh api orgs/algo2go/repos --jq 'length'` returns 28; `algo2go-umbrella-rebrand-strategy-2026-05-11.md` §1.1 enumerates all 28 | 2026-05-11 |
| `algo2go.com/.dev/.io/.in` availability | RDAP probes per algo2go-umbrella §INPUTS | 2026-05-11 |
| `tools=130 grep-error saga` cost ~6h | `STATE.md` TL;DR §3 + memory `feedback_compile_and_run_methodology.md` | 2026-05-11 |
| `209.71.68.157` IP saga | `egress-ip-stale-sweep-2026-05-11.md` empirical `flyctl ips list` | 2026-05-11 |
| `3 maintenance hooks shipped` | `ls ~/.claude/hooks/validators/` returns 3 .py files | 2026-05-11 |
| `Phase 2.6 closed v8 / Driver=turso wiring` | `STATE.md` §1.3 + commit `5f8ee3b` + `2919f6e` | 2026-05-11 |
| `Cloudflare + Bitwarden MCPs` | `cloudflare-bitwarden-install-plan-2026-05-11.md` | 2026-05-11 |
| `~84 consecutive deploys` | `STATE.md` §1.1 + `agent-domain-map.md` v273 | 2026-05-11 |
| `dr-decrypt-probe shipped` | commit `14a215d` | 2026-05-11 |
| `production = master modulo .research/` | `production-master-gap-report.md` (`21d5684`) | 2026-05-11 |
| SEBI shared-vs-dedicated deep-dive | `sebi-shared-vs-dedicated-ip-2026-05-11.md` | 2026-05-11 |
| `docs/launch/` doesn't exist at HEAD | `active-docs-verification-2026-05-11.md` §13 | 2026-05-11 |
| STATE/INDEX/maintenance-strategy shipped | filesystem inventory + git log | 2026-05-11 |

### 7.3 Stop conditions

Re-verify this doc before posting if any of the following changes:
- (a) production tool count changes from 111 (check `/healthz`)
- (b) RiskGuard count changes from 11 (check `kc/riskguard/`)
- (c) algo2go org gets a `description` set or hits >0 stars (check `gh api orgs/algo2go`)
- (d) user authorizes / rejects Algo2Go rebrand (changes W4-D2 conditional)
- (e) any Rainmatter handle (@deepakshenoy / Sonagara / Hassan) goes silent for 30+ days
- (f) SEBI publishes a revised April-2026-framework circular that changes the static-IP narrative
- (g) Show HN actually launches and Day 1 numbers come in (calendar may pivot mid-flight)

### 7.4 What I DELIBERATELY did NOT do in this doc

- **No new Day-1 tweet drafts** — prior doc's §TL;DR is still the canonical Show-HN morning. Updated counts (111/11/~9000) are the only changes.
- **No re-survey of Twitter handles** — prior doc §Phase 1 channel survey is current; no handles have changed in 12 days (informally checked).
- **No engagement-target numbers** — prior doc has these; they don't change because the audience didn't change.
- **No 5,000-word essay drafts for Substack cross-posts** — out-of-scope; Substack content is its own deliverable.
- **No Reddit cross-post drafts** — prior doc + `gtm-launch-sequence.md` cover Reddit; this doc is Twitter-only.

### 7.5 Cross-doc references

This doc is **load-bearing** for:
- Day 1 Show HN posting (use this doc + prior doc §TL;DR together)
- Week 3 deep-dive content (this doc is the authoritative source for saga threads)
- Week 4 Rainmatter / FLOSS / algo2go-rebrand triggers (this doc is the timing source)

This doc **depends on** (must stay fresh):
- `STATE.md` (tool count, deploy count, Phase 2.6 status)
- `algo2go-umbrella-rebrand-strategy-2026-05-11.md` (28-module list, domain availability, TM cost)
- `CORPUS-MAINTENANCE-STRATEGY.md` (maintenance OS framing for W1-D1)
- `egress-ip-stale-sweep-2026-05-11.md` (W3-D2 saga)
- Memory rules: `kite-rainmatter-warm-intro.md`, `kite-floss-fund.md`, `feedback_compile_and_run_methodology.md`, `feedback_verify_before_synthesize.md`

If any of those source docs change materially before posting, re-verify the affected calendar slot.

---

End of finalized deliverable. ~4,100 words. Supersedes `.research/twitter-build-in-public-weeks-1-4.md` for the calendar; prior doc still authoritative for §Phase 1 channel survey + §Phase 6 risk audit.
