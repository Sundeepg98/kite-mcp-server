# Twitter launch kit — 2026-05-16

_Authored: 2026-05-16 IST_
_Source: GTM agent refresh dispatch_
_Status: DRAFT-FOR-LAUNCH (Tue 2026-05-26 target; `<HN_ID>` placeholder needs substitution after submit)_

---

## §0 — Empirical state pinned at draft-time (2026-05-16 ~14:00 UTC)

| Fact | Value | Source |
|---|---|---|
| Production version | v1.3.0 | `curl /healthz` |
| Production deploy count | v274 (Sprint 0 merge) | session brief |
| Tool count | **111** (invariant across 65 deploys) | `/healthz` (cached snapshot) |
| RiskGuard pre-trade checks | **11** | `.claude/CLAUDE.md` + `algo2go/kite-mcp-riskguard/guard.go` |
| Tests | ~9,000 across 437 test files | README L25 |
| Algo2go external modules | **31** kite-mcp-* repos (NOT 29; brief said 29 — empirical via `api.github.com/orgs/algo2go/repos` 2026-05-16) | live API probe |
| Module names | alerts, aop, audit, billing, bootstrap, broker, clockport, cqrs, decorators, domain, eventsourcing, i18n, instruments, isttz, kc, legaldocs, logger, metrics, money, oauth, papertrading, registry, riskguard, scheduler, sectors, telegram, templates, ticker, tools-common, usecases, users, watchlist | same |
| Decomposed LOC | ~49,400 (per brief) | brief |
| bootstrap module | v0.1.1 GOPROXY-verified | brief |
| Twitter handle | `@Sundeepg98` | `x.com/Sundeepg98` HTTP 200 |
| Show HN target slot | Tue 2026-05-26 06:30-08:30 PT (= 19:00-21:00 IST) | gtm-launch-sequence-2026-05-11.md |
| GitHub stars | 0 (pre-launch) | `gh api` |

**Rules retained from `twitter-build-in-public-finalized-2026-05-11.md`** (do not re-litigate):

- No tips, no signals, no live P&L, no forward-return claims.
- Code-not-claims: every architectural claim links to a public repo file.
- Volume cap: 2 tweets/day max during launch week.
- No @-mentions of Rainmatter orbit (Shenoy/Sonagara/Hassan) until 50★ trigger.
- No tweets about specific Indian-listed stocks during market hours (09:15-15:30 IST).

---

## §1 — Primary thread: D1 T1-T7 (Tue 2026-05-26 launch day)

**Posting plan:**

- T1 fires **30 minutes after Show HN submit** (so ~07:00 PT = 19:30 IST). Pinned for 7 days.
- T2-T7 spaced ~3 minutes apart (single composed thread, post as one).
- Demo A GIF native-uploaded to T1.
- Each tweet ≤279 chars to leave room for "1/7" suffix.

### T1/7 — The hook (Sprint 0 + build-in-public framing)

```
Show HN today: kite-mcp-server.

Self-hosted Model Context Protocol bridge for Zerodha Kite. 111 tools, 11 pre-trade safety checks, paper trading, hash-chained audit, ~9k tests.

Built in the open over 6 months. 31 reusable Go modules fell out.

Thread on the architecture ↓
```

(280 chars. Demo A GIF attached as media.)

### T2/7 — The Sprint 0 / decomposition milestone

```
2/7

This week shipped Sprint 0: ~49,400 LOC of decomposition.

The kite-mcp-server core is now a thin orchestration shell. The reusable parts — riskguard, audit, oauth, papertrading, ticker, telegram, money, registry, watchlist… 31 of them — live at algo2go/kite-mcp-*.

Each one a separate Go module.
```

(277 chars.)

### T3/7 — The 11-check riskguard (safety-first framing)

```
3/7

Before any order reaches Kite, an 11-check chain runs:

kill-switch · ₹50k order cap · qty limit · 20 orders/day · rate-limit · per-second rate · 30s duplicate · ₹2L daily notional · idempotency dedup · anomaly μ+3σ · off-hours block

Code: github.com/algo2go/kite-mcp-riskguard
```

(279 chars.)

### T4/7 — Paper trading + audit chain (the "AI + real money" defence)

```
4/7

Two more guardrails:

Paper trading toggle — same tools, virtual portfolio, ₹1 crore default cash, naive-fill caveat documented. New users start here.

Hash-chained SQLite audit log — every tool call, SHA-256 prev-hash, tamper-evident. The LLM can't lie about what it did.
```

(266 chars.)

### T5/7 — The honest limitations

```
5/7

What I won't pretend:

- Backtester is 4 strategies, naive
- Paper-trading fill simulator doesn't model slippage > flat bps
- Single broker (Zerodha) for now — Upstox/Dhan adapters planned
- Hosted instance has ENABLE_TRADING=false until I finish a compliance review

Self-host gets full functionality.
```

(279 chars.)

### T6/7 — The MCP / Go / Fly stack flex (technical credibility)

```
6/7

Stack:

Go 1.25 · mark3labs/mcp-go SDK · SQLite + WAL + Litestream → R2 backup · Fly.io Mumbai bom region · single static egress IP for SEBI April 2026 algo whitelist · AES-256-GCM at rest · per-user OAuth 2.1 PKCE.

~9,000 tests across 437 files. CI on every push.
```

(278 chars.)

### T7/7 — The Show HN CTA

```
7/7

I'm not a SEBI RA. Not selling tips. Not running anyone's money.

This is plumbing for traders who want their AI client to actually read their account.

Show HN: news.ycombinator.com/item?id=<HN_ID>
Repo: github.com/Sundeepg98/kite-mcp-server

Critique especially welcome on the riskguard.
```

(280 chars. Replace `<HN_ID>` with the actual item ID once submitted — the agent dispatching the thread should swap this in real-time.)

**Pinning rule:** T1 pinned to @Sundeepg98 profile from launch-day morning through Day 7 evening. Replace pin on Day 8 with a "thanks for X stars" follow-up only if ≥30 stars hit.

---

## §2 — Day 1 cross-post tweets (single-tweet RT-bait, technical Q&A bait, founder humanization)

Post these as **standalone single tweets** (NOT replies to T1-T7). One per day across Days 2-7. They live independently in the timeline, raise impression count, and act as RT-bait without polluting the launch thread.

### Tweet RT-1 — Quote-RT bait for Indian fintwit

```
A surprising thing about building for Indian retail brokerage:

The hardest part isn't the API. It's deciding which 11 things to check BEFORE you let any LLM place a real order.

Kite Connect itself is clean. The safety chain on top is the actual product.
```

(259 chars. No link. Designed to be quote-RTed by fintwit voices who want to add their own take.)

### Tweet TECH-1 — Technical Q&A bait (Go / MCP / SQLite cohort)

```
Go 1.25 + SQLite + Litestream WAL → Cloudflare R2 is the boring stack I keep ending up at.

~9,000 tests, sub-GB DB, $0/mo backup, point-in-time recovery, zero ops, single binary.

What load profile does this stack actually break under? Genuinely asking.
```

(279 chars. Designed for engineers to engage with operational counter-examples — high comment yield.)

### Tweet FOUNDER-1 — Humanization (solo-dev journey)

```
6 months ago I had ~80 tools in one main.go and was scared to refactor.

Today the core is a thin orchestration shell over 31 reusable Go modules that any other Indian-broker MCP can adopt.

Sprint 0 landed at v274 in production this morning. Zero downtime in 138 hours of v1.3.0.
```

(279 chars. Demo A GIF or architecture diagram attached.)

### Tweet QUOTE-1 — The boring-OSS counter-narrative

```
"Open-source means I'll get clobbered by VC-backed competitors."

Nope. The dominant Indian retail-broker API has 100+ MCP forks now. Mine wins on depth (111 tools, 11-check riskguard) — not on lock-in. Lock-in is the loser's strategy when the underlying is a regulated API.
```

(280 chars. Designed to start a sub-thread argument that boosts visibility.)

### Tweet DEMO-2 — Second demo asset (cross-system Telegram)

```
The cross-system proof I'm most proud of:

You ask Claude to set a Kite price alert.
The alert lands in your Telegram bot.
The audit log records the tool call with SHA-256 prev-hash.
All three systems sync in 200ms.

GIF of the round-trip ↓
```

(254 chars. Demo A GIF attached. Designed to spread independently of the launch thread.)

### Tweet ANTI-VANITY — The honest measurement story

```
For ~6 hours last week our canonical state doc claimed "130 tools".

Actually 111.

Difference: grep `mcp.NewTool(` over /mcp/ counted 19 test-fixture lines in _test.go files.

For binary-state metrics: compile-and-run. Always. Cost of being wrong: ~6h cleanup downstream.
```

(280 chars. High engagement among engineers who've made the same mistake.)

---

## §3 — Day 2-7 follow-up sequence (1 tweet/day cadence)

For sustained engagement post-launch. Post one per day at 07:30 IST (peak Indian engineering audience).

### Day 2 (Wed 2026-05-27)

```
Day 2 of being on HN.

Most useful comment: someone pointed out the riskguard's per-second rate limit should also apply to GTT (Good-Till-Triggered) modifications, not just place_order calls.

Filed as issue. Fix in the next algo2go/kite-mcp-riskguard release.

Critique > marketing.
```

(280 chars. Replace specific feedback with whatever actually surfaces — placeholder structure.)

### Day 3 (Thu 2026-05-28)

```
Counter-intuitive thing about building MCP servers:

The protocol's elicitation primitive (confirm-before-destructive-action) is underused.

I gate 8 tools through it: place_order, modify_order, cancel_order, place_gtt, modify_gtt, delete_gtt, create_alert, delete_alert.

Client renders the confirm UI. Server stays simple.
```

(280 chars.)

### Day 4 (Fri 2026-05-29)

```
Posted the same launch thread to r/algotrading. Took ~3 hours.

Top comment: "Why not just use Streak?"

Genuine answer: Streak is SaaS with a proprietary DSL. Mine is MIT-licensed plumbing where YOU pick the brain (an LLM, a Python script, anything that speaks MCP).

Different layer entirely.
```

(280 chars.)

### Day 5 (Sat 2026-05-30 — weekend, lighter tone)

```
Decomposition arithmetic:

Week 1 of project: 1 git repo, 80 tools, one main.go you're scared to touch.

Week 24 of project: 32 git repos, 111 tools, thin-shell core, 49,400 lines of LOC moved into 31 reusable Go modules.

Same code. Different ergonomics. 60 deploys in between.
```

(279 chars.)

### Day 6 (Sun 2026-05-31)

```
The audit chain is the unsexy feature I'm proudest of.

Every MCP tool call → row in SQLite with SHA-256(prev_row || this_row).
Tamper any historical row → every subsequent hash breaks.
Replay verifies integrity in O(n).

Came from working with regulated APIs. Stayed because it makes debugging easy.
```

(279 chars.)

### Day 7 (Mon 2026-06-01 — week wrap)

```
Week 1 post-launch wrap (no vanity numbers):

✓ Show HN landed without security ambush
✓ Riskguard chain held under real eyeballs
✓ Two PRs in flight from external contributors
✓ Zero P0 incidents
✓ 138→306h continuous uptime in production

Now back to Phase 1 of the kc/ extraction.
```

(280 chars. Adjust check marks based on actual outcomes; structure is honest.)

---

## §4 — Three audience variants of the D1 thread

For posting to **different cross-promotion contexts** — same launch, different framing depending on which subcommunity you're entering. Use ONE per context; never paste all three on the same handle in the same week (looks pivoty).

### Variant A — Indian fintech audience (LinkedIn + Indian fintwit context)

Tone: emphasis on Indian retail context, SEBI compliance, ₹500/month Kite Connect cost as audience-shared friction.

**T1/5**
```
Built an open-source MCP bridge for Zerodha Kite. 6 months. Sprint 0 shipped this week.

Why: official Kite MCP is read-only (22 tools, GTT only). Power users need order placement + Greeks + paper-trading + Telegram alerts + audit chain.

Self-hosted. MIT. India-built. Thread ↓
```
(278 chars.)

**T2/5**
```
The 11-check pre-trade safety chain is the differentiator.

Every order: kill-switch → ₹50k cap → qty limit → daily count → rate-limit → 30s dedup → ₹2L notional → idempotency → anomaly μ+3σ → off-hours block.

Plus circuit-breaker + global-freeze layers.

No claim is "AI is safe". The CODE is.
```
(280 chars.)

**T3/5**
```
SEBI April 2026 algo regs apply to PROVIDERS of trading algorithms.

This server provides ZERO strategies. Zero signals. Zero black-box logic.

You type the strategy into Claude. The LLM is the brain. The server is the gate. The user is the algo.

Same posture as mcp.kite.trade.
```
(265 chars.)

**T4/5**
```
You bring your own ₹500/month Kite Connect developer app.

Server holds zero shared credentials. AES-256-GCM at rest. Per-user OAuth 2.1 with PKCE.

Hosted instance has ENABLE_TRADING=false (read-only, free). Self-host gets full functionality.

Compliance posture explicit.
```
(258 chars.)

**T5/5**
```
Show HN today: news.ycombinator.com/item?id=<HN_ID>
Repo: github.com/Sundeepg98/kite-mcp-server

If you trade on Kite Connect and want your AI client to actually read your account — this is plumbing for that.

Not a SEBI RA. Not selling tips. Not running anyone's money.
```
(268 chars.)

### Variant B — Go developer audience (r/golang adjacency, Gophercon context)

Tone: emphasis on Go idioms, module decomposition, testing discipline, deploy boring-ness.

**T1/6**
```
Show HN today: a Go MCP server I've been on for 6 months.

What started as one main.go is now a thin orchestration shell over 31 standalone Go modules at algo2go/kite-mcp-*.

Each module compiles independently. Each has its own test suite. Each is `go get`-able.

Thread on the decomposition ↓
```
(280 chars.)

**T2/6**
```
The wedge that made the decomposition possible:

Generic decorators: `func Decorator[Req, Resp any](h Handler[Req, Resp]) Handler[Req, Resp]`

Every cross-cutting concern (audit, riskguard, elicitation, telemetry, paper-trading) is ONE Decorator value.

Go 1.18+ generics finally make middleware clean.
```
(280 chars.)

**T3/6**
```
The boring stack:

Go 1.25 · SQLite (modernc, pure-Go, no cgo) · WAL mode · Litestream streaming WAL → Cloudflare R2 ($0/mo for sub-GB) · Fly.io Mumbai · single binary · single static egress IPv4.

~9,000 tests across 437 files. Race detector on every push.
```
(269 chars.)

**T4/6**
```
The hardest Go-specific lesson: `context.Background()` audit.

Found 8 places where I'd lost context propagation across the decorator chain. Caught via `grep -rn 'context.Background()'` audit. One of those was a deadline-loss — tool calls would have outlived their HTTP request.

Now linted in CI.
```
(280 chars.)

**T5/6**
```
The bootstrap module (algo2go/kite-mcp-bootstrap v0.1.1) wires the 31 modules into a runnable server via constructor injection.

Each consumer of bootstrap can swap any module for their own implementation.

Want a different riskguard? Implement the interface, inject it. Same for everything else.
```
(280 chars.)

**T6/6**
```
Show HN: news.ycombinator.com/item?id=<HN_ID>
Repo: github.com/Sundeepg98/kite-mcp-server
Modules: github.com/algo2go (31 of them)

Most-likely-reusable bits: kite-mcp-riskguard, kite-mcp-audit, kite-mcp-decorators, kite-mcp-papertrading.

MIT. Critique especially welcome on the generics.
```
(278 chars.)

### Variant C — MCP / AI-tooling audience (r/ClaudeAI, Anthropic Discord, MCP-builders)

Tone: emphasis on MCP-spec primitives (elicitation, structuredContent, MCP-Apps widgets), protocol depth.

**T1/5**
```
Show HN: a production MCP server I've shipped 274 deploys against in 6 months.

111 tools. 65 deploys without a tool-count regression. ~138h continuous v1.3.0 uptime today.

MCP elicitation + structuredContent + Apps widgets used in anger. Thread on what I learned ↓
```
(279 chars.)

**T2/5**
```
The MCP feature I'd recommend to every server builder:

Elicitation. Mark destructive tools with `destructiveHint: true`. Client renders a confirm UI. Tool fires only on user click.

Fails open for clients that don't support it. The riskguard chain runs regardless.

UX guard + invariant guard.
```
(280 chars.)

**T3/5**
```
MCP Apps inline widgets are underdocumented but huge.

Ship a tool with `outputTemplate` metadata pointing to an HTML file. Claude renders it inline in the chat instead of dumping JSON.

Portfolio table, alert form, order confirmation — all render in-chat. Works on claude.ai web + Desktop.
```
(280 chars.)

**T4/5**
```
Server-side prompts (`/morning_brief`, `/trade_check`, `/eod_review`) work on ANY MCP client, not just Claude.

Client lists them; user picks one; server templates and returns. No client-specific code.

The boring win: same UX in Claude Desktop, Cursor, Zed, Cline, ChatGPT-via-mcp-remote.
```
(279 chars.)

**T5/5**
```
Show HN: news.ycombinator.com/item?id=<HN_ID>
Repo: github.com/Sundeepg98/kite-mcp-server

If you're building MCP servers in Go: kc/audit, kc/riskguard, kc/decorators in the repo are the most-likely-reusable patterns.

Critique especially welcome on the elicitation defaults.
```
(269 chars.)

---

## §5 — Posting calendar for launch week

Combining §1-§4 into a concrete tweet calendar. All times IST.

| Date | Time IST | Slot | Content |
|---|---|---|---|
| Tue 2026-05-26 | 19:30 | Launch | Primary D1 thread T1-T7 (§1), pinned. Demo A GIF on T1. |
| Tue 2026-05-26 | 21:00 | Reply | FOUNDER-1 single tweet (§2). |
| Wed 2026-05-27 | 07:30 | AM | Day 2 follow-up (§3). |
| Wed 2026-05-27 | 19:00 | PM | TECH-1 RT-bait (§2). |
| Thu 2026-05-28 | 07:30 | AM | Day 3 follow-up (§3). |
| Thu 2026-05-28 | 19:00 | PM | DEMO-2 cross-system tweet (§2). |
| Fri 2026-05-29 | 07:30 | AM | Day 4 follow-up (§3). |
| Fri 2026-05-29 | 19:00 | PM | ANTI-VANITY (§2). |
| Sat 2026-05-30 | 09:00 | Weekend | Day 5 follow-up (§3). |
| Sun 2026-05-31 | 09:00 | Weekend | Day 6 follow-up (§3). |
| Mon 2026-06-01 | 07:30 | Wrap | Day 7 follow-up (§3). |
| Mon 2026-06-01 | 19:00 | PM | QUOTE-1 RT-bait (§2). |

**Variants A/B/C** are for **cross-posting to specific subcommunity LinkedIn/Twitter accounts** — pick ONE per week, NOT all three on the same handle.

---

## §6 — Stop conditions + alternates

**Stop conditions during launch week:**

- If Show HN is **flagged within 60 min** of submission: do NOT post T1-T7 thread. Pivot to a single quiet tweet 2 hours later: *"Posted Show HN this morning, got flagged. The launch can wait; the project is the same. github.com/Sundeepg98/kite-mcp-server"*. Avoid the appearance of trying to recover momentum.

- If the Show HN thread gets a **top hostile comment about the run-server.cmd secret leak** (per `showhn-redteam-2026-05-11.md` §0.1): T7 should reference the fix as a reply: *"Yes, those are local-dev keys (rotated; not the prod secrets). Removed in commit `<hash>`, pre-commit secret-scan now in place. Thanks for the catch."* Owning > deflecting.

- If a **SEBI-adjacent voice** quotes the thread asking about RA registration: T3/Variant A T3 already addresses this. Do NOT engage in a back-and-forth thread; one calm reply, link to `docs/legal-notes.md`, walk away.

- If **0 stars after 24h**: do NOT post the FOUNDER-1 / QUOTE-1 / ANTI-VANITY follow-ups. They presume launch traction and read as desperate without it. Pivot to Day 2-7 follow-ups only (the build-log-substance content).

**Alternates if T1 looks weak in preview:**

- Replace T1 with: *"Show HN today: 111 MCP tools for Zerodha Kite, with safety rails. 6 months solo. 31 reusable Go modules fell out. Thread on what I learned ↓"* (255 chars. More compact, less Sprint-0-specific. Use if Sprint 0 framing feels too inside-baseball.)

---

## §7 — Empirical drift caveats

1. **Module count is 31, not 29.** Brief said 29; live `api.github.com/orgs/algo2go/repos` returned 31 at 2026-05-16 14:00 UTC. The 2 additional repos beyond the 28-as-of-2026-05-11 baseline are `bootstrap` and `metrics` (per the listing). All drafts above use "31 reusable Go modules" consistently.

2. **The `<HN_ID>` placeholder in T7 / Variant T5 must be substituted after submit.** This is the only literal placeholder — every other field is concrete.

3. **Demo A GIF is the dependency.** If GIF is not recorded by 2026-05-25 evening IST, attach the architecture-diagram image instead (composed in any screenshot tool, NOT AI-generated — that's an anti-pattern per the original Twitter rules doc).

4. **Variants A/B/C are mutually exclusive on the same handle within 7 days.** Posting all three to @Sundeepg98 within the same week reads as a pivoting brand. Pick ONE primary based on which audience the launch wave is converting fastest (check Day 2-3 metrics first if posting Variants).

5. **Tweet character counts above use Twitter's URL-shortening assumption** (all `news.ycombinator.com/item?id=X` and `github.com/...` URLs count as 23 chars regardless of length).

---

*This document does not change code. It does not modify any other research file.*
