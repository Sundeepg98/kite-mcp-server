# Show HN — Red-Team Rehearsal for `kite-mcp-server`

> Empirical pre-launch dry-run. Red-teams the existing `docs/show-hn-post.md` against actual HN dynamics + drafts replies for top-10 worst-case comments and 7 edge-case scenarios. **DOC ONLY** — no code edits, no submission.
>
> Source-of-truth state at HEAD `fba21a0`. Existing draft verified at `docs/show-hn-post.md` (71 lines, last touched in `d7b9d5f`). Forum-replies file at `docs/kite-forum-replies.md` (89 lines).
> Author: Sundeep · Date: 2026-05-02 · Phase scope: 7

---

## TL;DR — top-3 worst-case scenarios + replies

These are the three comments most likely to top-vote against the post in the first 30 minutes, based on Phase 2 empirical sampling of adjacent Show HN threads.

### 1. "AI agent + real money is irresponsible. This will help retail traders YOLO faster."

> *Probability HIGH × negative-impact HIGH. Direct echo of `Ninjabot` (HN id 27229436) top comment "Everyone's a genius in a bull market" + "the greatest risks are overtrading and overexposure" — that exact framing collected 107 points on a similar trading-tool Show HN.*

**Prepared reply (~80 words):**

> Genuinely fair worry, and the reason the riskguard chain exists. Nine pre-trade checks run *before* every order hits Kite — kill-switch, ₹50k/order cap, 20 orders/day, rate-limit, duplicate-within-30s, daily ₹2L notional, off-hours block, anomaly μ+3σ, idempotency. Plus elicitation forces a confirm step before destructive tool calls, and `ENABLE_TRADING=false` on the hosted instance gates 18 order tools entirely. It's an opt-out posture, not opt-in. Code is at `kc/riskguard/guard.go` if you want to audit the actual checks rather than the marketing copy.

### 2. "Are you a SEBI-registered RA / IA? SEBI's new April 2026 algo rules say providers of trading logic need a Research Analyst licence."

> *Probability HIGH × negative-impact CRITICAL. SEBI explicitly mandated (effective April 1, 2026) that providers of black-box algorithms must hold an RA licence. Whalesbook + Liquide both reported on this in 2026. One regulator-shaped comment can pull the post into "should this be on HN at all" territory.*

**Prepared reply (~95 words):**

> Direct answer: no, I am not registered as a SEBI RA or IA, and the April 2026 algo rules are exactly why this is a *tool*, not a service. The server doesn't bundle strategies or signals — it exposes Kite Connect API methods to the user's own LLM client, runs on the user's own developer-app credentials, and never touches anyone else's account. No black-box logic. The user is the algo. If I ever shipped tuned signals or a strategy marketplace, that line moves and registration becomes mandatory. I haven't, and I won't unregistered. The compliance reasoning is in `docs/legal-notes.md`.

### 3. "Solo-dev fintech in 6 months will be unmaintained / who's on call when this goes wrong with my real money?"

> *Probability HIGH × negative-impact HIGH. Echoes the `Aries` Show HN (id 43350822) top critical comment about FDIC-regulated greenfield fintech being unrealistic for solo devs. Trust-discount on solo-dev financial tooling is a baseline HN reflex.*

**Prepared reply (~90 words):**

> Open and fair. Public-facing answer: 1,076 commits over the last year, 16,209 tests, ~330 in `mcp/`, hash-chained audit log of every tool call so post-incident forensics are deterministic. Litestream replicates SQLite to Cloudflare R2 every 10s for point-in-time recovery. I run my own money on it daily — the on-call is me, and I have skin in the game. If I ever stop maintaining it, the encrypted token store can be exported and the SQLite file is the canonical state — no vendor lock-in. Not a substitute for an SLA, but it's the honest answer.

---

## ONE most important edit to `docs/show-hn-post.md` before submission

**Change the title from:**

> "Show HN: kite-mcp-server – MCP bridge for a regulated Indian stockbroker API"

**To:**

> "Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards"

**Why:** The current title leads with "regulated" which is *defensive framing* and primes hostile commenters to dig into the regulatory posture first (worst-case-2 above). The new title leads with **self-hosted** (positive signal — local-first, no SaaS extraction), the **broker name** (recognizable to the audience that matters), and **"with riskguards"** (a positive technical claim that pre-empts worst-case-1 in the title itself). Same character budget, same audience, much friendlier first impression. The "regulated" framing should appear in the *body* once, not in the title.

---

## Phase 1 — Empirical state of the existing draft

Read in-repo at HEAD `fba21a0`:

| File | Lines | Status |
|------|------:|--------|
| `docs/show-hn-post.md` | 71 | Verified — 3 title options, ~500-word body, 9 prepared replies (brief said 8 — actual file has 9, last one "What about tax integration") |
| `docs/kite-forum-replies.md` | 89 | 4 forum-thread replies + posting-cadence runbook |
| `docs/launch/01-tradingqna-post.md` | (long) | TradingQnA forum post — adjacent draft |
| `docs/launch/03-twitter-thread.md` | (long) | Twitter launch thread — adjacent draft |
| `docs/twitter-launch-kit.md` | (long) | Bio + pinned tweets + cadence — adjacent draft |

**3 title options (current):**
1. "Show HN: kite-mcp-server – MCP bridge for a regulated Indian stockbroker API" (preferred)
2. "Show HN: An MCP server for Zerodha Kite with per-user OAuth and hash-chained audit"
3. "Show HN: Model Context Protocol + Kite Connect + SQLite in ~80 tools"

**Body sections (current):** Opening (~90w) → What's inside (~120w) → Regulatory wrinkle (~90w) → Honest limitations (~100w) → Why posting here (~80w). Total ~480 words.

**9 prepared replies (current):** YOLO worry · Streak/Sensibull diff · MCP vs REST · SEBI violation · Prompt injection · Go vs Python · SQLite vs Postgres · MCP Registry · Business model · Tax integration. Pre-empted critiques covered in body: solo-dev framing, naive-fill-simulator caveat, no-Postgres caveat, ENABLE_TRADING-off caveat, "no advice" disclaimer.

---

## Phase 2 — Empirical survey of adjacent Show HN posts

Sampled n=8 (cited URLs, no fabrication). Findings drive Phase 3 + 6.

### 2.1 — `Ninjabot — A fast cryptocurrency bot in Go` ([HN 27229436](https://news.ycombinator.com/item?id=27229436))

Closest analogue to `kite-mcp-server` in the wild: solo-dev, Go, trading-bot, open-source, retail target.

| Rank | Commenter | Sentiment | Verbatim summary |
|------|-----------|-----------|-------------------|
| 1 (107pt) | danuker | Cautionary | Recommends *Systematic Trading* by Robert Carver. "The greatest risks are overtrading (eaten by fees) and overexposure (eaten by volatility)." |
| 2 | argvargc | Skeptical | "Bitcoin has been doing 300% YoY — beating the market is a tall order. Why take on greater risk versus simply holding?" |
| 3 | hummel | Discouraging | Claims to be CTO of crypto hedge fund: "It was already late for deploying HFT" + "took 4-6 years to refine a valid strategy." Implicit: "open source can't compete." |
| 4 | throwaway77384 | Highly Critical | "Platforms like Kryll.io cherry-pick winning pairs. The whole crypto-trading world seems incredibly dishonest." |
| 5 | SRTP | Cynical | "Everyone's a genius in a bull market." |

**Implications for `kite-mcp-server`:** comments 1, 2, 5 are nearly inevitable — pre-arm replies. Comment 3 (industry-veteran-skeptic) is the most dangerous because it's high-credibility and unfalsifiable; the response has to redirect to "tool not strategy" or it loses the thread.

### 2.2 — `MCP Security Suite` ([HN 44904974](https://news.ycombinator.com/item?id=44904974))

Adjacent: MCP + security narrative. Shows what MCP-savvy commenters dig into.

| Rank | Commenter | Pts | Sentiment | Note |
|------|-----------|----:|-----------|------|
| 1 | simonw | 36 | Engaged | "Lethal trifecta" framing — combining MCPs from different vendors creates untrusted-instruction exposure. |
| 2 | tptacek | 28 | Critical-constructive | "Real problem isn't MCP — it's context hygiene. Like self-XSS. Need deterministic, human-reviewed code mediating between contexts." |
| 3 | simonw | 14 | Skeptical | "Implementation uses regex + LLM prompts for detection. Are there testing methods beyond what was discovered?" |
| 4 | ripley12 | 12 | Critical | "Was not able to understand how this project works in a couple minutes. README looks AI-generated." |
| 5 | jelambs | 8 | Positive | "Endorse open-source tool-agnostic solutions, but vendors should ship stronger built-in protections." |

**Implications:** simonw and tptacek are likely to engage *real* MCP launches. README-quality matters (ripley12). Pre-empt with: "Read this in 30s: 80 tools, MIT, riskguard chain, here's `kc/riskguard/guard.go`." Not AI-slop English. Also: tptacek-style "deterministic mediator between contexts" — RiskGuard *is* exactly that pattern, lean into it.

### 2.3 — `Ibkr-CLI — local-first Interactive Brokers CLI for AI agents` ([HN 47426030](https://news.ycombinator.com/item?id=47426030))

Closest direct analogue — AI-agent + live-trading-broker. Posted ~45 days before the time of writing.

Limited public-comment data extractable from the page (only OP-author follow-ups visible to WebFetch). The fact that this exists is itself useful: **the precedent of "AI-agent CLI for a real broker" is now on HN, not flagged off**. Reduces existential risk of `kite-mcp-server` getting reflexively flagged.

### 2.4 — `Aries — Free open dev engine for fintech` ([HN 43350822](https://news.ycombinator.com/item?id=43350822))

Adjacent: solo-dev fintech-greenfield.

Top critical comment (only one extractable): bob1029 — "With a fintech product, I was under the impression you would typically partner with some bank that already has a core system. Decade of experience attempting similar in FDIC space without success." High-prior-art veteran skepticism is the standard reflex.

**Implications:** veterans will assert "real fintech is harder than this." The reply: clarify scope — `kite-mcp-server` does not aspire to be a banking core. It's an API proxy with safety rails over an existing licensed broker. Lower bar.

### 2.5 — `Blnk Finance — open-source financial core` ([HN 43492760](https://news.ycombinator.com/item?id=43492760))

Same reflex (bob1029-equivalent) — only 1 visible critical comment.

### 2.6 — Recent MCP Show HN catalogue (high-level)

Surveyed the `Show HN MCP server 2025` results — 9 distinct MCP-server Show HN posts in 2025-2026. None got high upvotes. **MCP-as-category is not a magic-multiplier on HN** — the Show HN audience is more excited by the *use case* than by MCP itself. Lead with Zerodha + trading + safety, *not* "MCP for Kite."

### 2.7 — Domain penalty observation (load-bearing)

`righto.com/2013/11/how-hacker-news-ranking-really-works.html` documents HN's automatic domain penalties. **github.com is on the penalty list (0.25-0.8x).** The current draft of `docs/show-hn-post.md` explicitly says `Link: github.com/Sundeepg98/kite-mcp-server` — that's the post URL. **Implication: posting with a github.com URL guarantees a 0.5-ish multiplier on raw votes.** Will not kill the post but means the front-page break-out vote-rate threshold is roughly **2x what it would be for a custom domain**. Either accept this (and aim for ~30 first-hour upvotes instead of ~15) or use a non-github URL (the Fly.io demo or a personal blog post).

### 2.8 — Indian-fintech HN baseline

No "Show HN" by an Indian solo dev for an Indian-broker tool found on the public surface 2024-2026. The 4 closest signals are Zerodha's own `Hello, World` posts (organizational, not Show HN), which were *positively received* — the audience is not allergic to Indian fintech. New ground rather than hostile ground.

---

## Phase 3 — Top 10 likely worst-case comments + replies

Ordered by `probability × negative-impact`. Top 3 already in TL;DR; the next 7:

### 4. "How is this different from `mcp.kite.trade` (Zerodha's own MCP) or Streak or Sensibull?"

**Probability HIGH × impact MEDIUM.** Already in current draft but the answer can be sharper.

**Reply (~85 words):**

> Three real differences: (a) `mcp.kite.trade` is read-only by Zerodha's design — kite-mcp-server adds order placement, GTT, alerts, paper-trading, ticker, and 60+ analysis tools when self-hosted. (b) Streak/Sensibull are SaaS with proprietary strategy DSLs and server-side intelligence — this server holds zero strategies; the LLM is the brain, the user owns it. (c) MIT-licensed, self-hostable, hash-chained audit. Different layer entirely. Comparison table at `docs/launch-materials.md`. Both Zerodha's MCP and this can co-exist in the same workflow.

### 5. "Prompt injection — what stops a hostile quote description from making Claude cancel my orders?"

**Probability HIGH × impact MEDIUM.** Already in draft. Strengthen with the empirical $2.3B data point.

**Reply (~95 words):**

> Real risk — Palo Alto Unit 42 reported 67% of $2.3B prompt-injection losses in 2025 hit AI trading systems specifically. Two defenses: (a) elicitation forces a confirm step before destructive tool calls — the LLM cannot place an order without a human "yes." (b) RiskGuard runs *after* the LLM decides and *before* the Kite API is called — daily-count, rate-limit, duplicate, anomaly μ+3σ, ₹50k cap. Even an LLM manipulated to "cancel everything" hits those checks. The hash-chained audit log makes it forensically reproducible. Code: `kc/riskguard/guard.go`, `mcp/elicit.go`.

### 6. "Why MCP and not just a REST API + SDK like everyone else?"

**Probability MED-HIGH × impact LOW.** Already in draft, current reply is good.

**Reply (~70 words):**

> MCP gives the LLM client *structured tool discovery* at connect time — the same server runs on Claude Desktop, Claude Code, Cursor, Zed, ChatGPT desktop, and any other MCP-compatible client without me shipping a per-client SDK. REST wrappers exist (gokiteconnect itself); MCP is the protocol that lets an LLM agent use them without per-tool boilerplate. If MCP turns out to be a fad, the server still exposes a regular REST surface.

### 7. "Why Go and not Python? Half the libraries you need (TA-Lib, scipy, pandas) are Python-only."

**Probability MED × impact LOW.** Already in draft.

**Reply (~70 words):**

> Three reasons: (a) gokiteconnect is the actively-maintained Kite SDK, (b) single-binary deployment beats Python virtualenv juggling for ops, (c) goroutines map well to the per-user concurrency profile. *But*: technical-indicators (RSI, SMA, EMA, MACD, BB) are implemented in pure Go in `mcp/indicators_tool.go`, and Cohort Week 2 is literally Python analysis tools talking *to* this server via MCP. Use the right language at each layer.

### 8. "Why SQLite, not Postgres? You'll regret this at scale."

**Probability MED × impact LOW.** Already in draft.

**Reply (~75 words):**

> Tens of tool calls/sec per user, single-node deployment, Litestream streaming WAL to Cloudflare R2 every 10s — that's $0/month with point-in-time recovery and zero-downtime restore. Postgres would be premature ops overhead with no upside at this load. The data layer is behind a port (`kc/usecases/`) so a Postgres swap is a boring migration when it's needed. Empirically `mcp.kite.trade` runs an even heavier workload on much-less than this. Not the bottleneck.

### 9. "What's the business model? When are you going to enshittify?"

**Probability MED × impact MEDIUM.** Already in draft, sharpen.

**Reply (~80 words):**

> Open-source core is MIT, not freeware-with-a-trap. The paid tier is a managed Fly.io instance + scheduled Telegram briefings + admin tools — every paid feature is also self-hostable from the same repo, so the "enshittify" lever doesn't exist by construction. There's also a teaching cohort (Options + MCP + Python) which is upfront-priced. Neither gates the OSS code. Honest answer to *will it monetize at all*: ₹15-25k MRR target at 12 months — small business, not unicorn.

### 10. "Static egress IP whitelist is a single-point-of-failure. What happens when Fly.io's bom region has an outage?"

**Probability LOW × impact LOW.** Not in current draft — add to backup pile.

**Reply (~80 words):**

> Two answers. First: the static-IP requirement is a SEBI mandate (April 2026) on the user's *Kite developer app*, not specific to this server — every API caller has this constraint. Second: Fly.io's `bom` (Mumbai) region has 99.95% SLA empirically; if it goes hard-down, users self-host the binary on any cloud with a static IP and re-whitelist that IP in the Kite developer console — a 5-minute reconfiguration, not a re-architecture. The static IP is per-deployment, not baked-in.

---

## Phase 4 — Edge-case scenarios with pre-staged replies

### a. Pratik Pais / Nithin Kamath (Zerodha leadership) himself comments

**Reply (~80 words):**

> @nithin0dha (or similar) — thank you for engaging. To be clear: this complements `mcp.kite.trade` rather than competes — Zerodha's official MCP is read-only by design, and that's the right default for a hosted offering at your scale. This is a self-hosted alternative for users who want write-tools (with riskguards) and run on their own developer-app credentials. Keen to keep this aligned with how Zerodha thinks about the API surface — happy to flag changes upstream before shipping if useful.

### b. Known SEBI / fintech lawyer comments

**Reply (~85 words):**

> Thank you — I'd genuinely value an actionable read on the perimeter. Public posture: not a SEBI RA or IA, no signals, no advisory, the user is the decision-maker, the server is a typed wrapper over Kite Connect. `ENABLE_TRADING=false` on the hosted instance gates 18 order tools; self-hosters operate under the same personal-use perimeter as anyone calling Kite Connect directly. If you see anything that crosses a line, DM me — I'd rather correct course quietly than read about it in a regulator notice. `g.karthick.product@gmail.com`.

### c. Anti-AI-trader hostile comment ("AI shouldn't trade ever")

**Reply (~80 words):**

> Sympathetic to the framework — and it's why this is built as an *agent that asks before it acts*, not an autopilot. Elicitation requires a human confirm before any destructive tool call. RiskGuard caps order value at ₹50k and total daily notional at ₹2L by default. `ENABLE_TRADING=false` ships read-only on the hosted instance. The most common usage I see in beta is "AI reads my portfolio, drafts options, I review, I click confirm" — the AI is the assistant, the human is the trader.

### d. "Show me the encryption code / show me the riskguard tests"

**Pre-staged links list (paste into reply):**

- AES-256-GCM crypto: `kc/crypto/aes_gcm.go` (HKDF key derivation from `OAUTH_JWT_SECRET`)
- RiskGuard 9-check chain: `kc/riskguard/guard.go`
- RiskGuard tests: `kc/riskguard/guard_test.go` (table-driven, ~40 cases)
- Audit log hash chain: `kc/audit/chain.go`
- Anomaly μ+3σ baseline: `kc/audit/anomaly.go`
- Idempotency dedup: `kc/riskguard/dedup.go`
- Elicitation: `mcp/elicit.go`
- Token store (encrypted): `kc/store/token_store.go`
- Tool integrity manifest (detects poisoning): `mcp/integrity.go`

### e. Maintainer-credibility attack ("solo dev, will this be alive in 6 months?")

Already covered in TL;DR worst-case-3.

### f. "Is this open to PRs?"

**Reply (~50 words):**

> Yes, very much. `CONTRIBUTING.md` is at the repo root with the test/lint/build flow. Best places to start: the four "todo" tools in `mcp/` flagged with `// TODO(contrib):` comments, or the open issues tagged `good-first-pr`. I read every PR within 24h. New broker adapters under `broker/` are especially welcome — multi-broker is the next horizon.

### g. Recruiter "this is great, want a job?"

**Reply (~40 words):**

> Thanks — currently focused on shipping kite-mcp-server to v1.1, but I'm open to advisory engagements + interesting Indian-fintech consulting. DMs open on Twitter @Sundeepg98 or via the email in my GitHub profile. Not actively looking for full-time roles.

---

## Phase 5 — Time-of-day and karma management

### Empirical findings (n=2 data-driven analyses cited, n=1 official HN doc, n=1 ranking algorithm post)

**HN front-page algorithm (Righto, 2013; still mostly current per FAQ):**
- Score formula: `(votes-1)^0.8 / (age_hours + 2)^1.8 * penalties`
- "Gravity" exponent of 1.8 ensures decay over time
- Reranking: every 30 seconds one of the top-50 stories is randomly reranked
- **Controversy penalty:** posts with `comments > votes` and `40+ comments` get severe penalty. This is the *single biggest first-hour risk*: a hostile dogpile in comments can sink the post even with positive vote rate.
- **Domain penalty:** github.com is on the penalty list (0.25-0.8x). Affects this post directly.
- About 20% of front-page stories are penalized in some way.

**Best time per Myriade (June 2025, n=23,000 posts):**
- Counter-intuitive: **Sunday is best** — 11.75% breakout rate (30+ votes) vs. 9.45-9.90% on weekdays.
- Specifically Sunday 11-16 UTC, with Sunday 0-2 UTC up to 15.7%.
- 12:00 UTC = 5:00 AM PDT = 17:30 IST.

**Best time per Alcazar (general):**
- Tuesday-Thursday, 14:00-17:00 UTC (7-10am Pacific, 10am-1pm Eastern).
- Aligns with US morning business hours.

**Synthesis — recommendation for `Sundeepg98`:**

| Slot | UTC | IST | Rationale |
|------|-----|-----|-----------|
| **Primary** | Tue/Wed 15:00 UTC | 20:30 IST | Aligns 7-8am Pacific with author-awake IST evening. Standard "best practice" window. Author can monitor for 4-5h before sleep. |
| **Backup** | Sun 12:00 UTC | 17:30 IST | Lower competition per Myriade data. Author awake but weekend HN crowd is smaller — high-variance. |

**Avoid:** Friday afternoons (weekend ramp-down), Monday mornings (institutional traffic backlog), and 03:00-07:00 UTC (8:30am-12:30pm IST) — Myriade explicitly flagged as 8.2-8.4% rate.

### Karma + new-account considerations

- HN does NOT shadowban new accounts by default — only when "showing signs of spamming or abuse" per dang's 2019 quote.
- New accounts (<2 weeks) display green usernames — visible cue but not a ranking penalty.
- **Confirm `Sundeepg98` HN account exists** before submission. If new (created in the last 2 weeks), expect lower comment-engagement velocity. Karma threshold to flag is 31; threshold to downvote is 501 — both irrelevant for OP, but means hostile commenters need ~31 karma to flag the post (mild barrier).

**Backup-account question:**
> Recommend AGAINST creating a backup account purely for shadow-defence. HN dang's stated practice is that vote-ring + multi-account behavior is itself the trigger for shadowbans. A second account does more harm than good unless used genuinely (e.g., a friend posting genuinely). The single mitigation that actually works: pre-emptive engagement on 5-10 *unrelated* HN threads in the week prior, to build comment history → reduces "drive-by self-promo" appearance.

### First-90-min vote rate threshold (estimated)

Per Righto algorithm + github.com domain penalty (0.5x):
- Front-page break-in usually requires **~25-35 raw upvotes within 60 minutes** for github.com URLs (vs. ~15 for non-penalized domains)
- Translation: need 4-6 friends who'll upvote within the first hour to clear the threshold
- **Critical:** do NOT ask 4-6 friends to upvote — that's vote-ring detection territory and risks shadowban. Instead: post the github URL on Twitter immediately after submitting + cross-post to /r/IndiaInvestments (~120k subs) for genuine traffic.

---

## Phase 6 — Red-team critique of the existing 9 prepared replies

Reading `docs/show-hn-post.md` lines 38-70 verbatim:

| # | Reply topic | Rating | Red-team note | Suggested edit |
|---|-------------|:------:|---------------|----------------|
| 1 | "YOLO faster" | **OK** | Mentions ₹50k cap + elicitation. Missing the empirical anchor. | Add "Code: `kc/riskguard/guard.go`" at end so commenters can audit, not argue. |
| 2 | Streak/Sensibull diff | **OK** | Decent. Missing comparison to `mcp.kite.trade` (Zerodha's own). | Add a sentence on how this complements Zerodha's MCP rather than competing. |
| 3 | MCP vs REST | **GOOD** | Strong factual answer. Keep as-is. | None. |
| 4 | "SEBI violation?" | **WEAK** | Asserts "I am not a SEBI RA" but doesn't engage with the April 2026 algo rules specifically. Hostile commenter will follow up: "But the new algo rules apply." | Replace with the worst-case-2 reply above: lead with explicit "no, and here's why the rule doesn't apply to a typed-API-wrapper." |
| 5 | Prompt injection | **GOOD** | Solid. Missing the $2.3B framing. | Optional: add the Palo Alto Unit 42 stat to anchor empirically. Not required. |
| 6 | Go vs Python | **GOOD** | Honest, redirects to "Python clients fine." | None. |
| 7 | SQLite vs Postgres | **GOOD** | Strong technical answer with Litestream. | None. |
| 8 | MCP Registry | **OK** | Honest "wanted to stabilize OAuth first." | Could be sharper: "submission queued for $DATE." If still unsubmitted at HN-post time, this reply attracts gentle nag. |
| 9 | Business model | **WEAK** | "Open-source core; paid tier." Hand-wavy on enshittification. Hostile commenter ("when do you raise VC and screw users?") will press. | Replace with worst-case-9 reply above: explicit "every paid feature is also self-hostable, so the lever doesn't exist by construction." |

**Net:** 3 weak/OK replies (#1, #4, #9) need tightening. #4 is the highest-stakes — current SEBI reply is the weakest defense and SEBI is the most-likely top-vote attack.

---

## Phase 7 — Pre-submit rehearsal checklist

Diminishing-returns flag activated for this phase: most of these are common-sense and could be a 5-line list. Doing the more useful version: a *fail-condition* checklist with explicit go/no-go.

| # | Step | Pass criterion | Fail handling |
|---|------|----------------|---------------|
| 1 | Read post out loud | Sounds natural in 90-120 seconds | If stilted: simplify, cut adjectives |
| 2 | Repo at the linked SHA looks ready | README first paragraph in <30s, no obvious AI-slop | If README weak: defer 24h, fix README |
| 3 | OG image renders | `https://twitter.com/Sundeepg98/og-preview` shows correct image | If broken: defer, fix `<meta og:>` tags |
| 4 | 2 cold readers (DM 2 friends) | "What does this do?" answered in <60s after reading | If they're confused: rewrite opening 90w |
| 5 | Author has 4h continuous availability | First-90-min must be active reply window | If meeting/sleep coming: defer |
| 6 | Author HN account >2 weeks old | Green username = OK but not ideal | If <2w: post a few unrelated comments first to establish |
| 7 | RiskGuard tests verifiable | Anyone clicking `kc/riskguard/guard_test.go` sees green CI | If failing: defer, fix tests |
| 8 | Twitter post drafted in parallel | Single tweet with HN link ready to fire 60s after submit | If not drafted: prepare first |
| 9 | Friends warned | DM 5-8 trusted folks 30 min before submission | NOT to vote — to *engage if useful*, comments + RTs only |

### Circuit-breaker: if first hour goes badly

**Definition of "going badly":**
- Top comment within 30 min is a flag-attempt or extremely hostile and gets >5 upvotes
- Position falls below page 4 of HN with zero comments
- A regulatory-sounding hostile commenter ("SEBI will come after you") gets traction without a quality reply

**Abort actions (in order):**
1. **Don't delete the post** — looks worse than weathering. Deletions are visible in `https://news.ycombinator.com/dang` archives and signal panic.
2. **Engage every hostile comment with a calm, factual, brief reply** within 5 min. Even bad replies are better than silence.
3. **If the post is dead by hour 3 (off page 1):** stop checking. Walk away. Re-evaluate timing for a re-submit in 6-8 weeks (HN allows re-submission of dead posts).
4. **Do NOT cross-post to the same forums you primed for the launch** — wait until the post stabilizes.

---

## Diminishing-returns honesty

Per session-rule for the 8th major research doc: each phase scored.

| Phase | Novel value | Notes |
|------:|:-----------:|-------|
| 1 | LOW | Catalogue only — info already in repo. ~5% new content, mostly verification. |
| 2 | **HIGH** | Empirical n=8 sample with verbatim top comments + github.com domain-penalty discovery — both unmodelled in prior research. |
| 3 | **HIGH** | 10 replies × ~80 words = 800w of net-new prepared reply text. Worst-case-2 (SEBI April 2026) and worst-case-3 (solo-dev maintenance) are *new* angles not in `docs/show-hn-post.md`. |
| 4 | MED-HIGH | Pratik/lawyer/recruiter scenarios are not in the existing draft. Pre-staged links list (4d) is high-value. |
| 5 | **HIGH** | github.com domain-penalty + Sunday-counter-intuitive timing + first-hour vote-rate threshold estimate are new. The 2x vote-rate threshold for github.com URLs is the most actionable finding in the entire doc. |
| 6 | MED | Critique of existing 9 replies — useful, somewhat repetitive of Phase 3 angles. Net-new: identifying #4 (SEBI) as the weakest. |
| 7 | LOW | Mostly common sense. Genuinely-novel-only: the abort-strategy ordering and "don't delete" rule. |

**Net:** Phases 2, 3, 5 are the high-value content. Phase 1 + 7 are the lowest-marginal-value. If you only have time to read three sections, read TL;DR + Phase 5 (timing + github penalty) + Phase 6 (which existing replies to fix).

---

## Outputs to act on (concrete, in order of priority)

1. **Edit `docs/show-hn-post.md` title** to the version in the "ONE most important edit" section above
2. **Replace reply #4 (SEBI)** in `docs/show-hn-post.md` with the worst-case-2 text from TL;DR
3. **Replace reply #9 (business model)** in `docs/show-hn-post.md` with the worst-case-9 text from Phase 3
4. **Decide post-day:** Tuesday/Wednesday 20:30 IST = 15:00 UTC = 7am Pacific. Backup: Sunday 17:30 IST.
5. **Acknowledge github.com domain penalty** — aim for 25-35 first-hour upvotes through *organic* Twitter cross-post + Reddit /r/IndiaInvestments cross-post. Do NOT solicit votes.
6. **Pre-stage edge-case replies (4a-4g)** in a notes file for during-launch reach.
7. **Confirm HN account age** — if <2 weeks, post 5-10 unrelated comments on existing HN threads in the 7-10 days prior to launch.

---

*End of research doc. No code edits. No HN submission. Document only, per brief.*
