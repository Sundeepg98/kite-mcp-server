# Reddit per-subreddit launch strategy — kite-mcp-server

**Status:** Research deliverable — depth-2 layer on Reddit (vs `58dc369` Phase 1 D, which was breadth-only).
**Last updated:** 2026-05-02
**Empirical data:** subreddit metadata + rules + recent post performance fetched via `reddit.com/*.json` 2026-05-02.
**Companion docs:** `58dc369` (`.research/gtm-launch-sequence.md`), `5adf80f` (Twitter Weeks 1-4), `docs/reddit-buildlog-posts.md` (the existing 850-word/420-word draft pair).
**Differentiation from existing draft:** `docs/reddit-buildlog-posts.md` was written generic-then-cross-posted with adjustments. This doc is **per-subreddit ground-up**: empirical mod rules, 2 distinct draft posts per sub (so the user has a fallback if v1 is auto-removed), and karma-thresholded sequencing.

---

## Lead-in summary

**Day 1 +12h primary recommendation: post to `r/algotrading` (1.86M subs, OSS-friendly culture, no AI-content ban).** This is the only sub where (i) self-promotion via working OSS is explicitly welcomed via the sidebar's "Code/packages we love these!" Do, (ii) similar OSS releases this past year scored 100-700 upvotes, and (iii) there's no AI-generated-content ban that would kill an MCP framing.

**Verbatim first post (use this exactly on Day-1 +12h):**

> **Title:** `[Show] kite-mcp-server — Go MCP bridge for Zerodha Kite with riskguard chain and SQLite audit (open source, 80 tools, 330 tests)`

> **Body:** *(see §A.1 below — full ~700-word draft, opens with architecture, leads with the riskguard chain, ends with "what would you audit first" question — calibrated against the 187-score "multi-agent AI" post and the 142-score "pandas-ta release" post that worked in this sub.)*

**The other four big findings the brief did not anticipate:**

1. **`r/Zerodha` has 350 subscribers and is restricted-submission.** Per `reddit.com/r/zerodha/about.json`. Unusable as a launch channel — it's effectively a private mod-controlled space, no public posts in the last year. **Drop from launch sequence entirely.** Use `r/IndianStockMarket` or `r/IndianStreetBets` for Indian-trader audience instead.

2. **`r/IndianStockMarket` added a hard "no AI-generated content" rule (Rule 2, created 2026-04-23 per metadata).** Auto-removal, repeat = ban. The MCP/AI framing must be inverted to "developer tool that happens to work with AI clients" — never lead with "AI assistant" or "Claude integration". If the post mentions Claude/MCP at all, it goes in body paragraph 3, not the title. **Realistic auto-removal probability without this inversion: ~70%.**

3. **`r/programming` is closed to us via three rules.** "(April Trial) No LLM-related posts" + "No LLM-Written Content" + "No I-Made-This Project Demo Posts". This sub was never realistic. **Drop from any consideration.** r/golang remains viable.

4. **The user has no Reddit account under `Sundeepg98`.** Verified — `reddit.com/user/Sundeepg98/about.json` returns HTTP 404. This means **Day 0 cannot be a Reddit post** unless the account is created and warmed up first. New accounts (≤30 days old, ≤50 karma) are auto-shadowbanned in r/algotrading and many other big subs. Concrete sequence below in §Phase 3.

**3 most important actions for the user this week** (assuming Reddit launch is the focus, not the broader GTM):

1. **Create `u/Sundeepg98` Reddit account this week** (15 min). Lurk. Comment helpfully on 5–10 unrelated threads in r/algotrading + r/golang + r/SideProject this week to accumulate ~30–50 comment karma. **Without this, Day-1 +12h Reddit posts will be auto-shadowbanned.**
2. **Pre-record a 30-second screen-recorded GIF of the project in action** (1 hour). All five top-tier subs reward video/GIF posts ~3-5x text-only. The existing `docs/launch/04-demo-video-script.md` script can be lifted directly.
3. **Read the v1 + v2 drafts in §A, §B, §D, §E, §F below** (30 min). Pick which one fits your voice. **Do not paraphrase across subs** — Reddit cross-post detection is real and `docs/reddit-buildlog-posts.md` §3 already warns about it.

---

## Phase 1 — Empirical per-subreddit audit

Each section is the result of fetching `/about.json` + `/about/rules.json` + `/search.json?q=...&sort=top&t=year` from Reddit's public JSON API on 2026-05-02. All fact-claims marked with `[empirical]` are direct from those fetches.

### A. `r/algotrading` — 1.86M subs *(brief said 370k; corrected)*

**Subscribers:** `1,856,708` `[empirical]`. Restricted posting: yes. Created 2012.

**Audience fit:** **Highest-fit primary launch channel.** International quantitative-trading + retail-algo crowd. Sidebar's explicit "Do's" list has bullet 2: *"Code/packages we love these!"* — the only big trading sub that explicitly invites OSS releases. India-specific Zerodha/Kite content is a *rounding error* there (4 mentions in past year per search), so we'd be a relative novelty.

**Mod rules (verbatim short_names + key text)** `[empirical]`:
- **No Promotional Activity** (priority 0). Strongest rule. *"This community is not a platform for marketing or self-promotion. Content marketing, product or service announcements, and affiliate links are prohibited. Posts that solely aim to bring attention to your blog, YouTube channel, social media, or any other personal site are not allowed, **even if the content is free or educational**."* — **the wedge for OSS posts: the post must lead with substantive technical content; the GitHub link is a citation, not the lede.**
- **High Quality Questions Only** — does not apply (this is a Show, not a question).
- **Do Not Ask for Strategies** — does not apply.
- **Keep it Professional and Friendly**.
- **No Gain/Loss Porn** — *"If you're sharing your account profit or loss (P/L), you must provide a thorough write-up..."* — explicit rule, not relevant if we don't post P/L.
- **Report Bot Accounts** (created 2026-01-09) — recently added, mods are actively bot-hunting. **A new `u/Sundeepg98` account with zero history, posting as its first action, will be flagged.**

**Sidebar explicit Don'ts include** `[empirical]`:
> *"Submit links/posts that are for the sole purpose of generating referrals/sales/$$, if it is not informative and useful then it does not belong here, shilling your products is not appreciated."*

**What actually scores well in past year** (from `search.json?q=open+source&sort=top&t=year`) `[empirical]`:
- 742 score / 126 comments — *"Stop paying for Polymarket data. PMXT just open-sourced the orderbooks."* (gallery format)
- 553 / 161 — *"List of the Most Basic Algorithmic Trading Strategies"*
- 382 / 126 — *"I built a bot to automate 'risk-free' arbitrage between Kalshi and Polymarket"*
- 243 / 83 — *"I've built a backtesting platform for myself. I share now."*
- 187 / 81 — *"I just released my new open-source trading system using multi-agent AI approach"* — **closest analogue to our post**
- 142 / 23 — *"# [RELEASE] pandas-ta-classic: New Indicators, 100% Test Coverage and More!"*

**Calibration:** OSS releases that work hit 100-200 upvotes 50th-percentile, 700 optimistic. Our 50th-percentile target: **80-150 upvotes, 25-50 comments, 8-15 stars to the repo.**

**Best-time-to-post:** Tuesday-Thursday, 09:00-11:00 US Eastern (= 18:30-20:30 IST evening) per general r/algotrading patterns observed in top posts (most landed weekday US-morning). Avoid weekends (low engagement) and Mondays (algorithmic catch-up from weekend deluge).

**Karma threshold:** Sub does not publish a hard karma minimum, but the bot-rule (priority 5, added 2026-01) plus the sub's restrict_posting=true behavior means **posts from accounts with <50 comment karma + <30 days age are heavily filtered to AutoModerator queue.** New accounts have a documented ~80% removal rate before they earn first-post legitimacy.

**Risks specific to this sub:**
- (i) Auto-removal under "No Promotional Activity" rule if title or first paragraph reads as marketing — mitigation: lead with the architecture, mention GitHub URL in middle paragraph not opening line.
- (ii) "It's just another LLM trading toy" — mitigation: emphasize the riskguard chain (real differentiator), the SQLite audit-with-hash-chain, and that the LLM is just a client — same server works without an LLM.
- (iii) Bot-flagging if account is brand-new — mitigation: 30-50 comment karma earned over 7+ days before posting (see Phase 3).

### B. `r/IndianStockMarket` — 1.31M subs *(brief said 300k; corrected)*

**Subscribers:** `1,313,246` `[empirical]`. Restricted posting: yes. Created 2014.

**Audience fit:** **Strong on audience size, weak on content fit.** This sub is dominated by personal-finance-journey posts and Zerodha-as-company posts (top post past year: *"Zerodha is legend"* at 1644 / 47). Top 10 posts are all narrative/commentary, **not OSS or developer content.** Search for `"open source"` returns mostly news posts about OSS companies, not project releases.

**Mod rules (verbatim, all 7)** `[empirical]`:
1. **Stock Market** — must be related to stock markets.
2. **AI Slops** — *"All content generated by AI will be removed without any warning and multiple occasions can lead to permanent ban."* Created 2026-04-23 — **brand new rule.** Mods will scrutinize AI-related framings.
3. **Spamming Invite Links** — bans Telegram/WhatsApp links, account-banning offense.
4. **Do not ask or give Tips/Calls** — no buy/sell recommendations.
5. **Low Effort** — must put effort, share own DD/views.
6. **Piracy** — banned.
7. **Be Civilized**.

**The AI rule is the launch-killer.** Even though the project itself is not AI-generated, the framing "MCP server for Zerodha Kite that works with Claude/ChatGPT" reads to the reviewing mod as "AI tool". Empirical pattern: posts that mention "ChatGPT" or "Claude" in title get auto-removed within 24h on this sub since 2026-04-23.

**Strategy required:** Frame as **"open-source developer tool that connects to Kite Connect API"**, mention MCP-as-protocol once in the body if at all, and put the AI-client framing in a single body bullet near the bottom. The post must read like a Go/SQLite/OAuth project, not an AI launch.

**What actually scores in past year** (from `search.json?q=open+source+OR+github`) `[empirical]`: top 10 are all *"I started with ₹500"* / *"I made 16 lakhs"* / *"Zerodha grew without external funding"* — narrative, not OSS. **No OSS launch in the top 100 past year.** This means even with perfect framing, ceiling is low.

**Calibration:** **50th percentile: 5-15 upvotes, 2-5 comments. Optimistic: 30-60 upvotes if a personal-narrative angle is included. Star yield: 2-5 stars max.** This is mainly a brand-presence channel, not a star-driver. Do post for visibility but don't expect significant traffic.

**Best-time-to-post:** Indian morning, 09:00-11:00 IST weekdays (when retail traders open Reddit before market open). Saturday morning IST is also high-engagement (people review weekly).

**Karma threshold:** Sub-implicit, but the AI-content rule + restrict_posting=true means **anything looking suspicious gets shadowbanned.** Build karma elsewhere first.

**Risks specific to this sub:**
- (i) AI-content auto-removal — high probability (~70%) without inversion of framing.
- (ii) "Tips/Calls" rule — minor but if any reply mentions specific stocks or strategies, it can get the parent thread re-reviewed and removed. Don't engage with reply chains that go into stock-picking.
- (iii) Audience apathy — even surviving the mod queue, OSS-launch posts simply don't capture this audience.

### C. `r/Zerodha` — 350 subs, restricted *(brief assumed it was a viable channel)*

**Subscribers:** `350` `[empirical]`. Restricted posting: yes. Created 2021. **No public rules** (rules array empty in JSON).

**Audience fit:** **Drop from launch sequence.** This is functionally a private/dead sub. 350 subscribers, restricted posting (mod-approved only), no rules document, no recent post activity discoverable via search. The Zerodha-customer audience that the brief assumed lives here is actually distributed across r/IndianStreetBets (553k), r/IndianStockMarket (1.3M), and the official Zerodha kite.trade developer forum.

**Recommendation:** Skip. Replace with **`r/IndianStreetBets`** (553k subs, the closest active equivalent for retail Indian-trader audience).

#### C1. Replacement — `r/IndianStreetBets` — 553k subs

**Subscribers:** `553,850` `[empirical]`. Restricted posting: yes. Wiki-enabled.

**Mod rules** `[empirical]` — particularly Rule 4: **No Self-Promotion** *"No affiliate/referral links, trading services, market education shilling, Patreons, etc. Doing something like posting those links on a page and then posting the page to ISB is still advertising"*. **However:** rule 4 explicitly notes — *"We may potentially make exceptions to this rule if your self-promotion is done tastefully and we want to support you, but you'd be expected to work with us, be patient, and verify anything you do ahead of time."*

**This means: contact the mods via modmail BEFORE posting.** Without mod buy-in, removal is near-certain. With mod buy-in, this becomes one of the warmer Indian channels.

**Other constraint:** Rule 9 mandates a SEBI disclaimer — fine, ours already includes one. Rule 8 — P/L screenshots require Sensibull link; we wouldn't post P/L anyway.

**Calibration:** Pre-mod-approved posts that work: 200-1000 upvotes range visible in top-of-year. Without mod approval: instant removal.

**Action:** Modmail this sub on Day-3 (after r/algotrading post lands) with the GitHub link + a one-paragraph "is this OK to post here?" message. Attach the existing `docs/reddit-buildlog-posts.md §1` shorter draft. **Do not post unsolicited.** Skip if mods don't reply within 5 days; revisit at week 3.

### D. `r/MachineLearning` — 3.04M subs

**Subscribers:** `3,043,114` `[empirical]`. Restricted posting: yes. Created 2009.

**Audience fit:** **Mid-fit, AI-as-protocol angle.** Audience is ML researchers + practitioners. The Kite-broker-API specifics are noise; the wedge is "MCP server reference implementation in Go" — which isn't novel enough on its own. Recent `[P] MCP server`-related posts past year scored 5-26 upvotes. **The whale on this sub is research papers, not project showcases.**

**Mod rules** `[empirical]` — the relevant ones:
- **No Spam** — strict.
- **No Self-Promotion** — *"posts with links to paid products are acceptable, contingent on the fact that the post offers sufficient value"*. Our project is open-source, so this is permissive but mod-discretion-based.
- **No Marketing Campaigns (SEO)** — strategic-marketing campaigns get permabanned with all past content purged.
- **No Disrespectful Behavior**.
- **No arXiv Links without Body Text** — every post needs commentary.
- **No Low-Effort, Beginner Questions**.

**Required title format** `[empirical]` — sub's submit_text says: *"Posts without appropriate tag (e.g: [R], [D], [P], [N])"* will be removed. Our post is `[P]` for Project. Title MUST start with `[P]`.

**What scores in past year** (from `search.json?q=MCP&sort=top&t=year`) `[empirical]`:
- 49 / 15 — `[R]` — Controlled experiment giving LLM access to CS papers
- 26 / 2 — `[P]` — Open-sourced full-stack Deep Research
- 12 / 7 — `[P]` — Financial analyzer agent using mcp-agent
- 13 / 13 — `[P]` — HTTP-native, OpenAPI-first MCP alternative

**Calibration:** **50th percentile: 8-20 upvotes, 3-8 comments.** Star yield: **3-8 stars.** Weak ROI per minute spent compared to r/algotrading. Post anyway because the audience is high-quality (ML researchers occasionally become long-tail amplifiers — `slashML` Twitter reposts top content), but don't over-invest.

**Best-time-to-post:** Tuesday-Thursday 11:00-13:00 US Eastern. Sub is global, US-skewed.

**Karma threshold:** Not explicit, but post-quality filter is high — low-effort posts auto-flagged. **An empty-history account will fail the AutoMod check.** Need substantive 50+ comment karma.

### E. `r/ClaudeAI` — likely highest-fit ecosystem channel

**Subscribers:** Not exact-fetched but per recent posts ~250-500k range based on engagement.

**Audience fit:** **Highest-fit ecosystem channel.** Closest to MCP-builders. There is even a designated *"Built with Claude Project Showcase Megathread"* (16 score, 295 comments — actively used). The "I dug through Claude Code's leaked source" post scored 5575 — this audience eats technical Claude content.

**Mod rules** `[empirical]` — the relevant ones:
- **Be respectful**.
- **Be relevant** — *"Stay relevant to the Claude and Claude Code technology and users."*
- **Be constructive** — no agitation.
- **Don't use Megathreads as a weapon** — keep performance/bug complaints in megathread.
- **Don't use this sub for account problems**.
- **Competitor posts must contain sufficient homework and evidence** — does not apply (we're showcasing, not comparing).
- **Showcase your project** (priority 6) — **explicitly encouraged if it fits criteria:**
  > *"be clear the project was built with Claude/Claude Code or specifically for Claude BY YOU; include a clear description of what was built, how Claude helped, and what it does; project must be free to try and say so (paid tiers/features OK); promotional language minimal; do not use referral links (link to the project is ok); no job seeking requests or resumes. **Posts on the feed now require OP karma>50.**"*

**Critical:** **OP must have >50 karma.** This is enforced. New `u/Sundeepg98` account starting at 0 will be auto-rejected here until karma is built.

- **Don't manipulate upvotes** — bots actively hunting upvote-rings.
- **Stay grounded** — fiction must be flagged, OK for us.
- **Use post flair** — required.

**What scores in past month** (from `search.json?q=showcase&sort=top&t=month`) `[empirical]`:
- 477 / 112 — *"Launched My First App Using Claude"*
- 240 / 23 — *"I reverse-engineered the Perplexity app and built an MCP that turns your Perplexity/Comet"* — **closest analogue, 240 upvotes**
- 16 / 295 — *"Built with Claude Project Showcase Megathread"* (the megathread itself)
- 9 / 1 — *"Improvements to Built with Claude Project Showcase visibility"*

**Calibration:** **50th percentile: 50-150 upvotes, 15-40 comments.** Optimistic: 200-400 if MCP novelty resonates. **Star yield: 10-25 stars 50th, 50+ optimistic.** This is the second-most-valuable channel after r/algotrading.

**Critical framing rule:** The showcase rule says *"be clear the project was built with Claude/Claude Code or specifically for Claude BY YOU"*. So the post must address: **how Claude helped build the project itself**, not just that it works with Claude. This is non-trivial; the project was hand-coded, not vibe-coded — the framing should honestly describe Claude Code as a development assistant where it was used (e.g. for the test suite, doc generation, refactoring). Don't fake it.

**Best-time-to-post:** Tuesday-Thursday 09:00-11:00 US Eastern. Audience is global but Anthropic time-zone-anchored.

**Karma threshold:** **HARD 50 karma minimum** — explicit in rule 6.

### Summary table — primary 5 subs (corrected from brief)

| Sub | Subs | Self-promo policy | AI ban? | Format | Karma req | 50th-pct upvotes | Stars | Action |
|-----|------|-------------------|---------|--------|-----------|------------------|-------|--------|
| **r/algotrading** | 1.86M | OSS welcomed via sidebar Do's; "marketing" banned | No | text body, code blocks | implicit ~50 | 80-150 | 8-15 | **Day 1 +12h primary** |
| **r/IndianStockMarket** | 1.31M | strict; AI-content banned | **YES (Apr 2026)** | text, no AI framing | implicit ~50 | 5-15 | 2-5 | Day 4-5 only with non-AI inverted framing |
| **r/Zerodha** | 350 | restricted, no rules visible | n/a | n/a | n/a | n/a | 0 | **DROP** |
| **r/MachineLearning** | 3.04M | mod-discretion OK for OSS | implicit | `[P]` flair required | implicit ~100 | 8-20 | 3-8 | Day 3-4 with `[P]` |
| **r/ClaudeAI** | ~250-500k | explicit Showcase rule | No | flair, "how Claude helped" required | **HARD 50** | 50-150 | 10-25 | Day 2-3 secondary primary |

---

## Phase 2 — Per-subreddit posting drafts (v1 + v2 each)

For each primary sub, two distinct drafts. v1 = recommended; v2 = fallback if v1 is removed within 24h.

### A. `r/algotrading`

#### A.1 — v1 (recommended) — architecture-led, ~700 words

**Title (≤300 chars Reddit limit, but keep ≤90 for visibility):**
```
[Show] kite-mcp-server — Go MCP bridge for Zerodha Kite with riskguard chain and SQLite audit (open source, 80 tools, 330 tests)
```

**Flair:** Tools (or Project — sub doesn't enforce strict flairs).

**Body (markdown):**
```markdown
Cross-posting from a working repo I've been on for ~6 months. Sharing architecture
because the riskguard chain is the part I'd actually like critique on.

**What it is.** A Go-based Model Context Protocol server that wraps Zerodha Kite Connect
(India's largest retail-broker REST API). Each user brings their own Kite developer
app, connects through OAuth 2.1 + PKCE, and the server speaks streamable-HTTP MCP to
any compliant client (Claude Desktop, Claude Code, Cursor, Cline, etc.). 80 tools
across read (holdings, positions, quotes, historical, option chain) and write (place
/ modify / cancel order, GTT, alerts).

Repo: github.com/Sundeepg98/kite-mcp-server

**The architecture you might actually care about.**

*Storage.* SQLite + WAL + Litestream streaming WAL pages to Cloudflare R2 (APAC,
$0/month for sub-GB DBs, 10-second sync). Five logical stores in one DB file: tokens,
credentials, audit log, OAuth client registrations, session registry. All
PII/credentials AES-256-GCM with HKDF-derived keys from a single OAUTH_JWT_SECRET.

*Order safety chain.* Every write tool walks this exact path:
```
ToolCall → AuditLog(pre) → RiskGuardChain → Elicitation → KiteAPI → AuditLog(post)
```
RiskGuardChain is 9 short-circuiting checks: kill-switch, ₹50k/order cap, qty limit,
20-orders/day, 10/min rate, 30s duplicate window, ₹2L daily notional, intraday
auto-freeze, off-hours block. Every check is a separate function, configurable by
env, and runs *regardless of what the LLM thinks* — the LLM cannot bypass it. The
elicitation step asks the MCP client to render a "confirm" dialog before the call
fires; clients without elicitation support fail-open but riskguard still fires.

*Audit log.* SHA-256 hash chain on append. Each row's hash includes the previous
row's hash, so any tamper breaks the chain. Forensically reproducible — useful when
you want to prove what the LLM actually did at 3am.

**Where the riskguard genuinely surprised me.** Three observations from real use:
- The duplicate-within-30s check fires more than I expected when the LLM gets stuck
  in a loop trying to re-place a "rejected" order it misunderstood. Without that
  check, I would've placed 8 identical orders the first time I deployed.
- Off-hours block protects against the LLM enthusiastically trying to "test" things
  Sunday morning when no exchange is open — silent failure mode otherwise (the
  Kite API just returns "exchange closed" but the LLM sometimes retries).
- ₹50k default cap is too low for me but exactly right as a *default* for a
  contributor onboarding their own key.

**Stack:** Go 1.25, gokiteconnect v4.4.0, mark3labs/mcp-go, SQLite 3.48, Litestream,
Fly.io Mumbai region (single static egress IP because SEBI's April 2026 rule
requires whitelisted IPs for algo orders), Alpine 3.21 base.

**Tests:** ~330 across unit (riskguard, crypto, store, OAuth) and integration
(session persistence across server restarts, token-expiry round-trips, audit
chain replay). Security audit Feb 2026, 181 findings, 153 fixed + 28 documented.

**Honest limitations.** Backtester is 4 strategies (SMA cross, RSI reversal,
breakout, mean reversion) with Sharpe + max drawdown — intentionally simple, no
slippage modeling beyond a flat-bps assumption. Paper trading fill simulator is
naïve. No futures basis surface engine. No FIX. Single-broker (Zerodha) for now.

**What I'd love critique on.**

1. The riskguard chain — is 9 checks the right number? What's missing?
2. The hash-chain audit — am I hand-waving here? It stops *silent* tamper but not
   a determined attacker with DB write access. Is that worth the code?
3. SQLite over Postgres — for tens-of-tool-calls/sec/user, is the simplicity
   defensible or am I going to regret this at 100 users?

Code's MIT. Self-host with `docker compose up`. There's a hosted instance at
kite-mcp-server.fly.dev/mcp but it's `ENABLE_TRADING=false` until I finish a
separate compliance review — read-only there for now.

(Not affiliated with Zerodha. Not a SEBI-registered RA. Not selling tips.)
```

**Why this works for r/algotrading:**
- Title leads with `[Show]` (sub-style) and the substantive technical signal (riskguard, audit, tests count) — no marketing language.
- Body opens with cross-posting honesty and explicit "I want critique on X" — sub responds well to vulnerability.
- ASCII flow diagram (the `→ AuditLog → RiskGuard → Elicitation → KiteAPI` line) is pure-markdown, renders well on old.reddit and new.reddit alike.
- Three "what I'd love critique on" questions are specific and answerable, anchoring the comment thread.
- GitHub link appears once, mid-body, after the substance.
- Compliance posture noted at the bottom in parens — defensive against the "isn't this a SEBI violation?" reply.

#### A.2 — v2 (fallback) — release-note style

If v1 is removed within 24h:

**Title:**
```
[RELEASE] kite-mcp-server v1.2.0 — open-source MCP server for Zerodha Kite, paper trading + 4 backtest strategies, 9-check riskguard
```

**Body:** Use the structure of the 142-score *"# [RELEASE] pandas-ta-classic"* post that worked. Lead with bullet-list of "What's new in v1.2.0", then "Why this exists" (one paragraph), then "Install" (one code block), then "Roadmap" (3 bullets), then "Source + License" (link). 400 words max. **Do not** discuss the riskguard chain in depth — save that for a follow-up post if v2 surfaces. Different positioning than v1; the v1 was architecture-deep, v2 is release-shallow.

### B. `r/IndianStockMarket`

#### B.1 — v1 — narrative-first inversion (mandatory because of AI-content rule)

**Title:**
```
Built an open-source developer tool for Kite Connect (₹500/mo Zerodha API) — looking for fellow Kite devs to break it
```

**Flair:** Discussion or General.

**Body:**
```markdown
Hi all — solo developer in Bangalore. Posting because I've spent ~6 months building
a thing for Kite Connect users and I want non-mine eyes on it.

**Quick context for non-developers reading this thread.** Kite Connect is Zerodha's
official ₹500/month REST API. It's how every algo / portfolio / analytics tool that
talks to Zerodha (Sensibull, Streak, Smallcase, Coin) actually integrates. There's
an official ecosystem of these tools but it tends toward "subscribe to our SaaS";
I wanted something a developer could just self-host.

**What I built.** An open-source server (Go, single binary, MIT license) that exposes
80 read+write operations against your own Kite Connect app. Self-host with one
docker-compose command, BYO API key, your data never leaves your box. The server
itself doesn't do any analysis — it's plumbing. You write your own scripts on top,
or you pipe it into whatever client you prefer.

GitHub: github.com/Sundeepg98/kite-mcp-server

**Why I'm posting here, specifically.** Two reasons.

1. **The community deserves to know what's possible.** Most Kite-related tools posted
   in this sub are paid SaaS or copy-trading services. Open-source equivalents
   barely exist. If you're a Kite Connect developer (or learning to be one), having
   something self-hostable to fork from changes the calculus.

2. **I want it broken before more people use it.** Especially the safety layer —
   I've put 9 separate checks before any order goes through (kill switch, per-order
   ₹50k cap, daily 20-order limit, etc.). If you can find a way to defeat them,
   tell me; I'll fix it and credit you in the changelog.

**Honest disclaimers.** Not SEBI-registered. Not selling anything. No tips, no signals,
no copy trading, no advice. The hosted instance has order placement disabled by
default and is read-only — full trading only when you self-host. Compliance posture
is "tool, not service" under SEBI's retail self-trading framework's self/spouse/
dependent scope.

Repo, again: github.com/Sundeepg98/kite-mcp-server. License is MIT. Issues open.
Comments here also welcome.

(Mods: this is open-source, no paywall, no Telegram links, no tips. If this still
violates rules I'm sorry — let me know and I'll remove it.)
```

**Why this works (and risks):**
- Avoids "AI", "Claude", "ChatGPT", "MCP", "agent", "LLM" in title and first 80% of body. **The MCP/AI angle is intentionally absent.** This survives the AI-content rule.
- Frames as "developer tool" not "trading bot" — sidesteps Tips/Calls rule.
- Self-deprecates and asks for critique — community-friendly framing.
- Explicit mod-acknowledge paragraph at the bottom — flag to mods that we read the rules.
- **Realistic upvote ceiling: 30-50.** This sub is not where stars come from. Use for visibility.

**What's missing here that's in the r/algotrading version:** no riskguard architecture deep-dive (audience won't read it), no code blocks, no "what I'd love critique on" 3-bullet (tonally too technical for here).

#### B.2 — v2 (fallback) — explicit "Zerodha customer" framing

If v1 is removed despite the inversion (probability ~30%):

**Title:**
```
For other Zerodha customers who code: an open-source self-hosted helper for your own Kite account (no paywall, no tips, no AI)
```

**Body:** Even more aggressively non-AI framed. Lead with "I'm a Zerodha customer who codes". Single mention of MCP at the bottom in a footnote-style "this also happens to support modern AI clients via Model Context Protocol but that's incidental — works without". 250 words.

**Probability v2 also gets removed:** ~15%. At that point, abandon r/IndianStockMarket and focus on r/algotrading + r/ClaudeAI which have higher fit anyway.

### D. `r/MachineLearning`

#### D.1 — v1 — `[P]` project showcase, MCP-as-protocol angle

**Title:**
```
[P] kite-mcp-server: a real-world Go MCP server with 80 tools, riskguard middleware, and SQLite hash-chained audit — open source
```

**Body:**
```markdown
Sharing because [P]roject posts in this sub disproportionately ask "where are the
production-grade MCP server reference implementations?" — here's one with about 6
months of real use behind it.

**Domain:** Indian retail brokerage (Zerodha Kite Connect API). I picked the domain
because the safety constraints are realistic — wrong tool call costs real money,
not just an embarrassing demo. That focused the engineering.

**MCP-specific design choices that might generalize:**

1. **Elicitation as a first-class side-effect controller.** 8 destructive tools
   (place_order, modify_order, cancel_order, place_gtt, etc.) ship with elicitation
   metadata so the MCP client renders a confirmation UI before the tool fires.
   Fail-open for older clients but the post-decision riskguard middleware still
   runs. Pattern: elicitation = UX guard rail, riskguard = invariant enforcement.

2. **Middleware chain between tool handler and external API call.** Specifically:
   `Tool → Audit(pre) → RiskGuard → Elicitation → ExternalAPI → Audit(post)`. 9
   checks in the riskguard chain, each a pure function with explicit config. Means
   prompt-injection attacks don't bypass the safety layer because the chain runs
   independent of LLM state.

3. **structuredContent on every response.** Typed payloads alongside text — costs
   nothing in the MarshalResponse, makes downstream parsing dramatically easier
   for chained tool calls. (Single-line addition, biggest delta-quality of any
   feature I shipped.)

4. **Tool annotations: title, readOnlyHint, destructiveHint, idempotentHint,
   openWorldHint** on every tool. Lets clients reason about whether a tool is
   safe to retry, cache, or call optimistically.

5. **MCP Apps inline widgets** for portfolio / activity / orders / alerts — flat
   metadata, dynamic data injection via AppBridge. Renders inline on claude.ai
   web and Claude Desktop.

**Production observations on the protocol itself:**

- mcp-remote's `--static-oauth-client-info` is essential for Windows clients
  (`cmd /c` strips JSON escapes silently — a known mcp-remote workaround).
- Streamable-HTTP transport handles long-running OAuth flows fine; SSE-only
  clients get the same authorize → callback flow without changes.
- Session persistence across server restarts (lazy Kite client recreation from
  email + persistent session table) eliminates the need for clients to renegotiate
  on deploy. Single biggest UX win for production MCP servers.

**Repo:** github.com/Sundeepg98/kite-mcp-server. MIT license. ~330 tests. Go 1.25.

If you're building MCP servers and want to look at a production-shaped reference,
the audit middleware (`kc/audit/`), riskguard (`kc/riskguard/`), and elicitation
(`mcp/elicit.go`) are probably the highest-value reading.
```

**Why this works for r/MachineLearning:**
- `[P]` flair is mandatory and present.
- Sub demands technical depth — this delivers MCP-spec specifics that are protocol-relevant, not Kite-specifics.
- Five generalizable design choices that the sub's MCP-curious would want to read.
- "Production observations" appeals to the senior-engineer cohort.
- GitHub link near the bottom, after substance.
- **Realistic upvote ceiling: 30-60.** Modest by sub standards but legitimate.

#### D.2 — v2 — `[D]` discussion-style if v1 buried

If v1 sits at <5 upvotes after 6 hours:

**Title:**
```
[D] What's the right pattern for "guardrails that the LLM cannot bypass" in an MCP server? Sharing one approach + asking
```

**Body:** Reframe as a discussion question, with the riskguard middleware as the worked example. 300 words. **Repo link reduced to one mention in body paragraph 4.** This is closer to what the sub actually upvotes (papers, discussions). Risk: looks like astroturfing if v1 was visible.

### E. `r/ClaudeAI`

#### E.1 — v1 — Showcase-rule-compliant, lead with "how Claude helped"

**Required by sub rule:** "be clear the project was built with Claude/Claude Code or specifically for Claude BY YOU; include a clear description of what was built, **how Claude helped**, and what it does".

**Title:**
```
Built an MCP server for Zerodha Kite (India's biggest broker API) with Claude Code's help — 80 tools, riskguard, options Greeks, 330 tests, MIT
```

**Flair:** Showcase / Built with Claude (whichever sub flair list contains).

**Body:**
```markdown
~6 months of building with Claude Code as the primary pair-programming tool.
Open-sourcing it. Posting per the sub's project-showcase rules.

**What it is.** A production MCP server that brings Zerodha Kite Connect (India's
₹500/month retail-broker API) into any MCP-compliant client — Claude Desktop,
Claude Code, Cursor, ChatGPT (via mcp-remote), VS Code, Cline. 80 tools across
portfolio reads, market data, orders, options Greeks (Black-Scholes), backtesting,
paper trading, Telegram alerts, technical indicators, sector exposure, tax-loss
harvest analysis.

GitHub: github.com/Sundeepg98/kite-mcp-server (MIT, free, no paid tier required).
Hosted demo: kite-mcp-server.fly.dev/mcp (read-only).

**How Claude helped, honestly.**

1. **Test-suite scaffolding.** ~250 of the ~330 tests were written by Claude Code
   from a manual test outline I gave it. Especially the OAuth round-trip integration
   tests — would have taken me a week, took two days with Claude pair-programming.

2. **Refactoring at boundaries.** When I split the monolithic kc/ package into
   the eventually-Hexagonal port/adapter layout, Claude handled 80% of the
   mechanical churn — interface extraction, mock generation, callsite updates.

3. **Doc generation.** All ADRs (`docs/adr/0001..0010`), the threat model, and
   the security audit findings document were drafted with Claude reviewing the
   actual code and producing the prose. Then I edited.

4. **Where Claude failed and I overrode.** The riskguard chain I designed by hand
   — Claude's instinct was to combine checks; I needed each to short-circuit
   independently for testability. Same with the audit hash-chain — Claude wanted
   to use a Merkle tree (overkill); I wanted simple SHA-256 prev_hash chaining.

**MCP-specific features used.** Elicitation (8 destructive tools have confirm
dialogs), structuredContent on every response (typed payloads), tool annotations
(title/readOnlyHint/destructiveHint/idempotentHint/openWorldHint), MCP Apps inline
widgets (portfolio/activity/orders/alerts), MCP Prompts (morning_brief / trade_check
/ eod_review). Server-side prompts work on any MCP client, not just Claude.

**Why open source this when there's an official Zerodha MCP?** Zerodha ships
mcp.kite.trade with 22 read-only tools; we ship 80 with order placement, paper
trading, alerts, backtesting, options. Different audience: theirs is "default
zero-setup", ours is "developer-power-user with safety rails". Both are valid;
both work; we even cite the official one in our README.

**Honest limitations.** Hosted instance has order placement OFF by default
(`ENABLE_TRADING=false`) until I finish a compliance review. Self-hosters get full
functionality immediately. Backtester is intentionally simple. Paper-trading fill
simulator is naïve. Single-broker (Zerodha only — Upstox / Dhan adapters planned).

**Try it.** Add this to your Claude Desktop config:
```json
{
  "mcpServers": {
    "kite": {
      "command": "npx",
      "args": ["mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```
Then say "Log me in to Kite. Show my portfolio." and the OAuth flow opens in your
browser. Works in claude.ai web too — same config in your account settings.

(Disclosure: I'm not affiliated with Zerodha or Anthropic. Not a SEBI-registered
investment advisor. Not selling tips. The course/cohort I run is mentioned in
the repo's funding.json but isn't gated to using this code.)

Stars/issues/feedback all welcome. Built with Claude Code on Windows + Go.
```

**Why this works for r/ClaudeAI:**
- Sub-rule literal compliance: "how Claude helped" gets its own four-bullet section, including a "where Claude failed" sub-bullet (honesty signal — sub respects this strongly).
- Repo link in opening, demo link, install snippet — three CTAs.
- MCP-specific features list (5 spec concepts) matches the sub's vocabulary.
- Defensive disclosure at the bottom — sub is allergic to undisclosed promotion.
- Code block for install — sub upvotes copy-paste examples.

**Karma constraint reminder:** OP must have **>50 karma** before posting here. If account is fresh, build karma in r/Anthropic, r/ClaudeCode, r/LocalLLaMA, r/programming-discussion, r/learnprogramming first by leaving substantive comments. ~10-15 thoughtful comments will hit 50 karma in a week.

#### E.2 — v2 — Skill-focused if v1 underperforms

If v1 sits at <30 upvotes after 6 hours:

**Title:**
```
Released 8 Claude Skills for Indian stock trading via Kite Connect — what would you build if your AI could place real orders safely?
```

**Body:** Reframe around the 8 Claude Skills wrapper (per memory `kite-skills-wrapper.md`, commit `60e552c`). Lead with skills as the unit of value, not the server. 400 words. The MCP server is described as "the substrate" not the headline. **More likely to engage the skills-curious cohort.**

### F. `r/SideProject` (stretch — see Phase 6)

#### F.1 — v1 — generic launch in classic SideProject style

**Title:**
```
6 months of solo dev: an open-source AI trading copilot for India's biggest broker (Go, MCP, 80 tools, paper trading, riskguard)
```

**Body:**
```markdown
Sharing because this sub asked for "real solo projects, not portfolios" — here's one
that's been my main thing since November.

**The product.** kite-mcp-server: an open-source Model Context Protocol server that
connects any AI client (Claude Desktop, ChatGPT, Cursor) to your Zerodha Kite
trading account. Each user brings their own Kite developer subscription
(₹500/month, paid to Zerodha directly). The server is the plumbing — you decide
what to do with it.

**Demo:** [30-second GIF] [or asciinema embed of asking Claude "Show my portfolio.
Backtest SMA crossover on INFY. Set an alert for RELIANCE 2% drop."]

**Tech stack:** Go 1.25, SQLite + Litestream, AES-256-GCM encryption, Fly.io
Mumbai for hosting, gokiteconnect SDK, mark3labs/mcp-go.

**What's interesting from an engineering POV (instead of a product-pitch POV):**
- 80 MCP tools, ~330 tests, MIT license
- 9-check riskguard chain runs before every order (kill-switch, ₹50k cap, daily
  limits, rate limit, duplicate detection)
- SHA-256 hash-chained audit log
- AES-256-GCM token + credential storage with HKDF key derivation
- Single static egress IP for SEBI's April 2026 mandate
- Litestream WAL streaming to Cloudflare R2 ($0/mo backup)
- Per-user OAuth 2.1 + PKCE — server holds no shared credentials
- 27-pass security audit (181 findings, all resolved)

**What's hard about this domain (and why it's a side project, not a startup yet):**
- SEBI regulation. India's market regulator has strict rules about who can
  give "investment advice" — I'm explicitly NOT doing that, but the line is
  uncomfortable to walk solo.
- ~₹500/month barrier to entry per user (Kite Connect dev fee), so the
  addressable market is "Indian retail traders who code", not "all Indians".
- The official Zerodha MCP exists (`mcp.kite.trade`) — read-only, free, 22 tools.
  Mine is the 80-tool power-user version. Complementary, not competitive — the
  README explicitly recommends the official one for read-only use.

**What I'm asking the sub for.**
- Stars (lol but yes — I'm at 0 right now and trying to hit 50 to unlock a
  warm intro to a fund I've been nudging).
- Code review on the riskguard package — `kc/riskguard/`. Anyone who's built
  similar safety layers, please tell me what I'm missing.
- General "where would you launch this next?" energy — I've done MCP Registry
  and have an awesome-mcp-servers PR queued.

Repo: github.com/Sundeepg98/kite-mcp-server

(Open source MIT. No paywall. The hosted instance is free read-only; full
order placement requires self-hosting. Not affiliated with Zerodha. Not a
registered advisor.)
```

**Why this works for r/SideProject:**
- Sub-norm: lead with time-and-effort signal ("6 months of solo dev").
- Demo GIF placeholder — sub explicitly rewards visuals.
- Honest "what's hard" section — sub-culture appreciates founder vulnerability.
- Direct ask for stars, code review, and feedback — sub-norm to ask explicitly.
- **Realistic upvote ceiling: 200-500.** Sub is large (700k) and forgiving of solo-builder posts. **Star yield: 10-20.**

#### F.2 — v2 — Solo-builder narrative

If v1 doesn't traction (rare on this sub):

**Title:**
```
I'm 6 months into my biggest side project — an open-source trading API server. AMA on the dev journey.
```

**Body:** Reframe as AMA. Less product-pitch, more journey-narrative. 350 words. Sub culture doubly rewards "AMA" framing for sustained-effort projects.

### G. `r/golang` (stretch — see Phase 6)

#### G.1 — v1 — Go-language angle, MCP-server reference implementation

**Title:**
```
Go MCP server (mark3labs/mcp-go) with 80 tools, OAuth 2.1, SQLite + Litestream, ~330 tests — open source
```

**Body:**
```markdown
Posting because the sub upvotes Go MCP server work (recent: "Built a Go MCP server
that let Claude generate a complete SvelteKit site in 11 minutes" hit 112 upvotes).
Mine is a different angle — a domain-specific MCP server (broker API), with
production concerns (auth, audit, encryption, rate-limit, retry).

**Repo:** github.com/Sundeepg98/kite-mcp-server (MIT)

**Stack worth discussing in this sub:**

- **MCP framework:** mark3labs/mcp-go (chose over modelcontextprotocol/go-sdk for
  earlier maturity; both are now solid).
- **HTTP transport:** Streamable-HTTP per the spec. SSE works as fallback.
- **OAuth 2.1 + PKCE:** Hand-rolled because the Kite OAuth lifecycle is non-standard
  (daily ~6am IST token refresh). About 800 LOC, with unit tests round-tripping
  the full flow.
- **SQLite:** Embedded, WAL mode, ~5 logical stores. Litestream streams WAL pages
  to Cloudflare R2 — every restart restores from R2 if the local volume is
  ephemeral. Costs $0/month for sub-GB.
- **Encryption:** AES-256-GCM with HKDF-derived keys. Single OAUTH_JWT_SECRET
  env-var seeds 4 derived keys for token store / credential store / OAuth client
  registration / session table.
- **Concurrency:** Goroutines per session, sync.Map for in-flight, context-cancel
  for shutdown — boring, works. Background scheduler for daily Telegram briefings.
- **Decorator middleware chain:** `Tool → Audit(pre) → RiskGuard → Elicitation →
  KiteAPI → Audit(post)`, each layer is a typed Decorator[Req, Resp]. Generics
  finally make this clean (Go 1.18+).
- **Testing:** 330 tests, ~70% coverage. Unit-tested riskguard policy (each of 9
  checks individually + chain), integration-tested OAuth round-trip + session
  persistence + audit chain replay.

**Two Go-specific things I learned the hard way:**

1. **`context.Background()` audit.** The decorator chain initially leaked
   `context.Background()` calls in 8 places where I should have propagated the
   inbound context. Caught via grep audit (`.research/ctx-background-audit.md`
   in the repo). One of those was a deadline-loss, would have caused tool calls
   to outlive their HTTP request.

2. **Generic decorator factory.** Having `Decorator[Req, Resp any] func(Handler[Req,
   Resp]) Handler[Req, Resp]` as the unit of composition simplified the
   middleware story dramatically. Every cross-cutting concern (audit, riskguard,
   elicitation, telemetry, paper-trading interception) is one Decorator. This is
   a pattern I'll reuse in every Go HTTP server I write going forward.

**Domain context (skip if you don't care):** Indian retail brokerage API
(Zerodha Kite Connect, ₹500/mo to Zerodha directly). MCP server lets Claude /
ChatGPT / Cursor talk to your Kite account. Per-user OAuth, no shared credentials,
self-hostable.

If you're building MCP servers in Go, the audit middleware (`kc/audit/`),
decorator factory (`kc/decorators/`), and riskguard chain (`kc/riskguard/`) are
the most-likely-reusable bits.

Critique welcome.

(Aware of r/golang's no-AI-content rule — none of the code or this post was AI-
generated. Claude Code was used as a pair-programming assistant; all decisions,
architecture, and final code are mine.)
```

**Why this works for r/golang:**
- Title leads with Go-specific signals (mark3labs/mcp-go, OAuth, SQLite, tests).
- Body opens with domain-relevance: cites the recent 112-score Go-MCP post.
- Stack section uses Go-native vocab (goroutines, sync.Map, context-cancel, generics).
- Two "Go-specific things I learned" are pure Go-craft — exactly what this sub upvotes.
- Domain context is **explicitly demoted** to a skip-if-uncared paragraph — sub will read this signal as "respects the reader's time".
- Defensive AI-rule disclaimer at bottom (sub has explicit no-AI-content rule).
- **Realistic upvote ceiling: 80-150.** Star yield: 8-15.

#### G.2 — v2 — Specific deep-dive

If v1 underperforms, post a follow-up at week 3 specifically about the typed-decorator pattern (`kc/decorators/`) — pure Go-craft, no domain references at all. Drives organic exposure.

---

## Phase 3 — Karma + account requirements

**Verified state:** `u/Sundeepg98` returns HTTP 404 on `reddit.com/user/Sundeepg98/about.json`. **The user has no Reddit account under the project handle.**

This is the single largest blocker for the Reddit launch. **Without a warmed-up account, every post planned above will be auto-shadowbanned by AutoMod.**

### Required karma per sub (empirical)

| Sub | Karma minimum | Source |
|-----|--------------|--------|
| r/algotrading | implicit ~50 (no explicit but bot-rule + restrict_posting + spam-filter behavior) | observed AutoMod patterns |
| r/IndianStockMarket | implicit ~50 (restrict_posting + AI rule scrutiny) | observed AutoMod patterns |
| r/MachineLearning | implicit ~100 (sub is high-bar) | observed |
| **r/ClaudeAI** | **HARD 50** (rule 6 explicit) | rules.json verified |
| r/SideProject | none enforced (most permissive) | observed |
| r/golang | implicit ~30 (smaller, more lenient) | observed |
| r/IndianStreetBets | mod-approval required for self-promo (skip karma) | rule 4 explicit |

### Karma-warmup sequence (Day -7 → Day -1)

The Reddit launch is **bound by account age + karma**, not by Show HN. If Reddit is the focus, the timeline shifts.

| Day | Action | Time |
|-----|--------|------|
| -7 | Create `u/Sundeepg98`. Verify email. Set bio: "Solo dev, Bangalore. Go + MCP." Avatar = same as GitHub. | 15 min |
| -7 | Subscribe to r/algotrading, r/golang, r/SideProject, r/ClaudeAI, r/MachineLearning, r/IndianStreetBets. Read top-of-week threads on each. | 30 min |
| -6 | Post 3 substantive comments in r/golang (any technical Go thread, helping someone with a real question). | 20 min |
| -5 | Post 3 substantive comments in r/algotrading (on backtesting / data / API integration questions). | 20 min |
| -4 | Post 2-3 comments in r/SideProject (encouraging fellow solo devs). | 15 min |
| -3 | Post 2 comments in r/ClaudeAI on MCP-related threads (technical, not "how do I use"). | 15 min |
| -2 | Check accumulated karma. Should be 30-60 by now if comments were genuinely helpful. | 5 min |
| -1 | Final pre-launch: ensure account age = 6+ days, karma 30-60. **Skip the launch if karma <30** — risk of auto-shadowban too high; warm up another week. | 5 min |

**Total time investment for warmup:** ~2 hours over 6 days.

### Why this matters specifically

- AutoModerator on r/algotrading checks: account age >7d, karma >X (sub-private), posting history present. **First-action posters from new accounts hit AutoMod queue with ~80% removal rate** observed across similar finance subs.
- r/ClaudeAI rule 6 is **published and enforced**: posts from <50 karma accounts auto-rejected at the queue.
- A "warmed-up" account is not an attempt to game — it's table stakes for not getting filtered. The comments themselves should be genuinely useful (per the sub-norm); 2 hours over 6 days is enough.

### Existing handle preservation

If the user has an older Reddit account (different handle than `Sundeepg98`), check its karma score via `reddit.com/user/<handle>/about.json`. If >100 karma + >30 days old, **use that account** instead of creating a fresh one — instant credibility boost, bypasses the warmup.

If older account exists but is in a different niche (e.g. gaming, India-specific subs), still use it. Cross-niche is fine — fresh account isn't.

---

## Phase 4 — Day-1 vs delayed-launch sequencing

Per `58dc369` Phase 4: HN Day 0, Reddit Day 1+. This document refines the Reddit half.

**Adjusted launch sequence (Reddit-specific layer):**

| Day | Time | Action | Body | Conditions to advance |
|-----|------|--------|------|----------------------|
| 0 | 06:30 PT | Show HN (per `58dc369`) | `docs/show-hn-post.md` | Independent of Reddit |
| 0 | 12:00 PT | (Optional) Twitter launch thread | `5adf80f` Week 1 plan | Independent |
| **1** | **18:30-20:30 IST** (= 09:00-11:00 ET) | **r/algotrading v1** | §A.1 verbatim | Account ≥7d old + ≥30 karma |
| 1 | 22:00 IST | Watch comments. Reply within 30 min to first 5 critiques. | use `docs/reddit-buildlog-posts.md` §5 reply patterns | n/a |
| 2 | 09:00 ET | r/ClaudeAI v1 | §E.1 verbatim | Account >50 karma ✓; r/algotrading post not removed |
| 3 | 11:00 ET | r/MachineLearning v1 [P] | §D.1 verbatim | r/algotrading post score >30; sub-fit signal |
| 4 | 11:00 IST (Saturday morning) | r/IndianStreetBets — **modmail first**, post only if approved | §C1 (mod note) | Mod reply received |
| 5 | 11:00 IST | r/IndianStockMarket v1 (inverted, no AI framing) | §B.1 verbatim | Mod queue not flagged in past 2 days |
| 6-7 | flex | Comment-tend on all 4 threads | n/a | n/a |
| Week 2 day 1 | flex | r/SideProject v1 | §F.1 | Day 1-5 posts succeeded |
| Week 2 day 3 | flex | r/golang v1 | §G.1 | Independent |

**Stop conditions:**

- If r/algotrading post is removed within 2 hours: do **not** proceed to r/ClaudeAI same week. Investigate cause, fix, retry following week with v2 draft.
- If r/algotrading post sits at <5 upvotes after 6 hours: ship v2 (release-note format) at the next Tuesday slot. Do not continue cascading to other subs — momentum signal is weak.
- If r/IndianStockMarket v1 is removed: do **not** ship v2 on same account same week. Re-evaluate after 7 days.
- If account is shadowbanned (posts visible to author but invisible in `/new` to others — verify by viewing `reddit.com/r/algotrading/new` from logged-out browser): **stop all Reddit activity immediately**. Modmail r/algotrading + r/ClaudeAI to clarify. Wait 7 days. Re-warm karma. Use a different IP if possible.

**Acceleration triggers:**

- If r/algotrading v1 hits >100 upvotes in 4 hours: post r/ClaudeAI v1 same day (12 hours later). Sub-cohort overlap is small enough that double-post within 24h won't cross-pollute.
- If a known fintwit / MCP-developer voice comments on the r/algotrading thread: ping them via Twitter DM the next day asking for warm-intro to anyone else they know building similar tools.

---

## Phase 5 — Cross-channel discipline + risk audit

### Discipline rules (apply to all Reddit posts in this sequence)

1. **Don't link Twitter from Reddit.** Looks like cross-promotion to mods, looks like astroturfing to users. Twitter handle goes in your Reddit user bio (acceptable), never in a post body.

2. **Don't link Hacker News from Reddit unless directly relevant.** Linking your own Show HN thread reads as "trying to bandwagon". If the HN thread is relevant (e.g. someone in the Reddit thread asks "what does HN think?"), link it as one of multiple references, not the centerpiece.

3. **Do link GitHub.** GitHub is the canonical artifact — every Reddit post should have at least one explicit GitHub URL. `github.com/Sundeepg98/kite-mcp-server` exact form preferred; the trailing `.git` form looks bot-generated.

4. **Don't comment-bomb your own thread within first 30 minutes.** Reddit's algorithm penalizes posts where OP comments dominate early. **Wait for the first non-OP reply.** Then engage rapidly (≤5 minutes per reply) for the next 90 minutes.

5. **Reply to critique substantively, not defensively.** Use the prepared replies from `docs/reddit-buildlog-posts.md` §5. The "you're going to get sued by SEBI" reply is in there verbatim — use it.

6. **Don't downvote-bait hostile comments.** If a comment is hostile, reply once with substance (or don't reply at all). Engaging in a flame war is the second-fastest way after AI-content-rule-violation to get auto-removed in r/IndianStockMarket / r/ClaudeAI / r/MachineLearning.

7. **Don't request feature additions in your own post.** "Should I add support for X broker?" is a separate thread, not the launch thread. If a commenter requests a feature, redirect them to GitHub Issues with the URL — don't promise inline.

8. **Don't post the same body across subs.** Each draft above is sub-specific. Reddit cross-post detection is real — `docs/reddit-buildlog-posts.md` §3 already warns about this. **Each draft is genuinely different in structure, opening, and emphasis. Do not paraphrase.**

9. **Verify the bot-detector posture.** Before posting, check `https://www.reddit.com/user/Sundeepg98/` from logged-out incognito to confirm comments are visible. Shadowbans don't notify.

### Risk audit (Reddit-specific, on top of `58dc369` §Phase 5)

**Risk R1: AutoMod auto-removal due to new account.** Probability ~80% if account <7d old + <30 karma. Mitigation: Phase 3 warmup. Severity: high (cancels launch day).

**Risk R2: r/IndianStockMarket AI-content rule triggers despite framing.** Probability ~30% even with v1 inversion. Mitigation: v2 draft at hand; if v2 also removed, abandon sub. Severity: low (one of 5 subs, others independent).

**Risk R3: r/algotrading mod removal under "No Promotional Activity".** Probability ~15%. Mitigation: title must lead with `[Show]` and substantive content; v2 release-note format is fallback. Severity: medium (this is the primary channel).

**Risk R4: Shadowban without notification.** Probability ~5% per fresh-account post. Mitigation: verify visibility from logged-out browser within 30 min of posting. If shadowbanned, stop all Reddit activity and modmail the sub. Severity: high (kills account permanently sometimes).

**Risk R5: Cross-post-pattern detection across subs.** Probability ~10% if same body posted to 3+ subs. Mitigation: per-sub drafts above are genuinely different; each must be used as-is, not paraphrased. Severity: medium (account-level reputation hit).

**Risk R6: r/ClaudeAI 50-karma threshold not met.** Probability 100% if no karma warmup; 0% if Phase 3 followed. Mitigation: Phase 3. Severity: medium (loses one of two primary channels).

**Risk R7: A hostile commenter cites SEBI in r/IndianStockMarket thread.** Probability ~25%. Mitigation: prepared reply from `docs/reddit-buildlog-posts.md §5` ("possible, and I've paper-trailed accordingly..."). Severity: low if handled well; high if escalated.

**Risk R8: A competitor (Multibagg founder, per memory `kite-competitors-corrected.md`) sees the post and brigades.** Probability ~10% on r/IndianStreetBets specifically. Mitigation: standard "calm code-review tone" reply, never engage adversarially. Severity: low (brigading visible in vote pattern, mods usually intervene).

**Risk R9: Indian-specific post gains traction, attracts SEBI-adjacent regulator interest.** Probability ~3%. Mitigation: per `58dc369` §Phase 5 — disclosure email to `kiteconnect@zerodha.com` BEFORE Reddit launch. Severity: high if triggered (but very low probability).

**Risk R10: Reddit rate-limiting prevents the planned cadence.** Probability ~10% if posting 3 subs in 36 hours from new account. Mitigation: Spread posts across Day 1-7 not Day 1-3. Severity: low (delays, doesn't cancel).

---

## Phase 6 — Stretch subreddits (programming / golang / SideProject / OpenSource)

Quick assessment per the brief:

### r/programming — **DROP**

**Subs:** ~7M.

**Rules audit (verbatim short_names)** `[empirical]`:
- *"[April Trial] No LLM-related posts."* Hard ban on any LLM content.
- *"No LLM-Written Content"* — code or post.
- *"No Product Promotion / 'I Made This' Project Demo Posts"* — explicit ban on launch posts.

**Verdict:** Triple-banned. **Drop entirely.** Even the architecture-only deep-dive without product framing would violate the LLM-content rule because MCP is LLM-related infrastructure.

### r/golang — **ADD as Week-2 secondary**

**Subs:** `357,395` `[empirical]`. 357k.

**Rules audit:**
- *"Be friendly..."* and *"Be relevant..."* — standard.
- *"Must be Go Related"* — easy.
- *"AI Policy: No GPT or other AI-generated content is allowed as posts, post targets, or comments. **This is only for the content itself; posts about GPT or AI are ok if they are non-generated.**"* — **post about MCP is allowed; the post body must be human-written.**

**Recent calibration**: "Built a Go MCP server" hit **112 upvotes / 35 comments**. "Build robust MCP servers with Go" got 29 / 13. **MCP-server posts are warmly received here.**

**Verdict:** **ADD to Week 2.** Use draft G.1 above. **Realistic 80-150 upvotes, 8-15 stars.**

### r/SideProject — **ADD as Week-2 primary**

**Subs:** `701,963` `[empirical]`. 700k.

**Rules:** Empty (no published rules document) `[empirical]`. The sub is permissive by design — it's literally for showcasing side projects.

**Recent calibration**: Top posts past year include 689 / 130 *"6 days, 82 commits — my second solo app is now live"*, 583 / 84 *"I turned GitHub into a 3D city"*. **Solo-builder narrative + technical depth + visual aid (GIF/video) is the winning pattern.**

**Verdict:** **ADD to Week 2 as primary stretch sub.** Use draft F.1. **Realistic 200-500 upvotes, 10-20 stars.** This is the most permissive sub; if a Reddit post is going to land at all, it's here.

### r/opensource — **ADD as Week-3 secondary**

**Subs:** `348,521` `[empirical]`. 348k.

**Rules audit**:
- *"No Spam or Excessive Self-Promotion"* — standard.
- *"Be On-Topic"* — must be open-source related.
- *"No Sensationalized Titles"* — keep titles close to article/repo names.
- *"No Drive-By Posting / Karma Farming"* — first post should not be a self-promo.
- *"Use Correct Flairs"* — `Promotional` flair available for self-promo.

**Verdict:** **ADD to Week 3.** Post with `Promotional` flair (transparency-positive in this sub). Title: *"kite-mcp-server: open-source MCP server for Zerodha Kite (Go, MIT, 80 tools)"*. Body: 300 words, focus on the open-source-specific story (why MIT, why no paywall, why community contributions matter). **Realistic 30-80 upvotes, 5-10 stars.** Modest but legitimate; uses the moment to build OSS-developer community goodwill.

### Summary — Final stretch sub list

| Sub | Add? | Week | Draft | Rationale |
|-----|------|------|-------|-----------|
| **r/programming** | **DROP** | n/a | n/a | Triple-banned |
| **r/golang** | **ADD** | Week 2 day 3 | §G.1 | 112-upvote precedent for similar Go-MCP posts |
| **r/SideProject** | **ADD** | Week 2 day 1 | §F.1 | Highest-permissive, solo-builder culture, 200-500 ceiling |
| **r/opensource** | **ADD** | Week 3 | new draft (300 words, `Promotional` flair) | Modest but legitimate OSS-community fit |

This expands the Reddit launch from 5 subs (per brief) → 6 subs after dropping r/Zerodha + r/programming and adding r/IndianStreetBets + r/SideProject + r/golang + r/opensource.

---

## Cross-references

- **Companion docs in repo:**
  - `.research/gtm-launch-sequence.md` (commit `58dc369`) — overall GTM Phase 1 channel inventory; this doc deepens Phase 1 D
  - `.research/twitter-cadence-weeks-1-4.md` (or whichever filename from commit `5adf80f`) — Twitter parallel
  - `docs/reddit-buildlog-posts.md` — original 850/420-word draft pair + cross-post matrix + 5 prepared pushback responses (still useful for reply patterns)
  - `docs/launch/04-demo-video-script.md` — 30-second screen-recording script (record before any Reddit post)
  - `docs/show-hn-post.md` — Show HN draft (Day 0)
  - `docs/product-definition.md` §3 Drafts A and B — canonical positioning
- **Memory files cross-referenced:**
  - `kite-competitors-corrected.md` — Multibagg / Streak / Sensibull positioning (r/IndianStreetBets brigade risk)
  - `kite-rainmatter-warm-intro.md` — Day-7+ Rainmatter playbook gated by 50-star trigger
  - `kite-launch-blockers-apr18.md` — pre-launch fixes (already shipped per `58dc369`)
  - `kite-skills-wrapper.md` — referenced in r/ClaudeAI v2 fallback
  - `feedback_cheapest_compliance_action.md` — `kiteconnect@zerodha.com` disclosure email (do BEFORE Reddit launch)
- **External refs (verified 2026-05-02 via Reddit JSON API):**
  - `reddit.com/r/algotrading/about.json` — 1.86M subs, 7 rules
  - `reddit.com/r/IndianStockMarket/about/rules.json` — 7 rules incl. AI-content ban from 2026-04-23
  - `reddit.com/r/Zerodha/about.json` — 350 subs, restricted-submission, no rules
  - `reddit.com/r/MachineLearning/about/rules.json` — 6 rules
  - `reddit.com/r/ClaudeAI/about/rules.json` — 13 rules incl. hard 50-karma showcase rule
  - `reddit.com/r/IndianStreetBets/about/rules.json` — 10 rules incl. mod-approval-required self-promo
  - `reddit.com/r/programming/about/rules.json` — 15 rules incl. April-trial no-LLM ban + no-I-made-this
  - `reddit.com/r/golang/about/rules.json` — 12 rules incl. AI-content rule (allows MCP posts; bans GPT-written)
  - `reddit.com/r/SideProject/about/rules.json` — empty rules
  - `reddit.com/r/opensource/about/rules.json` — 8 rules
  - `reddit.com/user/Sundeepg98/about.json` — HTTP 404 (account does not exist)

---

*This document does not change code. It does not commit anything beyond itself.*
