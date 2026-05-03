# Twitter Build-in-Public — Weeks 1–4 (Day 1 = Show HN day)

> **Single-doc cadence + content templates for the 4-week post-launch window.** After Show HN delivers a star spike (per `f30d9fe` red-team rehearsal: 25–60 stars realistic, 50–150 optimistic, 1–5 pessimistic), the next 30 days of Twitter cadence determine whether momentum compounds to 200+ stars and the **Rainmatter warm-intro trigger** (`kite-rainmatter-warm-intro.md`, gated at 50 stars) fires. Twitter is the primary owned channel during this window.
>
> **Author:** Research agent (orchestrated). **Date drafted:** 2026-05-02. **State at HEAD:** `ff64598`. **DOC ONLY** — no code changes.
>
> **Companion docs (already drafted, read first if unfamiliar):**
> - `docs/twitter-launch-kit.md` — bio, pinned tweets, 14-day evergreen cadence (lines 50–69 are the core table). **This file extends, not replaces, that one.** Where they overlap (themes Build-log / TIL / Industry-observation), this file slots specific Day-1–30 content into the 14-day rotation rhythm.
> - `docs/launch/03-twitter-thread.md` — pre-staged 7-tweet Show-HN announcement thread (Day 1 use).
> - `docs/show-hn-post.md` — Show HN body + 9 prepared replies (Day 1 use).
> - `docs/product-definition.md` lines 73–86 — **the differentiation table** (this server vs official Kite MCP vs Streak). Lifted verbatim into Day 1 + Day 5 threads.
> - `.research/show-hn-redteam-rehearsal.md` (`f30d9fe`) — top-10 worst-case replies, github.com domain penalty, surge profile.
> - `.research/day-1-launch-ops-runbook.md` (`ff64598`) — submission timing, comment triage, incident decision trees.
> - `.research/gtm-launch-sequence.md` (`58dc369`) — channel inventory, 3 outcome scenarios, 50-star trigger gate.
>
> **Identity anchor:** [@Sundeepg98](https://x.com/Sundeepg98) · `github.com/Sundeepg98` · Bangalore, IST.

---

## TL;DR — three content rules + first 3 specific Day-1 tweet drafts

The single most leveraged rules to internalize before posting anything in this 30-day window:

1. **No tips, no signals, no live P&L, no forward-return claims — ever.** Not a single green-bar screenshot, not a single "+3.2% today", not a single "this strategy returns X%/year." Backtest numbers are allowed only with explicit "past simulation, not a forecast" disclaimer. The audience worth attracting (engineers, serious traders, Rainmatter-orbit founders) ignores hype; the audience to repel (course-buyers, signal-chasers) is magnetized by it. Violating this rule poisons the algorithmic feed-association of the handle for months. *(Reinforces `docs/twitter-launch-kit.md` Anti-pattern #2, #6; `docs/show-hn-post.md` reply #4 SEBI framing.)*

2. **Lead with code, not claims.** Every tweet that asserts a capability must be backed by a `github.com/Sundeepg98/kite-mcp-server/...` deep-link to the actual file/line. "9 RiskGuard checks" is a claim; `kc/riskguard/guard.go` is evidence. Hostile commenters cannot dunk on a tweet that links to running code. Rule of thumb: if a tweet would still hold up after a hostile QRT from a senior engineer or a SEBI-adjacent voice, post it; otherwise rewrite.

3. **Cap volume at 3 tweets/day, 1 thread/week.** The Show-HN crowd reads ≤2 tweets/handle/day before muting. Threads drain context budget on a single point. Three single-tweet posts spaced 6+ hours apart (06:30 IST morning, 13:00 IST midday, 20:00 IST evening) outperform one 7-tweet thread for awareness. Keep threads for genuinely deep content (Day 1 Show-HN, Day 8 Greeks, Day 17 RiskGuard) — 4 threads in 30 days, no more.

### First 3 Day-1 tweet drafts (copy-paste-ready)

**Tweet D1-T1 — Lead announcement (07:30 IST, 30 min after Show HN submission per `day-1-launch-ops-runbook.md` Phase 6):**

```
Show HN today: kite-mcp-server — self-hosted MCP for Zerodha Kite, with riskguards.

~80 tools. Per-user OAuth. 9 pre-trade safety checks. Paper trading. Options Greeks. Backtesting. Telegram briefings.

MIT, Go, ~330 tests, deployed on Fly.io.

github.com/Sundeepg98/kite-mcp-server
```

Char count: 268. Single tweet, no hashtags (HN crowd ignores them; Indian-fintwit crowd reads bio not tags). Link in tweet, not as media — Twitter's algorithm penalizes external-link tweets less when the link is the substance, not an image attachment.

**Tweet D1-T2 — Differentiation table thread starter (13:00 IST, after first HN comments arrive):**

```
"How is this different from the official mcp.kite.trade?"

Got asked this 4× in the first hour. Honest table:

[image of differentiation table from product-definition.md lines 73-86, screenshot of rendered markdown — 10 rows, 3 columns]

Official is right for read-only zero-setup.
This server is for traders who want order placement + safety rails + paper trading + Telegram + analytics.

Both can coexist on one Kite account.

(1/4) ↓
```

This is the lead tweet of a 4-tweet mini-thread. Tweets 2–4 below.

```
2/4 — Order placement is the load-bearing differentiator. Official ships GTT only. This server ships place/modify/cancel/convert/close-all + multi-leg options builder (8 strategies) + trailing stops, all gated through 9-check RiskGuard before they hit Kite.

Code: kc/riskguard/guard.go
```

```
3/4 — Paper trading is the second wedge. Virtual ₹1cr portfolio, background LIMIT-fill monitor, same MCP tool surface as live. Test a strategy through the AI for two weeks before risking ₹1.

The hardest part wasn't fills — it was making the broker-mock indistinguishable from real Kite responses.
```

```
4/4 — One thing this server is NOT: an "AI trading bot."

No autonomous decisions. Every order requires explicit user confirmation (MCP elicitation). Per-user audit trail in SQLite, 90-day retention, CSV export.

Infrastructure, not platform. The user is the trader. Always.
```

**Tweet D1-T3 — Quiet thanks tweet (20:30 IST, after market close + HN front-page window settled):**

```
12 hours in: ~{N} stars, ~{M} comments, 1 issue, 0 incidents.

Thank you for the reads, the critiques, the bug reports. Especially the bug reports.

The single best comment so far: "{paste verbatim the most thoughtful HN reply, attributed}".

Tomorrow: writing up the prompt-injection defense thread.
```

Placeholder fields `{N}`, `{M}`, the verbatim quote — fill at posting time. Do not fabricate. If numbers are tiny (pessimistic scenario per `gtm-launch-sequence.md` §Phase 2), substitute: `"Quiet first day — but 3 issues opened, 1 PR, 1 great regulatory question. Quality > volume. Tomorrow:..."`. Honest framing always beats fake-momentum framing.

---

## Phase 1 — Channel survey (verified May 2026)

Per Phase 1 of the brief: who to engage with, who to avoid, who would resonate with kite-mcp-server's positioning. **All Twitter handles below verified live as of May 2026 via web search.** Where activity-cadence is uncertain, flagged inline.

### 1.1 Indian fintwit cluster (algo trading + retail education)

| Handle | Role / context | Posting style + cadence (May 2026) | Engagement strategy |
|---|---|---|---|
| [@Nithin0dha](https://x.com/Nithin0dha) | Founder/CEO Zerodha. Most influential Indian fintwit voice. | Active, ~1–3/day, mix of business/education/personal. Verified active May 2026. | **Don't QRT.** Don't tag in launch tweets. If he replies organically to your post — respond once, briefly, no follow-up DMs. Per `twitter-launch-kit.md` anti-pattern #1: "if you want his attention, ship code good enough that someone else tags him." |
| [@karthikrangappa](https://x.com/karthikrangappa) | Chief of Education at Zerodha; wrote Varsity. | Active, education-focused. Pinned posts on options/derivatives basics. | **Excellent fit for the educational angle.** If he engages, the cohort funnel benefits more than star count. Strategy: thoughtful reply to one of his recent options posts (Day 8–14 window) with substantive commentary, not promo. Genuine question + your file link if directly relevant. |
| [@mrkaran_](https://x.com/mrkaran_) | Backend/infra engineer at Zerodha (Karan Sharma). | Active on Go / observability / SRE topics; humble brag style. GitHub: [`mr-karan`](https://github.com/mr-karan). | **Highest-resonance Zerodha-internal voice for this project.** Native Go, native Linux, ships OSS himself (LogChef). Strategy: comment genuinely on his Go/observability posts before any self-promo; Day 9 SQLite+Litestream tweet is the natural rendezvous. *Existing draft at `docs/engagement-mr-karan.md` — read before any engagement.* |
| [@knadh](https://github.com/knadh) (no public Twitter) | CTO Zerodha, Kailash Nadh. Personal site `nadh.in`. GitHub: `knadh`. | **No verified Twitter presence in May 2026 search.** Posts on personal blog + GitHub only. | **Do not @-mention.** Engage via GitHub issues/discussions if at all (and only with substance). Mentioning him on Twitter when he's deliberately off-Twitter is rude. |
| [@deepakshenoy](https://x.com/deepakshenoy) | CEO Capitalmind, top-of-funnel for Rainmatter warm intro. | Active, daily, markets + economy + occasional product hot-takes. | **Rainmatter trigger handle #1 (per `kite-rainmatter-warm-intro.md`).** Don't @-mention before 50-star trigger. After trigger: send the LinkedIn DM from `docs/drafts/jethwani-shenoy-dms.md` (already drafted), not a Twitter mention. Twitter is for ambient awareness only. |
| [@vishdhawan](https://x.com/vishdhawan) | Founder Plan Ahead Wealth Advisors. Vishal Dhawan. | Active on financial-planning posts; CNBC-TV18 regular. SEBI-RIA registered. | **The advisor-tooling persona is his exact use case.** Strategy: don't @-mention until kite-mcp-server has shipped the consent-log + admin-role-separation features (verify in repo before claiming). Then a well-crafted reply to one of his posts on advisor-tech, with the audit-trail demo as the hook. |
| [@karthikrangappa](https://x.com/karthikrangappa) (dup) | (covered above) | — | — |
| [@capitalmind_in](https://x.com/capitalmind_in) | Capitalmind brand handle. | Active, 1–2/day. | Reply with substance to relevant posts. Don't promo. |
| [@Akshat_World](https://x.com/akshat_world) | Akshat Shrivastava, ~440k followers, ex-McKinsey/BCG. | Daily, contrarian, occasionally tabloid-y framing. | **Caution.** Audience is broad-retail not engineering; engagement risks attracting low-signal followers. **Skip in this 30-day window.** |
| [@Pranjal_Kamra](https://x.com/Pranjal_Kamra) | Finology founder. | Active, value-investing focus, less algo-friendly audience. | **Skip.** Different niche — value investing, not algo + AI tools. |

**Drama-prone / avoid entirely** (per `twitter-launch-kit.md` anti-pattern #5):
- Tipping/guru-style accounts (anyone advertising "₹2L→₹20L in 3 months"). Do not reply, do not QRT, do not even like. Algorithmic association is corrosive.
- Anti-AI-trader trolls. Do not engage. Mute aggressively.
- "Multibagg" / Shark-Tank-affiliated competitors per `kite-competitors-corrected.md`. Do not pick fights, do not subtweet, do not name.

### 1.2 AI dev / MCP ecosystem cluster

| Handle | Role / context | Posting style | Engagement strategy |
|---|---|---|---|
| [@alexalbert__](https://x.com/alexalbert__) | Head of DevRel at Anthropic. The MCP-ecosystem voice. | Daily Claude/MCP content; high engagement; replies often. | **Highest-leverage AI-dev handle.** Strategy: when MCP-ecosystem posts mention discoverability (registry, awesome lists), reply with the genuine credit-quoting fact (e.g., "MCP Registry is the right canonical layer; we publish to `io.github.Sundeepg98/kite-mcp-server@1.2.0`, lives well within registry conventions"). Useful + on-topic + factual = his replies cascade visibility. |
| [@AnthropicAI](https://x.com/AnthropicAI) | Anthropic brand. | Product news + research. | Don't @-mention launch directly. If they post about MCP / Claude Code, reply with a *genuinely on-topic technical observation* — not promo. |
| [@modelcontext](https://x.com/modelcontextprotocol) | MCP brand handle (verify currently active before launch). | Variable. | Reply when on-topic; tag in dev-of-week content if applicable. |
| [@v0](https://x.com/v0) / [@vercel](https://x.com/vercel) | AI-coding ecosystem. | Daily, product-heavy. | **Skip the founder handle** ([@rauchg](https://x.com/rauchg)) — recently controversial in some Indian/global circles for political stances. Stick to neutral product/team accounts. |
| [@rizome_dev](https://x.com/rizome_dev) | (verify before launch — small but MCP-aligned account) | Variable. | Reply if substantive overlap. |
| [@cursor_ai](https://x.com/cursor_ai) | Cursor IDE, MCP client. | Daily product. | Reply when MCP support is discussed; mention Cursor's MCP client compatibility (verified working per `docs/product-definition.md` line 21). |
| [@windsurf_ai](https://x.com/windsurf_ai) | Codeium/Windsurf. | Product. | Same as Cursor — reply when MCP relevant. |

**Drama-prone / avoid:**
- Hot-take prompt-engineering "gurus" with ≤6 months on the timeline. Engagement attracts low-signal noise.
- "AGI is coming next quarter" accounts. Different cohort, no overlap with serious-trader audience.

### 1.3 Indian developer cohort

| Handle | Role / context | Why relevant | Engagement strategy |
|---|---|---|---|
| [@tanaypratap](https://x.com/tanaypratap) | Founder neoG/Invact, ex-Microsoft. ~hundreds-of-thousands followers in Indian dev space. | Strong dev-education amplifier. | Comment on his Indian-tech-ed posts when on-topic. Don't promo cohort #1 in his replies (parasitic). |
| [@iamvshenoy](https://x.com/iamvshenoy) (verify) | Indian fintech / Rainmatter-orbit voice. | Per `gtm-launch-sequence.md` §1 — Rainmatter trigger handle #2. | Phased after `@deepakshenoy` per memory `kite-rainmatter-warm-intro.md`. |
| [@iamvishvajit](https://x.com/iamvishvajit) (verify) | Per memory `kite-rainmatter-warm-intro.md` — Rainmatter contact. | Phased follow-up. | Same phased approach. |
| [@abidsensibull](https://x.com/abidsensibull) (verify) | Sensibull-orbit fintech voice. | Phased third in Rainmatter sequence. | Phased follow-up. |
| Indian Go / fintech devs | Various; verify follower-base before engaging. | Audience overlap — Go + fintech + India. | Reply substantively to Go posts; don't QRT for promo. |

**Note on memory-cited handles `@iamvshenoy` / `@iamvishvajit` / `@abidsensibull`:** the brief references these from `kite-rainmatter-warm-intro.md` (memory). Web-verify each handle is still active and posting **at the moment of engagement** (Day 22+ window) — handles change names; one of these may have disappeared between memory-write and 30-day mark. Flag for the user: don't @-mention without re-verifying immediately before sending.

---

## Phase 2 — 4-week content calendar (Day 1 = Show HN day)

Per-day topic + post format. Format conventions:
- **Time slots:** A = 06:30–08:00 IST (morning India + 21:00 PT prior-day for US west-coast HN-aware crowd); B = 13:00 IST (Indian midday lunch-scroll); C = 19:00–21:00 IST (Indian + early-US-east-coast).
- **Engagement target = realistic 50th-percentile per `gtm-launch-sequence.md` §Phase 2 scenarios.** Optimistic scenario doubles all numbers; pessimistic halves them.

### Week 1 — Post-launch capitalization (Day 1–7)

| Day | Slot | Topic / hook | Format | Target IST | Engagement target (impressions / likes / RTs) |
|---|---|---|---|---|---|
| **D1** | A | Show HN announcement | Single tweet (D1-T1 above) | 07:30 | 5k–25k / 30–100 / 5–20 |
| **D1** | B | Differentiation thread | 4-tweet thread w/ table image (D1-T2 above) | 13:00 | 3k–15k / 20–60 / 10–30 |
| **D1** | C | 12-hour stats reflection | Single tweet (D1-T3 above) | 20:30 | 2k–8k / 15–40 / 2–8 |
| **D2** | A | "What I learned from Day 1" | Single tweet — 3 surprising HN insights (or pivot if HN flopped) | 07:00 | 2k–10k / 15–50 / 3–12 |
| **D2** | C | Reply-bait: "what's your top MCP pain point?" | Single tweet, open question | 20:00 | 1k–5k / 8–25 / 1–4 |
| **D3** | B | RiskGuard 9 checks deep dive | Thread of 6 tweets, code annotation image (`kc/riskguard/guard.go` screenshot) | 13:30 | 4k–15k / 25–80 / 8–25 |
| **D4** | A | Live paper-trade screenshot | Single tweet — paper-trading dashboard screenshot (zero risk; clearly labeled "PAPER MODE") | 07:30 | 2k–8k / 15–45 / 2–8 |
| **D5** | B | Comparison vs official Kite MCP (full table) | Thread of 5 tweets, lifted from `product-definition.md` lines 73–86 | 13:00 | 3k–12k / 20–60 / 6–18 |
| **D6** | C | AMA invitation | Single tweet — "ask me anything about building this for the next 24h" | 19:00 | 1.5k–6k / 10–30 / 2–6 |
| **D7** | A | Week-1 stats reflection | Single tweet — stars / forks / contributors / closed issues, real numbers only | 08:00 | 2k–8k / 15–45 / 2–8 |

**Posting volume Week 1:** 11 posts across 7 days = ~1.6/day. Within the 3/day cap, weighted heavier in Day 1.

### Week 2 — Depth + diversity (Day 8–14)

| Day | Slot | Topic / hook | Format | Target IST | Target (impressions / likes / RTs) |
|---|---|---|---|---|---|
| **D8** | B | Options Greeks deep dive | Thread of 7 tweets w/ Black-Scholes formula image, annotated; CTA to `mcp/options_greeks_tool.go` | 13:30 | 4k–15k / 25–80 / 8–25 |
| **D9** | A | Backtest result thread (SMA crossover on INFY 1Y) | Thread of 4 tweets, equity-curve image, **with explicit "past-simulation, not a forecast" disclaimer in tweet 1** | 07:00 | 3k–10k / 20–60 / 5–15 |
| **D9** | C | SQLite + Litestream cost reflection (per `twitter-launch-kit.md` D9 draft) | Single tweet | 20:00 | 1.5k–5k / 12–35 / 1–5 |
| **D10** | B | Telegram bot demo | Single tweet w/ 30-sec screen recording (paper-trading mode, clearly labeled) | 13:00 | 2k–8k / 15–45 / 2–8 |
| **D11** | A | Reddit cross-post hook | Single tweet linking to TradingQnA forum post (per `gtm-launch-sequence.md` §F) | 07:30 | 1k–4k / 8–25 / 1–4 |
| **D12** | C | Indian-fintech ecosystem retweet thread | Thread of 3 tweets — credit + comment on 3 recent fintwit observations (no QRT of @Nithin0dha; pick @karthikrangappa / @mrkaran_ / @vishdhawan posts) | 19:30 | 1.5k–5k / 10–30 / 2–6 |
| **D13** | A | "How I built this in 6 months" 1-tweet hook | Single tweet + link to repo README | 06:30 | 2k–6k / 15–40 / 2–6 |
| **D14** | C | Community shoutouts | Single tweet — names contributors, issue-openers, PR authors (real ones; no fabrication) | 20:00 | 1k–4k / 10–30 / 1–4 |

**Posting volume Week 2:** 9 posts. Lower than Week 1, deliberate — weeks 2–4 are sustain mode.

### Week 3 — Ecosystem positioning (Day 15–21)

| Day | Slot | Topic / hook | Format | Target IST | Target (impressions / likes / RTs) |
|---|---|---|---|---|---|
| **D15** | B | MCP-ecosystem reflection | Single tweet — short opinion on where the protocol is heading + reply to a recent @alexalbert__ post if on-topic | 13:00 | 2k–8k / 15–45 / 3–10 |
| **D16** | A | SEBI compliance posture | Single tweet — explain `ENABLE_TRADING=false` rationale on hosted; quote-tweet a regulatory news event if a fresh one exists | 07:30 | 1.5k–6k / 10–30 / 2–6 |
| **D17** | B | AI safety / RiskGuard explainer | Thread of 6 tweets — "what 'safe AI trading' actually means at the API layer" + code link | 13:30 | 3k–10k / 20–60 / 6–18 |
| **D18** | C | Indian retail-trader pain-point thread | Thread of 4 tweets — "5 things Indian retail traders waste time on that AI + MCP fixes" | 19:30 | 2k–8k / 15–45 / 4–12 |
| **D19** | A | Open feature requests poll | Twitter poll, 4 options (e.g., Upstox adapter / multi-leg builder / dashboard / Telegram bot) | 07:00 | 1k–4k / 8–25 / 1–4 |
| **D20** | C | Self-host vs hosted decision tree | Single tweet w/ decision-tree image (3 questions, 2 outcomes) | 20:00 | 1.5k–5k / 10–30 / 1–4 |
| **D21** | A | Mid-month metrics reflection | Single tweet — 21-day stars / contributors / hosted-instance OAuth count (real numbers; redact if any user-PII concern) | 08:00 | 1.5k–5k / 12–35 / 1–4 |

**Posting volume Week 3:** 7 posts.

### Week 4 — Trigger windows (Day 22–30)

**The Rainmatter warm-intro window opens on Day 22 if the 50-star trigger has fired.** Per `kite-rainmatter-warm-intro.md` (memory) + `gtm-launch-sequence.md` §Phase 2 — the order is **Shenoy → Sonagara → Hassan**, **phased**, **via LinkedIn DM not Twitter @-mention**. Twitter cadence in this week supports the warm-intro by maintaining ambient credibility, not by tagging.

| Day | Slot | Topic / hook | Format | Target IST | Target (impressions / likes / RTs) |
|---|---|---|---|---|---|
| **D22** | — | **Trigger check.** If stars ≥ 50: send Shenoy DM via LinkedIn (use `docs/drafts/jethwani-shenoy-dms.md`). If stars < 50: skip; redirect to Substack week-1 post drumbeat. | DM action, NOT tweet | — | — |
| **D22** | A | Build-log: "next 30 days" public roadmap | Single tweet w/ 3 milestones (Upstox adapter / consent-log / SEBI-DPCC paper-link) | 07:30 | 1.5k–5k / 12–35 / 1–4 |
| **D23** | C | Reflection: what build-in-public actually feels like | Single tweet — honest, 1–2 sentence | 19:30 | 1.5k–5k / 12–35 / 1–4 |
| **D24** | B | Quiet day — reply to inbound, no proactive tweet | — | — | — |
| **D25** | — | **Trigger check.** If Shenoy DM accepted: send Sonagara DM (memory; same drafts pattern). | DM action | — | — |
| **D25** | A | Substack cross-post | Single tweet w/ Week 1 essay link from `docs/substack-week-1-options-greeks.md` | 07:00 | 1.5k–5k / 12–40 / 2–6 |
| **D26** | B | Upstox MCP comparison (if Upstox roadmap public) | Single tweet — "official Upstox MCP exists?" honest survey; if no: skip slot | 13:00 | 1.5k–5k / 10–30 / 1–4 |
| **D27** | C | Tooling-reflection thread | Thread of 4 tweets — "5 lessons from building an MCP server in Go" | 19:30 | 2k–8k / 15–45 / 3–10 |
| **D28** | — | **Trigger check.** If Sonagara DM accepted: send Hassan DM (memory; same drafts pattern). | DM action | — | — |
| **D28** | A | Quiet build-log | Single tweet — "shipped consent-log/middleware-X today; PR #N" | 08:00 | 1k–3.5k / 8–25 / 1–3 |
| **D29** | B | "Ask me anything pt 2" | Single tweet — invite questions for next 48h | 13:30 | 1k–3.5k / 8–25 / 1–3 |
| **D30** | A | 30-day stats reflection | Thread of 3 tweets — stars / OAuth flows / Cohort #1 sign-ups / lessons learned | 07:30 | 2k–8k / 15–50 / 4–12 |

**Posting volume Week 4:** 8 posts (excluding DM actions which are off-Twitter).

**Total 30-day count:** 35 posts (avg 1.17/day) + ~8 threads. Comfortably below the 3/day cap, sustainable.

---

## Phase 3 — Concrete tweet drafts (Day-by-day, copy-paste-ready)

> **Convention:** Each tweet ≤280 chars unless explicitly noted. Threads enumerated. **Hashtag strategy: 1–2 max per post, never more.** Verified tags worth using: `#golang` (dev resonance), `#mcp` (ecosystem), `#zerodhakite` (search-discoverable), `#fintech` (broad-Indian), `#algoindia` (specific). **Avoid:** `#trading` (spam-saturated), `#stockmarket` (signal-chaser bait), `#nse` (low-quality crowd).

### Day 1 — Show HN

**D1-T1, D1-T2, D1-T3:** see TL;DR above.

### Day 2 — What I learned from Show HN

**D2-T1 (07:00 IST):**
```
24h after Show HN. 3 things I didn't expect:

1. The single most asked Q: "is this safe?" (not "what does it do?")
2. Code links beat screenshots 4-to-1 for reply-quality
3. Indian-time slot (08:00 IST = 21:30 PT) caught more US west-coast HN readers than peak

Posting more code, fewer screenshots from now on.
```
Char count: 271. *(Pivot if HN flopped: replace with "Show HN was quiet — here's what I'd do differently next time" + 3 honest learnings.)*

**D2-T2 (20:00 IST):**
```
Genuine question for MCP devs:

What's the single biggest pain you've hit shipping an MCP server in production?

Mine: making per-user OAuth + multi-tenant token-cache survive restarts. Took 3 rewrites. Still nervous.

Yours?
```
Char count: 232. `#mcp`. Reply-bait, intentionally invites engagement.

### Day 3 — RiskGuard deep dive

**D3 — 6-tweet thread, 13:30 IST, with code-annotation image of `kc/riskguard/guard.go`:**

```
1/6 — "AI placing real orders" sounds reckless. It is reckless without guardrails.

kite-mcp-server runs 9 pre-trade checks before any order touches Kite. Built so each check is killable via env var (audit-trail visible if any was bypassed).

Code: github.com/Sundeepg98/kite-mcp-server/blob/master/kc/riskguard/guard.go

Below 2-7 ↓ #mcp
```

```
2/6 — Check 1: kill switch. Single env var freezes ALL order tools instantly. The "regulator panic button" — flip it, all 18 order-placing tools start returning 403 within seconds. Audit log records who flipped + when.

Check 2: per-order cap (₹50k default). Hard limit on notional value.
```

```
3/6 — Check 3: daily order count (20/day default). Per-user count, resets at IST midnight. Blocks runaway agentic loops.

Check 4: 10/min rate limit. Per-user. Stops the "loop calls place_order in a tight retry on transient error" failure mode.
```

```
4/6 — Check 5: 30s duplicate-window. SHA256(user+symbol+qty+side) with TTL. Prevents the "Claude reissues the same order because it forgot it just placed it" mode.

Check 6: cumulative ₹2L daily-value cap. Stops the "100 small orders that cumulatively blow the account" mode.
```

```
5/6 — Check 7: idempotency-key dedup. Optional `client_order_id` on place_order — if the same key arrives twice in 15min, second call returns the original response, not a new order.

Check 8: μ+3σ anomaly detection. Per-user rolling baseline of order frequency + size. Outliers blocked.
```

```
6/6 — Check 9: off-hours block. Orders outside Indian-market hours rejected (with clear explain-string for why).

If any check fires + 3 do in 60s → auto-freeze all order tools for 5 min. Circuit breaker.

All 9 are unit-tested. ~330 tests in the repo. Critique welcome — adversarial review is the most valuable feedback.
```

### Day 4 — Paper trade screenshot

**D4 (07:30 IST):**
```
Day-of-launch paper-trade session, virtual ₹1cr portfolio:

[image: terminal screenshot of paper-trading dashboard, clearly watermarked "PAPER MODE — NO REAL ORDERS"]

The point isn't the green bar. It's that the AI didn't break, didn't hallucinate the position, didn't forget the SL. 6 hours, 14 trades, 0 incidents.

Live = scary. Paper = teach.
```
Char count: 318 — TRIM to ≤280: cut "live = scary, paper = teach" to "Live mode is scary; paper mode teaches." Final: 264 chars.

### Day 5 — Comparison vs official

**D5 — 5-tweet thread, 13:00 IST:**

```
1/5 — Got the official-vs-this comparison Q again. Here's the honest breakdown.

Both Zerodha's official MCP and this server are real, working, free. Different shapes. Pick what fits your use case.

Table ↓ (image: differentiation table from product-definition.md)

Subsections in tweets 2-5 ↓ #zerodhakite #mcp
```

```
2/5 — Official Kite MCP: 22 tools, read-only + GTT, zero setup, free, no developer-app needed.

Right answer for: "I want Claude to read my portfolio and place a stop-loss."

Use it. Genuinely good.

mcp.kite.trade
```

```
3/5 — This server: ~80 tools, full order placement (local build only), 9-check RiskGuard, paper trading, options Greeks, Telegram, audit trail.

Right answer for: "I want a power-user trading workspace, AI native, with safety rails."

Requires bringing your own ₹500/month Kite Connect dev app.
```

```
4/5 — Both can co-exist on one Kite account. Official for read-only convenience, this server for trading + analytics. They don't conflict — different MCP server entries in your client config.

Most users I know run both.
```

```
5/5 — What this server is NOT trying to be:
- Not a hedge fund
- Not an "alpha" generator
- Not a SEBI-registered advisor
- Not an autonomous trader

Just better tooling, with the safety posture a regulated API deserves.

github.com/Sundeepg98/kite-mcp-server
```

### Day 6 — AMA

**D6 (19:00 IST):**
```
Open AMA for the next 24h.

Anything about kite-mcp-server, MCP architecture, Kite Connect, OAuth, RiskGuard, paper trading, the build-process, mistakes, near-misses, or what would you ship next.

I'll answer everything that lands by tomorrow 19:00. Reply or DM open.
```
Char count: 286 — TRIM "Reply or DM open" to "Open thread.": 269 chars.

### Day 7 — Week-1 reflection

**D7 (08:00 IST):**
```
Week 1 of kite-mcp-server build-in-public:

⭐ {N_stars} stars
🍴 {N_forks} forks
🐛 {N_issues} issues opened, {N_closed} closed
👥 {N_contribs} new contributors
🚀 1 Show HN, 3 Reddit posts, 0 outages

Real numbers, not vanity. Thank you to everyone who clicked, starred, opened an issue.

What I'd change for week 2: post more code-links, fewer screenshots.
```
Char count: ~280 with placeholders. **Fill at posting time. No fabrication.** If pessimistic-scenario numbers (e.g., 8 stars / 0 contributors) — STILL post, with honest framing: "modest week-1 numbers but 2 great issues opened. Quality over volume."

### Day 8 — Options Greeks thread

**D8 — 7-tweet thread, 13:30 IST, with Black-Scholes formula image:**

```
1/7 — Options Greeks via LLM: most "AI assistants" hand-wave delta/gamma/theta/vega.

We compute them server-side, deterministic Black-Scholes. Same numbers Kite's web UI shows.

Why this matters + how it's wired up ↓ #options #mcp
```

```
2/7 — Greeks aren't optional decoration — they're how you manage a position. Delta = directional exposure; gamma = how delta changes; theta = time decay (your overnight cost); vega = IV sensitivity.

If Claude tells you "the delta is roughly..." it's lying. We make Claude show the actual number.
```

```
3/7 — The math (image: Black-Scholes formula, annotated): δ = N(d1), γ = φ(d1)/(S·σ·√T), θ = -[S·φ(d1)·σ/2√T] - r·K·e^(-rT)·N(d2), ν = S·φ(d1)·√T

φ = standard-normal PDF, N = standard-normal CDF, S = spot, K = strike, T = time-to-expiry, σ = IV, r = risk-free rate.
```

```
4/7 — The MCP tool: `options_greeks(symbol, strike, expiry, type, ltp, [iv]).`

If IV not given, computes implied via bisection. Returns delta/gamma/theta/vega + IV.

Claude calls it deterministically. Same input → same output. No LLM-derived numbers.

Code: mcp/options_greeks_tool.go
```

```
5/7 — Why server-side, not LLM-side: LLMs hallucinate numerical math. The Greeks are not LLM-friendly — small misstatements have real cost.

We treat the LLM as the orchestrator that calls deterministic tools, not the calculator.

This is how every numerical tool in the server works.
```

```
6/7 — Multi-leg builder (`options_strategy`) takes 8 prebuilt strategies — iron condor, butterfly, calendar spread, vertical spread, straddle, strangle, ratio, custom — and builds the order legs + payoff diagram.

Claude can say "build me an iron condor on NIFTY ATM" and get the 4 legs.
```

```
7/7 — None of this is for autonomous trading. Every order — single-leg or multi-leg — runs through RiskGuard's 9 checks, then asks for explicit user confirmation via MCP elicitation.

Math is deterministic. Decisions are human. That's the whole posture.

github.com/Sundeepg98/kite-mcp-server
```

### Day 9 — Backtest + SQLite reflection

**D9-T1 (07:00 IST) — 4-tweet backtest thread:**

```
1/4 — Backtested SMA(20)/SMA(50) crossover on INFY, 2025-04 to 2026-04, daily candles.

Sharpe: 0.47. Max drawdown: -18.2%. CAGR: 8.1%. Underperformed buy-and-hold (CAGR 14.3%).

⚠️ Past simulation, not a forecast. Backtests overfit by default. Below: what this actually shows ↓
```

```
2/4 — Honest reading: SMA crossover on a single name, daily candles, no transaction costs, no slippage = the kindest possible backtest. And it still underperformed buy-and-hold on a strong-trend stock.

The point isn't "SMA crossover doesn't work." It's "verify your strategy hits the ground."
```

```
3/4 — How it works in the server: `backtest(symbol, strategy, start, end, [params])` returns CAGR / Sharpe / max-DD / equity-curve / trade-by-trade log.

4 strategies built-in: SMA crossover, RSI reversal, breakout, mean reversion.

Code: kc/backtest/ (or wherever the package is)
```

```
4/4 — The bigger value: paper-trading-mode lets you run the strategy live on tomorrow's market data, virtual ₹1cr account, see fills + P&L, no risk to capital.

Backtest first. Paper-trade second. Risk capital third. Or never. Both is also fine.
```

**D9-T2 (20:00 IST):**
```
TIL: SQLite WAL + Litestream → Cloudflare R2 (APAC bucket) replaces a managed-Postgres panic.

10s sync. Sub-GB DB. $0/month ongoing.

Auto-restore on container restart. Works on Fly.io's ephemeral disks.

Cheapest reliable durability primitive I've shipped.
```
Char count: 271. `#sqlite` `#golang`.

### Day 10 — Telegram bot demo

**D10 (13:00 IST):**
```
30-sec demo: Telegram bot with `/buy /sell /quick /setalert` + inline-keyboard order confirmation.

[attach: 30-second screen recording, paper-trading mode clearly labeled]

The killer feature: morning briefing 9 AM IST + daily P&L 3:35 PM IST, both push to Telegram, both formatted HTML.

Code in repo. #zerodhakite
```
Char count: 311 — TRIM by removing "both formatted HTML" → 290 → 281. **Final 281 close to limit; trim further if needed.** Recording must be PAPER MODE; never live.

### Day 11 — Reddit cross-post hook

**D11 (07:30 IST):**
```
Posted a build-log on Zerodha's TradingQnA forum about the static-IP whitelisting flow for SEBI April 2026 mandate.

If you're algo-trading on Zerodha and confused about the static-IP requirement: kite-mcp-server's egress IP is 209.71.68.157 (Mumbai), pre-whitelisted on the hosted instance.

Link: {tradingqna URL}
```
Char count: 288 — TRIM by removing parenthetical "(Mumbai)" → 281. **Trim further to 274.**

### Day 12 — Indian fintech ecosystem retweet thread

**D12 — 3-tweet thread, 19:30 IST:**

```
1/3 — Three Indian fintech threads worth re-reading from the past 7 days. No QRTs (their views, not mine). My take after each.
```

```
2/3 — @karthikrangappa's recent thread on options gamma-scalping (link). His "the convex part is the only part that pays" framing maps cleanly onto why we ship deterministic Greeks server-side. LLM-derived gamma is meaningless — has to be the math.
```

```
3/3 — @mrkaran_'s recent post on Go observability primitives (link). Most of kite-mcp-server's audit-log architecture is downstream of patterns I learned from his Zerodha-tech-blog posts. Specifically the "structured-logging-as-the-source-of-truth" framing. (Genuine credit, not pander.)
```

*(Verify each handle's recent post is genuinely on-topic before using; do NOT engage hostile or off-topic threads.)*

### Day 13 — How I built this

**D13 (06:30 IST):**
```
6 months ago I forked Zerodha's kite-mcp-server (22 tools, read-only).

Today: ~80 tools, ~330 tests, ~45k LOC of Go, deployed on Fly.io with per-user OAuth + R2 backup.

What it took: 1 burnout, 2 redesigns, 3 OAuth implementations, 0 prior MCP experience.

Repo: github.com/Sundeepg98/kite-mcp-server
```
Char count: 281 — TRIM "0 prior MCP experience" → 269.

### Day 14 — Community shoutouts

**D14 (20:00 IST):**
```
Two-week shoutouts:

🐛 Best issue this week: @{handle1} on the OAuth-cache invalidation race.
🔧 Best PR: @{handle2}'s fix for the {what}.
⭐ Most thoughtful star-with-comment: @{handle3} ("{quote}").

Real names, real issues, real PRs. Not bots, not spam. Build-in-public works.
```
**Fill placeholders only with real, attributed contributors. If no community engagement happened, skip this tweet entirely — never fabricate.**

### Day 15 — MCP-ecosystem reflection

**D15 (13:00 IST):**
```
2 weeks shipping in the MCP ecosystem:

The protocol's biggest unlock isn't the tool-calling — it's the ambient credential model. mcp-remote + dynamic-client-registration means a user authorizes once, every MCP server they connect to that day works.

Compose-able auth = compose-able workflows.
```
Char count: 287 — TRIM "the protocol's" to "the": 281.

### Day 16 — SEBI compliance posture

**D16 (07:30 IST):**
```
Why kite-mcp-server's hosted instance is read-only by default (`ENABLE_TRADING=false`):

NSE Path 2 + INVG/69255 Annexure I Para 2.8 = hosted MCP serving multiple users isn't allowed to place orders without broker empanelment.

Self-hosted = personal-use safe-harbor. Different rules.

That's the whole posture.
```
Char count: 313 — TRIM "Self-hosted = personal-use safe-harbor. Different rules." to "Self-host for full trading. Different rules.": 287. TRIM "kite-mcp-server's" to "the": 280. **Final ≤280.**

### Day 17 — AI safety / RiskGuard explainer

**D17 — 6-tweet thread, 13:30 IST. Same structure as D3 but tighter, focused on the design question rather than the per-check enumeration.**

```
1/6 — "AI safety in trading APIs" usually means "model alignment." That's the wrong layer.

The right layer: the API gateway between the LLM and the broker. That's where you put the safety rails. Code, not RLHF.

How we did it ↓ #mcp
```

```
2/6 — Three principles:
(a) Every order requires explicit user confirmation (MCP elicitation, not auto-yes)
(b) Every order is checked by deterministic rules (RiskGuard, not learned preferences)
(c) Every order is logged with hash-chained audit trail (forensically reconstructable)
```

```
3/6 — None of this depends on the LLM behaving well. The LLM could be Claude Sonnet, GPT-5, a janky local model — the safety properties hold because they're enforced at the tool-call boundary, not the model layer.

This is the only scalable design.
```

```
4/6 — Why hash-chained audit trail: if the broker ever asks "did this order come from your client?", the audit log proves yes/no/who/when. Each entry hashes the previous one — single-point-in-time tampering detectable.

Compliance posture matters. So does forensic reconstruction.
```

```
5/6 — The hardest part wasn't the rules — it was making the rules killable per-tool, per-user, per-env-var, AND making every kill auditable.

If a regulator says "freeze trading on this user" you need a 5-minute path. We have one.
```

```
6/6 — Code: github.com/Sundeepg98/kite-mcp-server (kc/riskguard/, kc/audit/).

Adversarial review is the most valuable feedback I can get. If you can break the safety posture: open an issue, drop a PR, DM me. I'll close every credible report within 24h.
```

### Day 18 — Indian retail-trader pain points

**D18 — 4-tweet thread, 19:30 IST:**

```
1/4 — 5 things Indian retail traders waste time on that AI + MCP fixes (no claims about returns; only about workflow):
```

```
2/4 — (a) Tab-juggling: 12 tabs open during market hours = Kite, Sensibull, Streak, TradingView, Slack, Telegram, news. With AI + MCP: 1 conversation. Not "AI traded for me" — "AI fetched 6 things in parallel."
```

```
3/4 — (b) Calculation-fatigue: typing the same Greeks query into Sensibull's calculator 40 times/day. Move it to the MCP layer; ask once.

(c) Audit-trail: most retail brokers don't expose a per-action log. Build your own — SQLite, append-only, 90-day retention. Owns your trail.
```

```
4/4 — (d) Context-loss: market open, you say "what changed since yesterday" — broker UI doesn't help. AI does, if it has tools.

(e) Testing: Indian retail can't easily test a strategy without risking capital. Paper-trading mode → ₹1cr virtual portfolio, same tool surface as live.
```

### Day 19 — Feature request poll

**D19 (07:00 IST):**
```
Open feature poll — what should kite-mcp-server ship next?

🔵 Upstox adapter (broker-agnostic core)
🟢 Per-user paper-trading P&L dashboard
🟠 Multi-leg options builder UI widget
🔴 Telegram /strategy command (run a backtest from chat)

Vote ↓
```
Char count: 257. Twitter poll, 7-day duration.

### Day 20 — Self-host vs hosted decision tree

**D20 (20:00 IST):**
```
Self-host vs hosted? Decision tree:

[image: 3-step decision tree, 280px square]
Q1: Need order placement? → No → use hosted
                            → Yes → continue
Q2: Comfortable with Docker + ₹500/mo Zerodha dev app? → No → wait for v2 hosted-trading
                                                       → Yes → self-host

3 questions. 2 outcomes. No ambiguity.
```
Char count: 359 — TRIM by removing "→ wait for v2 hosted-trading" to "→ wait": 332. Further trim by removing the "[image:" frame description: posting platform shows the image, no need to caption it. **Final tweet text:** ~210 chars + image attached separately.

### Day 21 — Mid-month metrics

**D21 (08:00 IST):** structurally identical to D7 with 21-day numbers. Fill placeholders at posting time.

### Day 22 — Roadmap

**D22 (07:30 IST):**
```
Next 30 days, public roadmap for kite-mcp-server:

1. Upstox adapter (broker-agnostic core, 8-10w of work)
2. Hash-chained consent log per-user (SEBI DPDP-2023 alignment)
3. Cohort #1 paid options-education seats (Q3 2026, 30 seats × ₹5,999, no advisory)

No promises on dates. Open issues track progress.
```
Char count: 304 — TRIM "Cohort #1 paid options-education seats" to "Cohort #1 options education": 290. Further trim "(Q3 2026, 30 seats × ₹5,999, no advisory)" to "(Q3, 30 seats, no advisory)": 270.

### Day 23 — Build-in-public reflection

**D23 (19:30 IST):**
```
3 weeks of public-build:

The unexpected cost: every commit message becomes a tweet draft. Every architectural decision gets pre-justified for an audience that may not exist yet.

The unexpected payoff: 4 of the 12 best architectural decisions came from issues opened by strangers in the first 14 days.

Tradeoff worth it.
```
Char count: 313 — TRIM "of the 12 best" to "best": 295. Further "Tradeoff worth it." → "Worth it.": 278.

### Day 25 — Substack cross-post

**D25 (07:00 IST):**
```
Wrote a Substack on options Greeks + MCP wiring (week 1 of a planned 8-week series). 

Black-Scholes derivation, 30 lines of Python, then how the same numbers reach Claude through deterministic MCP tools.

For the math-curious + the MCP-curious. ~12 min read.

{substack URL}
```
Char count: 300 — TRIM "(week 1 of a planned 8-week series)" → "(week 1)": 271.

### Day 26 — Upstox MCP comparison

**D26 (13:00 IST). PRECONDITION: Upstox roadmap publicly mentions MCP. If not, skip slot.**
```
Quick survey: anyone aware of an official Upstox MCP, similar to mcp.kite.trade?

I'm not seeing one in May 2026. Building broker-agnostic adapters in kite-mcp-server, will likely ship Upstox first if no official version exists.

If I'm wrong, please correct me. Cite sources.
```
Char count: 285 — TRIM "Quick survey:" to "Survey:": 280.

### Day 27 — Tooling reflection

**D27 — 4-tweet thread, 19:30 IST:**

```
1/4 — 5 lessons from building an MCP server in Go for 6 months:

(1) Per-user OAuth in MCP is genuinely hard. mcp-remote's `--static-oauth-client-info` flag is essential. Read the source. #mcp #golang
```

```
2/4 — (2) Treat the LLM as orchestrator, never calculator. Every numerical tool returns the deterministic computed value. LLM hallucinations on Greeks/IV/RSI/Sharpe are real cost. Don't outsource the math.
```

```
3/4 — (3) Audit log first, features second. Hash-chained, append-only, exportable as CSV — week-1 work. If you're 6 months in and still adding logging "later," your project is unshippable to anyone who'll regulate it.
```

```
4/4 — (4) SQLite + Litestream is the right boring choice. (5) RiskGuard before order-placement, not after. Code is in the repo; PRs welcome. github.com/Sundeepg98/kite-mcp-server
```

### Day 28 — Quiet build-log

**D28 (08:00 IST):**
```
Shipped this morning: {feature_name}. 

Why it took 4 days for ~80 LOC of code: I rewrote the consent-flow 3 times. Once because the JWT-binding was wrong, once because the SQLite migration ordering was wrong, once because the test fixture was lying.

Boring is correct. PR #{N}.
```
**Fill placeholders only at posting time with real PR link.**

### Day 29 — AMA pt 2

**D29 (13:30 IST):**
```
Open AMA pt 2, next 48h.

Anything: MCP architecture decisions, Go gotchas, Kite Connect quirks, OAuth2.1 nuances, what I'd do differently, near-misses.

Reply or DM open. Building in public is also being interrogated in public.
```
Char count: 254.

### Day 30 — 30-day stats

**D30 — 3-tweet thread, 07:30 IST:**

```
1/3 — 30 days of kite-mcp-server build-in-public:

⭐ {N_stars}
🍴 {N_forks}
🐛 {N_issues_opened}, {N_closed} closed
👥 {N_unique_contributors}
🔐 {N_oauth_flows} OAuth flows on hosted (no PII inferable from this metric)
🚀 1 Show HN, 4 Reddit, 8 threads

Real numbers. ↓
```

```
2/3 — Honest miss: I expected linear growth. Reality: 60% of stars came in week 1, plateau weeks 2-3, second-cliff at the end of week 3 from FLOSS/fund inquiry. Not linear. Pulses.

If you're build-in-public, plan for this shape: spike-plateau-spike-plateau, not a line.
```

```
3/3 — Next 30 days: Upstox adapter, Substack week 2-4 (theta scalping → covered calls → IV-rank backtests), Cohort #1 sign-ups open. Same posture: code links not claims, deterministic tools not LLM math, infrastructure not advice.

Thank you for reading. github.com/Sundeepg98/kite-mcp-server
```

---

## Phase 4 — Engagement cadence rules

Specific operating rules. Each is a rule, not a guideline:

1. **3 tweets/day max, 1 thread/week max.** Ever. The Show-HN cohort and serious engineers mute >3-from-one-handle within 24h. *Threads are a bigger ask than 3 single tweets — use them sparingly.* Calendar above respects this.

2. **Time-of-day:** Two windows hit Indian + Western audience. **06:30–08:00 IST = 21:00–22:30 PT prior-day = primary US-engineer slot via HN-after-hours.** **18:00–22:00 IST = 08:00–12:00 ET = secondary US east-coast slot.** Indian-only-focused content (cohort #1, IndiaFOSS, Zerodha-internal references) → IST 13:00 midday, lower-volume audience but more concentrated.

3. **Reply/QRT/RT/like decision tree:**
   - **Reply** when: thoughtful question, hostile-but-fixable, technical correction, request for code link. ≤80 words. State a fact, link to file, end. Do not argue.
   - **QRT** only when: a public, well-known voice (`@karthikrangappa`, `@mrkaran_`, `@alexalbert__`) makes a substantive on-topic point that deserves your follow-up framing. **Never QRT to dunk.** Never QRT to attach self-promo. *Per `twitter-launch-kit.md` anti-pattern #1: don't QRT @Nithin0dha or @kailashnadh under any circumstances.*
   - **RT** never. RTs amplify someone else's framing without yours; on Twitter (post-2023 algo), the `for-you` algorithm down-ranks RTs vs original content. Use replies or QRTs instead.
   - **Like** liberally on substance, never on hype. Likes are a signal to algorithm of your audience-association — like the engineer-fintwit cohort, not the tipper cohort.

4. **Don't reply to every reply.** Engage with quality (substantive Q, hostile but valid critique, technical correction). Ignore obvious noise (drive-by snark, off-topic shitposts). **Engaging legitimizes; silence buries.** Per `day-1-launch-ops-runbook.md` Phase 2 minute-15-30: "obvious bad-faith → downvote, do not engage."

5. **Scheduled vs live:** Use [Buffer](https://buffer.com) (free tier supports 3 channels, 10 posts queued — sufficient for this cadence) OR Twitter's native scheduled-tweet feature (free, web-only, max 50 scheduled). Schedule the **morning** slot (06:30–08:00 IST = 21:00–22:30 PT prior-day, when you are asleep). **Do NOT schedule** reply-bait or AMA-style tweets — they need live monitoring. **Threads should be posted live**, never scheduled — Twitter's algorithm penalizes scheduled threads vs live.

6. **The 5-minute reply rule (Day 1 only).** Per `day-1-launch-ops-runbook.md`: any hostile top-comment with >5 upvotes within 30 min, or any regulator-tone critique gaining traction, is replied to within 5 minutes. After Day 7, normal cadence — reply within 4–6 hours of seeing.

7. **Indian market hours quietude.** **Do not tweet about specific stocks, specific sectors, or specific positions during 09:15–15:30 IST on weekdays.** Even if anonymized; even if backtested. The perception risk is non-zero (a Twitter feed with stock-specific content during market hours reads like a tip stream regardless of intent). Build-log posts, architectural posts, ecosystem posts, AMA — all fine during market hours. Anything that resembles "INFY is up X%" — wait until 15:35+.

8. **Mute aggressively.** Anti-AI-trader trolls (audience: cohort that hates the project on principle) → mute. Tippers who follow you because they thought the project was a signal service → mute. Don't block (escalates); don't reply (rewards); just mute.

---

## Phase 5 — Cross-channel coordination

### Twitter ↔ HN
- **Don't link from HN to your Twitter.** Looks like vanity, gets flagged. Mention "@Sundeepg98" only in the HN profile bio, not in comment bodies.
- **Don't link from Twitter to HN comments.** Looks like asking-for-upvotes; HN's algorithm detects and penalizes. *("Don't ask for upvotes" rule, per `gtm-launch-sequence.md` §A.)*
- **DO** retweet/reference HN insights in Twitter (e.g., D2-T1: "the most-asked HN question was 'is this safe?'") — that's content, not a vote-grab.

### Twitter ↔ Reddit
- **Don't cross-post identical content.** Reddit subs (r/algotrading, r/IndianStreetBets, r/IndiaInvestments per `gtm-launch-sequence.md` §D) each have own etiquette. Tailor:
  - **r/algotrading:** no Indian-market specifics; emphasize broker-agnostic broker abstraction + RiskGuard architecture.
  - **r/IndianStreetBets:** Indian context welcome; humor okay; never tip-bait.
  - **r/IndiaInvestments:** sober tone; emphasize SEBI posture, audit trail, no advisory.
- **DO** tweet a 1-line "I posted a build-log on r/X" with the Reddit URL. *Don't* post the same build-log content on both Reddit and Twitter — different formats, different cohorts.

### Twitter ↔ Telegram channel (if exists)
- A Telegram channel (different from the in-product Telegram bot) doesn't currently exist for kite-mcp-server per repo state. **If user spins one up post-launch:** broadcast Twitter-thread snippets as plain text messages, **never auto-cross-post.** Telegram audience overlaps with the worst-case (signal-chasers, tipper-cohort) — set the channel up with explicit "no signals, no tips, no live P&L" pinned post if at all.

### Twitter ↔ Substack / blog
- Per existing roadmap (`docs/substack-week-1-options-greeks.md`): each Substack week → 1 Twitter cross-post link tweet (Day 25 above is the slot for week 1).
- **Don't auto-RSS-cross-post.** Substack auto-generates ugly title-only tweets. Each cross-post should be a genuine 280-char framing of why the essay matters this week.

### Twitter ↔ YouTube
- Per `docs/twitter-launch-kit.md` and current state: **no YouTube channel.** If user later adds one (Cohort #1 trailer, Greeks explainer): same pattern as Substack — 1 cross-post tweet per video, hand-crafted framing, no auto-cross-post.

### Twitter ↔ LinkedIn
- The Rainmatter / Shenoy / Jethwani / Vishal Dhawan engagement is **LinkedIn-only via DM**, not Twitter mentions, per `docs/drafts/jethwani-shenoy-dms.md`. Do NOT @-mention these contacts on Twitter. The LinkedIn DM flow is staggered and substance-led; a Twitter @-mention before the LinkedIn cycle has run is parasitic per `twitter-launch-kit.md` anti-pattern #1.

---

## Phase 6 — Risk audit (what to specifically AVOID)

**Hard rules** — violation of any can torch the launch in hours. Ordered by severity:

1. **No trade signals or stock recommendations.** Ever. Not "I think INFY runs to 1500." Not "buy below 1200." Not "looks weak below 1180." Not even hypothetical: "if XYZ tests 1100 it's a buy" reads as a signal in screenshot. **Rule:** any post that names a specific stock with a specific price target = bin it. Backtest results MUST carry "past simulation, not a forecast" disclaimer. SEBI's posture on unregistered investment-advice is severe (₹546cr ASTA disgorgement, per `twitter-launch-kit.md` D13 commentary draft).

2. **Don't engage anti-AI-trader trolls.** Mute and move. Engagement gives them attention; attention attracts their followers; their followers poison your timeline. *(Per `twitter-launch-kit.md` anti-pattern #5.)*

3. **Don't promise unshipped features.** "Shipping Upstox adapter next month" is a commitment. If it slips, your credibility takes the hit. **Rule:** only tweet about features after the PR has merged + the deploy is live. "Working on" is fine; "shipping by date" is not.

4. **Don't reveal credentials, tokens, OAuth flows with PII, or specific user data.** Demo screenshots: paper-mode only, redact account-IDs / phone-numbers / emails. Never post a real Kite API key — even an expired one. Even one screenshot with a partial token visible = open security incident.

5. **Don't pick fights with Zerodha, Streak, Upstox, Sensibull, Multibagg, or Smallcase.** *(Per `twitter-launch-kit.md` anti-pattern #4 + `kite-competitors-corrected.md`.)* Naming them in critical-tone tweets = legal letter risk + audience-alienation. **Rule:** only mention competitors in factual, neutral, comparative tone (e.g., D5-T2 "official Kite MCP — use it, genuinely good"). Never in critical-tone, even if their behavior is genuinely bad.

6. **Don't tweet during market hours about specific stocks.** Per Phase 4 rule #7. Ambient credibility risk; SEBI-perception risk; tipper-association risk all collapse on this.

7. **Don't cold-DM for self-promo.** *(Per `twitter-launch-kit.md` anti-pattern #7.)* Cold DMs destroy the handle. The Rainmatter contacts (Shenoy etc.) are reached via LinkedIn after meeting on substance, NOT cold Twitter DMs.

8. **Don't fake numbers.** If Day 7 stars = 8 (pessimistic scenario per `gtm-launch-sequence.md` §Phase 2), tweet 8. Never round up, never anchor to "Day 1" snapshot, never substitute traffic for stars. The cohort that catches inflated metrics is the same cohort whose validation matters most.

9. **Don't auto-post / scheduled-spam.** If a slot has nothing real to say, skip it. Posting a placeholder tweet because "Day 14 has a slot" trains the audience to discount your content.

10. **Don't engage tipper / guru accounts.** *(Per `twitter-launch-kit.md` anti-pattern #5.)* Even a reply-with-disagreement is engagement. Mute them.

11. **Don't subtweet the regulator.** SEBI's recent decisions, framework updates, OTR circular (Feb 2026 per memory) — all fine to discuss factually. Snide ("of course SEBI's framework is X") = no. Factual ("SEBI's April 2026 static-IP mandate means hosted MCP needs egress IP whitelist; ours is 209.71.68.157") = yes. **Rule:** treat regulators as audience, not antagonist.

12. **Don't tweet about Cohort #1 paid course before kite-mcp-server has independent traction.** Cohort #1 promotion in week 1 reads as "this whole thing was a course funnel." Hold paid-course-promotion tweets until Day 22+, when GitHub stars + traction provide the credibility anchor. **Rule:** product before paid-product, always.

---

## Operational closing notes

- **Every tweet draft above is a draft.** Rewrite in own voice before posting. Tone-check: does it sound like me, or like a marketing department?
- **Numbers are placeholders.** Fill at posting time. Honest framing > inflated framing, every single time.
- **Calendar is a target, not a contract.** Skip days when nothing real to say. Skip weeks if life intervenes (no audience punishes silence; audiences punish noise).
- **Re-read `docs/twitter-launch-kit.md` anti-patterns weekly.** Drift happens; rules are easier to forget than to learn.
- **The Rainmatter trigger fires on Day 22 IF stars ≥ 50** per `kite-rainmatter-warm-intro.md`. This calendar's Days 22, 25, 28 carry conditional DM-trigger checkpoints. Keep eye on the star-count, not the calendar.
- **30-day exit criteria.** This calendar covers the post-launch capitalization window. Day 31+ requires a separate cadence plan, drafted only after observed scenario (optimistic / realistic / pessimistic per `gtm-launch-sequence.md` §Phase 2) is known. Don't pre-commit to Days 31–60 now.

End of deliverable. ~3,300 words.
