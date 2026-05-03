# Go-to-Market Launch Sequence — kite-mcp-server

**Status:** Research deliverable — concrete launch plan from 0 → 50+ stars (Rainmatter-warm-intro trigger).
**Last updated:** 2026-05-02
**Author:** Research agent (orchestrated)
**Reference docs verified:** `docs/show-hn-post.md`, `docs/twitter-launch-kit.md`, `docs/reddit-buildlog-posts.md`, `docs/kite-forum-replies.md`, `docs/launch/01..05`, `docs/drafts/{foss-united-grant-email,indiafoss-2026-cfp,jethwani-shenoy-dms,vishal-dhawan-dms,zerodha-compliance-email}.md`, `docs/floss-fund-proposal.md`, `docs/rainmatter-onepager.md`, `docs/launch-materials.md`, `docs/blog/oauth-13-levels.md`, `docs/product-definition.md`, `server.json`, `smithery.yaml`, `funding.json`.
**Repo state checked:** `master` clean against `origin/master` at `75aa284`; ~50 untracked `.research/*-msg.txt` working notes; 228 build artifacts at repo root; MCP Registry entry `io.github.Sundeepg98/kite-mcp-server@1.2.0` is **live and active** as of 2026-04-19 (verified via `https://registry.modelcontextprotocol.io/v0/servers?search=kite`); GitHub stars currently **0**, forks **0**, issues **0** (verified via `gh repo view`).

This document does not change code. It is a launch playbook only.

---

## Lead-in summary (read this first if nothing else)

**Realistic time-to-50-stars: 4–6 weeks** from a clean Show-HN launch on a Tuesday/Wednesday morning Pacific time. Optimistic (front-page Show HN) is 7–14 days. Pessimistic (Show HN flops + Reddit downvoted) is "never on this trajectory" — escalation path documented in §Phase 2.

**Three most important actions for the user this week:**

1. **Repo cleanup before any launch** — 228 build artifacts, ~50 untracked `.research/*-msg.txt`, 8 stray repo-root `*.md` working notes. ~30 min of work. Recipe in §Phase 3. *Without this, Show HN reviewers will land on the GitHub repo and bounce in 5 seconds.*
2. **Submit the three `awesome-mcp-servers` PRs** — `punkpeye` (85k★, sub-hour merges), `mcpservers.org` (covers `wong2`), `jaw9c` (strict-OAuth). Prepared entry text in memory. ~45 min total. Cascades into `glama.ai` auto-index within a week. *Registry is already published; these PRs are the discoverability multiplier.*
3. **Show HN on the next Tuesday or Wednesday at 06:30–08:30 Pacific** using the existing `docs/show-hn-post.md` draft (unchanged — it's well-calibrated). 2 hours of active comment-triage on the day. *This is the single biggest spike-of-attention shot in the plan; it gates the Rainmatter warm-intro window.*

Everything below is the supporting structure for these three actions plus the longer-tail Twitter/Reddit/Substack cadence already drafted.

---

## Phase 1 — Channel inventory (audience, mechanics, drafts, expected outcome, risk)

Format per channel: **(a) what / who / fit, (b) submission mechanics, (c) drafted state in repo, (d) realistic 50th-percentile outcome, (e) risks.**

### A. Show HN (`news.ycombinator.com/showhn`)

**(a)** Hacker News' "Show HN" front-page is the single highest-quality top-of-funnel for technical credibility audiences. ~1M weekday DAU on the site, of which the Show HN reader cohort is ~50–150k pageviews per surfaced post. Audience fit: **strong for AI early-adopters, MCP ecosystem nerds, infosec-curious devs**; weak for Indian retail traders specifically (they aren't on HN in volume). The wedge here is *engineer trust*, not retail-trader user count — a Rainmatter warm-intro contact will absolutely care about a successful Show HN, even if very few HN readers become Kite users.

**(b)** Submit at `news.ycombinator.com/submit` with the title prefixed `Show HN:`. The post body (≤2,000 chars) goes into the URL field via `text:` (or post a URL and self-comment the body). Best window: **Tuesday or Wednesday, 06:30–08:30 Pacific Time** (which is 19:00–21:00 IST evenings, when the Indian author is awake). Don't post on Mondays (Sunday queue still draining), don't post on Fridays (weekend dead zone), don't post during US holidays. Once submitted, watch for the first 90 minutes — that's when you need to answer the first batch of questions in 5–10 minutes each. After 90 minutes the position freezes and the algorithm decides front-page or not. **Do not ask for upvotes** (HN moderators detect and demote); do not flag your own post off the second-chance pool.

**(c)** Drafted at `docs/show-hn-post.md` (verified — 71 lines, three title options ranked, ~500-word body, eight prepared comment replies). The draft is calibrated, not naive — it leads with "regulated Indian stockbroker API" rather than "AI trading copilot," names limitations honestly (`ENABLE_TRADING=false` on hosted, naive paper-trading fill simulator), and pre-empts the 8 most predictable critiques (riskguard / streak / why MCP / SEBI / prompt injection / Go vs Python / SQLite vs Postgres / business model). A second-cut at `docs/launch-materials.md` exists but is older and has stale tool counts (`~100`, `8 safety checks`) — **use `docs/show-hn-post.md` not `launch-materials.md`**.

**(d) Realistic outcome (50th percentile, well-prepared post):** front-page for 4–8 hours, ~3,000–8,000 pageviews to the GitHub repo, 25–60 stars in 24 hours, 5–15 comments, 1–3 "I'd hire you" / "I'd invest" DMs. Optimistic (top 5 of front page): 50–150 stars in 24 hours, 30–60 comments, 1 mention by a known fintech voice. Pessimistic (off front page within 30 minutes): 1–3 stars, ≤5 comments, no traction. The well-prepared post probability splits roughly 50% / 25% / 25% across realistic / optimistic / pessimistic for a first-time poster with a real, working artifact.

**(e) Risks:** (i) HN crowd hates "AI trading bot" framing — the draft explicitly avoids it but a careless reply ("alpha", "edge", "make money") destroys the thread; (ii) one bad-faith commenter ("just helps people YOLO options") can become the top-voted reply if you don't respond well in the first 30 minutes — prepared replies in the draft mitigate this; (iii) Zerodha staff or a SEBI-adjacent voice in the thread asking "is this an unregistered RA?" — answer is in the draft (no advice, no signals, per-user, infra-not-platform); (iv) cross-pollination risk from prior Indian fintech disasters — pre-empt by not naming specific tippers/influencers; (v) front-page survivorship bias: most Show HN posts don't make it, so build the rest of the plan to not depend on this single shot.

### B. MCP Registry (`registry.modelcontextprotocol.io`)

**(a)** Anthropic-blessed canonical registry of MCP servers. Auto-cascades into `glama.ai/mcp/servers` within ~1 week (per memory). Audience fit: **MCP-savvy developers across the ecosystem** — moderate-traffic but high-quality. Currently in preview; "data resets are possible" per registry docs.

**(b)** `mcp-publisher login github` then `mcp-publisher publish ./server.json`. Synchronous validation — listing live in API within seconds. To re-publish after edits, bump the `version` field in `server.json` (immutable per-version).

**(c)** **Already published.** Verified live: `io.github.Sundeepg98/kite-mcp-server@1.2.0`, status `active`, `isLatest: true`, publishedAt 2026-04-19T06:32:53Z. `server.json` in repo root is current. Memory note `kite-mcp-registry-publisher.md` documents the publisher tooling and the `MCP_GITHUB_TOKEN=$(gh auth token) ./mcp-publisher.exe login github` env-var auth that bypasses the device-flow.

**(d) Realistic outcome:** ~5–15 stars per month from registry-driven discovery, steady drip, no spike. The registry's own UI is preview-quality; most discovery comes via `glama.ai` and via "is this on the official registry?" being a credibility signal in PR submissions to other lists.

**(e) Risks:** (i) preview-mode data reset wipes the entry — mitigation: re-publish takes <60s, document the command; (ii) someone files a name collision with `io.github.zerodha/kite-mcp-server` if upstream Zerodha publishes — namespace is GitHub-OAuth-bound so this can't happen accidentally; (iii) status changes (`deprecated` / `deleted`) being misread as project death — mitigation: don't touch status until project actually deprecates.

### C. `awesome-mcp-servers` PRs

Three lists in priority order (per memory `kite-awesome-mcp-listings.md`):

**C1. `punkpeye/awesome-mcp-servers`** (85k★ — the gravity well)

**(a)** Largest curated MCP list on GitHub. Audience fit: **MCP-ecosystem builders, AI tool tinkerers**. Listing here is more weighty than the registry itself for many readers because it's curated and explicitly cross-referenced by other lists.

**(b)** PR to add an entry under `### 💰 Finance & Fintech`. Append `🤖🤖🤖` to PR title to fast-track (per CONTRIBUTING.md). Sub-hour merge time per memory. Entry format (per memory):
```
- [Sundeepg98/kite-mcp-server](https://github.com/Sundeepg98/kite-mcp-server) 🏎️ 🏠 ☁️ 🐧 🪟 🍎 - Trade Indian stocks on Zerodha Kite via MCP. 80+ tools: holdings, orders, GTT, alerts, backtesting, options Greeks, paper trading, Telegram briefings. Deployed at kite-mcp-server.fly.dev with per-user OAuth.
```

**(c)** Entry text drafted in memory. PR body should reference our differentiation table (vs `aranjan/kite-mcp` already on the list — Python, 14 tools, TOTP, local-only). PR body text needs to be drafted from scratch in ~10 minutes.

**(d) Realistic outcome:** ~10–25 stars in 48 hours from the merge notification + GitHub network-effect (Sundeepg98 page appears in the list watchers' feeds).

**(e) Risks:** PR rejected if entry violates style — mitigation: copy nearby Finance entries verbatim before submitting; if rejected, take feedback in good faith and re-submit.

**C2. `mcpservers.org`** (covers `wong2/awesome-mcp-servers`, ~4k★)

**(a)** Form-submission front for the `wong2` curated list (`wong2` refuses direct PRs). Audience: same MCP-ecosystem cohort, slightly different curator viewpoint.

**(b)** Submit via the form on `mcpservers.org`. Free tier exists; $39 fast-review optional (skip — free tier is fine for a non-commercial OSS project).

**(c)** Not drafted as a separate file; reuse the `punkpeye` entry text with a 2-sentence rewording.

**(d) Realistic outcome:** ~5–10 stars within a week of the listing going live.

**(e) Risks:** form-submission queues are opaque — could take 1–4 weeks. No mitigation; just submit early.

**C3. `jaw9c/awesome-remote-mcp-servers`** (~1k★, strict)

**(a)** Strict-curation list focusing on remote/hosted MCP servers with OAuth 2.0 + production-readiness + maintainer-support. We satisfy all three (OAuth 2.1 + PKCE, Fly.io deployed, author-maintained).

**(b)** PR with a longer entry that explicitly addresses the curator's strict criteria.

**(c)** Not drafted; ~15 minutes to write, citing `server.json` capabilities + Fly.io deployment + 330+ tests.

**(d) Realistic outcome:** ~3–8 stars + the harder-to-quantify "we passed the strict bar" credibility signal that downstream reviewers (Rainmatter, FLOSS/fund) notice.

**(e) Risks:** PR rejected for "not production-ready enough" if the strict-curator isn't convinced — mitigation: include the security-audit summary, the test count, and the Fly.io deployment proof in the PR body.

### D. Reddit (multi-subreddit)

**(a)** Reddit is the **highest-volume retail-trader audience** in the plan. Five subreddits with different etiquette:

- `r/algotrading` (~370k subscribers) — international algorithmic traders. Audience fit: high. Treats marketing posts harshly.
- `r/algotradingIN` (~6k) — small but India-specific.
- `r/IndianStreetBets` / `r/IndianStockMarket` (~300k+) — Indian retail. Treats developer build-logs more warmly than algorithmic walls of code.
- `r/IndiaInvestments` (~600k) — disliked derivatives content; trim trading framing.
- `r/developersIndia` (~700k) — tech audience, strip trading framing entirely.
- `r/LocalLLaMA` / `r/ClaudeAI` — MCP-as-implementation audience, broker is a detail.

**(b)** Each subreddit has its own self-promotion rules. Common pattern: read the sidebar, check that the sub allows "build log" or "show your project" posts, **never** post the same body verbatim to multiple subs (cross-post detection is strict on `r/algotrading` in particular). Best window: weekday morning IST (3–5 AM Pacific, when the US algo crowd is also online). One subreddit per day, never two on the same day.

**(c)** **Drafted at `docs/reddit-buildlog-posts.md`** (verified — 202 lines, two full post bodies (short ~420 words / long ~850 words with code blocks), a five-subreddit cross-post matrix with required adjustments per sub, a pinned-comment FAQ template, and seven prepared pushback responses). Quality is high; do not rewrite.

**(d) Realistic outcome (50th percentile):** `r/algotrading` longer body — 30–80 upvotes, 8–20 comments, 5–15 stars to the repo over 48 hours. `r/IndianStreetBets` — 50–150 upvotes (this audience upvotes Indian-developer build-logs warmly), 10–25 comments, 3–8 stars. `r/IndiaInvestments` — 5–20 upvotes if not removed by mods (50% removal risk on derivatives-adjacent content). `r/developersIndia` — 20–60 upvotes, 5–10 stars, very few questions (audience reads, doesn't comment).

**(e) Risks:** (i) `r/algotrading` removes posts perceived as self-promotion — mitigation: build-log framing in the draft, no Fly.io URL above the fold; (ii) `r/IndiaInvestments` mod removal — pre-empt by leading with "tool not advice" disclaimer; (iii) brigade from competing tippers/coaches if any has a Reddit presence — mitigation: don't engage; (iv) "where's the demo video?" comments — easy to address but takes 1–2 hours to record and edit; (v) cross-post detection — only post one full body per sub, paraphrase others.

### E. Twitter / X

**(a)** Twitter is the **single best Indian fintwit cluster** for warm-intro discovery. Audience fit: high — both Indian retail traders and AI/MCP early-adopters concentrate here. Specific names from memory `kite-rainmatter-warm-intro.md` and `kite-registry-and-funding-refs.md`:
- `@deepakshenoy` (Capitalmind, Rainmatter portfolio Aug 2025) — *first* warm-intro contact when 50-star trigger fires
- `@iamvishvajit` (Rainmatter podcast alum)
- `@abidsensibull` (Sensibull)
- Vasanth Kamath (Rainmatter — closer to the fund itself)
- Nikhil Kamath / Nithin Kamath (Zerodha — last resort, do not burn until Pvt Ltd + 500 users per memory)

**(b)** Post a launch thread (7 tweets) on the same day as Show HN goes live, ~2 hours after Show HN. Use `docs/launch/03-twitter-thread.md` or `docs/twitter-launch-kit.md` as starting drafts. Do **not** quote-RT Nithin/Kailash/Zerodha threads to bait attention (anti-pattern explicit in `twitter-launch-kit.md`). Do **not** cold-DM anyone before the 50-star trigger.

**(c)** **Two drafts exist.** `docs/launch/03-twitter-thread.md` is a 7-tweet thread with a stated demo-video attachment that doesn't exist yet. `docs/twitter-launch-kit.md` is a more sophisticated 14-day cadence plan with bio variants, pinned tweet options, anti-patterns. **Use the cadence plan for sustained presence; use the 7-tweet thread on launch day with the demo-video attached or replaced with a code screenshot.**

**(d) Realistic outcome:** launch thread — 100–500 impressions per tweet, 5–15 likes on tweet 1, 1–5 retweets if any fintwit account amplifies. Sustained 14-day cadence — slow follower growth (5–15 followers per week) plus organic discovery via the build-log content. Pinned-tweet asking-for-audit ("what would you audit first?") historically performs 2–3x baseline.

**(e) Risks:** (i) Twitter algorithm punishes link-out tweets — put GitHub link in tweet 7 not tweet 1; (ii) hashtag spam (`#nifty #sensex #stockmarket`) marks the account as a tipper — anti-patterns doc explicitly forbids this; (iii) accidental engagement with a tipping account poisons the algorithmic feed-association — anti-patterns doc forbids this; (iv) NSE/SEBI staff or a regulator-adjacent journalist quote-tweets a single tweet out of context — mitigation: every tweet on financial topic must self-include a "tooling not advice" cap; (v) live P&L screenshots — anti-patterns doc forbids unconditionally.

### F. Indian Discord / Slack communities

**(a)** Lower-volume, higher-trust channels. Specific groups:
- Zerodha Pi Discord (if still active — verify) — would be the highest-trust audience but smallest
- Quantra alumni Slack (QuantInsti Quantra graduates)
- BangaloreAI / ChennaiAI / DelhiAI / HyderabadAI Discord/Slack (5–15k each)
- pyladies-india, DataKind Bangalore
- Foss United Discord (relevant to FLOSS/fund app)

**(b)** Each requires invite or referral. No mass-broadcast — pick 2–3 max. Lead with build-log substance, not link-and-leave.

**(c)** Not drafted as a separate file; reuse the Reddit short body trimmed to ~150 words.

**(d) Realistic outcome:** ~3–10 stars per channel + the warmer "I'll DM the project to my friend who trades on Zerodha" effect that doesn't show up as direct attribution.

**(e) Risks:** (i) seen as spammy if you join a channel and post immediately — mitigation: lurk for 1 week, comment on 2–3 unrelated posts genuinely first; (ii) violating channel norms; (iii) low ROI — these channels are slow.

### G. Claude Code Discord / `r/ClaudeAI` / Anthropic-community

**(a)** Anthropic ecosystem channels. Audience fit: **highest for the MCP-as-protocol angle, lowest for trading-specifics.** Treat as a supporting drumbeat, not a primary launch channel. Anthropic Discord ~10k+, `r/ClaudeAI` ~50k+.

**(b)** Post in `#showcase` or equivalent channel with a 2-sentence intro and the GitHub link. On `r/ClaudeAI`, lead with MCP-spec nerdery (tool discovery, elicitation, structuredContent, prompts, resources, widgets) per the cross-post matrix in `docs/reddit-buildlog-posts.md`.

**(c)** Not drafted as a standalone file; trivial to write — 2 sentences + GitHub link.

**(d) Realistic outcome:** ~5–15 stars per channel + 1–3 "this is interesting" replies + occasional bug report (positive — means people tried it).

**(e) Risks:** (i) Anthropic moderators may dislike `place_order` tools shipping in a public MCP server (real-money side-effects in an LLM context is a genuine concern) — mitigation: lead with riskguard + elicitation + `ENABLE_TRADING=false` posture, not with the order placement; (ii) cross-post fatigue if Anthropic Discord users also see the Show HN.

### H. Anthropic-direct outreach (cookbook contribution / bug report as introduction)

**(a)** "Bug report as introduction" — file a thoughtful issue on `anthropics/anthropic-cookbook` or `modelcontextprotocol/registry` that genuinely helps them and incidentally introduces the project. Audience: Anthropic developer-relations (very small but very high-leverage if it lands).

**(b)** Find a real, small bug or doc gap in `anthropic-cookbook` or in `registry.modelcontextprotocol.io` (we already hit one — registry path-case sensitivity returning 404 vs 200 depending on capitalization). File it with a fix-PR if possible. Mention `kite-mcp-server` only in passing as the project that surfaced the bug.

**(c)** Not drafted; ~30 minutes if a bug exists. A real example: the `Sundeepg98` vs `sundeepg98` 404 path-case behavior on the registry GET endpoint.

**(d) Realistic outcome:** Maybe nothing visible, but DevRel-cohort awareness is a long-tail asset. ~0–10 stars direct, but the strategic value is "Anthropic knows we exist and we contribute back."

**(e) Risks:** (i) coming across as performative — mitigation: only file if there's a real bug, never invent one; (ii) timing — file 2–3 weeks before Show HN so it doesn't look opportunistic.

### I. Hacker News non-Show submissions (Ask HN, regular)

**(a)** Risky fallback. Ask HN ("Ask HN: how do you let an LLM trade for you safely?") could surface the project organically, but reads as low-effort if your real Show HN flopped first. Audience same as Show HN, lower attention.

**(b)** Submit at `news.ycombinator.com/submit` as a regular question, not Show HN.

**(c)** Not drafted; this is a contingency, not a planned beat.

**(d) Realistic outcome:** front-page rare for Ask HN; usually 5–20 comments, 0–5 stars to the linked repo.

**(e) Risks:** Looks desperate if Show HN already happened and didn't take. **Don't run unless Show HN is a 30-day-stale failure and you have something genuinely new to say.**

### J. Z-Connect editorial pitch (Zerodha's blog)

**(a)** Per memory `kite-zerodha-no-marketplace.md`, Zerodha's Z-Connect blog accepts editorial pitches. Audience: **literally Zerodha customers**, the highest-fit retail-trader audience anywhere. Post-500-stars threshold per memory — this is *not* a Week 1 channel.

**(b)** Pitch via Zerodha's Z-Connect editorial contact (find via `kite.trade/forum` admin DM or Z-Connect bottom-of-page contact). Lead with "open-source developer tooling for Kite Connect users" framing, never with "trading copilot."

**(c)** Not drafted; pitch email ~200 words drafted in ~30 minutes when threshold hits.

**(d) Realistic outcome (when triggered at 500★):** if accepted as a guest post — 500–2,000 unique readers, 50–200 stars, 5–20 GitHub issues filed (good signal). If declined politely — Zerodha now has the project on their internal radar, which is itself useful.

**(e) Risks:** (i) Zerodha declines because the project competes with `mcp.kite.trade` — mitigation: lead with the "complementary not competitive" framing in `docs/floss-fund-proposal.md` §"Complementarity with Zerodha's own MCP"; (ii) Zerodha-staff reviewer flags `place_order` capability as off-policy — mitigation: explicit `ENABLE_TRADING=false` framing on hosted; (iii) being seen to use Z-Connect for monetization later violates editorial spirit — never pitch a paid tier post-Z-Connect.

### K. Adjacent channels not in the brief but worth flagging

**TradingQnA forum (Zerodha's official developer forum).** Drafted at `docs/launch/01-tradingqna-post.md` — verified 122 lines. Audience: ~5k Kite Connect developers, perfectly targeted. Lower-volume than Reddit but **higher conversion to actual users** (audience already has Kite Connect subscriptions). Post 1–2 days after Show HN. Risk: low.

**`docs/kite-forum-replies.md` — four reply templates for specific existing kite.trade forum threads.** Drafted with thoughtful 7-day posting cadence to avoid spam-tagging by Zerodha forum mods. Use these *before* the TradingQnA standalone post to build handle-history first.

**FLOSS/fund grant submission.** Drafted at `docs/floss-fund-proposal.md` (verified — full ask of $25–30k, breakdown by line-item). Submission via `floss.fund` form. Outcome is grant + brand-amplification (FLOSS/fund publicly announces grantees on Twitter and their site). Window: submit any time, no calendar dependency.

**FOSS United / IndiaFOSS 2026 CFP.** Drafts at `docs/drafts/foss-united-grant-email.md` and `docs/drafts/indiafoss-2026-cfp.md`. CFP submission is a calendar event — check IndiaFOSS 2026 dates and submit a talk proposal ("Building a regulated-API-aware MCP server in Go"). If accepted, it's an in-person credibility-anchor that beats most online channels.

**Substack / blog.** Drafted at `docs/substack-week-1-options-greeks.md` (Week 1 of an options + MCP + Python series). Drumbeat content, not a launch beat — but an active Substack on day-7 of the launch builds the cohort sales funnel.

**Hacker News blog cross-post.** `docs/blog/oauth-13-levels.md` is a 13-level deep-dive on the OAuth callback URL (per memory `kite-callback-deepdive.md`). This is a *separate* HN post (not Show HN) — submit as a regular link 2–3 weeks after the Show HN, when the thread can stand on its technical depth alone.

---

## Phase 2 — Time-to-50-stars realistic projection

**Scenario probabilities for a well-prepared launch sequence (Phase 3 cleanup done, Show HN draft used, Reddit + Twitter + Registry executed in sequence):**

### Scenario 1: Optimistic (probability ~25%) — 50 stars in week 1

**Trigger conditions:** Show HN front-page top-10 for 4+ hours OR Indian-fintwit amplifier (e.g. `@deepakshenoy` retweets organically) OR a known MCP voice (Anthropic DevRel, Riza founder, etc.) shares it.

**Trajectory:** Day 0 launch → 30–60 stars day 1 → 50 stars by day 2–4 → coverage in `glama.ai/mcp/servers` auto-index by week 1 → first FLOSS/fund inquiry by week 2.

**Signals to watch:** (i) Show HN at >40 points by hour 3; (ii) Twitter thread tweet 1 at >25 likes by hour 2; (iii) any known fintwit/devrel handle replies to the launch tweet within 24 hours.

**Escalation path if optimistic hits:** Activate Rainmatter warm-intro per `kite-rainmatter-warm-intro.md` immediately. DM `@deepakshenoy` first, then `@iamvishvajit` 1 week later, then `@abidsensibull` 2 weeks later. **Do not spam — phased.**

### Scenario 2: Realistic (probability ~50%) — 50 stars in 4–6 weeks

**Trigger conditions:** Show HN moderate (10–30 stars day 1, off front page within 2 hours) + steady drip from Reddit cross-posts + `awesome-mcp-servers` PRs merge + Twitter cadence quiet but consistent.

**Trajectory:** Day 0 Show HN → 12–25 stars day 1 → +5–10 stars/week from steady drip across Reddit, Twitter, `awesome-mcp-servers` cascade → 50 stars by week 4–6. FLOSS/fund inquiry from a Twitter follow-up around week 5.

**Signals to watch:** (i) Show HN at 10–30 points after hour 3; (ii) Reddit post in `r/algotrading` survives mod review (50/50); (iii) `punkpeye/awesome-mcp-servers` PR merges within 24 hours; (iv) `r/IndianStreetBets` gives the longest-tail engagement (warm Indian audience).

**Escalation path if realistic hits:** Continue the 14-day Twitter cadence per `docs/twitter-launch-kit.md`. Don't ping warm-intro contacts yet — wait for the 50-star bar. Use weeks 2–4 to publish the `oauth-13-levels.md` blog as a second-wave HN submission, and to ship Substack Week 1 (options Greeks).

### Scenario 3: Pessimistic (probability ~25%) — never reaches 50 on this trajectory

**Trigger conditions:** Show HN flagged or buried within 30 minutes (low-quality account, bad title, bad timing); Reddit removed by mods; competitor backlash on Twitter (Multibagg founder publicly QRTs criticizing AI-trading dangers per memory `kite-competitors-corrected.md`); SEBI-adjacent regulatory discussion picks up the project name.

**Trajectory:** Day 0 → 1–5 stars → +1–3 stars/week → plateau at 15–25 stars by week 8 → no Rainmatter trigger ever fires.

**Signals to watch:** (i) Show HN flagged within 60 minutes (zero-comment posts get auto-flagged by quality scoring); (ii) `r/algotrading` post auto-removed; (iii) hostile QRT thread on Twitter with >50 retweets; (iv) any single comment from a SEBI-adjacent voice raising a regulatory concern that gets >100 engagement.

**Escalation path / Plan B if pessimistic hits:**
1. **Pause public launch** — stop posting, do not re-attempt Show HN, do not engage QRT threads.
2. **Address the substantive concerns first.** If the regulator-tone critique is technically right (e.g. `place_order` shouldn't be in a hosted MCP), ship the fix (the project already has `ENABLE_TRADING=false` on hosted; reinforce that messaging).
3. **Switch the wedge to FOSS/funding rather than retail-trader stars.** FLOSS/fund grant + IndiaFOSS talk + GitHub Sponsor on `funding.json` becomes the credibility anchor, not stars.
4. **Direct relationship with Zerodha first.** Email `kiteconnect@zerodha.com` with the disclosure draft at `docs/drafts/zerodha-compliance-email.md` (per memory `feedback_cheapest_compliance_action.md` — "cheapest paper trail"). Zerodha-positive relationship is more valuable than 50 stars from a botched launch.
5. **Re-launch in 6 months under a renamed project** (per memory `kite-algo2go-rename.md` — domain + trademark already verified available; backup `Tradarc`). Fresh identity, fresh Show HN, fresh narrative around the regulatory-aware second-version positioning.

---

## Phase 3 — Cleanup prerequisites BEFORE any launch

This is the highest-leverage / lowest-effort work in the entire plan. The Show HN crowd is going to land on the GitHub repo, scroll to the file list, and 30% of them will close the tab if they see hundreds of `*.out` / `*.exe` / `cov_*.html` artifacts.

**Empirical state (verified 2026-05-02):**
- 228 build artifacts at repo root (matches `docs/product-definition.md` §2 inventory)
- 152 tracked `.research/*.md` files
- ~50 untracked `.research/*.{cov,sh,txt}` working files
- 8 stray repo-root scratch markdown: `a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md`, plus `COVERAGE.md` (the latter may be intentional — verify)

**Recipe (do not execute as part of this deliverable; run manually before launch):**

```bash
# Step 0 — verify current state
cd D:/Sundeep/projects/kite-mcp-server
git status
git log --oneline -5

# Step 1 — preview gitignored cleanup (228 build artifacts)
git clean -fXn   # -X = only gitignored, -n = preview, -f required for non-interactive
# Read the output. Confirm only build artifacts (.out / .exe / .cov / .html / .test / .prof).
# Verify NO source files appear. If anything unexpected, STOP and investigate.

# Step 2 — execute the gitignored cleanup
git clean -fX
# This deletes 228 untracked-and-gitignored files from disk.
# git status should now be much shorter.

# Step 3 — handle the stray repo-root markdown
# These are workspace-scratch and not gitignored. Verify each:
git ls-files a.md ch.md mod.md req.md gen_ref.md api.md admin.md COVERAGE.md
# If any are tracked, decide per-file:
#   - 'admin.md' / 'api.md' might be intentional sub-product docs; verify content first
#   - 'a.md' / 'ch.md' / 'mod.md' / 'req.md' / 'gen_ref.md' are almost certainly scratch
#   - 'COVERAGE.md' may be intentional CI artifact; check first

# For files confirmed as scratch:
git rm a.md ch.md mod.md req.md gen_ref.md
git commit -o -- a.md ch.md mod.md req.md gen_ref.md \
  -m "chore(cleanup): remove repo-root scratch markdown before launch"

# For untracked files in repo root that are scratch:
rm -i <name>   # interactive remove

# Step 4 — handle untracked .research/ working notes
# ~50 files like *-msg.txt, *.cov, *.sh that are commit-message scratch
# Decide: gitignore them (so they don't pollute git status) OR delete entirely.
# Recommended: add to .gitignore as .research/*-msg.txt, .research/*.cov, .research/*.sh
# (The 152 tracked .research/*.md files stay for now — see Phase 4 for the larger move.)

# Step 5 — verify repo is presentable
ls | head -30   # repo root should show ~30-40 entries, not ~330
git status      # should be short and clean
git log --oneline -5

# Step 6 — commit the cleanup decision
git commit -o -- .gitignore -m "chore(launch): gitignore .research/ working scratch (msg.txt, cov, sh)"

# Step 7 — push
git push origin master

# Optional Step 8 — the bigger .research/ move per docs/product-definition.md §2
# This is OUT OF SCOPE for the launch-prep cleanup. Suggested as a SEPARATE follow-up:
#   git mv .research/ ../kite-mcp-internal/   (private companion repo)
#   git rm -r .research/
#   commit + push
# This is 152 tracked-file move — do NOT bundle with the launch-prep cleanup commit.
# Recommended sequence: launch-prep cleanup ships first, .research/ migration is a
# separate effort 1–2 weeks after launch.
```

**Order of cleanup commits (avoid the "git stash everywhere" rule per memory):**
1. `chore(cleanup): remove repo-root scratch markdown before launch` (5 small files)
2. `chore(launch): gitignore .research/ working scratch (msg.txt, cov, sh)` (.gitignore only)
3. `git push` (single push for both)

**Time budget:** 30–45 minutes if you're careful, 5 minutes if you trust the recipe. Recommend careful — this is the front door to a 5,000-pageview Show HN.

---

## Phase 4 — Sequencing across channels

### Day –7 to Day 0: Preparation week

| Day | Action | Time | Gate |
|-----|--------|------|------|
| -7 | Audit repo: run Phase 3 commands in preview mode, decide what to keep | 30 min | none |
| -6 | Execute Phase 3 cleanup commits + push | 30 min | preview output reviewed |
| -5 | Re-read `docs/show-hn-post.md`; pick title option 1; tweak if anything stale | 20 min | repo clean |
| -4 | Re-read `docs/twitter-launch-kit.md` and `docs/launch/03-twitter-thread.md`; merge into one launch thread; decide whether to record a 30-second demo video | 60 min | none |
| -3 | Re-read `docs/reddit-buildlog-posts.md`; decide which two subreddits to post to (recommend `r/algotrading` + `r/IndianStreetBets`) | 20 min | none |
| -2 | Draft `awesome-mcp-servers` PR bodies for punkpeye + jaw9c (mcpservers.org via form on Day +2) | 30 min | none |
| -1 | Final review: README hero text, `docs/product-definition.md` §3 Draft B (≤70 words above the fold), `funding.json`, `smithery.yaml` | 30 min | none |
| 0 morning IST | Last gut-check: Twitter/HN are reachable, GitHub repo loads cleanly, `mcp-publisher` listing still active | 10 min | none |

### Day 0: Launch day (Tuesday or Wednesday)

| Time (Pacific) | Time (IST) | Action |
|---------------|-----------|--------|
| 06:30–08:30 | 19:00–21:00 | **Submit Show HN** with title option 1 from `docs/show-hn-post.md`. Stay at the keyboard for 90 minutes minimum. |
| 08:30–10:00 | 21:00–22:30 | **Submit `punkpeye/awesome-mcp-servers` PR** + **submit `jaw9c/awesome-remote-mcp-servers` PR** + **submit `mcpservers.org` form**. (Registry is already published — verified Apr 19, 2026 — no action needed.) |
| 10:00–11:00 | 22:30–23:30 | **Post Twitter launch thread** (7 tweets per `docs/launch/03-twitter-thread.md` or merged version). Pin tweet 1. |
| 11:00–13:00 | 23:30–01:30 next day | Active comment-triage on Show HN. Use prepared replies from `docs/show-hn-post.md` §3. **Do not be defensive.** |
| 22:00 (next day morning IST) | 10:30 IST next day | Quick check on Show HN, Twitter, PR statuses. |

### Day 1–7: Drumbeat week

| Day | Action |
|-----|--------|
| 1 | Post `docs/launch/01-tradingqna-post.md` to TradingQnA forum (Zerodha's developer forum). |
| 2 | Post `r/algotrading` long body from `docs/reddit-buildlog-posts.md` §2. |
| 3 | Quiet day on social — engage with replies on Show HN / Twitter / Reddit, do not post new content. |
| 4 | Post `r/IndianStreetBets` short body from `docs/reddit-buildlog-posts.md` §1. |
| 5 | Post `docs/kite-forum-replies.md` Reply 1 (to thread #15064 on kite.trade forum). Quiet day on Twitter. |
| 6 | Quiet day. Engage genuinely with one unrelated kite.trade forum thread (per the cadence in `kite-forum-replies.md`). |
| 7 | Twitter Day 7 from `docs/twitter-launch-kit.md` cadence (Sunday "light / personal" tweet). Take stock of star count. |

### Week 2–4: Sustained cadence

- **Twitter daily** per `docs/twitter-launch-kit.md` 14-day plan.
- **Reddit cross-posts** to the secondary subreddits (`r/IndiaInvestments` trimmed, `r/developersIndia` tech-only remix, `r/ClaudeAI` MCP-only remix) — one per week, never two in the same week.
- **kite.trade forum** replies 2, 3, 4 from `docs/kite-forum-replies.md` per the prescribed cadence (interleaved with non-self-linking help).
- **FLOSS/fund grant submission** (Week 2) — `docs/floss-fund-proposal.md` is ready, submit via the form on `floss.fund`.
- **Substack Week 1 post** (Week 3) — `docs/substack-week-1-options-greeks.md` cross-posted from Twitter Day 12.
- **Indian Discord/Slack drops** (Week 4) — pick 2–3 channels, lurk first, drop a build-log link.

### Week 4–8: Trigger checks

- **Star count check at end of week 4.** Hit 50? Activate Rainmatter warm-intro per `kite-rainmatter-warm-intro.md` — DM `@deepakshenoy` first, ~7-day phased follow-ups for `@iamvishvajit` and `@abidsensibull`. Don't burn `@nikhilkamath` / `@nithinkamath` until Pvt Ltd is formed AND 500+ users.
- **Star count below 30 at end of week 4?** Don't activate warm-intro. Switch focus: ship the second-wave HN post (`docs/blog/oauth-13-levels.md`) as a regular HN submission; submit `IndiaFOSS 2026 CFP` per `docs/drafts/indiafoss-2026-cfp.md`; aim for the FLOSS/fund grant as the credibility anchor instead of stars.
- **Pessimistic-scenario triggered?** Execute Plan B from §Phase 2 Scenario 3: pause launch, address regulatory concerns explicitly, send the Zerodha-compliance disclosure email, replan a 6-month later relaunch under the Algo2Go rename per `docs/algo2go-tm-search.md`.

### Month 3+: Long-tail

- **500-star check.** Hit 500? Pitch Z-Connect editorial per `docs/zerodha-no-marketplace.md` memory note (Zerodha's blog accepts editorial pitches at this scale).
- **Cohort #1 paid education** (Q3 2026 per `docs/rainmatter-onepager.md`) — soft-launch via Substack subscriber list.
- **Multi-broker adapter** (Dhan port per `docs/multi-broker-plan.md`) ships Q3, opens up the `r/dhan` and similar subreddit channels.

---

## Phase 5 — Honest risk audit

**Risk 1: Zerodha cease-and-desist if positioning lands as competing too directly with `mcp.kite.trade`.**
- Severity: medium. Probability: ~10–15%.
- Mitigation: lean on `docs/product-definition.md` §"Differentiation vs official Zerodha Kite MCP" — explicit "complementary not competitive" framing. Send the proactive disclosure email per `docs/drafts/zerodha-compliance-email.md` *before* launch (per memory `feedback_cheapest_compliance_action.md` — cheapest paper trail). Note in `docs/floss-fund-proposal.md`: "Not a competitor — a superset" with the explicit "useful patterns are available upstream to merge or mirror" phrasing.
- Watch signal: Zerodha staff DM, kite.trade forum thread referring to "third-party MCPs", `kiteconnect@zerodha.com` reply that flags the project.

**Risk 2: SEBI / regulatory backlash if `place_order` capability gets noticed pre-empanelment.**
- Severity: medium-high. Probability: ~5–10% before 500 users, much higher above that.
- Mitigation: hosted endpoint is read-only by default per `ENABLE_TRADING=false` (memory + `app/app.go`). Self-host runs under SEBI's retail self-trading framework's "self/spouse/dependent" scope (per `docs/rainmatter-onepager.md` §"The regulatory question"). Lead all launch copy with "tooling, not advice; you remain the SEBI Client of record." Never claim or imply autonomous trading.
- Watch signal: SEBI-adjacent Twitter handle quoting the project; any mention of "unregistered RA" in HN / Reddit comments; `kiteconnect@zerodha.com` reply mentioning SEBI.

**Risk 3: Multibagg / Streak / Sensibull competitive response.**
- Severity: low-medium. Probability: ~30% over 6 months.
- Mitigation per `docs/product-definition.md` differentiation table: Streak/Sensibull are hosted SaaS with proprietary DSLs — different layer. Multibagg is anti-MCP per memory `kite-competitors-corrected.md` (Shark Tank competitor). Don't engage hostile QRTs. If Multibagg founder publicly criticizes the project as unsafe, the riskguard chain + elicitation + audit-trail story is the response — but in calm code-review tone, not in adversarial tweets.
- Watch signal: Multibagg founder QRT, Streak/Sensibull official handle responding to a launch tweet, any "AI is dangerous in trading" thread linking to the project.

**Risk 4: Indian fintwit dogpile claiming financial advice / SEBI registration concerns.**
- Severity: medium. Probability: ~15–20%.
- Mitigation: every launch tweet self-includes "tooling not advice; you remain SEBI Client of record" per `docs/twitter-launch-kit.md` anti-patterns. Never post live P&L. Never engage tipping/guru accounts. The drafted prepared replies in `docs/show-hn-post.md` §3 and `docs/reddit-buildlog-posts.md` §5 cover this directly.
- Watch signal: a fintwit account with >5k followers QRTing with "this is a SEBI violation" — respond once, calmly, in code-review tone with the regulatory framing from `docs/rainmatter-onepager.md`.

**Risk 5: Repo cleanup not done → Show HN crowd lands on a junk-littered repo.**
- Severity: high (this is the highest-probability damage vector). Probability: ~100% if Phase 3 is skipped, ~5% if executed.
- Mitigation: do not launch without Phase 3.
- Watch signal: the first Show HN comment is "what is all this `cover_*.html` stuff in your repo root?"

**Risk 6: MCP Registry data reset wipes the v1.2.0 listing during launch week.**
- Severity: low. Probability: ~5%.
- Mitigation: the `mcp-publisher publish ./server.json` command is fast (verified <60s). Keep the binary on PATH and the GitHub OAuth env-var ready. If reset happens during launch week, re-publish takes 5 minutes.

**Risk 7: Show HN + Twitter timing collision — a major news story (NSE crash, SEBI announcement, AI policy) drowns the launch.**
- Severity: low. Probability: ~10%.
- Mitigation: check `news.ycombinator.com` front page in the hour before submission. If the front page is dominated by a major fintech / AI / regulatory story, defer 1–2 days.

**Risk 8: GitHub repo discovery via the registry-cascade goes to `aranjan/kite-mcp` first (the competitor on `punkpeye` Finance per memory).**
- Severity: low. Probability: ~30% on day 1.
- Mitigation: the differentiation text in our `awesome-mcp-servers` PR explicitly contrasts (80+ tools vs 14, hosted+self-host vs local-only, OAuth 2.1 vs shared TOTP, riskguard vs none). After both are listed, organic comparison readers self-route to ours based on feature set.

**Risk 9: Rainmatter warm-intro burned too early.**
- Severity: high (these contacts only get one shot). Probability: ~10% if the playbook is followed, much higher if user is impatient.
- Mitigation: strict 50-star gate. Per `kite-rainmatter-warm-intro.md`: Shenoy first, then Sonagara, then Hassan, phased over weeks. Never burn Nikhil / Nithin Kamath until Pvt Ltd + 500 users.

**Risk 10: The user's energy gives out before sustained cadence completes.**
- Severity: medium. Probability: ~50% (this is the most realistic risk in any solo launch).
- Mitigation: pre-schedule the 14-day Twitter cadence in a queue tool (Buffer / Typefully) before Day 0. The Reddit / Substack / forum posts are 1-day actions, not weeks. Build in a hard "rest day" every 3 days during the launch fortnight.

---

## Phase 6 — Final actionable list (5–7 items, ranked, time-budgeted)

For the user **this week,** ranked by impact-per-minute:

### 1. Phase 3 cleanup (Tuesday / Wednesday)

**Time:** 30–45 minutes.
**Output:** clean GitHub repo root, ~30 entries instead of ~330; tightened `.gitignore`; one push to `origin/master`.
**Why first:** every other action assumes the GitHub repo presents well. Highest impact-per-minute in the entire plan. Skip this and Show HN burns.

### 2. Submit `awesome-mcp-servers` PRs (Wednesday / Thursday)

**Time:** 45 minutes for all three (punkpeye PR, jaw9c PR, mcpservers.org form).
**Output:** three submissions live. Punkpeye usually merges in <1 hour (per memory). PR text in memory `kite-awesome-mcp-listings.md` ready to copy.
**Why second:** registry is already published (Apr 19, 2026 — verified). These three lists are the discoverability multiplier on top of the registry. Cascades into `glama.ai` auto-index in ~1 week.

### 3. Show HN on next Tuesday or Wednesday (06:30–08:30 Pacific) (this coming week)

**Time:** 10 minutes to submit + 90–120 minutes active comment triage.
**Output:** the single biggest spike-of-attention moment. Realistic 25–60 stars in 24 hours; optimistic 50–150 stars.
**Why third (not first):** Phase 3 + awesome-mcp PRs need to land first because Show HN traffic spikes hard during the first 90 minutes. If Phase 3 isn't done, the Show HN audience lands on a junk repo. **Use `docs/show-hn-post.md` as-is — do not rewrite.**

### 4. Twitter launch thread (same day as Show HN, ~2 hours after)

**Time:** 30 minutes (writing + scheduling).
**Output:** 7-tweet thread per `docs/launch/03-twitter-thread.md` and `docs/twitter-launch-kit.md`. Pinned. The pinned-tweet asking-for-audit ("what would you audit first?") historically performs 2–3x baseline.
**Why fourth:** complements Show HN — same-day momentum without cannibalizing attention. Twitter is also where Indian fintwit lives (the Rainmatter warm-intro pool).

### 5. Day 1: TradingQnA forum post (`docs/launch/01-tradingqna-post.md`)

**Time:** 15 minutes (the post is drafted; just paste).
**Output:** Zerodha-developer-audience post on `kite.trade/forum`. Lower-volume than Reddit but **higher conversion to actual users.** Lower brand-confusion risk because it's the developer crowd, not retail-trader crowd.
**Why fifth:** day-1 drumbeat. Post late evening IST same day as Show HN ends, so the Tuesday-IST Indian developer cohort sees it Wednesday morning.

### 6. Day 2: Reddit `r/algotrading` long body post (`docs/reddit-buildlog-posts.md` §2)

**Time:** 20 minutes (post + reply queue).
**Output:** ~30–80 upvotes 50th percentile, 8–20 comments, 5–15 stars.
**Why sixth:** day-2 drumbeat. Don't post Reddit and HN same day (cross-pollution / over-broadcasting). Use the long body specifically — `r/algotrading` is the architecture-curious audience.

### 7. (Calendar trigger, NOT this week:) Rainmatter warm-intro to `@deepakshenoy` (when 50-star bar hits)

**Time:** 30 minutes (drafting + sending one Twitter DM).
**Output:** highest-leverage warm-intro contact unlocked. Use the script in `kite-rainmatter-warm-intro.md` — pitch is "open-source first, no monetization yet, looking for guidance," NOT funding ask.
**Why last on this week's list:** gated on 50-star count. Realistic timeline is 4–6 weeks (Scenario 2). Do **not** front-load.

**Total time investment for the user this week:** ~3–4 hours of focused work on launch-day, ~1 hour/day for 7 days post-launch, ~30 min/day for the 14-day Twitter cadence.

---

## Cross-references (file paths verified; URLs from memory)

- `docs/show-hn-post.md` — Show HN draft (use as-is)
- `docs/twitter-launch-kit.md` — Twitter bio + 14-day cadence + anti-patterns
- `docs/launch/03-twitter-thread.md` — alternative 7-tweet launch thread
- `docs/reddit-buildlog-posts.md` — Reddit short + long bodies + cross-post matrix + FAQ
- `docs/launch/01-tradingqna-post.md` — TradingQnA forum post
- `docs/kite-forum-replies.md` — kite.trade forum reply templates with cadence
- `docs/launch/04-demo-video-script.md` — 30-second demo video script (record before Day 0 if time permits)
- `docs/floss-fund-proposal.md` — FLOSS/fund grant application (submit any time)
- `docs/rainmatter-onepager.md` — Rainmatter conversation leave-behind (use after warm-intro lands)
- `docs/drafts/jethwani-shenoy-dms.md`, `docs/drafts/vishal-dhawan-dms.md` — DM drafts for specific Indian fintwit handles
- `docs/drafts/zerodha-compliance-email.md` — proactive Zerodha disclosure (send before launch per memory `feedback_cheapest_compliance_action.md`)
- `docs/drafts/foss-united-grant-email.md`, `docs/drafts/indiafoss-2026-cfp.md` — FOSS-India ecosystem
- `docs/blog/oauth-13-levels.md` — second-wave HN submission (week 3)
- `docs/substack-week-1-options-greeks.md` — Substack drumbeat
- `docs/product-definition.md` §3 Drafts A and B — Show HN body and README hero
- `server.json` — registry entry (verified live)
- `funding.json`, `smithery.yaml` — discoverability metadata
- `kite-rainmatter-warm-intro.md` (memory) — warm-intro priority order + thresholds
- `kite-awesome-mcp-listings.md` (memory) — list submission strategy with entry text
- `kite-mcp-registry-publisher.md` (memory) — registry publisher tooling + auth
- `kite-launch-blockers-apr18.md`, `kite-launch-ready-fixes.md` (memory) — pre-launch fixes already shipped
- `kite-zerodha-no-marketplace.md` (memory) — Z-Connect editorial pitch (post-500-stars)
- `kite-competitors-corrected.md` (memory) — Multibagg / Streak / Sensibull positioning
- `kite-algo2go-rename.md` (memory) — fallback rename + Tradarc backup if pessimistic scenario triggers
- `feedback_cheapest_compliance_action.md` (memory) — pre-launch Zerodha email recommendation

---

*This document does not change code. It does not commit anything beyond itself.*
