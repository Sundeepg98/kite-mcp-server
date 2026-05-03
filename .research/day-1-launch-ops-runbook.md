# Day-1 Launch Operations Runbook — Show HN day

> Single-page operational runbook for Show-HN submission day. Covers traffic-surge handling, comment-triage workflow, monitoring, incident response, and rollback. Distinct from `58dc369` GTM playbook (high-level cadence) and `f30d9fe` red-team rehearsal (comment content); this is **what to actually run on the laptop the morning of submission**.
>
> Author: Research agent (orchestrated). Date drafted: 2026-05-02. State at HEAD `14a188e`. **DOC ONLY** — no code changes.
>
> Companion docs: `docs/incident-response.md` (post-launch incidents), `docs/operator-playbook.md` (day-2 ops), `.research/show-hn-redteam-rehearsal.md` (comment replies), `.research/gtm-launch-sequence.md` (channel cadence), `docs/pre-deploy-checklist.md` (pre-deploy gate).

---

## TL;DR — three operationally critical items the user MUST verify or set up BEFORE pressing Submit

These are the items where **inaction on Day 1 is a self-inflicted outage**. Everything else in this runbook is "nice to have under pressure." These three are go/no-go.

1. **`flyctl machines clone` an extra `bom` machine 10 minutes before submitting.** Today's prod = 1 machine, 512 MB, `min_machines_running=1` (`fly.toml:27`). Show-HN front-page peaks at 50–150 concurrent visitors per `f30d9fe` Phase 2; a single 512 MB machine can serve the **landing page** fine but the SSE-style `/mcp` discovery endpoint plus `/.well-known/oauth-authorization-server` polls under load are the first things to wobble. Pre-stage horizontal capacity: `flyctl machines clone <bom-machine-id> --region bom -a kite-mcp-server` (~₹30/day extra for 24–48h, single-digit USD; tear down via `flyctl machine stop` post-launch). Both machines share the same static egress IP `209.71.68.157` so the SEBI Kite-developer-app whitelist is unaffected. **Do this BEFORE submission, not after the surge starts** — `flyctl machines clone` is a 60–90s cold-start, and the moment you realise you need it is already too late.

2. **Capture and freeze a "last-known-good" Fly.io release ID and Docker image tag.** Open one terminal, run `flyctl releases list -a kite-mcp-server | head -5` and **paste the output into a sticky note / scratch file the user can see during launch**. Likewise `flyctl image show -a kite-mcp-server`. Reason: under stress, "rollback to last good" is a 5-minute fix only if you already know which release was last good. Without the snapshot, finding the right `vN` mid-incident takes 10–15 min and you're rolling back blind. Companion: do NOT push code or `flyctl deploy` between this snapshot and post-launch + 24h. The launch-day diff is "zero new code shipped."

3. **Validate `/healthz?format=json` returns `status: ok` AND `dropped_count: 0` AND verify Litestream replication is live.** Run `./scripts/smoke-test.sh` (13 checks, ~5–15s — already exists at `scripts/smoke-test.sh`). All 13 must be green. Then verify Litestream by SSH'ing in and inspecting WAL freshness: `flyctl ssh console -a kite-mcp-server -C 'ls -la /data/alerts.db-wal /data/alerts.db'` — WAL mtime must be within the last 60 seconds during business hours. If smoke-test fails or Litestream is silent, **defer the launch** until both are green. A silent audit-trail or a stale WAL during a 50–150-concurrent-visitor surge means hours of compliance gap, no rollback path, and any incident-response action that follows is forensically un-reconstructable.

If any of these three is red, **the right action is to delay the launch by 24–48 hours**, not to launch and hope. HN re-submission is allowed; a botched launch is harder to recover from than a deferred one.

---

## Phase 1 — Rate-limit and capacity posture under HN surge

### 1.1 Empirical rate-limit defaults (verified at `app/ratelimit.go:182-197`)

| Endpoint group | Per-IP rate | Per-IP burst | Per-user rate | Per-user burst |
|---|---:|---:|---:|---:|
| `auth` (`/oauth/register`, `/oauth/authorize`, `/oauth/email-lookup`, `/auth/login`, `/auth/browser-login`, `/auth/admin-login`, `/auth/admin-mfa/*`, `/auth/google/*`) | 2/sec | 5 | 2/sec | 5 |
| `token` (`/oauth/token`) | 5/sec | 10 | 5/sec | 10 |
| `mcp` (`/mcp`, `/sse`, `/message`) | 20/sec | 40 | 20/sec | 40 |

Layered (`app/http.go:1088-1145`): IP-rate → `RequireAuth` → user-rate → handler. `Fly-Client-IP` header is honored as the source IP; falls back to `r.RemoteAddr` with port stripped (`app/ratelimit.go:255-263`). `429` responses include an `X-RateLimit-Scope: ip|user` header so callers can distinguish — already documented at `docs/operator-playbook.md` § 2 "HTTP 429 from any tool."

The memory note "auth 2/sec, token 5/sec, MCP 20/sec" is **empirically correct** and **also defended at the per-user layer** (added in a layered defense pass not reflected in older notes). Cleanup goroutine clears stale per-IP/per-user entries every 10 minutes (`app/ratelimit.go:195`).

**Public endpoints with NO in-process rate limit:** `/healthz`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/`, `/robots.txt`, `/security.txt`, `/terms`, `/privacy`. Fly.io edge has its own DDOS protection but no per-IP throttle on these surfaces. **A naive crawler / search-engine bot or a Twitter-card preview farm could hit `/.well-known/*` thousands of times per minute with no in-process rate-limit pushback.** This is the single biggest unknown under surge.

### 1.2 HN surge profile (per `f30d9fe` Phase 2)

- Show-HN front-page top-10 sustains roughly **50–150 concurrent visitors** at peak (~3,000–8,000 unique pageviews over the 4–8h front-page window for a well-prepared post).
- Of those: **~95% never leave GitHub** — they read the README, scroll the file list, decide. Zero load on Fly.io.
- **~3–5% click through** to the hosted demo at `https://kite-mcp-server.fly.dev/`. Most just look at the landing page.
- **~0.3–1%** actually attempt to wire up an MCP client and OAuth in. Each successful flow is ~6–8 HTTP round-trips: `/.well-known/oauth-authorization-server` → `/oauth/register` (dynamic client reg) → `/oauth/authorize` → external Kite redirect → `/oauth/token` → `/mcp` initialize.
- **The github.com domain penalty** (`f30d9fe` Phase 5) means votes need to be ~2× the un-penalized threshold for front-page; the practical effect on traffic is the same ceiling, but the post is more likely to plateau than to spike further.

### 1.3 Capacity check — what breaks first under that profile

Single 512 MB / 1 shared-vCPU machine in `bom`. The break-points, ordered:

| Break-point | At approximately | Symptom | Pre-positioned fix |
|---|---|---|---|
| `/.well-known/oauth-authorization-server` discovery hits unrate-limited | 100+ concurrent crawlers | CPU climb, slog spam, no errors yet | None pre-positioned; Fly.io edge would absorb. Consider Cloudflare in front (out of scope today). |
| Per-IP MCP rate hit by mcp-remote retries at 20/sec | One badly-coded user looping | First user gets 429s, everyone else fine | Working as designed. Operator inspects logs to identify which user. |
| `/mcp` SSE concurrent connections climb past memory headroom | ~80–120 concurrent OAuth'd sessions | Memory crosses 400 MB (`monitoring.md` § 8 alert) | Scale up — see § 1.4. |
| SQLite contention on `tool_calls` audit writes | ~50–100 writes/sec sustained | `dropped_count` from `/healthz` climbs above 0 | Already has buffered async writer; should not happen at HN-surge scale. |
| Fly.io OOM kill | 512 MB exhausted | Machine restart visible in `flyctl status`, `uptime_s` resets in `/healthz` | Pre-staged second machine absorbs without user-visible outage. |

**Most likely actual outcome:** the CPU+memory profile of a 512 MB shared-vCPU machine is more than enough for a 50–150-concurrent-visitor landing-page workload. The risk window is the unauthenticated `/.well-known/*` polling burst plus any surprise from a viral mcp-remote demo (e.g., a popular MCP-tool aggregator scraping every entry on the registry the same hour). The conservative posture is to **double horizontal capacity for 24–48h regardless** rather than wait to react.

### 1.4 Specific tweaks worth pre-launch — exact commands

**A) Horizontal scale (recommended — safest):**

```bash
# 10 min before submission. Idempotent — clones from existing machine in bom.
flyctl machines list -a kite-mcp-server                   # capture the current machine id
flyctl machines clone <machine-id> --region bom -a kite-mcp-server
flyctl machines list -a kite-mcp-server                   # verify count = 2

# Both share the same static egress IP. SEBI whitelist unaffected.
# Cost: ~$0.30-0.60/day on the second machine, depending on Fly metering. Negligible.

# Tear down 24-48h post-launch:
flyctl machine stop <new-machine-id> -a kite-mcp-server
flyctl machine destroy <new-machine-id> -a kite-mcp-server
```

**B) Vertical bump (alternative — louder, more expensive):**

```bash
# Doubles RAM on existing machine. Triggers a restart (~30s of 503s).
# Don't do this WHILE the front-page surge is live — it's a deliberate self-outage.
flyctl scale memory 1024 -a kite-mcp-server
# Reverse:
flyctl scale memory 512 -a kite-mcp-server
```

**C) Rate-limit tightening (NOT recommended pre-launch):**

The current limits are already well-calibrated for the surge profile. Tightening (`auth` to 1/sec, `mcp` to 10/sec) before launch creates 429s for legitimate first-time mcp-remote OAuth flows that are already 6–8 requests in a 10-second window. **Leave defaults alone.** If a single abusive IP shows up post-launch, the right action is identifying it from logs and Fly.io edge-blocking, not narrowing global limits.

**Cost estimate for 24–48h pre-staged surge protection:** A second `bom` machine for 48h is roughly $0.60–$1.20 — single-digit dollars. Compared to a botched launch costing weeks of recovery, this is the cheapest insurance in the plan.

---

## Phase 2 — First 90-min HN comment triage workflow

Source: `f30d9fe` red-team rehearsal Phase 5 + Phase 7 (verbatim timing model retained).

### Minute 0–15: Submit and wait (do nothing visible)

- [ ] Open `news.ycombinator.com/submit`. Use the title from the red-team rehearsal: *"Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards"* (NOT the older "regulated Indian stockbroker" framing — see `f30d9fe` "ONE most important edit").
- [ ] Submit. Note the post URL and HN item ID immediately.
- [ ] **Do not respond to anything yet.** Let upvotes and the algorithm decide whether the post is alive.
- [ ] Open `news.ycombinator.com/show` in a separate tab and refresh once a minute to see your post's relative position.
- [ ] Open the **operator dashboard** (Fly.io console + `flyctl logs -a kite-mcp-server`) in a third tab. Both for monitoring AND so you have working hands when an incident hits.
- [ ] **Do NOT** also tweet yet. The Twitter cross-post comes at minute 60–90 (Phase 6 below) — **not** at minute 0. (`gtm-launch-sequence.md` Channel E: "post a launch thread on the same day as Show HN goes live, ~2 hours after Show HN.")

### Minute 15–30: First comments arrive — triage rules

- [ ] **Good-faith technical questions** (e.g., "how does prompt-injection defense work?", "why Go not Python?"): respond immediately, brief, ≤80 words. Use prepared replies from `f30d9fe` Phase 3 (top-10 worst-cases) and `docs/show-hn-post.md` lines 38–70 (existing 9 prepared replies, with #4 SEBI and #9 business-model already replaced per red-team's recommendation). **Sources are pre-staged** — copy-paste, lightly customize for the specific commenter, send within 5 minutes of seeing the comment.
- [ ] **Obvious bad-faith** (drive-by snark, "tipping bot lol", off-topic shitposts): downvote (you have karma to do so), do not engage. Engaging legitimizes them.
- [ ] **Explicit spam / abuse**: flag to mods (small flag icon on each comment). Do not reply.
- [ ] **The killers** (per `f30d9fe` Phase 7 abort actions): a hostile top comment with >5 upvotes within 30 min, or a regulator-tone critique gaining traction. Engage these **immediately, calmly, factually, ≤5 minutes after seeing**. Even a brief reply beats silence — silence reads as "they don't have an answer."
- [ ] Keep replies short. Aim ≤80 words each. **Don't argue.** State a fact, link to code, end the reply. The reply that sounds like "I'm right, you're wrong" is a magnet for downvotes.

### Minute 30–60: Position decided — front-page or not

- [ ] **If on front-page top-30 by minute 30**: maintain comment cadence, aim for one substantive reply every 5–10 minutes. Don't over-respond — replying to every single comment looks needy. Pick the best 1–2 in each batch and ignore the rest until they accumulate upvotes.
- [ ] **If NOT on front-page** (post is on page 3+, or worse, flagged): the post is essentially dead in this window. Acknowledge it. **Do not panic-post**. Don't try to rescue with more replies — replies on a buried post don't move the algorithm.
- [ ] **Pivot to second-chance candidates**: HN's second-chance pool ([`hn.algolia.com`](https://hn.algolia.com/) + `news.ycombinator.com/pool`) overnight-rescues posts that had quality but wrong-time. Once a post has at least 5 votes and ≥1 thoughtful comment, the second-chance pool may pick it up overnight US time (~02:00–06:00 UTC). **Don't rage-delete** — see `f30d9fe` Phase 7: deletions are visible in archives and signal panic.

### Minute 60–90: Position freezes (per Righto algorithm `f30d9fe` Phase 5)

- [ ] **Algorithm freeze**: HN's gravity exponent (`(votes-1)^0.8 / (age_hours + 2)^1.8`) and the controversy-penalty rule (`comments > votes` + `40+ comments` triggers severe penalty per `f30d9fe`) mean by minute ~90 the post's trajectory is largely set. Don't try to rescue with frantic comment-thread engagement; that **increases** the comments-to-votes ratio and *worsens* ranking via the controversy penalty.
- [ ] **Twitter cross-post NOW** (only now, not before — see `gtm-launch-sequence.md` Channel E). One single tweet thread, link to HN post in tweet 7 (not tweet 1; algorithm punishes tweet-1 link-out). Source: `docs/launch/03-twitter-thread.md` and `docs/twitter-launch-kit.md`. Don't QRT Nithin/Kailash/Zerodha to bait — anti-pattern explicit in `twitter-launch-kit.md`.
- [ ] If the post is alive: post the existing Reddit `r/algotrading` long-form draft (`docs/reddit-buildlog-posts.md`). **Wait 60–90 min between HN and Reddit** so the HN audience and the Reddit audience don't see the same content within the same scroll.

### Minute 90+: Step back (this is the rule, not an option)

- [ ] **React to net activity, not minute-by-minute**. Check every 15–30 min, not every 30 seconds. Constant refreshing trains your nervous system to catastrophize each comment.
- [ ] **If a hostile comment threads >50 net upvotes against you**: re-read the prepared reply for that scenario in `f30d9fe`, post **once**, walk away. **Do not double-post, do not edit-bomb, do not engage replies-to-replies**.
- [ ] **Step away for an hour at minute 90** if the launch went badly enough to be triggering. The post does not need you. Coming back angry/defensive is when founders post the regrettable response.

### Standing rules (apply throughout the 90 min)

- **No vote-soliciting** — `f30d9fe` Phase 5 explicit: do NOT message friends asking for upvotes. Vote-rings are detection-trivial and shadowban risk is real. The Twitter cross-post + Reddit cross-post **organic** traffic is allowed; messaging individuals is not.
- **No deletion** — `f30d9fe` Phase 7. Even if the post is dying, leave it. Deletions are archived and look worse than weathering a flop.
- **No drinking** — your judgment is the load-bearing constraint here, not the server's. Caffeine, water, and one screen at a time.

---

## Phase 3 — Day-1 metrics dashboard (what to watch)

Each line: **what** | **how** | **healthy range** | **alert threshold (deferred-action: log it, decide later)** vs **panic threshold (act now)**.

### 3.1 Project signals (where the launch lives)

```bash
# GitHub stars trajectory
gh api repos/Sundeepg98/kite-mcp-server | jq '.stargazers_count'
# Healthy: increases monotonically. Alert: 0-3/hr after first hour. Panic: never; this is just a signal.

# HN post position (manual, no scriptable API — refresh news.ycombinator.com/show)
# Healthy in first hour: top 30 of /show. Panic threshold: page 3+ at hour 1 = post is dead.

# HN comment count + score (per item ID; replace 12345 with actual ID)
gh api 'https://hacker-news.firebaseio.com/v0/item/12345.json' | jq '{score, descendants}'
# Healthy: comments < score * 1.2 (avoids controversy penalty per Righto). Panic: comments > score * 2.

# Twitter launch tweet engagement (after minute 60-90 cross-post)
# Healthy: >5 likes on tweet 1 within 30 min of posting. Panic: 0 likes at 1h - thread is dead.
```

### 3.2 Server signals (where outages live)

```bash
# /healthz — single source of truth for application state
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
# Healthy: status=ok, components.audit.status=ok, components.riskguard.status=ok,
#          components.audit.dropped_count=0, uptime_s monotonically increasing.
# Alert: components.audit.dropped_count > 10 sustained.
# Panic: status != ok for >5 min, OR uptime_s resets (machine crash-loop).

# Smoke-test (13 checks bundled — run before launch + at minute 30 + minute 90)
./scripts/smoke-test.sh https://kite-mcp-server.fly.dev
# Healthy: 13/13 PASS. Alert: 1-2 warnings. Panic: any FAIL.

# /mcp hit rate (Fly.io request logs — tail-ahead during launch)
flyctl logs -a kite-mcp-server | grep '/mcp '
# Healthy: trickle (~0-5 requests/sec at peak, mostly initialize handshakes).
# Alert: 50+/sec sustained = something is looping.
# Panic: 5xx errors on /mcp = middleware is broken.

# OAuth completions (count distinct sessions in audit log over the launch window)
flyctl ssh console -a kite-mcp-server -C 'sqlite3 /data/alerts.db \
  "SELECT COUNT(DISTINCT user_email) FROM tool_calls \
   WHERE ts > datetime(\"now\", \"-2 hours\");"'
# Healthy: any non-zero number after 1h means at least one user successfully OAuth'd.
# Panic: 0 after 2h with the post on front-page = OAuth flow is broken end-to-end.

# Error rate
flyctl logs -a kite-mcp-server --limit 500 | grep -iE 'error|panic|fatal' | head -50
# Healthy: zero panics, occasional benign 'rate-limited' or 'kite token expired' for users.
# Panic: any panic, OR sustained 5xx in logs.

# Memory / CPU on Fly.io instance
flyctl metrics -a kite-mcp-server                  # live, last 1h
flyctl status -a kite-mcp-server                   # current machine state
# Healthy: memory <400 MB, CPU <70% sustained (per docs/monitoring.md § 8).
# Alert: memory 400-450 MB sustained for 5+ min.
# Panic: memory >450 MB - machine likely to OOM.
```

### 3.3 Cost signal (so the bill doesn't surprise you)

```bash
# After launch, check egress + machine-hour billing
flyctl billing show -a kite-mcp-server
# Healthy day: <$1 incremental for the cloned-machine + slight egress bump.
# Surprise threshold: >$10 for the launch day = something pulled traffic abnormally.
```

---

## Phase 4 — Incident response decision trees

Each: **trigger** → **first action** → **decision criterion** → **rollback option**. Read once before launch; don't read mid-incident.

### 4a. Hosted demo crashes mid-launch (`/healthz` 5xx or non-200)

**Trigger:** `curl -s -o /dev/null -w "%{http_code}" https://kite-mcp-server.fly.dev/healthz` returns 5xx for >2 min, or `flyctl status` shows machine red.

**Action sequence:**
1. `flyctl logs -a kite-mcp-server --limit 500 | grep -A 20 panic | head -80` — what's the actual error?
2. If panic in audit/riskguard middleware: **rollback** rather than diagnose under stress.
3. **Rollback**:
   ```bash
   flyctl releases -a kite-mcp-server                 # find prior release vN
   flyctl rollback vN -a kite-mcp-server               # ETA <5 min
   ```
   Reuse the snapshot from TL;DR item 2 — saves the lookup.
4. Post a single GitHub Discussion comment + a single HN reply: "Hosted demo briefly down — investigating, repo is at github.com/... while I look. Self-hosters unaffected." **One** post, no thread.

**Decision rule:** if rollback restores `/healthz: ok` within 10 min, don't post-mortem until tomorrow. If rollback doesn't help (the bug is in data, not code), **scale to 0 machines** and pivot the launch narrative to "self-hosted only, hosted demo offline due to surge — repo here." Better than 30 min of intermittent 5xx that everyone notices.

### 4b. Unauthenticated `/mcp` traffic surge causes session-store DOS

**Trigger:** `flyctl logs | grep 'session created'` shows 100+/min, OR `flyctl ssh console -C 'sqlite3 /data/alerts.db "SELECT COUNT(*) FROM sessions;"'` returns >1000 (vs ~10–50 normal).

**Action sequence:**
1. Identify pattern. Is it one IP looping, one user-agent, one referrer? `flyctl logs | grep '/mcp '` and look at the `Fly-Client-IP` distribution.
2. If single IP: have Fly.io edge-block via the dashboard's **Apps → Network** rules (no in-process work needed, no deploy).
3. If pattern (e.g., a Twitter card-preview farm hitting the discovery endpoint): the in-process rate-limiter *should* have caught this on `/mcp` (20/sec), but the unauth `/.well-known/oauth-authorization-server` endpoint is unrate-limited (Phase 1.1). Fly.io edge-block is the fix.
4. **Don't** narrow global rate limits mid-incident. They're calibrated for honest users; tightening blocks legitimate first-time OAuth flows that are 6–8 requests in 10 seconds.

**Decision rule:** if Fly.io edge-block restores normal session-creation rate within 15 min, monitor and continue. If session count keeps climbing, **scale to 0 machines for 30 min** to drain — then come back up cleanly.

### 4c. Zerodha noticed + sent C&D email mid-launch

**Trigger:** an email at `sundeepg8@gmail.com` (or any monitored inbox) from a `@zerodha.com` address with subject containing "kite-mcp-server" and tone formal.

**Action sequence:**
1. **Acknowledge within 24h** — three-line acknowledgment. Per `docs/incident-response.md` Scenario 4 / Scenario 1: do NOT respond on your own; engage Spice Route Legal first if it reads as legal.
2. If the email is from `kiteconnect@zerodha.com` (developer-relations) and reads informational/concerned: this is the friendly track. The pre-drafted compliance disclosure at `docs/drafts/zerodha-compliance-email.md` is the response template — **but lean on Path 2 / per-user OAuth posture** explicitly. Cite `ENABLE_TRADING=false` on hosted (verified at `fly.toml:47`).
3. **Don't escalate.** Don't quote-tweet, don't post to HN, don't tell supporters. Anything you tell anyone becomes public if forwarded (Hour 0–2 rule from `docs/incident-response.md` Scenario 1).
4. If C&D names a specific ask (e.g., "stop using the name Kite" or "disable trading on hosted"): comply with that specific ask within 72h. The `kite-algo2go-rename.md` rename plan is pre-staged for the trademark case; the `flyctl secrets set ENABLE_TRADING=false` is already current.

**Decision rule:** if the email is operational/cordial, the launch can continue but slow down to one-channel-at-a-time and monitor for follow-up. If it's a formal C&D, **pause the launch immediately**, take down the Twitter thread, leave the HN post (deletion looks worse), engage lawyer.

### 4d. SEBI-adjacent voice tweets / posts hostile

**Trigger:** a SEBI-known handle (or a fintech journalist with regulator-adjacent reach) QRTs the launch tweet or comments on the HN thread with a "this is unregistered investment advice" framing.

**Action sequence:**
1. **Don't respond on Twitter.** Quote-RT engagement amplifies. Mute the QRT thread.
2. **If the comment lands on HN**: respond ONCE with the SEBI rebuttal from `f30d9fe` Phase 4 (TL;DR worst-case 2): "Direct answer: no, I am not registered as a SEBI RA or IA, and the April 2026 algo rules are exactly why this is a *tool*, not a service. The server doesn't bundle strategies or signals — it exposes Kite Connect API methods to the user's own LLM client, runs on the user's own developer-app credentials..." [~95 words verbatim from `f30d9fe`]
3. **One reply only.** Replies-to-replies on a regulatory thread go nowhere good. State the fact, link `docs/legal-notes.md`, walk away.
4. If the reach hits 1k+ retweets / >100 upvotes on HN: time to **email Zerodha proactively** with `docs/drafts/zerodha-compliance-email.md` as a "I noticed this discussion; here is my architectural posture, please flag any concerns" disclosure. Cheapest paper trail per memory.

**Decision rule:** if traction stays under 100 net upvotes / 100 retweets, ride it out. Above that threshold, proactive Zerodha disclosure is the move BEFORE they notice on their own.

### 4e. HN thread top-voted unfair criticism

**Trigger:** a top comment within the first hour with >20 upvotes, framing the project as YOLO-tooling / scam / unmaintained.

**Action sequence:**
1. Match the criticism to a prepared reply in `f30d9fe`:
   - "AI + real money = irresponsible" → worst-case 1
   - "SEBI registered?" → worst-case 2
   - "Solo dev, 6 months out?" → worst-case 3
   - "How does it differ from mcp.kite.trade / Streak / Sensibull?" → worst-case 4
   - "Prompt injection attack?" → worst-case 5
   - "Why Go / SQLite / MCP?" → worst-case 6/7/8
   - "Business model / enshittification?" → worst-case 9
   - Other → write fresh, keep ≤80 words, link to code.
2. If criticism is **technically correct**: 1-line acknowledgment ("fair point — `mcp/integrity.go:17` does X today; switching to Y is on the roadmap"). Concede + commit. **Don't argue.**
3. If criticism is **technically wrong**: brief factual rebuttal, link to code, ≤80 words. Don't argue with downvoters; the comments thread isn't where minds change.
4. **If a hostile comment hits >50 upvotes against you**: do NOT post a second reply. The thread has decided; doubling-down looks defensive.

**Decision rule:** for every prepared reply, the explicit go-criterion is "≤80 words, link to code, one reply per criticism." Anything more elaborate is wrong.

### 4f. RiskGuard accidentally blocks legitimate users

**Trigger:** `admin_list_anomaly_flags` MCP tool returns >0 entries with reason `verify-blocked-suspicious` from organic launch traffic. Or: a user reports "place_order returned 'anomaly threshold exceeded'" and they look legitimate.

**Action sequence:**
1. Check the audit trail for that user: `flyctl ssh console -a kite-mcp-server -C 'sqlite3 /data/alerts.db "SELECT * FROM tool_calls WHERE user_email = \"X\" ORDER BY ts DESC LIMIT 20;"'`. Is the pattern actually anomalous?
2. **If it's a real attack pattern**: keep the block, explain to the user, point them at the audit trail.
3. **If it's a false positive** (e.g., a new user trying their first 5 orders and tripping the daily-count): increase the threshold via env var. The relevant envs are documented at `kc/riskguard/limits.go` (per memory: 20 orders/day, ₹2L notional, ₹50k/order). Adjust ONE at a time, redeploy, monitor.
4. **Critical**: don't disable RiskGuard wholesale. Mid-launch is the worst time to remove the safety net — a runaway LLM in any user's workflow becomes a regulator-grade incident in minutes.

**Decision rule:** false-positive-rate <5% over the launch window = no action; >5% = nudge one threshold up by 50% and redeploy. Anything more aggressive = post-launch only.

---

## Phase 5 — Disaster-recovery checklist (Litestream)

Per memory `kite-session-apr3.md`: SQLite `/data/alerts.db` replicates to Cloudflare R2 bucket `kite-mcp-backup` (APAC) every 10s. Auto-restore on boot. Wired at `etc/litestream.yml` (verified). $0/month effective cost.

### 5.1 Pre-launch validation (run today, before submission)

```bash
# 1. Is Litestream actively running on the prod machine?
flyctl ssh console -a kite-mcp-server -C 'pgrep -af litestream'
# Healthy: returns one or more litestream processes. Empty = NOT replicating.

# 2. WAL is being written
flyctl ssh console -a kite-mcp-server -C 'ls -la /data/alerts.db /data/alerts.db-wal /data/alerts.db-shm'
# Healthy: all three exist; -wal mtime is within last 60s during business hours.

# 3. R2 has a recent generation
flyctl ssh console -a kite-mcp-server -C 'litestream snapshots -config /etc/litestream.yml /data/alerts.db'
# Healthy: at least one snapshot in the last 24h, freshest within last hour.

# 4. (OPTIONAL — risky to do on launch day) test restore in WSL2 to a scratch path
# Skip on launch day. Add as TODO post-launch.
```

### 5.2 Restore drill — TODO honestly

**Has a real restore drill been performed on this codebase?** Per memory: backup is wired and "Auto-restore" is documented, but **no record of a successful from-scratch restore test against this specific deployment was found** in the docs surveyed. The Litestream binary's restore *path* is well-tested upstream; the *integration* with this deployment's encryption keys (token-store re-decrypts after restore, anomaly-cache rebuilds, `SessionRegistry` lazy-init) **has not been demonstrated end-to-end**.

**On launch day**: defer drill. Add as a TODO for week 2 post-launch.

**Drill procedure (when run)** — schedule for first quiet weekend post-launch:

```bash
# In WSL2, scratch directory
cd /tmp/restore-drill && rm -rf alerts.db alerts.db-wal alerts.db-shm

# Get a known-good Litestream config (copy etc/litestream.yml + R2 creds in env)
litestream restore -config /tmp/restore-drill/litestream.yml -o /tmp/restore-drill/alerts.db

# Verify schema, sample tool_calls rows decrypt, sample kite_credentials decrypts
sqlite3 /tmp/restore-drill/alerts.db '.schema tool_calls'
sqlite3 /tmp/restore-drill/alerts.db 'SELECT COUNT(*) FROM tool_calls;'

# Result: known-good baseline timestamp recorded as "restore confirmed working at YYYY-MM-DD"
# Update docs/incident-response.md and docs/operator-playbook.md with the actual confirmation date.
```

### 5.3 Last-known-good chain checkpoint

**Today (Day 0)**: assume the chain works because per-component health flags it active. Capture today's date as the *boundary* of last-known-good. If a launch-day incident requires restore, **the drill happens during the incident**, not before — accept that risk explicitly. The mitigation is: the Fly.io machine has its own local SQLite `/data/alerts.db` that survives a process-restart, and rollback (Phase 4a) covers the more likely outage class. R2 restore is the disaster-grade fallback.

---

## Phase 6 — Post-90-min stretch goals

If launch goes well (Show HN top-30 sustained at hour 1, organic Twitter pickup):

- [ ] **Twitter cross-post** at minute 60–90. One thread, 7 tweets, GitHub link in tweet 7. Source: `docs/launch/03-twitter-thread.md` and `docs/twitter-launch-kit.md`. (`gtm-launch-sequence.md` Channel E — already drafted.)
- [ ] **Reddit `r/algotrading` long-form** at hour 2–3 (wait 60–90 min after Twitter, so the audiences don't see the same thing). Source: `docs/reddit-buildlog-posts.md` long body. NOT `r/IndianStockMarket` until Day 2 — same-day double-post fragments traffic and triggers cross-post detection on `r/algotrading`.
- [ ] **`awesome-mcp-servers` 3 PRs** — `punkpeye` (sub-hour merges), `mcpservers.org` (form), `jaw9c` (strict). All three can submit in parallel. Sources: `gtm-launch-sequence.md` Channel C1/C2/C3.
- [ ] **MCP Registry**: already published per memory (`io.github.Sundeepg98/kite-mcp-server@1.2.0`, `publishedAt 2026-04-19`). No action.

If launch is meh (Show HN buried, no traction):

- [ ] **Don't burn other channels same day**. Save Reddit for Day 2.
- [ ] **Twitter still goes** — owned channel, low risk; the cadence pays off independently of HN result.
- [ ] **Don't re-attempt Show HN**. Wait 6–8 weeks per `f30d9fe` Phase 7 abort actions; the second-chance pool may pick up the existing post overnight.
- [ ] Switch the wedge to FLOSS/fund + IndiaFOSS CFP per `gtm-launch-sequence.md` Phase 2 Scenario 3 — the Rainmatter trigger isn't 50 stars from a botched launch; it's 50 stars from sustained credibility-building.

---

## Phase 7 — Standing rules during the day

- WSL2 (`/mnt/d/`) for any code reads, log probes, smoke-test runs.
- `git commit -o -- <path>` path-form for any commits.
- NO `git add -A`, NO `--rebase`, NO worktrees, NO `git stash`.
- DOC ONLY — zero code shipped Day 0.
- `flyctl deploy` is forbidden Day 0 except as an emergency rollback (Phase 4a). Code freeze starts the morning of submission.
- Caffeine, water, ONE screen at a time. The launch needs the operator more than the operator needs the launch.

---

## Cross-references

- `docs/incident-response.md` — formal incident classes (PR/API/security/legal). Day-1 covers Scenarios 1+2 in passing; full procedures live there.
- `docs/operator-playbook.md` — daily-ops, recurring tasks, post-incident routines.
- `docs/monitoring.md` — full surface inventory (`/healthz`, `server_metrics`, audit chain, RiskGuard counters, `X-Request-ID` correlation, Fly.io platform signals, Telegram health).
- `docs/pre-deploy-checklist.md` — pre-deploy gate (run before any code deploy; redundant for launch day since no deploy happens).
- `.research/show-hn-redteam-rehearsal.md` — top-10 worst-case prepared replies, edge cases (4a–4g), domain-penalty discovery, timing model.
- `.research/gtm-launch-sequence.md` — channel cadence, Day-0/Day-1-7 sequencing, three-scenario probability projection.
- `app/ratelimit.go` — empirical rate-limit defaults (line 182).
- `fly.toml` — single-machine `bom` posture (line 23–47).
- `scripts/smoke-test.sh` — 13-check post-deploy validation, run pre-launch + at minute 30/90.
- `etc/litestream.yml` — Litestream R2 config for SQLite WAL backup.

*End of runbook. No code edits. Document only, per brief.*
