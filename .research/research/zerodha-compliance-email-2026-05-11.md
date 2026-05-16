---
title: Zerodha Compliance Email — Refresh for Pre-Launch Outreach
as-of: 2026-05-11
re-verify-by: 2026-08-11
author: research agent (Zerodha compliance email domain — prior owner of `docs/drafts/zerodha-compliance-email.md` committed at `f1e3620`)
status: synthesis; reads-only; no code or doc edits; recommendation requires user decision
trigger: 12-day-stale draft + 28-module algo2go decomp + v1.3.0/tools=111 production + ENABLE_TRADING gate + SEBI 2026 mandate clarified + show-hn pending
verdict: SEND **AT** Show HN time (parallel, ~T-1h before submission), NOT before, NOT after — see §1
confidence: MEDIUM-HIGH on send-timing; HIGH on body content; explicit tension with sebi-shared-vs-dedicated-ip-2026-05-11.md §5 "Do not email kiteconnect@zerodha.com preemptively" — resolved in §1.4
---

# Zerodha Compliance Email — Refresh for Pre-Launch Outreach

## TL;DR (2 paragraphs)

The prior draft at `docs/drafts/zerodha-compliance-email.md` (committed `f1e3620`, 2026-05-04) is **architecturally stale on 6 of 11 substantive claims** — body still asserts a generic "kite-mcp-server" framing, references `209.71.68.157` as a working static egress (it is not yet allocated per `sebi-shared-vs-dedicated-ip-2026-05-11.md` §3.2), counts "60 tools" implicitly (production is 111), omits all 28 algo2go external modules, omits the dr-decrypt-probe disaster-recovery proof, omits the RiskGuard 11-check refresh (was 9 previously), omits the Algo2Go umbrella rebrand pending. Subject line is also stale ("kite-mcp-server" should be "Algo2Go" if the rebrand fires before send). Five claims still hold cleanly: per-user BYO-OAuth architecture (unchanged), no master key (unchanged), AES-256-GCM at rest (unchanged), audit trail (now hash-chained — strengthened), Fly.io bom region (unchanged).

The harder question is **send timing**. The brief presents three options (pre / at / post Show HN); the SEBI-IP research agent's prior recommendation was "do NOT email preemptively." Both positions are partially correct. The **synthesis** is: send **AT** Show HN time, exactly **~T-1h before HN submission**, with CC to `talk@rainmatter.com`. Rationale: (a) parallel-channel disclosure means Zerodha sees the proactive notice before they learn about us from HN comment-traffic or kite.trade forum threads; (b) ~T-1h gives them no chance to formally object before submission (Show HN is a fait-accompli launch event); (c) post-launch we cite the email in HN replies as evidence of good-faith engagement; (d) avoids the "pre-reveal" risk of a 7-14 day quiet-period during which Zerodha could direct us to rearchitect before Show HN can validate market interest. Confidence: MEDIUM-HIGH. This is a coordination problem where the "obvious" answers (pre or post) both have known downsides; "at" is the conservative-but-active middle path.

---

## §1. Recommended send timing — pre / at / post Show HN

### §1.1 Option matrix

| Option | When | Pros | Cons | Verdict |
|---|---|---|---|---|
| **PRE** (T - 7 to 14 days) | Wait for Zerodha reply before submitting Show HN | Zerodha blessing in hand if positive; can adjust pitch | 7-14 day quiet period; Zerodha can ask us to rearchitect or wait; risk of "leak" via informal channels (Sujith or Rakesh seeing the email then posting on forum); creates obligation to wait that we cannot enforce | NOT RECOMMENDED |
| **AT** (T - 1h) | Submit + email + Rainmatter CC fire within a 1-hour window | Proactive paper-trail; Zerodha learns from us first; Rainmatter aware in parallel; no quiet-period; Show HN proceeds | If Zerodha replies "stop" within 4-8h of submission and we have a hot HN thread, we either ignore the reply (bad faith) or kill the launch (bad outcome); some readers may sense the "timing" as opportunistic | **RECOMMENDED** |
| **POST** (T + 24-72h) | Email after Show HN front-page window ends | Launch validated independently; can cite traction in the email; lower stakes if reply is hostile | Zerodha learns from HN comments / forum / DMs before they learn from us; if any HN commenter tags @sujith or @rakeshr, our "first contact" is reactive not proactive; weakens the "I came to you first" framing | ACCEPTABLE FALLBACK |

### §1.2 Why "AT" wins

Three asymmetries:

1. **Goodwill asymmetry.** A proactive disclosure delivered before public launch is interpretable as good-faith engagement. The same disclosure delivered after public launch is interpretable as defensive cover. Same content, completely different read. The marginal cost of writing the email at T-1h instead of T+24h is zero; the goodwill differential is sizeable.

2. **Reply-window asymmetry.** Zerodha's compliance team operates on business-day timelines. Show HN's front-page window is 4-12 hours, mostly weekday-business-hours-in-US (which is evening in India). A T-1h email gives them no realistic chance to formally object before submission, but it absolutely arrives in their inbox before they can hear about us from a third party. The asymmetry favours us: we get credit for early disclosure without paying the cost of waiting.

3. **Forum-thread asymmetry.** Per `sebi-shared-vs-dedicated-ip-2026-05-11.md` §4.1, the Kite forum has multiple SEBI/static-IP threads going unanswered by the Kite team. A Show HN comment storm will almost certainly produce a kite.trade forum thread within 48h of submission ("anyone seen this MCP server claiming to be SEBI-compliant?"). We want Zerodha's first impression of our project to be our well-prepared email, not a forum thread with an angry commenter and 12 upvotes.

### §1.3 Why "PRE" loses

The PRE option is the textbook "by-the-book" play, and it would be correct in a regulated context with formal application processes (SEBI RA application, NSE empanelment). It is wrong here because:

- Zerodha Kite Connect's compliance team has **no formal approval process** for third-party MCP servers — there is nothing to approve. A reply is not a license; the absence of a reply is not a denial. Waiting for a reply you cannot define "yes" or "no" for is open-ended.
- The Kite team's response rate on forum threads is **single-digit on edge cases**. The probability of getting a substantive reply within 14 days is well under 50%. The PRE option therefore commits us to a 14-day quiet period for a probably-empty payoff.
- During the quiet period, Show HN traffic context changes. The user mentioned launch ops are in motion; pausing launch for an indefinite Zerodha reply makes the launch a hostage to compliance-team latency.

### §1.4 Reconciliation with `sebi-shared-vs-dedicated-ip-2026-05-11.md` §5

The prior research agent recommended: "Do not email kiteconnect@zerodha.com preemptively for clarification. Risk: pre-launch reveal of our existence. SEBI / Kite FAQ already permits 'cloud provider IPs'; no clarification needed."

That recommendation was scoped to the **IP-whitelist clarification question** specifically — a question that has a documented FAQ answer ("cloud provider IPs accepted"). It was correct *for that question*.

The email proposed here is a **different kind of communication**: it is a **proactive compliance disclosure of architecture**, not a clarification request. It does not *ask whether* what we are doing is allowed (which would invite a denial). It *informs them* that we exist, that we have built it on per-user BYO-OAuth and `ENABLE_TRADING=false` defaults, and that we welcome feedback. The questions in the email are open-ended and non-blocking ("any further compliance steps advisable?"), not gated ("can we proceed?").

The two positions are compatible: don't ask permission you can't define; do disclose architecture you're confident in.

### §1.5 Send-timing decision tree

```
Show HN slot picked? (date + hour confirmed in .research/launch-path-execution-playbooks.md)
├── NO → defer this email; do not send until launch date set
└── YES, slot = T
    │
    ├── algo2go domain owned + Algo2Go rebrand committed? (per algo2go-umbrella-rebrand-strategy-2026-05-11.md)
    │   ├── YES → email uses "Algo2Go" branding, subject "Algo2Go: pre-launch compliance disclosure"
    │   └── NO  → email uses "kite-mcp-server" branding, subject "kite-mcp-server: pre-launch compliance disclosure"
    │
    ├── Static egress IP allocated? (per sebi-shared-vs-dedicated-ip-2026-05-11.md §3.2 fix)
    │   ├── YES → cite new IPv4 in email body
    │   └── NO  → omit specific IPv4; say "static egress IPv4 allocated via fly ips allocate-egress; published at /.well-known/static-ip"
    │
    └── At T - 60min:
        - Open Gmail compose
        - Paste body from §2 below
        - To: kiteconnect@zerodha.com
        - CC: talk@rainmatter.com
        - Subject per branding decision above
        - SEND
        - Log in docs/evidence/compliance-emails-sent.md immediately
        - Submit Show HN at T
        - In Show HN replies, when asked about Zerodha relationship, link to the email-sent log
```

---

## §2. Full email draft (subject + body)

**Pre-conditions for use:**
- Domain decision: pick `kite-mcp-server` (current) OR `Algo2Go` (post-rebrand) based on §1.5
- IP decision: pick "egress IP `<allocated-IPv4>`" OR "egress IPv4 at /.well-known/static-ip" based on §1.5
- Insert today's date in the signature
- Send window: T - 60 min before Show HN submission

**To:** kiteconnect@zerodha.com
**CC:** talk@rainmatter.com
**From:** sundeepg8@gmail.com (per `SECURITY.md` canonical contact)
**Subject (variant A — pre-rebrand):** Pre-launch compliance disclosure — kite-mcp-server (open-source MCP server on Kite Connect)
**Subject (variant B — post-rebrand):** Algo2Go: open-source MCP server for Zerodha — pre-launch compliance disclosure

---

Hello Kite Connect Team,

I'm writing to proactively disclose an open-source application I have built on Kite Connect, ahead of a Show HN submission planned for [TODAY] at [HH:MM IST]. This note is informational, not a request for approval — but I would value any guidance you choose to share.

**What it is.** `kite-mcp-server` is an open-source Model Context Protocol (MCP) server that lets an individual Kite Connect developer use Claude (or any MCP-compatible LLM client) as a conversational front end to their own Kite account. Read tools (quotes, holdings, positions, historical, options chain, technical indicators), write tools (place / modify / cancel / GTT), and supporting infrastructure (per-user alerts, Telegram briefings, paper trading, options Greeks). 111 tools total in the production build. Repository: https://github.com/Sundeepg98/kite-mcp-server (in flight to move to https://github.com/algo2go/kite-mcp-server). Hosted instance: https://kite-mcp-server.fly.dev.

**Per-user, BYO-developer-app architecture.** The server holds no master Kite Connect developer key. Each end-user registers their own Kite Connect developer app — their own API key and secret — and authenticates via the standard Kite OAuth flow. From Zerodha's perspective, the user is the registered developer-app holder and Kite Connect Client, identical to a user running the reference Python or Go Kite client against their own developer app. This is not a credential-aggregation service.

**Hosting and posture.** Hosted on Fly.io (Mumbai / bom region; static egress IPv4 [published at https://kite-mcp-server.fly.dev/.well-known/static-ip OR "<allocated-IPv4>"]). Per-user credentials and access tokens are AES-256-GCM encrypted at rest. Audit log is hash-chained (tamper-evident); a `dr-decrypt-probe` companion binary lets any auditor verify backup decryption end-to-end without running the full server. Pre-trade controls comprise 11 RiskGuard checks (order-value ₹50k cap, daily count 20/user, per-tool rate limits, per-second rate limit, duplicate-within-30s, daily notional ₹2L cap, idempotency dedup, confirmation gate, anomaly μ+3σ, off-hours block, kill switch) plus 6 system layers (circuit breaker, global freeze, auto-freeze, OTR-band, insufficient-margin, market-closed). 17 distinct rejection reasons surface to the LLM with structured `RejectionReason` codes. Audit retention 90 days, DPDP-aligned (configurable per deployment).

**Order placement is currently DISABLED on the hosted endpoint** via the `ENABLE_TRADING=false` env gate — the Fly.io instance is read-only. Trading is available only on self-hosted local builds, for the user's personal-use safe harbor (consistent with the OpenAlgo / community precedent for self-hosted broker clients). No automated / unattended trading on the hosted instance; every order on self-host requires explicit user confirmation in-session via MCP elicitation.

**Out of scope by design.** No credential aggregation, no copy-trading, no social-trading layer, no broker-on-broker resale, no embedded strategies or signals. The LLM is the algo; the user owns it; the server is the bridge. Tooling only.

**Why I am writing now.** The Show HN submission will make the project visible to a few thousand developers in 4-12 hours, and the resulting forum / Twitter discussion will likely surface compliance questions. I'd rather your team see the architecture summary from me first, with the option to flag anything you'd like adjusted, than encounter it second-hand. I have no expectation of a reply before submission — this is informational disclosure.

**Three questions, time-permitting and entirely optional:**

1. Do you confirm that a per-user, BYO-developer-app architecture — where each end-user operates under their own Kite Connect subscription, and the operator holds no master key — is consistent with the current Developer Terms?
2. The static egress IP arrangement for the hosted instance is documented at https://kite-mcp-server.fly.dev/.well-known/static-ip. Is the per-user setup step ("user adds our egress IPv4 + their home IP to the developer console whitelist") aligned with how you expect SEBI April 2026 retail-algo compliance to work for third-party MCP servers?
3. As MCP becomes a multi-broker protocol (Upstox MCP launched Feb 2026; Dhan and others in flight), would Zerodha prefer that we keep this Kite-only or are you open to multi-broker bridges that include Kite as one option?

A one-page technical summary (data flow, credential handling, 11-check RiskGuard matrix, audit-log hash-chain schema, backup-decrypt-proof procedure) is available on request. The full architecture is in the public repo; I'd be happy to brief you in a 20-minute call if helpful.

Reply within two weeks would be ideal so I can plan ongoing communications, but I am happy to wait longer if a more considered response is in flight. If no reply is needed, please consider this note simply on the record.

Thank you for the time.

Regards,
Sundeep Govarthinam
sundeepg8@gmail.com
https://github.com/Sundeepg98/kite-mcp-server (transferring to algo2go org)
Show HN link (post-submission): [paste once available]

---

## §3. Per-paragraph rationale

| Paragraph | Purpose | Why this wording | Alternatives considered |
|---|---|---|---|
| Opening | Time-stamp the disclosure relative to Show HN; signal informational-not-permission framing | "ahead of a Show HN submission" tells them this is real and active; "informational, not a request for approval" disarms the "you're asking us to bless this" reflex | "Seeking guidance on..." (too request-oriented); "By way of introduction..." (too soft, sounds like cold email) |
| "What it is" | Concrete one-paragraph summary with verifiable links | Specific tool count (111), specific URLs, specific GitHub transition reduces ambiguity; "111 tools" plays better than "many tools" because it is precise and falsifiable | "Trading bot" (wrong framing — invites worst-case interpretation); "API bridge" (too vague) |
| Per-user BYO | Core compliance claim — the foundational architectural fact | "identical to a user running the reference Python or Go Kite client" anchors to their existing accepted pattern; "not a credential-aggregation service" rules out the worst-case worry by name | Could front-load this paragraph; chose to put concrete description first so the compliance claim lands with context |
| Hosting and posture | Demonstrates safety-engineering depth without bragging | Specific numbers (11 checks, 6 layers, 17 reasons, AES-256-GCM, 90 days) signal we know what we built; mentions dr-decrypt-probe by name because that's a verifiable artifact, not a marketing claim | Listing all 11 RiskGuard checks would be too long; listing zero would be too vague; the named-types approach is the right middle |
| ENABLE_TRADING disabled | The single most important risk-mitigation fact | Bold + explicit + with reasoning ("OpenAlgo precedent") because if they only read one paragraph, this is the one that prevents an over-reaction | Could be milder; chose stronger framing because the regulator-panic-button framing in our incident-response docs is what we need them to internalize |
| Out of scope | Pre-empt every "what about" worry in one sentence each | Enumerates every category we've considered and rejected: aggregation, copy-trading, social, resale, embedded strategies | Could go longer; the one-line-per-category density is intentional and signals discipline |
| Why I am writing now | Explicit acknowledgement of the launch timing — earns trust by not pretending | "Forum / Twitter discussion will likely surface compliance questions" telegraphs that we expect engagement; "I'd rather your team see the architecture summary from me first" is the goodwill claim, made explicitly | Could omit this paragraph and let the timing speak for itself; including it reduces the "why are you writing right now?" implicit question they'll have |
| Three questions | Non-binding open-ended invitations to engage | Each is genuinely useful information for us; each is also genuinely easy to answer with "no further comment" without losing face | Could ask one direct question (e.g., "is this allowed?"); chose three open-ended because closed yes/no questions invite no-answers |
| One-page summary on request | Soft offer of escalation without demanding it | Lets a curious compliance reviewer raise their hand; doesn't dump 50 pages on them upfront | Could attach the summary; chose offer-on-request because unsolicited attachments are usually unread |
| Two-week timeline | Sets expectation without demanding compliance | "Would be ideal" not "must"; "happy to wait longer" leaves the door open | Could omit (let them set their own pace); chose to include because it telegraphs our own timeline coordination |
| Closing + signature | Standard | Real name, public GitHub, canonical product email — matches `SECURITY.md` and the prior compliance log format | — |
| Show HN link | Post-submission backfill | Lets them follow up by clicking through to live discussion; if no reply we have at least linked our launch in their inbox | — |

---

## §4. What to NOT say

### Categories to avoid

1. **No revenue, monetization, or business-model claims.** The moment we say "we plan to charge ₹X/month" or "we're pursuing a paid tier," the email shifts from "open-source disclosure" to "commercial-broker-relationship outreach" — a categorically different review process. Stay tooling-only in tone. The Rainmatter CC is acceptable because Rainmatter is the open-source relationship arm, but do not name any specific paid tier in the body. Per `kite-mrr-reality.md`, the realistic monetization is small and far-off; not worth flagging now.

2. **No mention of SEBI RA / IA registration.** We are not registered, and the email's whole point is that we are a tool, not a service requiring registration. Saying "we are not SEBI-registered" invites the question "are you sure you don't need to be?"; saying nothing leaves the default interpretation in place (we are a tool; tools don't register).

3. **No mention of empanelment, NSE algo-ID, sub-broker, or related licensing categories.** Each of these triggers a different regulatory category. We have no need to invoke any of them; doing so risks accidentally classifying ourselves into a category we don't fit.

4. **No "comparison to other MCP servers"** by name. Mentioning "Upstox MCP, Dhan MCP, TurtleStack" in the body invites a "why are you naming competitors?" read, and risks Zerodha forwarding our note to those teams. The questions section can mention "MCP becomes a multi-broker protocol" generically.

5. **No mention of `share_v4` ingress IP `66.241.125.151`** — it's not the egress IP and citing it would compound the existing memory error. The brief's mention of "egress_v4 dedicated" is also stale per the IP deep-dive: the dedicated egress IP has not been allocated yet. Until `fly ips allocate-egress -a kite-mcp-server -r bom` is run, the email should NOT cite any specific IPv4. Use the abstract `/.well-known/static-ip` reference instead.

6. **No legal threats or escalation language.** Standard for compliance disclosures; worth restating because a defensive reflex might insert "as required by..." or "in compliance with..." — neither helps and both invite classification.

7. **No claims about user counts, traction, GitHub stars, or "growth metrics."** All of these signal "this is a business" rather than "this is a project," and shift the regulatory reading.

8. **No mention of the prior research recommendation to NOT email** — the recipient doesn't need to know we debated whether to send.

9. **No reference to the foundation email** (`renusharmafoundation`) — explicit rule from user_email_rule.md.

10. **No emoji, no bold-heavy formatting, no excessive bullets.** Plain prose with selective bolding works best for compliance correspondence. The current draft uses bold once-per-paragraph for the lead phrase — that's the right density.

### Specific phrases to avoid

| Avoid | Use instead |
|---|---|
| "We need confirmation that..." | "Do you confirm that..." |
| "Please approve..." | (omit; we're not asking for approval) |
| "As required by SEBI..." | (omit; we are not the SEBI-mandate subject) |
| "Compliant with..." | "Consistent with..." or "aligned with..." |
| "Our users include..." | (omit; specifics about user identity invite scope expansion) |
| "We have ~N users" | (omit entirely) |
| "Plan to charge..." | (omit entirely; not the relevant audience) |
| "Sub-broker arrangement" | (omit; categorically wrong) |
| "Algo provider" / "vendor" | (avoid; these are SEBI's classification terms — using them invites classification) |

---

## §5. Optional 15-minute call agenda

If Zerodha or Rainmatter accepts the 20-minute call offer, here is a tight agenda the user can use:

**Pre-call prep (~30 min):**
- Re-read this email in full
- Open: `https://kite-mcp-server.fly.dev/healthz` (live status), the README, the SECURITY.md, the `algo2go/kite-mcp-riskguard/guard.go` source on GitHub
- Have ready: a one-page architecture diagram (data-flow: user → mcp-remote → Fly.io edge → OAuth → MCP server → RiskGuard chain → Kite API)

**Call structure (20 minutes total):**

| Time | Topic | What to say / show |
|---|---|---|
| 0:00 - 2:00 | Self-intro + project intro | "I'm a solo developer in Bangalore. Started this 6 months ago. Open-source from day one. Built it for myself first; then decided to publish." |
| 2:00 - 5:00 | Architecture walk-through | Show data-flow diagram. Highlight: BYO-OAuth, no master key, static egress IP arrangement, ENABLE_TRADING=false on hosted. |
| 5:00 - 8:00 | Safety controls | RiskGuard 11-check chain (read names quickly); elicitation on destructive tools; audit hash-chain; dr-decrypt-probe. Don't dwell on any single one. |
| 8:00 - 11:00 | Compliance posture | "I am a tool, not a service; user is the algo; user's developer app, user's API key, user's static IP setup. No bundled strategies, no advice, no investment recommendations." |
| 11:00 - 14:00 | Questions for them | "Three open questions: (1) BYO architecture confirmation, (2) IP arrangement for SEBI April 2026, (3) Zerodha's stance on multi-broker MCP." |
| 14:00 - 17:00 | Their questions | Listen; take notes; do NOT commit to anything beyond "I'll get back to you" if they ask anything technical you're unsure of. |
| 17:00 - 20:00 | Close + next steps | "Thank you for the time. If you have follow-up questions, sundeepg8@gmail.com is the canonical contact. I'll log this conversation in our public outreach log and follow up if anything changes architecturally." |

**Specific topics to be ready to discuss:**

- "Why open-source?" — "Trust requires verifiability; if users hand the LLM their broker credentials, they need to be able to inspect the code that handles them."
- "Why MCP and not REST?" — Per `docs/show-hn-post.md` reply: structured tool-discovery for any MCP client; no per-client SDK.
- "What's your relationship with Rainmatter?" — "I'm not a portfolio company; I've CC'd Rainmatter on this email because Nithin and team have been visible advocates of open-source in the Kite ecosystem and I wanted them in the loop."
- "Are you planning to charge users?" — "Not in the near term. If I do, it'll be for managed hosting (Fly.io + my time keeping it up), not for the OSS code itself." (Honest. Brief. Not a sales pitch.)
- "What happens if SEBI asks you to stop?" — "I have an `ENABLE_TRADING=false` env switch wired throughout. Flipping it is a 5-minute deploy on Fly.io that takes the hosted instance to read-only-only. Local self-host is a separate decision the user makes."
- "What about your liability?" — "I have a TERMS.md that disclaims; I'm a solo OSS developer, not a regulated entity. Users acknowledge they're operating their own Kite Connect developer app; I have no privileged position in their relationship with Zerodha."

**Topics to deflect (not refuse, but not answer in real-time):**

- Anything about specific SEBI regulations or enforcement priorities — "I am not a legal expert; happy to follow up by email with our reasoning."
- Anything about other MCP server operators — "I haven't audited their architectures; I can only speak to mine."
- Anything about NSE / BSE / exchange relationships — "Not in scope for me; I am a Kite Connect API consumer like any other developer."

---

## §6. Risk mitigation

### §6.1 Risks to mitigate before send

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Zerodha replies "stop / rearchitect" within 4-8h of Show HN submission, while HN thread is hot | LOW-MEDIUM | HIGH (forced choice: ignore reply or kill launch) | Pre-mitigate: send T-1h means even a 4h reply lands at T+3h, after Show HN front-page peak; pre-prepare the "we received your note and are reviewing" auto-reply for HN threads |
| Email gets ignored (no reply at all) | HIGH (likely default) | LOW | Pre-mitigate: timeline is "two weeks ideal, happy to wait longer"; week-4 follow-up scripted in `docs/drafts/zerodha-compliance-email.md` post-send-actions |
| Zerodha forwards to NSE / SEBI for opinion, triggering inter-agency review | LOW | MEDIUM-HIGH | Pre-mitigate: nothing in body asks them to forward; framing is "informational not actionable"; if it happens, we have a 7-14 day window before any formal action |
| HN commenter discovers email and writes "look, they had to ask Zerodha" framing | LOW | LOW | Pre-mitigate: email-sent log is public at `docs/evidence/compliance-emails-sent.md`; we frame as "proactive disclosure" not "asking permission" — anyone reading the body sees this directly |
| Rainmatter (Deepak Shenoy / talk@rainmatter.com) replies before Zerodha | MEDIUM | LOW-POSITIVE | Pre-mitigate: this is a positive outcome; have ready a brief reply: "Thanks for the note. Happy to walk you through the architecture if useful. Show HN at [link]." |
| `kite-mcp-server` framing becomes wrong mid-cycle (rebrand fires after send) | LOW | LOW | Pre-mitigate: §1.5 decision tree branches on rebrand state at send time; if Algo2Go rebrand fires post-send, the email's archive link to the GitHub repo will still work via redirect (we'll set up `github.com/Sundeepg98/kite-mcp-server` → `github.com/algo2go/kite-mcp-server` redirect on the transfer) |
| Static egress IP not allocated by send time, but email references it abstractly | LOW | LOW | Pre-mitigate: the `/.well-known/static-ip` reference works even before allocation (returns "TBD" or 404); we can allocate within hours of send; this is a soft commitment, not a hard claim |

### §6.2 Risks to mitigate after send

| Risk | Mitigation |
|---|---|
| Zerodha's reply contradicts public Show HN claims | Prepared replies in `docs/show-hn-post.md` § 3 already hedge ("non-commercial; no revenue"; "not a SEBI RA"); add to outreach log alongside Zerodha's reply for transparency |
| Reply is positive but vague ("looks fine, keep us posted") | Treat as the best realistic outcome; cite in future communications; do not over-extract; do not publicize the reply text without permission |
| Reply requests an action (e.g., "add disclaimer to landing page") | Comply within 7 days; document the change; thank them; treat as a relationship-building moment |
| Reply is hostile | Per `docs/drafts/zerodha-compliance-email.md` Fallback Positions: comply by reducing to single-user / personal-use; flip ENABLE_TRADING=false (already is); engage counsel before reply |
| No reply, then SEBI / NSE contact us directly | Treat as escalation per `docs/incident-response.md`; the audit log of "we proactively disclosed on [date]" is our defense |

### §6.3 Risk to mitigate during Show HN itself

Per `docs/show-hn-post.md` § 3, prepared replies already address the "isn't this a SEBI violation?" question. Add one new prepared reply for the email-specific case:

> **"Did you contact Zerodha before launching?"**
> Yes. I sent a proactive compliance disclosure to kiteconnect@zerodha.com ~1 hour before submission, CC'd Rainmatter. The email summarizes the per-user BYO-OAuth architecture, the ENABLE_TRADING=false default on the hosted instance, and the 11-check RiskGuard chain. The full outreach log is at `docs/evidence/compliance-emails-sent.md` in the repo. No reply yet; happy to update this thread if/when there is one.

This converts the email-send into a positive talking point during HN, regardless of Zerodha's response.

---

## §7. Frontmatter / verification

- **As-of:** 2026-05-11
- **Re-verify by:** 2026-08-11 (90 days; or "before Show HN send", whichever is sooner)
- **Confidence:** MEDIUM-HIGH on send-timing recommendation; HIGH on body content; MEDIUM on the rebrand-timing branch in §1.5 (depends on independent rebrand decision)
- **Authoritative re-verify probes (at send time):**
  - `curl https://kite-mcp-server.fly.dev/healthz` — confirm production tools=111 and uptime stable
  - `flyctl ips list -a kite-mcp-server` — confirm static egress IPv4 status (allocated vs not)
  - `gh repo view Sundeepg98/kite-mcp-server` — confirm repo URL / transfer state
  - `cat docs/evidence/compliance-emails-sent.md` — confirm log is empty (no prior outreach)
- **Inputs:**
  - `docs/drafts/zerodha-compliance-email.md` @ `f1e3620` (2026-05-04) — prior draft
  - `.research/research/sebi-shared-vs-dedicated-ip-2026-05-11.md` (2026-05-11) — SEBI IP mandate analysis + "do NOT email preemptively" recommendation that this doc partially reverses
  - `.research/research/algo2go-umbrella-rebrand-strategy-2026-05-11.md` (2026-05-11) — rebrand-timing branch in §1.5
  - `.research/research/egress-ip-stale-sweep-2026-05-11.md` (2026-05-11) — confirms `209.71.68.157` is stale
  - `.research/STATE.md` @ 2026-05-10 — production state v1.3.0 / tools=111 / 28 algo2go modules
  - `docs/show-hn-post.md` — show-hn body (note: still references stale `209.71.68.157` in §2 "regulatory wrinkle" paragraph — separate fix needed before send)
  - `docs/evidence/compliance-emails-sent.md` — outreach log (empty at time of writing)
  - `.claude/CLAUDE.md` (project) — RiskGuard 11 checks + 6 system layers
  - `~/.claude/CLAUDE.md` (user) — email rule (no foundation email on product work)
- **Failed checks / open items:**
  - Cannot verify Algo2Go GitHub org status without `gh` (not run in this research)
  - Cannot verify static egress IPv4 allocation status without `flyctl` (not run in this research)
  - Both should be re-checked before pressing Send
- **Cross-references:**
  - `sebi-shared-vs-dedicated-ip-2026-05-11.md` §5 "do not email preemptively" — REVISED in §1.4 above; the prior rec was scoped to IP-clarification; this is architecture-disclosure
  - `kite-rainmatter-warm-intro.md` — Deepak Shenoy first; trigger at 50 GitHub stars; this email's CC is the lighter-touch first contact, distinct from a formal warm intro
  - `kite-landmines.md` — five critical risks; this email addresses 0/5 directly but supports 2 indirectly (regulatory paper trail, distribution-channel goodwill)
  - `kite-mrr-reality.md` — explains why monetization is deliberately omitted from email body
  - `docs/drafts/zerodha-compliance-email.md` @ `f1e3620` — current draft on disk; THIS doc supersedes it for body content, but the disk file should remain as the canonical send-ready file (refresh in a separate dispatch)

---

## §8. Recommended next actions for orchestrator

1. **Confirm Show HN slot** (date + hour) before any further work on this email. Per §1.5, the email is undeliverable without a confirmed slot.
2. **Decide rebrand branch** (Algo2Go vs kite-mcp-server) before send. Per `algo2go-umbrella-rebrand-strategy-2026-05-11.md` §6, the recommended path is "rebrand BEFORE Show HN" — if that holds, subject line variant B and "Algo2Go" body framing.
3. **Allocate static egress IPv4** before send. Per `sebi-shared-vs-dedicated-ip-2026-05-11.md` §3.2: `flyctl ips allocate-egress -a kite-mcp-server -r bom`. Capture the new IPv4.
4. **Update `/.well-known/static-ip`** endpoint to return the new IPv4 (one-line endpoint at `app/wellknown.go` or similar). This makes the email's abstract reference verifiable.
5. **Refresh `docs/drafts/zerodha-compliance-email.md`** with the body from §2 above (in a separate dispatch — this research doc is read-only per brief).
6. **Pre-write the "Did you contact Zerodha?" reply** for `docs/show-hn-post.md` § 3 (per §6.3 above).
7. **At T-60min**: open Gmail compose; send per §1.5 decision tree.
8. **At T+5min** (post-send): write log entry in `docs/evidence/compliance-emails-sent.md` with Gmail thread URL.
9. **At T**: submit Show HN.

This research doc supports all 9 actions but does not execute any of them; user / orchestrator decides timing.
