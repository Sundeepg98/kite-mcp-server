# Draft — Zerodha Kite Connect compliance disclosure

**Status:** Ready to send. Minor personalization only.
**To:** kiteconnect@zerodha.com
**CC:** talk@rainmatter.com
**From:** <product-email-placeholder> <!-- TODO: replace with product email before publishing -->
**Subject:** Compliance notification — kite-mcp-server (per-user BYO-key architecture)

---

Hello Kite Connect Team,

I am writing to proactively disclose an application I have built on Kite Connect and to request confirmation that its architecture is compatible with the Kite Connect Developer Terms.

**What it is.** `kite-mcp-server` is an open-source Model Context Protocol (MCP) server that lets individual Kite Connect developers use Claude (and other MCP-compatible LLMs) as an interactive interface to their own Kite account. Each order is initiated by the user in chat and confirmed via an explicit click-through prompt before reaching Kite.

**Architecture — single-user by construction.** The server does not aggregate user credentials onto a single developer app. Each user registers their own Kite Connect developer application (their own API key and secret) and logs in via the standard Kite OAuth flow. My deployment holds no master developer key for Kite. Per Developer Terms Section 3, the end-user is Zerodha's Client operating under their own developer subscription — identical to a user running the reference Python/Go Kite client against their own app.

**Hosting & posture.** Hosted on Fly.io (Mumbai region, static egress 209.71.68.157). Credentials and access tokens are AES-256-GCM encrypted at rest. All tool calls are audit-logged. The deployment runs pre-trade risk checks (order-value caps, rate limits, idempotency keys, anomaly detection, off-hours blocks, kill-switch) and a full audit trail per user. No fully-automated / unattended trading — every order requires the user's confirmation in-session.

**Scope.** Read tools (quotes, holdings, positions, historical, research analytics), order tools (place / modify / cancel / GTT) which are currently **DISABLED on the hosted endpoint** pursuant to NSE/INVG/69255 Annexure I Para 2.8 and enabled only on self-hosted local builds for the user's personal-use safe harbor. Alerts, Telegram notification bot (private 1:1, user-initiated). No credential aggregation, no copy-trading, no social layer, no broker-on-broker resale. Non-commercial; no revenue.

**Requests.**
1. Written acknowledgement that a per-user, BYO-developer-app architecture — where each end-user operates under their own Kite Connect subscription — is compatible with the Developer Terms and requires no additional exchange approval.
2. If any further compliance steps are advisable, please advise.
3. A point of contact for ongoing compliance questions as the project evolves.

A one-page technical summary (data flow, credential handling, risk checks, audit schema) is available on request. Happy to join a call.

Appreciate a response within two weeks if feasible, so I can plan accordingly.

Regards,
Sundeep Govarthinam
<product-email-placeholder> <!-- TODO: replace with product email before publishing -->
Repository: https://github.com/Sundeepg98/kite-mcp-server

---

## Pre-send checklist (30 seconds)

- [ ] Subject line includes product name (avoid "URGENT" etc.)
- [ ] CC talk@rainmatter.com (Rainmatter = relationship arm)
- [ ] No legal threats or regulatory citations that invite classification
- [ ] Mention BOTH hosted (read-only) and local (trading-enabled) explicitly
- [ ] No performance claims, no revenue figures
- [ ] Paste this content into Gmail compose, send

## If they respond: record in `docs/evidence/compliance-emails-sent.md`

## If no response in 4 weeks:
- Follow up politely in same thread (CC Rainmatter again)
- At week 6, post a neutral thread at kite.trade/forum tagging @sujith / @rakeshr — public record creates implicit-tolerance defense
- At week 8, Rainmatter portfolio founder warm intro (Deepak Shenoy @deepakshenoy first)

## Fallback positions if negative response
- "Single-user only": comply immediately; reduce to personal-use self-hosted. `ENABLE_TRADING=false` stays on Fly.io.
- "Need exchange approval": ask Zerodha to sponsor per ToS §2(e). Pivot to self-hosted-only if prohibitive.
- "Rearchitect X": request specifics; evaluate. Read-only rearchitect is already complete via Path 2.
