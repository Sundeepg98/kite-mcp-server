# Final — Zerodha Kite Connect compliance disclosure email

**Status:** Ready to send. Placeholder resolved (product email = `sundeepg8@gmail.com`).
**To:** kiteconnect@zerodha.com
**CC:** talk@rainmatter.com
**From:** sundeepg8@gmail.com
**Subject:** Compliance disclosure — kite-mcp-server (per-user BYO Kite Connect app architecture)

---

## Final email body (paste this into Gmail compose)

Hello Kite Connect Team,

I am writing to proactively disclose an open-source application I have built on Kite Connect and to confirm its architecture is consistent with the Kite Connect Developer Terms before I publicise it more widely.

**What it is.** `kite-mcp-server` is a Model Context Protocol (MCP) server that lets an individual Kite Connect developer use Claude (or another MCP-compatible LLM client) as a conversational front end to their own Kite account — quotes, holdings, positions, historical data, and order placement initiated by the user in chat with explicit click-through confirmation before the order leaves the server.

**Per-user, BYO-developer-app architecture.** The server holds no master Kite Connect developer key. Each end-user registers their own Kite Connect developer app — their own API key and secret — and authenticates via the standard Kite OAuth flow. From Zerodha's perspective the user is the registered developer-app holder and Kite Connect Client, identical to a user running the reference Python or Go Kite client against their own developer app. This is not a credential-aggregation service.

**Hosting and posture.** Hosted on Fly.io (Mumbai region; static egress IP `209.71.68.157` available for IP-whitelisting). Credentials and access tokens are AES-256-GCM encrypted at rest. Every tool call is audit-logged per user. Pre-trade controls include order-value caps, per-tool rate limits, idempotency keys, anomaly detection, off-hours blocks, and a kill switch. Order placement on the hosted endpoint is currently **DISABLED** via the `ENABLE_TRADING=false` env gate — read-only on the Fly.io deployment, with order placement available only on self-hosted local builds for the user's personal-use safe harbor. No automated / unattended trading; every order requires explicit user confirmation in-session.

**Out of scope, by design.** No credential aggregation, no copy-trading, no social layer, no broker-on-broker resale, no commercial revenue.

**Three questions, if you can clarify:**

1. Do you confirm that a per-user, BYO-developer-app architecture — where each end-user operates under their own Kite Connect subscription, and the operator holds no master key — is compatible with the Developer Terms and requires no additional exchange approval?
2. If we later wish to recover hosting costs (for example a small per-month fee covering Fly.io infra, with the end-user still on their own Kite Connect app), is there a position you can share on monetisation of an MCP bridge of this kind?
3. As MCP becomes a multi-broker protocol, would Zerodha prefer that we keep this Kite-only or are you open to multi-broker bridges that include Kite as one option?

A one-page technical summary (data flow, credential handling, risk-check matrix, audit-log schema) is available on request, and I would be happy to join a 20-minute call if helpful. Repository: https://github.com/Sundeepg98/kite-mcp-server. Hosted endpoint: https://kite-mcp-server.fly.dev.

A reply within two weeks would be ideal so I can plan my public launch around your guidance, but I am happy to wait longer if a more considered response is in flight.

Thank you for the time.

Regards,
Sundeep Govarthinam
sundeepg8@gmail.com
https://github.com/Sundeepg98/kite-mcp-server

---

## Send-readiness checklist

| Check | Status | Note |
|-------|--------|------|
| Product email resolved (no `<placeholder>`) | DONE | `sundeepg8@gmail.com` per SECURITY.md, .env.example, plugin.json, funding.json |
| Foundation email NOT used anywhere | DONE | Verified — no foundation-context email reference in body or signature |
| Recipient + CC correct | DONE | `kiteconnect@zerodha.com`, CC `talk@rainmatter.com` |
| Subject line clear, no urgency theatre | DONE | "Compliance disclosure — kite-mcp-server (per-user BYO Kite Connect app architecture)" |
| Three substantive questions present | DONE | Per-user model confirmation, monetisation stance, multi-broker future |
| Concrete next-step ask | DONE | "Reply within two weeks" + "20-minute call if helpful" |
| Hosted vs local distinction explicit | DONE | `ENABLE_TRADING=false` on Fly.io, trading on self-hosted only |
| No legal threats, no SEBI invocations | DONE | No regulatory citations beyond Kite Connect Developer Terms |
| No revenue / performance / user-count claims | DONE | Explicit "no commercial revenue" |
| Repo + hosted URL included | DONE | Both surfaced in body and signature |
| Prior outreach to confirm not-already-contacted | DONE | `docs/evidence/compliance-emails-sent.md` log is empty — first contact |
| Attachments needed before send | OPTIONAL | One-page tech summary offered "on request"; no need to attach upfront |

**Verdict: SEND-AS-IS.**

No blockers. The earlier `<product-email-placeholder>` was resolvable cleanly to `sundeepg8@gmail.com` from in-repo evidence. Once sent, record the outreach in `docs/evidence/compliance-emails-sent.md` per the example entry there.

## Post-send actions (not part of this brief)

- Log entry in `docs/evidence/compliance-emails-sent.md` with Gmail thread URL
- If no response in 4 weeks: polite follow-up in same thread, CC Rainmatter again
- At week 6: neutral kite.trade/forum thread tagging @sujith / @rakeshr — public record creates implicit-tolerance defense
- At week 8: Rainmatter portfolio-founder warm intro (Deepak Shenoy first, per `kite-rainmatter-warm-intro.md`)

## Fallback positions if negative response

- **"Single-user only":** comply immediately; reduce hosted endpoint to dashboard-only, `ENABLE_TRADING=false` stays
- **"Need exchange approval":** request Zerodha sponsorship per Developer Terms §2(e); pivot to self-hosted-only if prohibitive
- **"Rearchitect X":** request specifics; read-only rearchitect already complete via Path 2 (`ENABLE_TRADING=false`)

---

## Prior draft

Preserved verbatim from the previous version of this file for history.

> # Draft — Zerodha Kite Connect compliance disclosure
>
> **Status:** Ready to send. Minor personalization only.
> **To:** kiteconnect@zerodha.com
> **CC:** talk@rainmatter.com
> **From:** <product-email-placeholder> <!-- TODO: replace with product email before publishing -->
> **Subject:** Compliance notification — kite-mcp-server (per-user BYO-key architecture)
>
> ---
>
> Hello Kite Connect Team,
>
> I am writing to proactively disclose an application I have built on Kite Connect and to request confirmation that its architecture is compatible with the Kite Connect Developer Terms.
>
> **What it is.** `kite-mcp-server` is an open-source Model Context Protocol (MCP) server that lets individual Kite Connect developers use Claude (and other MCP-compatible LLMs) as an interactive interface to their own Kite account. Each order is initiated by the user in chat and confirmed via an explicit click-through prompt before reaching Kite.
>
> **Architecture — single-user by construction.** The server does not aggregate user credentials onto a single developer app. Each user registers their own Kite Connect developer application (their own API key and secret) and logs in via the standard Kite OAuth flow. My deployment holds no master developer key for Kite. Per Developer Terms Section 3, the end-user is Zerodha's Client operating under their own developer subscription — identical to a user running the reference Python/Go Kite client against their own app.
>
> **Hosting & posture.** Hosted on Fly.io (Mumbai region, static egress 209.71.68.157). Credentials and access tokens are AES-256-GCM encrypted at rest. All tool calls are audit-logged. The deployment runs pre-trade risk checks (order-value caps, rate limits, idempotency keys, anomaly detection, off-hours blocks, kill-switch) and a full audit trail per user. No fully-automated / unattended trading — every order requires the user's confirmation in-session.
>
> **Scope.** Read tools (quotes, holdings, positions, historical, research analytics), order tools (place / modify / cancel / GTT) which are currently **DISABLED on the hosted endpoint** pursuant to NSE/INVG/69255 Annexure I Para 2.8 and enabled only on self-hosted local builds for the user's personal-use safe harbor. Alerts, Telegram notification bot (private 1:1, user-initiated). No credential aggregation, no copy-trading, no social layer, no broker-on-broker resale. Non-commercial; no revenue.
>
> **Requests.**
> 1. Written acknowledgement that a per-user, BYO-developer-app architecture — where each end-user operates under their own Kite Connect subscription — is compatible with the Developer Terms and requires no additional exchange approval.
> 2. If any further compliance steps are advisable, please advise.
> 3. A point of contact for ongoing compliance questions as the project evolves.
>
> A one-page technical summary (data flow, credential handling, risk checks, audit schema) is available on request. Happy to join a call.
>
> Appreciate a response within two weeks if feasible, so I can plan accordingly.
>
> Regards,
> Sundeep Govarthinam
> <product-email-placeholder> <!-- TODO: replace with product email before publishing -->
> Repository: https://github.com/Sundeepg98/kite-mcp-server
>
> ---
>
> ## Pre-send checklist (30 seconds)
>
> - [ ] Subject line includes product name (avoid "URGENT" etc.)
> - [ ] CC talk@rainmatter.com (Rainmatter = relationship arm)
> - [ ] No legal threats or regulatory citations that invite classification
> - [ ] Mention BOTH hosted (read-only) and local (trading-enabled) explicitly
> - [ ] No performance claims, no revenue figures
> - [ ] Paste this content into Gmail compose, send
>
> ## If they respond: record in `docs/evidence/compliance-emails-sent.md`
>
> ## If no response in 4 weeks:
> - Follow up politely in same thread (CC Rainmatter again)
> - At week 6, post a neutral thread at kite.trade/forum tagging @sujith / @rakeshr — public record creates implicit-tolerance defense
> - At week 8, Rainmatter portfolio founder warm intro (Deepak Shenoy @deepakshenoy first)
>
> ## Fallback positions if negative response
> - "Single-user only": comply immediately; reduce to personal-use self-hosted. `ENABLE_TRADING=false` stays on Fly.io.
> - "Need exchange approval": ask Zerodha to sponsor per ToS §2(e). Pivot to self-hosted-only if prohibitive.
> - "Rearchitect X": request specifics; evaluate. Read-only rearchitect is already complete via Path 2.
