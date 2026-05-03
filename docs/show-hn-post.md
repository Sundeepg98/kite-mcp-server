# Show HN — Launch Kit for kite-mcp-server

> Three artifacts: title options, post body, and prepared replies to the comments the HN crowd will actually write.

Author handle: `Sundeepg98` · `github.com/Sundeepg98` · `<your product email>`

---

## 1. Title options (≤80 chars each, ranked)

1. **Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards** *(preferred — "self-hosted" signals local-first/no-SaaS-extraction, the broker name is recognisable to the audience that matters, and "with riskguards" pre-empts the "AI-YOLOs-real-money" worst-case-1 in the title itself)*
2. Show HN: An MCP server for Zerodha Kite with per-user OAuth and hash-chained audit
3. Show HN: Model Context Protocol + Kite Connect + SQLite in 117 tools

---

## 2. Post body (~500 words)

**Opening — what it is and what problem it solves (~95 words)**
Hi HN — I'm Sundeep, a solo developer in Bangalore. For the past few months I've been building `kite-mcp-server` — a Model Context Protocol server that lets Claude (and other MCP clients) talk to Zerodha's Kite Connect API. Kite Connect is India's most widely used retail-broker REST API. The Indian-broker-MCP space has filled out fast (Zerodha official `mcp.kite.trade`, Upstox official, Dhan community, TurtleStack multi-broker) — this server picks the *depth-on-Zerodha* lane: 117 tools with order placement, 9 pre-trade safety checks, paper trading, options Greeks, Telegram briefings. The repo is open-source, Go, MIT-ish permissive.

Link: `github.com/Sundeepg98/kite-mcp-server`

**What's inside (~120 words)**
117 tools exposed to the LLM — read-only (holdings, positions, quotes, historical, option chain) and write (place / modify / cancel order, alerts, GTTs). Per-user OAuth — each user brings their own Kite developer API key, so the server never holds anyone else's credentials. AES-256-GCM encryption for cached tokens, stored in SQLite. A 9-check riskguard chain runs before every order (kill-switch, order-value cap, quantity limit, daily order count, rate-limit, duplicate-within-30s, daily notional, auto-freeze on losses). Hash-chained append-only audit log of every tool call. Elicitation for the 8 destructive tools (the LLM has to confirm before executing). Deployed on Fly.io Mumbai, single static egress IP for the new SEBI mandate. 16,209 tests across 630 test files.

**The regulatory wrinkle (~90 words)**
India's market regulator (SEBI) has a strict boundary between unregistered tools and "investment advisory" services. So this is explicitly a **tool**, not a service — the server runs *your* account, uses *your* API key, executes *your* decisions. I am not a SEBI-registered Investment Advisor; I do not give advice; the tool does not recommend trades. There is also an April 2026 mandate requiring algo trades to come from whitelisted static IPs, which is why the Fly.io deployment pins a single egress IP per region (209.71.68.157 for Mumbai at the time of writing).

**Honest limitations (~100 words)**
Not on the public MCP Registry yet. Documentation is below what I'd like. Order placement is off by default on the hosted instance (`ENABLE_TRADING=false`) until I finish a separate compliance review — you can still use the hosted instance read-only, or self-host with the trading flag on. Paper-trading mode ships, but the fill simulator is naïve. No Postgres — SQLite + Litestream to Cloudflare R2 instead, which I'll defend in the comments if anyone asks. Some of the backtesting code is intentionally simple; I'd rather ship an honest simple backtester than a "gamed to look good" one.

**Why I'm posting this here (~80 words)**
Two reasons. First, I want critique from people who'll actually read the security model and the riskguard code. Indian fintech Twitter is great but leans at launches, not architectures. Second, MCP has a real and growing ecosystem, and I want to know what MCP-savvy people think of the tool surface — what's missing, what's wrong-shaped, what's over-engineered. Happy to answer anything about the design, the regulatory calculus, or the deployment.

---

## 3. Prepared comment replies

These are drafts for the critiques I expect. Keep them 1–2 sentences, specific, non-defensive.

**"This just helps people YOLO options faster."**
> Genuinely fair worry, and the reason the riskguard chain exists. Nine pre-trade checks run *before* every order hits Kite — kill-switch, ₹50k/order cap, 20 orders/day, rate-limit, duplicate-within-30s, daily ₹2L notional, off-hours block, anomaly μ+3σ, idempotency. Plus elicitation forces a confirm step before destructive tool calls, and `ENABLE_TRADING=false` on the hosted instance gates 18 order tools entirely. It's an opt-out posture, not opt-in. Code is at `kc/riskguard/guard.go` if you want to audit the actual checks rather than the marketing copy.

**"How is this different from `mcp.kite.trade` (Zerodha's own MCP), or Streak / Sensibull?"**
> Three real differences: (a) `mcp.kite.trade` is read-only by Zerodha's design — kite-mcp-server adds order placement, GTT, alerts, paper-trading, ticker, and 60+ analysis tools when self-hosted. (b) Streak/Sensibull are SaaS with proprietary strategy DSLs and server-side intelligence — this server holds zero strategies; the LLM is the brain, the user owns it. (c) MIT-licensed, self-hostable, hash-chained audit. Different layer entirely. Comparison table at `docs/launch-materials.md`. Both Zerodha's MCP and this can co-exist in the same workflow.

**"Why use yours over Upstox MCP (launched Feb 2026)?"**
> Different broker, different tool surface. Upstox MCP is excellent if your account is at Upstox — it's read-only, hosted, OAuth-based, with daily re-auth. This is for Zerodha users specifically: 117 tools when self-hosted, order placement with 9 pre-trade safety checks, paper trading, options Greeks, Telegram briefings, hash-chained audit log, Litestream backup. The two don't compete. If anything, the Upstox launch validates the category — third-party MCPs for Indian retail brokers are now industry-norm, not edge-case.

**"What about TurtleStack (multi-broker — Zerodha + Groww + Dhan + AngelOne)?"**
> TurtleStack is the most advanced multi-broker offering surfaced — it picks breadth (4 brokers + 40 indicators). This server picks depth on a single broker — RiskGuard pre-trade chain, paper trading with naive-fill caveat documented, options Greeks (Black-Scholes), elicitation on destructive tools, hash-chained audit log, Path 2 hosted compliance, Litestream WAL replication. ~95% of Indian retail trades on a single broker; for that user, depth beats breadth. The two are different bets on the same opportunity.

**"Why are there suddenly so many Zerodha / Indian-broker MCPs?"**
> Because Anthropic shipped MCP in Nov 2024 and Indian retail trading is a giant single-API ecosystem. The proliferation (Upstox official, Dhan community, TurtleStack, Indian-Broker-MCP, several `aranjan/kite-mcp` forks) proves the demand is real. This server differentiates on tool count (117 vs ~20-40), safety rails (9-check riskguard chain — none of the others ship this), and operational maturity (Litestream, audit chain, Telegram bot, scheduled briefings). The category will consolidate; depth + safety wins the long tail.

**"Why MCP instead of a REST wrapper or a chatbot?"**
> Because MCP gives the LLM structured tool discovery — the client learns the tool schema at connect time rather than hard-coding an API client. Means the same server works for Claude Desktop, Claude Code, Cursor, Zed, etc., without me shipping a client for each. REST wrappers already exist; they're what MCP wraps.

**"Isn't this a SEBI violation? The April 2026 algo rules say providers of trading logic need an RA licence."**
> Direct answer: no, I am not registered as a SEBI RA or IA, and the April 2026 algo rules are exactly why this is a *tool*, not a service. The server doesn't bundle strategies or signals — it exposes Kite Connect API methods to the user's own LLM client, runs on the user's own developer-app credentials, and never touches anyone else's account. No black-box logic. The user is the algo. If I ever shipped tuned signals or a strategy marketplace, that line moves and registration becomes mandatory. I haven't, and I won't unregistered. The compliance reasoning is in `docs/legal-notes.md`.

**"Prompt injection — can a hostile quote description make Claude cancel my orders?"**
> Real risk, addressed in two places: elicitation forces a confirm step before destructive tool calls, and the riskguard chain runs *after* the LLM decides and *before* the Kite API call, so an LLM that gets manipulated into "yes, cancel everything" still hits the daily-count and rate-limit checks. Plus the hash-chained audit log makes it forensically reproducible.

**"Why Go and not Python?"**
> I know Go better, single-binary deploy is clean, and the gokiteconnect SDK is actively maintained in Go. That said — the MCP *clients* (Claude Desktop, etc.) are the LLM's side; users writing Python analysis tools on top of this server is totally fine, and Week 2 of my cohort is literally that.

**"Why SQLite not Postgres?"**
> Single-node, writes are low-volume (tens of tool calls/sec per user, realistically fewer), and SQLite + WAL + Litestream streaming to Cloudflare R2 gives me point-in-time recovery and zero-downtime deploys for $0/month. Postgres would be premature operational overhead. If the load profile changes, it's a boring migration.

**"Why isn't this on the MCP Registry?"**
> Honest answer: I wanted to stabilise the OAuth and session-persistence layer first, plus finish the security audit. That's done now; registry submission is on the near-term list. If anyone from the Registry maintainers is reading, DMs open.

**"What's the business model? When are you going to enshittify?"**
> Open-source core is MIT, not freeware-with-a-trap. The paid tier is a managed Fly.io instance + scheduled Telegram briefings + admin tools — every paid feature is also self-hostable from the same repo, so the "enshittify" lever doesn't exist by construction. There's also a teaching cohort (Options + MCP + Python) which is upfront-priced. Neither gates the OSS code. Honest answer to *will it monetize at all*: ₹15-25k MRR target at 12 months — small business, not unicorn.

**"What about tax integration — Clear, Quicko, etc.?"**
> Not in scope for the MCP server itself (it's a real-time tool), but there's a tax-harvesting analysis tool that computes LTCG/STCG and an export format that Clear-compatible CSVs can read. Full tax-filing integration would be a separate thing.
