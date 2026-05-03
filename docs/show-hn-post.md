# Show HN — Launch Kit for kite-mcp-server

> Three artifacts: title options, post body, and prepared replies to the comments the HN crowd will actually write.

Author handle: `Sundeepg98` · `github.com/Sundeepg98` · `<your product email>`

---

## 1. Title options (≤80 chars each, ranked)

1. **Show HN: kite-mcp-server – MCP bridge for a regulated Indian stockbroker API** *(preferred — leads with "regulated API" which signals real scope and filters casual tippers)*
2. Show HN: An MCP server for Zerodha Kite with per-user OAuth and hash-chained audit
3. Show HN: Model Context Protocol + Kite Connect + SQLite in 117 tools

---

## 2. Post body (~500 words)

**Opening — what it is and what problem it solves (~90 words)**
Hi HN — I'm Sundeep, a solo developer in Bangalore. For the past few months I've been building `kite-mcp-server` — a Model Context Protocol server that lets Claude (and other MCP clients) talk to Zerodha's Kite Connect API. Kite Connect is India's most widely used retail-broker REST API; I wanted a setup where I could ask an LLM "what's my options exposure today?" and get it to read my actual positions, not a generic example. The repo is open-source, Go, MIT-ish permissive.

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
> Fair worry, and I share it — that's why there's a 9-check riskguard chain, an ₹50k/order default cap, elicitation on destructive tools, and `ENABLE_TRADING=false` on the hosted instance. Guardrails are opt-out, not opt-in.

**"How is this different from Streak or Sensibull?"**
> Streak and Sensibull are hosted SaaS with proprietary strategy DSLs. This is an MCP bridge you run against your own Kite API key — no strategy marketplace, no server-side intelligence, no data leaves your own setup other than what the LLM call itself sends. Different layer.

**"Why MCP instead of a REST wrapper or a chatbot?"**
> Because MCP gives the LLM structured tool discovery — the client learns the tool schema at connect time rather than hard-coding an API client. Means the same server works for Claude Desktop, Claude Code, Cursor, Zed, etc., without me shipping a client for each. REST wrappers already exist; they're what MCP wraps.

**"Isn't this a SEBI violation?"**
> No, because the tool doesn't give advice or take custody. A user brings their own SEBI-regulated broker credentials, runs the tool on their own infra or ours read-only, and makes their own decisions. If I ever shipped hand-tuned "alpha" or a signal feed, that line changes — and I haven't, and I won't without registration.

**"Prompt injection — can a hostile quote description make Claude cancel my orders?"**
> Real risk, addressed in two places: elicitation forces a confirm step before destructive tool calls, and the riskguard chain runs *after* the LLM decides and *before* the Kite API call, so an LLM that gets manipulated into "yes, cancel everything" still hits the daily-count and rate-limit checks. Plus the hash-chained audit log makes it forensically reproducible.

**"Why Go and not Python?"**
> I know Go better, single-binary deploy is clean, and the gokiteconnect SDK is actively maintained in Go. That said — the MCP *clients* (Claude Desktop, etc.) are the LLM's side; users writing Python analysis tools on top of this server is totally fine, and Week 2 of my cohort is literally that.

**"Why SQLite not Postgres?"**
> Single-node, writes are low-volume (tens of tool calls/sec per user, realistically fewer), and SQLite + WAL + Litestream streaming to Cloudflare R2 gives me point-in-time recovery and zero-downtime deploys for $0/month. Postgres would be premature operational overhead. If the load profile changes, it's a boring migration.

**"Why isn't this on the MCP Registry?"**
> Honest answer: I wanted to stabilise the OAuth and session-persistence layer first, plus finish the security audit. That's done now; registry submission is on the near-term list. If anyone from the Registry maintainers is reading, DMs open.

**"What's the business model?"**
> Open-source core; paid tier for people who want a managed instance + scheduled briefings + extra tools. There's also a cohort I'm running on options + MCP + Python, which is upfront-priced and explicitly not a "signals" product. Both are disclosed; neither gates the open-source code.

**"What about tax integration — Clear, Quicko, etc.?"**
> Not in scope for the MCP server itself (it's a real-time tool), but there's a tax-harvesting analysis tool that computes LTCG/STCG and an export format that Clear-compatible CSVs can read. Full tax-filing integration would be a separate thing.
