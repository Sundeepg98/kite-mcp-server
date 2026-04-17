# Launch Materials: Kite MCP Server

**IMPORTANT before posting:** Review all factual claims. The agent that drafted this made some unverified claims — specifically around tool counts, test counts, and commit counts. Verify against current state before you post. Notable correction already applied: Kite tokens expire daily at ~6 AM IST, NOT "every 6 hours" as the draft originally said.

---

## Show HN

### Title
**Kite Trading MCP Server – Execute orders + backtest on Zerodha via Claude, ChatGPT, VS Code**

### Body
We shipped a Model Context Protocol server that connects any AI assistant to Zerodha Kite for real trading. ~100 tools (vs. the official 22 read-only tools). Order placement, paper trading, backtesting SMA/RSI/breakout, options Greeks, Telegram alerts, tax loss harvesting analysis. 8 safety checks prevent runaway orders. Self-hostable (Docker + Go). Live at https://kite-mcp-server.fly.dev. MIT license, free—you bring a ₹500/mo Kite Connect app.

Designed for algorithmic developers in India. Ask Claude: "Show my portfolio", "Backtest SMA crossover on INFY", "What are the Greeks on NIFTY 50 calls?".

---

## Tweet thread (7 tweets)

**Tweet 1** (Hook)
Tired of your Kite algos breaking at 6 AM IST when the daily token expires? We shipped a Model Context Protocol server so Claude, ChatGPT, and your AI can execute orders, backtest strategies, and analyze Greeks — all on Zerodha.

~100 tools. Paper trading mode. 8 safety checks. Zero cost (you bring the ₹500/mo Kite app).

https://github.com/Sundeepg98/kite-mcp-server

**Tweet 2**
The problem we solve:
- Zerodha token expires daily at 6 AM IST → manual re-auth
- Official MCP server is read-only (22 tools, no orders)
- Backtesting requires separate tools (Streak, AlgoTrade)
- Options Greeks need separate calculation
- Tax loss harvesting is manual spreadsheet work

We glued it all together.

**Tweet 3**
What you can ask Claude now:

"Place a limit buy for 10 RELIANCE @ 3200"
"Show me my P&L by sector"
"Backtest SMA(50,200) crossover on INFY — 2023 data"
"What are the Greeks on NIFTY 50 June calls?"
"How much can I tax-loss harvest this year?"
"Alert me if SENSEX drops 2%"

All in one conversation.

**Tweet 4**
Why it's safe:
- Kill-switch per user (freeze trading instantly)
- Order value cap (default ₹5,00,000)
- Rate limit (10 orders/minute, prevents loops)
- Duplicate detection (blocks same order within 30s)
- Daily order cap (200/day)
- Circuit breaker (auto-freeze after 3 rejections)

Paper trading mode = zero real money risk.

**Tweet 5**
Tech stack:
- Go + mcp-go (fast, low-overhead)
- SQLite (encrypted credentials, alerts, audit trail)
- OAuth 2.1 PKCE (each user brings their own Kite app)
- Fly.io static IP (209.71.68.157 for SEBI compliance)
- Telegram daily briefings (9 AM alerts + 3:35 PM P&L)
- Litestream replication to R2

Self-hosted Docker option included.

**Tweet 6**
Compared to:
- Official Zerodha MCP: read-only, no orders, no backtesting
- Streak: now free for Zerodha users, web-only
- AlgoTrade: limited to equity, no AI integration

This: order placement, paper trading, Greeks, backtesting, tax analysis, audit trail. MIT license.

**Tweet 7**
Live demo: https://kite-mcp-server.fly.dev
GitHub: https://github.com/Sundeepg98/kite-mcp-server
Docs: quick start in 3 steps (OAuth login → ask Claude → done)

Feedback/issues welcome. This solves a real itch for algo traders in India — hope it helps.

---

## Reddit — r/IndiaAlgoTrading

### Title
Built a free, open-source MCP server that lets Claude execute Zerodha orders, backtest, and calculate Greeks. ~100 tools, 8 safety checks, paper trading.

### Body

Shipping this today after months of work. Real problem: token expiry, fragmented tools (Streak for backtesting, separate option calc, manual tax loss harvesting), and no AI integration for execution.

**The pain points we heard:**
- Kite token expires daily at 6 AM IST → API calls fail → scripts break
- You have to use Streak OR AlgoTrade (limited) for backtesting
- Greeks calculation? Write it yourself or use heavy libraries
- Tax loss harvesting? Spreadsheet time
- Official Zerodha MCP is read-only (22 tools, zero order execution)

**What we shipped:**

~100 tools across 14 categories:
- **Trading**: Place/modify/cancel orders, GTT, convert positions, close all
- **Portfolio**: Holdings, positions, P&L by sector, concentration analysis
- **Backtesting**: SMA crossover, RSI reversal, breakout, mean reversion
- **Options**: Greeks (delta/gamma/theta/vega), option chain with inline Greeks
- **Tax**: Tax-loss analysis, PnL journal
- **Alerts**: Price alerts, composite (AND/OR) alerts, volume spikes, Telegram notifications
- **Market Data**: Quotes, historical candles, instrument search
- **Paper Trading**: Simulate orders risk-free, toggle on/off instantly
- **MF & Watchlists**: Holdings, place/cancel MF orders, create watchlists

**Safety first (8 checks):**
1. Kill switch (freeze your account instantly if needed)
2. Order value limit (default ₹5,00,000)
3. Quantity limit (exchange freeze limits)
4. Daily order cap (200/day)
5. Rate limit (10 orders/minute — stops runaway loops)
6. Duplicate detection (blocks same order within 30 seconds)
7. Daily value cap (₹10,00,000 cumulative)
8. Circuit breaker (auto-freeze after 3 rejections in 5 min)

All limits are per-user and configurable in the dashboard.

**How it works:**
1. OAuth login (once) — you bring your own Kite Connect app (₹500/mo from Zerodha)
2. Talk to Claude / ChatGPT / VS Code / any MCP client
3. Natural language: "Show my portfolio", "Backtest SMA on INFY", "Alert me on RELIANCE drops"
4. Orders execute, paper trades simulate, backtests run locally

**Real talk:**
- Static IP (209.71.68.157) — must be whitelisted in your Kite developer console per SEBI April 2026 mandate
- Paper trading is local simulation (good for practice, not order-execution stress testing)
- Requires Kite Connect app (₹500/mo from Zerodha — their cost, not ours)
- All data encrypted in SQLite (AES-256-GCM)
- Audit trail on every tool call (who did what, when — dashboard view)

**Tech / deployment:**
- Go 1.25 + mcp-go
- Docker (easy self-host) or cloud (Fly.io with static IP)
- Litestream SQLite replication to R2
- Telegram daily briefings (9 AM + 3:35 PM P&L)
- MIT license

**Live:** https://kite-mcp-server.fly.dev
**GitHub:** https://github.com/Sundeepg98/kite-mcp-server

Honest ask: if you're an algo dev in India using Kite, would you use this? Feedback on safety checks, tool gaps, or workflow pain points = gold.

---

## Reddit — r/selfhosted

### Title
Self-hosted Zerodha trading API for AI assistants – MCP server, Docker, MIT license, audit trail, ~100 tools

### Body

For the self-hosting crowd: we built a Model Context Protocol (MCP) server that gives any AI assistant (Claude, ChatGPT, local LLMs via Ollama) full access to Zerodha trading — order placement, portfolio analysis, backtesting, Greeks calculation. Self-hostable. MIT license. All data stays on your infrastructure.

**Why this matters for self-hosters:**

1. **No API vendor lock-in** – Zerodha's official MCP is proprietary-hosted, read-only, 22 tools. This: open-source, ~100 tools, order execution.
2. **Own your trading data** – SQLite on your machine, encrypted locally (AES-256-GCM). No 3rd-party SaaS intermediary.
3. **Audit everything** – Hash-chained audit trail logged to SQLite. Every tool call timestamped, attributed, verifiable.
4. **Run anywhere** – Docker Compose (2-minute setup), bare metal Go (1.25+), or cloud (Fly.io).
5. **No monthly fees** – MIT license. Only cost: ₹500/mo Zerodha Kite Connect app (Zerodha's charge, not ours).

**Self-hosting in 3 commands:**
```bash
git clone https://github.com/Sundeepg98/kite-mcp-server
cp .env.example .env    # edit: set OAUTH_JWT_SECRET
docker compose up -d
```

Data flow: OAuth tokens encrypted in SQLite → never leave your machine → API calls signed locally.

**Data sovereignty:**
- Zerodha tokens stored in SQLite with AES-256-GCM (not plaintext)
- OAuth sessions encrypted per-user via HKDF-derived keys
- Alerts, watchlists, paper trading all local SQLite
- Audit trail is append-only, hash-chained (tamper-evident)
- Optional: external hash-chain publisher to S3/R2 for compliance

**Monitoring / observability:**
- `/healthz` endpoint (plain + JSON component status with audit / riskguard / litestream visibility)
- Structured logging (Slog, debug/info/warn/error levels)
- Dashboard audit stream (live or CSV export)

**The honesty:**
- Requires Zerodha Kite Connect app (₹500/mo) — Zerodha's charge, not us
- Static IP whitelist (`209.71.68.157`) required by Kite developer console — SEBI April 2026 mandate
- Paper trading is local simulation only

**License & community:**
MIT. Issues/PRs welcome.

**Links:**
- **GitHub**: https://github.com/Sundeepg98/kite-mcp-server
- **Live demo**: https://kite-mcp-server.fly.dev
- **Docs**: Docker setup, env var reference, self-hosting guide, compliance docs

---

## Launch strategy

### Pre-launch (48 hours before)

**Key personas to tell (5–10):**
1. Algo traders on r/IndiaAlgoTrading (active community)
2. MCP early adopters (Claude Code, Anthropic community, HN regulars)
3. Go/systems engineers (architecture interest)
4. Self-hosting enthusiasts (r/selfhosted)
5. Zerodha community (Nithin Kamath via Twitter/LinkedIn — their MCP post expressed enthusiasm for MCP)
6. AlgoTest / Streak users (potential crossover)

**Preparation:**
- Schedule Show HN post for Tuesday 9 AM EST (10:30 PM IST) — best historical day for dev tools
- Draft Twitter thread, post to drafts
- Add release notes to GitHub releases page
- Optional: record 2-3 min demo video (live Claude interaction)

### Launch day (Tuesday, 9 AM EST)

**Sequence:**

**9:00 AM EST** — Submit Show HN + GitHub release with CHANGELOG summary
**9:15 AM EST** — Post to r/IndiaAlgoTrading + r/selfhosted
**9:30 AM EST** — Tweet 1 (Hook)
**10:00 AM EST** — Reply to all top-level Show HN comments (transparency: explain trade-offs, answer questions)
**12:00 PM EST** — Finish Twitter thread, share in relevant Discord communities
**6:00 PM EST** — Check HN ranking, respond to GitHub issues/PRs

### 24 hours after launch

**Typical concerns & responses:**
- "What about crypto?" → "Zerodha's API doesn't cover crypto. Could add a multi-broker layer later."
- "Official Kite MCP exists — why another?" → "Official is read-only (22 tools). We add order placement, backtesting, safety checks. Complement, not competition."
- "Static IP whitelist?" → "Yes, `209.71.68.157`. SEBI mandate, not a bug. We documented it upfront on the landing page."
- "Cost?" → "Free (MIT). Kite Connect is ₹500/mo from Zerodha — that's on them."

### Week 2+

- YouTube Shorts demo (3 min)
- Medium/Dev.to technical deep-dive: "Architecture of a trading MCP server"
- Tutorial: "How to self-host Zerodha API"

---

## Tone & voice notes

All materials are written in **first-person technical voice**:
- Honest: acknowledge the static IP, the ₹500/mo cost, the limitations
- Under-sold: describe what we built, not why it's "revolutionary"
- Specific: cite real numbers where verified
- Community-focused: contribution to algo traders in India, not a product launch

---

## Channels checklist

- [ ] Show HN (Tuesday 9 AM EST)
- [ ] GitHub release with CHANGELOG
- [ ] Twitter thread (7 tweets)
- [ ] r/IndiaAlgoTrading (shortly after HN)
- [ ] r/selfhosted (shortly after HN)
- [ ] Discord (AlgoTrade India, Zerodha API, MCP servers)
- [ ] YouTube Shorts demo (Week 2)
- [ ] Medium/Dev.to tutorial (Week 2)

---

**Verify before posting:** tool count, test count, commit count, pricing claims (Streak is now free, not ₹2000/mo). Agent draft hallucinated some specifics.
