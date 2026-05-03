# Kite MCP Server

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev)
[![CI](https://github.com/Sundeepg98/kite-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/Sundeepg98/kite-mcp-server/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/Tests-16209-brightgreen)](https://github.com/Sundeepg98/kite-mcp-server/actions)
[![Security Audit](https://img.shields.io/badge/Security%20Audit-passed-brightgreen)](SECURITY_AUDIT_REPORT.md)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> Self-hosted MCP server that turns Claude / ChatGPT into a power-user trading copilot for your Zerodha Kite account.

<!-- TODO: 30-second demo GIF of portfolio analysis + order placement flow -->

## What this is

A Go server that speaks the [Model Context Protocol](https://modelcontextprotocol.io/) and bridges any MCP-compatible AI client to Zerodha's Kite Connect API. Users bring their own Kite developer app (per-user OAuth 2.1 with PKCE) — credentials never leak between accounts. Ships 117 tools spanning portfolio analysis, market data, options Greeks, backtesting, alerts, paper trading, and order placement, plus MCP Apps widgets that render inline inside chat. Works inside Claude Desktop, Claude Code, claude.ai, ChatGPT Connectors, Cursor, VS Code Copilot, Windsurf — anything MCP-compliant. Forked from and complementary to [Zerodha's official read-only MCP](https://mcp.kite.trade) (22 tools, GTT only); this server adds order placement, Telegram alerts, riskguard safety rails, and analytics.

## Why trust this

- **16,209 tests** across 630 test files — run `go test ./... -count=1`
- **Security audit**: 27-pass manual analysis, 181 findings, all resolved — see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) and [SECURITY_PENTEST_RESULTS.md](SECURITY_PENTEST_RESULTS.md)
- **AES-256-GCM encryption** at rest for every sensitive value — Kite tokens, API secrets, OAuth client secrets — key derived via HKDF from `OAUTH_JWT_SECRET`
- **RiskGuard** (9 checks) — kill switch, per-order value cap (Rs 50,000 default), quantity limit, daily order count (20/day), rate limit (10/min), duplicate detection (30s window), daily cumulative value cap (Rs 2,00,000), auto-freeze circuit breaker
- **Per-tool-call audit trail** with 90-day retention — every MCP call logged to SQLite, CSV/JSON export via dashboard
- **CI on every push** — `go build`, `go vet`, `go test -race` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml))
- **MIT license, open source** — inspect anything. Upstream attribution to Zerodha Tech preserved in [LICENSE](LICENSE)
- **Threat model**: [THREAT_MODEL.md](THREAT_MODEL.md). Security policy: [SECURITY.md](SECURITY.md)

## Quick start

### Option A — hosted demo (read-only)

Point your MCP client at:

```
https://kite-mcp-server.fly.dev/mcp
```

Order-placement tools are gated off on the hosted instance pursuant to NSE/INVG/69255 Annexure I Para 2.8. Read-only tools (portfolio, market data, backtesting, analytics) work. You still bring your own Kite developer app (per-user OAuth).

### Option B — run locally (personal use, full functionality)

```bash
git clone https://github.com/Sundeepg98/kite-mcp-server && cd kite-mcp-server
cp .env.example .env               # edit: set OAUTH_JWT_SECRET (required)
docker compose up -d               # builds Dockerfile.selfhost and starts it
curl http://localhost:8080/healthz # should return "ok"
```

Point your client at `http://localhost:8080/mcp` (use `--allow-http` if your client requires it). Running locally against your own Kite account is the personal-use safe-harbor path — you remain the Zerodha Client; the software just helps you place orders.

Go users can skip Docker: `go build -o kite-mcp-server && ./kite-mcp-server`.

### Option C — connect from your MCP client

Add this to your client config (`~/.claude.json`, `claude_desktop_config.json`, `.vscode/mcp.json`, etc.):

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

Then say: *"Log me in to Kite"* — complete the OAuth flow in your browser — then ask anything: *"Show my portfolio"*, *"Backtest SMA crossover on INFY"*, *"Enable paper trading mode"*.

New to this? Start with paper trading: *"Enable paper trading mode"* — virtual Rs 1 crore portfolio, no real money at risk.

## Features

- **Portfolio analysis** — holdings, positions, margins, P&L, sector exposure (150+ stocks mapped), tax-loss harvest, concentration, dividends
- **Market data** — quotes, LTP, OHLC, historical candles, instrument search, 10+ technical indicators (SMA, EMA, RSI, MACD, Bollinger Bands)
- **Options** — Black-Scholes Greeks (delta, gamma, theta, vega, IV), option chain, 8 multi-leg strategy templates
- **Backtesting** — 4 built-in strategies (SMA crossover, RSI reversal, breakout, mean reversion) with Sharpe ratio and max drawdown
- **Alerts** — price above/below, percentage drop/rise, composite conditions, volume spike, Telegram delivery + native Kite GTT alerts
- **Paper trading** — virtual Rs 1 crore portfolio, simulated orders, background LIMIT fill monitor, toggle on/off
- **RiskGuard** — 9 safety checks run before every order hits the exchange
- **MCP Apps widgets** — inline portfolio / orders / alerts / activity UI on claude.ai, Claude Desktop, and ChatGPT
- **Telegram bot** — `/buy`, `/sell`, `/quick`, `/setalert` with inline keyboard confirmation; morning briefing (9 AM IST) and daily P&L (3:35 PM IST)
- **Order placement** — place, modify, cancel, GTT, convert positions, close-all (local build only; hosted deployment is read-only)

Full tool taxonomy with counts per category in [ARCHITECTURE.md](ARCHITECTURE.md).

## Architecture

Clean / hexagonal architecture:

```
AI Client <-> MCP Protocol <-> Tool Handler <-> Use Case <-> CQRS Command/Query <-> Broker Port <-> Kite Adapter <-> Kite Connect API <-> NSE/BSE
```

Go 1.25 + [mcp-go](https://github.com/mark3labs/mcp-go) v0.46.0. SQLite for persistence (credentials, alerts, sessions, audit trail — all AES-256-GCM encrypted), with [Litestream](https://litestream.io/) continuous replication to Cloudflare R2. OAuth 2.1 + PKCE, each user brings their own Kite developer app. Middleware chain: Timeout -> Audit -> Hooks -> RiskGuard -> Rate Limiter -> Billing -> Paper Trading -> Dashboard URL. Deployed on Fly.io (Mumbai region) with static egress IP for SEBI-mandated whitelisting. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Legal / compliance status

> **Not a SEBI-registered intermediary.** This is infrastructure software, not an advisory or brokerage service.
>
> - Per-user BYO Kite developer app — **you remain the Zerodha Client of record.** The server holds no pooled user funds and executes no trades on its own behalf.
> - The hosted deployment at `kite-mcp-server.fly.dev` is **read-only**; order-placement tools are gated off pursuant to **NSE/INVG/69255 Annexure I Para 2.8**. Order placement requires running the server locally against your own account.
> - Running the server locally against your personal Kite account is the **personal-use safe-harbor path** — analogous to running your own algo script. See [OpenAlgo's framing](https://www.marketcalls.in/fintech/exchange-compliance-for-algo-vendors-what-you-need-to-know.html) of the compliance landscape for Indian algo vendors.
> - Static egress IP (`209.71.68.157`, Mumbai) is published so users can whitelist it in their Kite developer console per the SEBI April 2026 mandate.
> - [TERMS.md](TERMS.md) and [PRIVACY.md](PRIVACY.md) are **DRAFT** and under independent legal review. Do not rely on them as final legal agreements.
> - Trading involves risk. This software is not financial advice. Not affiliated with Zerodha.

## Environment variables

`OAUTH_JWT_SECRET` is the only required variable for multi-user HTTP deployments. Everything else is optional and activates specific features when set. Full table:

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `OAUTH_JWT_SECRET` | Yes (HTTP) | — | Signs JWT tokens for OAuth sessions; also seeds AES-256-GCM encryption key |
| `KITE_API_KEY` | No | — | Global Kite app API key (per-user OAuth used if unset) |
| `KITE_API_SECRET` | No | — | Global Kite app API secret |
| `KITE_ACCESS_TOKEN` | No | — | Pre-authenticated Kite token (bypasses browser login, local dev only) |
| `ENABLE_TRADING` | No | `false` | Enables order-placement tools (gated off on hosted deployment) |
| `EXTERNAL_URL` | No | `http://localhost:8080` | Public URL for OAuth callbacks |
| `APP_MODE` | No | `http` | `http`, `sse`, or `stdio` |
| `APP_PORT` | No | `8080` | HTTP listen port |
| `ALERT_DB_PATH` | No | `alerts.db` | SQLite database path |
| `TELEGRAM_BOT_TOKEN` | No | — | Telegram bot for alerts and daily briefings |
| `ADMIN_EMAILS` | No | — | Comma-separated admin email list |
| `GOOGLE_CLIENT_ID` / `_SECRET` | No | — | Google SSO for dashboard |
| `STRIPE_*` | No | — | Billing tier enforcement |
| `LITESTREAM_*` | No | — | R2/S3 SQLite replication |
| `EXCLUDED_TOOLS` | No | — | Comma-separated tool names to disable |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, `error` |

## Client setup

Any MCP-compliant client works with the same `mcp-remote` bridge above. Client-specific file locations:

- **Claude Code** — `~/.claude.json` (`mcpServers` key)
- **Claude Desktop** — `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/.config/Claude/claude_desktop_config.json` (macOS/Linux)
- **ChatGPT Desktop** — Settings -> Tools & Integrations -> MCP Servers -> add URL
- **VS Code / Cursor / Windsurf** — `.vscode/mcp.json` or equivalent

## Documentation

### For users
- **[Quick start](#quick-start)** — run locally or connect to hosted
- **[Terms of Service](TERMS.md)** & **[Privacy Policy](PRIVACY.md)** (currently DRAFT — under legal review)
- **[BYO Anthropic API key](docs/byo-api-key.md)** — bypass Claude.ai Pro tool-call limits

### For developers
- **[Architecture / how it works](docs/blog/oauth-13-levels.md)** — 2,500-word OAuth deep-dive (also published as blog)
- **[Contributing](CONTRIBUTING.md)**
- **[Adding a new tool](docs/adding-a-new-tool.md)**
- **[Environment variables](docs/env-vars.md)**

### Operations
- **[Release checklist](docs/release-checklist.md)**
- **[Operator playbook](docs/operator-playbook.md)**
- **[Incident response runbook](docs/incident-response.md)** — 4 crisis scenarios + contact directory
- **[Evidence package skeleton](docs/evidence/)** — pre-built for regulator/incident response

### Compliance / legal
- **[NSE algo framework status](docs/sebi-paths-comparison.md)** — Path 1-4 comparison
- **[Kite v4 migration hedge](docs/kite-version-hedge.md)** — dependency risk mitigation
- **[SBOM generation](docs/sbom.md)** — software bill of materials for supply chain transparency
- **[SECURITY.md](SECURITY.md)**

### Funding / ecosystem
- **[FLOSS/fund proposal](docs/floss-fund-proposal.md)** — Zerodha open-source grant application
- **[funding.json](funding.json)** — machine-readable funding manifest

### Claude Skills wrapper
- **[8 Skills](skills/README.md)** — /kite:morning, /kite:trade, /kite:eod, etc.

### Research / strategic
- **[Launch materials](docs/launch-materials.md)**
- **[Billing activation plan](docs/billing-activation-plan.md)**
- **[Multi-broker plan](docs/multi-broker-plan.md)**

## Dashboard

Once logged in via MCP OAuth, the dashboard cookie is set automatically (no second login).

| Page | Path | Description |
|------|------|-------------|
| Portfolio | `/dashboard` | Holdings, positions, P&L chart, order attribution |
| Activity | `/dashboard/activity` | AI tool-call audit trail with filters and CSV/JSON export |
| Orders | `/dashboard/orders` | Order history with AI attribution |
| Alerts | `/dashboard/alerts` | Active price alerts with enriched market data |
| Safety | `/dashboard/safety` | RiskGuard status, freeze controls, limit configuration |
| Paper Trading | `/dashboard/paper` | Paper portfolio, simulated orders, positions |
| Admin Ops | `/admin/ops` | All users, sessions, logs, metrics (admin only) |

## Comparison

| Feature | This server | [Official Kite MCP](https://mcp.kite.trade) | Streak |
|---------|:-----------:|:-------------------------------------------:|:------:|
| Tools | 117 | 22 | N/A |
| Order placement | Yes (local) | GTT only | Yes |
| Paper trading | Yes | No | No |
| Safety checks | 9 | 0 | 0 |
| Backtesting | 4 strategies | No | Yes |
| Options Greeks | Yes | No | No |
| Telegram alerts | Yes | No | No |
| Self-hostable | Yes | No | N/A |
| Cost | Kite Connect app (Rs 500/mo) | Free | Free + paid |

The official server is the right choice for read-only, zero-setup use. This server is for traders who want order placement, safety rails, and analytics.

## Prerequisites

- A [Kite Connect](https://kite.trade) developer app (Rs 500/month from Zerodha)
- `npx` (Node.js 18+) for `mcp-remote` — or Go 1.25+ to self-host from source

## Registry

Listed on the [official MCP Registry](https://modelcontextprotocol.info/tools/registry/) as `io.github.sundeepg98/kite-mcp-server`. Auto-indexed by [Smithery](https://smithery.ai) and [Glama](https://glama.ai). See [`server.json`](server.json).

## Contributing / funding

- **Issues / PRs** — [github.com/Sundeepg98/kite-mcp-server/issues](https://github.com/Sundeepg98/kite-mcp-server/issues). See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Built on** — [zerodha/kite-mcp-server](https://github.com/zerodha/kite-mcp-server) (MIT). Huge thanks to Kailash Nadh and the Zerodha team for open-sourcing the foundation.
- **Development** —

  ```bash
  nix develop          # or: install Go 1.25+
  just build           # compile
  just test            # run the full test suite
  just lint            # format + vet + golangci-lint
  ```

## License

[MIT](LICENSE). Copyright notice preserved for original Zerodha Tech contribution.

## Disclaimer

**Trademark:** `kite-mcp-server` is not affiliated with, endorsed by, or sponsored by Zerodha Broking Ltd. "Kite" and "Kite Connect" are trademarks of Zerodha Broking Ltd. This project is an independent open-source implementation of the Model Context Protocol server for the Kite Connect developer API.

**Not investment advice:** This software is a developer tool. Nothing in this repository, its documentation, or any output generated by the server constitutes investment, financial, legal, or tax advice. Trading decisions are the sole responsibility of the user operating their own Kite Connect developer application.

**Personal-use scope:** This server is designed for personal self-use by retail investors operating their own Kite Connect developer applications, consistent with SEBI's February 4, 2025 retail algorithmic trading framework §I(c) "family" carve-out (self, spouse, dependent children, dependent parents) and the <10 orders-per-second threshold. Multi-user hosting requires broker empanelment per SEBI §III(a) and NSE/INVG/67858 and is NOT supported by this repository.

## Compliance

**Applicable regulatory regimes (India):**
- SEBI (Stock Brokers) Regulations 2026 — retail algorithmic trading framework (effective April 1, 2026)
- Digital Personal Data Protection Act, 2023 (DPDP Act) — enforcement ramping 2026; rules partially notified
- CERT-In Directions (April 2022) — cybersecurity incident reporting

**What this server enforces out of the box:**

| Control | Default | Where enforced |
|---------|---------|----------------|
| Per-calendar-second order cap (9/sec) | Enforced | `kc/riskguard/per_second.go` (defensive; SEBI threshold = 10) |
| Per-minute order cap (10/min) | Enforced | `kc/riskguard/guard.go` |
| Daily order count cap | 20/day | `kc/riskguard/guard.go` |
| Per-order value cap | Rs 50,000 | `kc/riskguard/guard.go` |
| Daily cumulative value cap | Rs 2,00,000 | `kc/riskguard/guard.go` |
| Human confirmation on every order | Required (MCP elicitation) | `mcp/elicit.go` |
| Audit hash-chain | Tamper-evident | `kc/audit/store.go` |
| Per-user OAuth + encrypted credentials | AES-256-GCM via HKDF | `kc/crypto/` |
| Static egress IP whitelist | 209.71.68.157 (Fly.io bom) | Operator's Kite developer console |
| ENABLE_TRADING flag | `false` on hosted | Path 2 compliance |

**SEBI framework posture:**
- **Self + family** scope under SEBI §I(c) retail algo framework (Feb 4, 2025 circular): permitted for retail investor coding their own algo, on their own account, below 10 OPS threshold, for self/spouse/dependent-children/dependent-parents
- **Multi-user hosting** = empanelment required under §III(a) + broker-hosting mandate under NSE/INVG/67858 §I(h). **Not supported by this repository.**
- **Algo-ID tagging** (mandatory from April 1, 2026): injected server-side by Zerodha OMS for <10 OPS retail users — no client-side action required

**DPDP posture:**
- Data fiduciary: operator of the deployment
- Encryption at rest: AES-256-GCM via HKDF-derived keys
- Encryption in transit: TLS
- Audit log retention: 90 days (configurable via `AUDIT_RETENTION_DAYS`)
- Deletion on request: email `<grievance officer email>` or use dashboard tool
- Breach notification: CERT-In within 6 hours, users within 72 hours
- Personal/household exemption under DPDP s.17(2)(a): applies to self-only self-hosted use; voided by any external user

**If you are self-hosting:** you are the data fiduciary for your deployment. This section describes the code's capabilities; legal responsibilities belong to the operator.

**Where this code cannot help:**
- SEBI Investment Adviser / Research Analyst registration (different regime; out of scope)
- Tax compliance / GST (44ADA for sole prop, see your CA)
- Kite Connect Rs 500/month subscription (payable to Zerodha directly)

Reference documents in this repo:
- [`docs/PRIVACY.md`](docs/PRIVACY.md) — DPDP-aligned privacy notice (to be customized before hosting)
- [`docs/TERMS.md`](docs/TERMS.md) — SEBI-safe terms of service
- [`docs/incident-response.md`](docs/incident-response.md) — breach playbook
- [`docs/algo2go-tm-search.md`](docs/algo2go-tm-search.md) — trademark search procedure (if renaming)
