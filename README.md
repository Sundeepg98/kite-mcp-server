# Kite Trading MCP Server

> Trade on Indian stock markets via AI — Claude, ChatGPT, VS Code, or any MCP client.

80 tools · Paper trading · Backtesting · Options Greeks · 8 safety checks · Telegram alerts · SEBI compliant

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev)
[![Tools](https://img.shields.io/badge/Tools-80-blue)]()
[![Tests](https://img.shields.io/badge/Tests-694-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## Registry

Listed on the [official MCP Registry](https://modelcontextprotocol.info/tools/registry/) as `io.github.sundeepg98/kite-mcp-server`.
Auto-indexed by [Smithery](https://smithery.ai) and [Glama](https://glama.ai).
See [`server.json`](server.json) for the full registry manifest.

## What it does

Connect any AI assistant to your Zerodha Kite account. Place orders, analyze portfolio, run backtests, compute options Greeks — all through natural conversation. 8 RiskGuard safety checks prevent costly mistakes before orders hit the exchange. Paper trading mode lets you practice risk-free.

## Quick Start

**1. Connect** — add to your MCP client config:
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

**2. Login** — tell your AI: *"Log me in to Kite"*. Complete the OAuth flow in your browser.

**3. Trade** — ask anything: *"Show my portfolio"*, *"What's RELIANCE at?"*, *"Backtest SMA crossover on INFY"*.

> **New to this?** Start with paper trading: *"Enable paper trading mode"* — all orders are simulated, no real money at risk.

## Features

| Category | Tools | Highlights |
|----------|------:|------------|
| **Trading** | 11 | Place/modify/cancel orders, GTT, convert positions, close all |
| **Portfolio** | 10 | Holdings, positions, margins, P&L, trades, order history |
| **Market Data** | 8 | Quotes, LTP, OHLC, historical data, instrument search, market status |
| **Analytics** | 7 | Portfolio summary, concentration, sector exposure, dividends, tax P&L |
| **Options** | 3 | Greeks calculator, option chain, strategy analysis |
| **Backtesting** | 1 | 4 built-in strategies: SMA crossover, RSI reversal, breakout, mean reversion |
| **Technical** | 2 | 10+ indicators (SMA, EMA, RSI, MACD, Bollinger), pre-trade analysis |
| **Paper Trading** | 3 | Simulated orders, paper portfolio, toggle on/off |
| **Alerts** | 9 | Price above/below, % drop/rise, Telegram notifications, native GTT alerts |
| **Mutual Funds** | 7 | MF holdings, place/cancel MF orders, SIP management |
| **Watchlists** | 6 | Create, manage, and monitor instrument watchlists |
| **Ticker** | 5 | Real-time WebSocket streaming, subscribe/unsubscribe |
| **Rebalancing** | 1 | Portfolio rebalance suggestions against target allocation |
| **Trailing SL** | 3 | Trailing stop-loss: start, status, cancel |
| **Infrastructure** | 2 | Login, open dashboard |

## Comparison

| Feature | This Server | [Official Kite MCP](https://mcp.kite.trade) | Streak |
|---------|:-----------:|:-------------------------------------------:|:------:|
| Tools | 80 | 22 | N/A |
| Order placement | Yes | GTT only | Yes |
| Paper trading | Yes | No | No |
| Safety checks | 8 | 0 | 0 |
| Backtesting | 4 strategies | No | Yes |
| Options Greeks | Yes | No | No |
| Telegram alerts | Yes | No | No |
| Self-hostable | Yes | No | N/A |
| Cost | Kite Connect app (Rs 500/mo) | Free | Free + paid |

The official server is the right choice for read-only use. This server is for traders who want order placement, safety rails, and analytics.

## Client Setup

### Claude Code

```json
// ~/.claude.json → mcpServers
{
  "kite": {
    "command": "npx",
    "args": ["mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
  }
}
```

### Claude Desktop

Add to `~/.config/Claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

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

### ChatGPT Desktop

Settings → Tools & Integrations → MCP Servers → Add:
```
https://kite-mcp-server.fly.dev/mcp
```

### VS Code / Cursor

Add to `.vscode/mcp.json`:
```json
{
  "servers": {
    "kite": {
      "command": "npx",
      "args": ["mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

### Windsurf

Add to MCP configuration:
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

### Self-hosted with Docker

Run kite-mcp-server on your own machine — no Go toolchain, no Fly.io required:

```bash
git clone https://github.com/Sundeepg98/kite-mcp-server && cd kite-mcp-server
cp .env.example .env                  # then edit: set OAUTH_JWT_SECRET (required)
docker compose up -d                  # builds Dockerfile.selfhost and starts it
curl http://localhost:8080/healthz    # should return "ok"
```

Point your MCP client at `http://localhost:8080/mcp` (use `--allow-http` if your
client requires it). To expose it publicly, put it behind a reverse proxy such as
Caddy, nginx, or a [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
tunnel — then set `EXTERNAL_URL` in `.env` to the public HTTPS URL so OAuth
callbacks work.

**Persistence warning:** the `kite_data` Docker volume holds `/data/alerts.db`
with AES-256-GCM encrypted Kite tokens, OAuth clients, alerts, and the audit
trail. If you lose the volume, all user logins die with it and must be redone.
Back it up if continuity matters. A bind-mount example is included (commented)
in `docker-compose.yml`.

### Self-hosted from source (Go users)

```bash
git clone https://github.com/Sundeepg98/kite-mcp-server && cd kite-mcp-server
go build -o kite-mcp-server && ./kite-mcp-server
```

Point your client to `http://localhost:8080/mcp` with `--allow-http`.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `OAUTH_JWT_SECRET` | Yes (HTTP mode) | — | Signs JWT tokens for OAuth sessions |
| `KITE_API_KEY` | No | — | Global Kite developer app API key (per-user OAuth if unset) |
| `KITE_API_SECRET` | No | — | Global Kite developer app API secret |
| `KITE_ACCESS_TOKEN` | No | — | Pre-authenticated Kite token (bypasses browser login, local dev only) |
| `EXTERNAL_URL` | No | `http://localhost:8080` | Public URL for OAuth callbacks and links |
| `APP_MODE` | No | `http` | Server mode: `http`, `sse`, or `stdio` |
| `APP_PORT` | No | `8080` | HTTP listen port |
| `APP_HOST` | No | `0.0.0.0` | HTTP listen host |
| `ALERT_DB_PATH` | No | `alerts.db` | Path to SQLite database file |
| `TELEGRAM_BOT_TOKEN` | No | — | Telegram bot token for alert notifications and daily briefings |
| `ADMIN_EMAILS` | No | — | Comma-separated list of admin email addresses |
| `ADMIN_ENDPOINT_SECRET_PATH` | No | — | Secret URL path segment for admin endpoints |
| `ADMIN_PASSWORD` | No | — | Password for admin login (bcrypt hashed at runtime) |
| `EXCLUDED_TOOLS` | No | — | Comma-separated tool names to disable |
| `LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID for SSO login |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret for SSO login |
| `STRIPE_SECRET_KEY` | No | — | Stripe secret key to enable billing tier enforcement |
| `STRIPE_WEBHOOK_SECRET` | No | — | Stripe webhook signing secret |
| `STRIPE_PRICE_PRO` | No | — | Stripe Price ID for the Pro tier |
| `STRIPE_PRICE_PREMIUM` | No | — | Stripe Price ID for the Premium tier |
| `LITESTREAM_BUCKET` | No | — | R2/S3 bucket name for Litestream SQLite replication |
| `LITESTREAM_R2_ACCOUNT_ID` | No | — | Cloudflare R2 account ID for Litestream |
| `LITESTREAM_ACCESS_KEY_ID` | No | — | R2/S3 access key ID for Litestream |
| `LITESTREAM_SECRET_ACCESS_KEY` | No | — | R2/S3 secret access key for Litestream |

Only `OAUTH_JWT_SECRET` is required for multi-user HTTP deployments. All other variables are optional and enable specific features when set.

## Safety: RiskGuard

Every order passes through 8 checks before reaching the exchange. Any failure blocks the order instantly.

| # | Check | What it does |
|---|-------|-------------|
| 1 | **Kill switch** | Freeze/unfreeze trading per user — immediate halt |
| 2 | **Order value limit** | Block orders exceeding Rs 5,00,000 (configurable) |
| 3 | **Quantity limit** | Reject quantities above exchange freeze limits |
| 4 | **Daily order count** | Cap at 200 orders/day (configurable) |
| 5 | **Rate limit** | Max 10 orders/minute to prevent runaway loops |
| 6 | **Duplicate detection** | Block identical orders within 30-second window |
| 7 | **Daily value cap** | Cumulative placed value capped at Rs 10,00,000/day |
| 8 | **Circuit breaker** | Auto-freeze account after 3 rejections in 5 minutes |

All limits are per-user, configurable, and persisted to SQLite. Paper trading mode bypasses the exchange entirely — orders are simulated locally.

## Dashboard

| Page | Path | Description |
|------|------|-------------|
| Portfolio | `/dashboard` | Holdings, positions, P&L chart, order attribution |
| Activity | `/dashboard/activity` | AI tool call audit trail with filters, live stream, CSV/JSON export |
| Orders | `/dashboard/orders` | Order history with AI attribution |
| Alerts | `/dashboard/alerts` | Active price alerts with enriched market data |
| Safety | `/dashboard/safety` | RiskGuard status, freeze controls, limit configuration |
| Paper Trading | `/dashboard/paper` | Paper portfolio, simulated orders, positions |
| Admin Ops | `/admin/ops` | All users, sessions, logs, metrics (admin only) |

SSO is automatic — login once via MCP OAuth, dashboard session follows.

## Architecture

```
AI Client ←→ MCP Protocol ←→ Kite MCP Server ←→ Kite Connect API ←→ NSE/BSE
```

- **Go** with [mcp-go](https://github.com/mark3labs/mcp-go) v0.46.0
- **SQLite** for persistence (credentials, alerts, sessions, audit trail — all AES-256-GCM encrypted)
- **OAuth 2.1 + PKCE** — each user brings their own Kite developer app
- **Fly.io** deployment with static egress IP for SEBI compliance
- **Litestream** continuous SQLite replication to R2
- **Telegram** daily briefings (9 AM alerts + 3:35 PM P&L)

## Prerequisites

- A [Kite Connect](https://kite.trade) developer app (Rs 500/month from Zerodha)
- `npx` (Node.js 18+) for `mcp-remote` — or self-host with Go 1.25+

## Contributing

Contributions welcome. Check [open issues](https://github.com/Sundeepg98/kite-mcp-server/issues) for ideas.

```bash
nix develop          # or: install Go 1.25+
just build           # compile
just test            # run 694 tests
just lint            # format + lint
```

## License

[MIT](LICENSE)

## Disclaimer

This software is not financial advice. Not affiliated with Zerodha. Trading involves risk — use at your own risk. SEBI-regulated operations require compliance with applicable regulations.
