# FLOSS/fund Application — Kite MCP Server

Repository: https://github.com/Sundeepg98/kite-mcp-server
Deployment: https://kite-mcp-server.fly.dev/
License: MIT

## Why this project matters

Zerodha's official Kite MCP server (`mcp.kite.trade`) is read-only: quotes, holdings, positions, GTT. This fork fills the execution half. It adds order placement (gated behind `ENABLE_TRADING`), price alerts with Telegram briefings, paper trading, options Greeks (Black-Scholes delta/gamma/theta/vega/IV), backtesting across four strategies, technical indicators, and a riskguard safety layer (kill switch, per-order caps, daily limits, rate limits, duplicate detection, auto-freeze). Being MCP-native, it runs inside Claude, ChatGPT, or any MCP-aware client — turning a retail broker API into a programmable trading copilot.

## Impact metrics today

- ~80 MCP tools, 330+ tests, v1.0.0 shipped
- Production on Fly.io (Mumbai region), SQLite + Litestream to Cloudflare R2
- MIT licensed, built on Zerodha's upstream fork
- Per-user OAuth, AES-256-GCM encrypted credential and token stores
- Security posture: ~9.5/10 after a 27-pass manual audit (181 findings, all resolved)
- Full AI-activity audit trail (every tool call logged, PII-redacted, 90-day retention)

## Complementarity with Zerodha's own MCP

Not a competitor — a superset. Zerodha's hosted MCP is the right default for 99% of users (managed, free, read-only). This project serves the power-user slice that needs order placement and programmatic controls. Because everything is MIT, useful patterns (OAuth model, audit trail, riskguard) are available upstream to merge or mirror.

## How funds would be used (ask: $25,000–$30,000)

- Indian Pvt Ltd incorporation + FY1 compliance — **$1,500**
- Trademark registration (Class 36 + 42) — **$500**
- CERT-In VAPT security audit — **$3,000**
- Independent external code/security audit — **$5,000**
- Six months of focused maintainer runway — **$20,000**

## Deliverables (12-month roadmap)

- **Q1** — Incorporation and compliance done; landing-page demand test live; BYO-API-key hedge shipped so users are never locked out by our app-tier limits.
- **Q2** — Concall analyzer, FII/DII flow tool, peer-comparison tool, expanded analytics.
- **Q3** — Multi-broker adapter (Dhan port) behind the same MCP surface.
- **Q4** — NSE empanelment application submitted; first paid tier live if traction justifies it.

## Maintainer

Sundeep Govarthinam — Bengaluru, India. 2+ years active Kite Connect developer. Sole maintainer of this fork since inception. Publishes all code under MIT; upstream PRs welcomed.

## Contact

- Email: g.karthick.renusharmafoundation@gmail.com
- GitHub: https://github.com/Sundeepg98
- Project: https://github.com/Sundeepg98/kite-mcp-server
