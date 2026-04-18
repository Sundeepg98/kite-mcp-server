# v1.1.0 — Path 2 compliance + research copilot

**Release date (target):** 2026-04-18
**Previous release:** v1.0.0

## Headline

Three new research-copilot MCP tools, Path 2 NSE/INVG/69255 compliance, 10+ security hardening upgrades.

## What's new

### 3 new research tools

- **`analyze_concall`** — earnings call summarizer. Returns structured guidance for LLMs to fetch + summarize concall transcripts.
- **`get_fii_dii_flow`** — institutional flow pointer + themes to extract.
- **`peer_compare`** — PEG / Piotroski F-score / Altman Z-score comparison for 2–6 stocks.

Plus `server_version` for deployment debugging (git SHA + uptime + region + env flags).

### Path 2 compliance (breaking change for hosted endpoint)

- **New env var: `ENABLE_TRADING`** (default: `false` on Fly.io hosted, `true` for local self-host)
- When false, 18 order-placement tools are **not registered** (place / modify / cancel / GTT / MF / trailing-stop / native-alert)
- This makes `kite-mcp-server.fly.dev/mcp` read-only pursuant to NSE/INVG/69255 Annexure I Para 2.8
- For trading: self-host locally with `ENABLE_TRADING=true` — the OpenAlgo-style personal-use safe harbor

### Security hardening

- Idempotency keys (`client_order_id`) on `place_order` / `modify_order` (Alpaca pattern)
- Anomaly detection: 30-day rolling μ+3σ baseline + 2–6 AM IST off-hours block
- Tool-description integrity manifest (detects line-jumping attacks)
- `X-Request-ID` correlation across HTTP → MCP → audit
- SSRF blocklist on audit publish endpoints
- RiskGuard default caps tightened: 20 orders/day, ₹2L notional, ₹50k per-order
- Default-on confirmation required per order
- OAuth consent cookie ordering verified (8 regression tests)
- Fuzz harnesses on `ArgParser` + widget injection + Telegram command parser
- SBOM generation in CI (CycloneDX to GitHub Code Scanning)

### New admin tools

- `admin_get_user_baseline` — per-user μ+3σ stats
- `admin_stats_cache_info` — cache hit rate + size
- `admin_list_anomaly_flags` — recent anomaly-blocked orders

### Operational improvements

- Pre-commit git hooks (gofmt / go vet / go build)
- Audit export script for DPDP Access Requests
- SBOM + gosec + govulncheck weekly CI scans
- `test-race` workflow for concurrency-critical packages
- `funding.json` + FLOSS/fund grant application submitted (Zerodha OSS fund)

### Documentation

- Incident response runbook (4 scenarios + contact directory)
- OAuth 13-levels technical blog post
- Monitoring + observability guide
- Kite token refresh runbook (6 AM IST daily expiry)
- Pre-deploy checklist (5-min operator runbook)
- Evidence package skeleton
- BYO Anthropic API key guide

### Legal + compliance

- `TERMS.md` + `PRIVACY.md` marked **DRAFT** pending lawyer review
- MIT attribution in Docker images + landing footer
- Zerodha Kite Connect compliance disclosure email drafted (ready to send)
- Claude Skills wrapper (8 skills) for one-command Claude Code install

## Migration

### If you self-host

- Upgrade to v1.1.0 by: `git pull` + `go build ./... && flyctl deploy`
- Optionally set `ENABLE_TRADING=true` in your `fly.toml` `[env]` block to preserve order placement
- See `docs/incident-response.md` for compliance posture

### If you use the hosted demo

- Order-placement tools now show as "unavailable" via MCP — this is intentional (Path 2)
- Research tools (`analyze_concall`, `get_fii_dii_flow`, `peer_compare`) are new — try them
- See landing page "Hosted vs Self-Host" callout

### Breaking changes

- **Path 2 env gate**: hosted endpoint loses order-placement tools. Local + `ENABLE_TRADING=true` preserves.
- **No API contract breaks** for tool schemas — same inputs/outputs everywhere they exist.

## Contributors

Sundeep Govarthinam + Claude (all commits co-authored)

## Next (v1.2.0 targets)

- NSE algo-provider empanelment (if commercially viable post-Rainmatter)
- Multi-broker adapter (Dhan port — see `docs/multi-broker-plan.md`)
- Concall + fundamental-data ingestion (auto-fetch, not just URL pointer)
- Prometheus metrics endpoint

## Thanks

Built on Zerodha's open-source Kite MCP Server (MIT). Thanks to the Kite Connect team, Kailash Nadh, and the MCP community.

---

**Verify your deploy ran this version:** call the `server_version` MCP tool and check `git_sha`.
