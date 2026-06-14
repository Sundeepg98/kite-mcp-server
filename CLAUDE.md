# CLAUDE.md - Kite MCP Server

Orientation for a fresh Claude session. Keep this a stable map; volatile status lives in `README.md` / git / the docs below, not here.

## What it is

**Kite MCP Server** (`github.com/Sundeepg98/kite-mcp-server`, Go 1.25, MIT) - an MCP server that gives Claude / ChatGPT / any MCP client direct access to a **Zerodha Kite** trading account: order placement, paper trading, options Greeks, backtesting, Telegram alerts, and **RiskGuard** (11 pre-trade safety checks). **110+ tools.** Complementary to Zerodha's official read-only MCP (which is 22 tools, GTT only).

Two ways it runs, and the distinction matters for everything below:

| Mode | Where | Trading | Notes |
|------|-------|---------|-------|
| **Hosted demo** | Fly app `kite-mcp-server` (region `bom`), `https://kite-mcp-server.fly.dev/mcp` | **READ-ONLY** | `ENABLE_TRADING=false` gates off all 18 order-placement tools. This is a legal posture, not a feature gap (see SEBI note). |
| **Self-host** | `Dockerfile.selfhost` / `docker compose up -d`, `http://localhost:8080/mcp` | **FULL** | Personal-use safe harbor - you remain the Zerodha Client; the software just helps you place your own orders. Set `OAUTH_JWT_SECRET`. |

## Branch / repo

- Active branch is **`master`** (not `main`/`development`). Remote `Sundeepg98/kite-mcp-server`.
- **Deploy is MANUAL.** `git push origin master` does **NOT** auto-deploy (contrast appscriptly, which auto-deploys on push). CI (`.github/workflows/ci.yml`) runs `go build` / `go vet` / `go test -race`; `smoke-canary.yml` smoke-tests the live URL every 30 min. To ship a change you must run `flyctl deploy -a kite-mcp-server` yourself.

## Commands

```bash
go build -o kite-mcp-server && ./kite-mcp-server   # local build/run (Go, no Docker)
docker compose up -d                               # self-host full-trading (Dockerfile.selfhost)
go test ./... -count=1                              # tests (run per module; ~9000 across 32 algo2go modules + deploy repo)
curl http://localhost:8080/healthz                 # health probe ("ok")

# Deploy the hosted app (MANUAL):
flyctl deploy -a kite-mcp-server                                   # full build + deploy from Dockerfile
flyctl deploy -a kite-mcp-server --image <current-image> --config fly.toml -y   # config-only, no rebuild (safest for a trading app)
flyctl status -a kite-mcp-server                                   # machine state / version / live image
flyctl logs -a kite-mcp-server --no-tail                          # boot + runtime logs
```

## Architecture (brief)

- **Modular via `go.work`:** the heavy logic lives in **32 externalized `algo2go/kite-mcp-*` modules** (riskguard, paper, oauth, audit, alerts, app, ops, telegram, rotate, kc, ...); this deploy repo holds `cmd/` + `main.go` + glue and wires them together. ~9000 tests across 493 files. **The modules live in the sibling folder `../algo2go/` (each its own `github.com/algo2go/kite-mcp-*` repo) — see `../algo2go/CLAUDE.md` for the engine-module map + their restart-behavior audit findings.**
- **RiskGuard** (`algo2go/kite-mcp-riskguard`): 11 pre-trade checks fire on every trade (per-order value cap Rs 50k, qty limit, 20 orders/day, 10/min + per-second rate limits, 30s duplicate window, Rs 2L daily cumulative cap, idempotency dedup, confirmation-required, anomaly mu+3sigma, off-hours block) + kill switch + circuit breaker + global freeze + OTR-band + margin-sufficiency.
- **Security:** AES-256-GCM at rest for every sensitive value (Kite tokens, API/OAuth secrets), key via HKDF from `OAUTH_JWT_SECRET`. Per-tool-call **audit trail** (90-day retention, hash-chained, optional S3 anchor). **OAuth 2.1** with Kite as the identity provider. **DPDP consent log**. Security audit: 6 HIGH all fixed (see `SECURITY_AUDIT_FINDINGS.md`, `THREAT_MODEL.md`).
- **State / DR:** SQLite at `ALERT_DB_PATH=/data/alerts.db` on a Fly volume (`kite_data`), continuously replicated to **S3 via litestream** (`replica sync` log line every ~10s).

## Guardrails (regulatory + operational - keep)

- **SEBI / read-only gate:** the hosted instance MUST keep `ENABLE_TRADING=false`. With trading enabled, the multi-user hosted server would fall under NSE/INVG/69255 Annexure I Para 2.8 "Algo Provider" classification. Order tools are only for self-host / local single-user. Do not flip `ENABLE_TRADING=true` on the hosted app.
- **Static egress IP is load-bearing - DO NOT CHANGE IT.** The dedicated egress IP **`209.71.68.157`** (bom) is on each user's Kite developer-console / SEBI allow-list. In-region machine **stop/start preserves it** (it's an app-level dedicated allocation), so scale-to-zero is safe. A **region change WOULD change it** -> every order fails "IP not whitelisted". This is why `primary_region = "bom"` is fixed and multi-region (`sin`) is gated behind adding a non-Kite broker (see `fly.toml` header + `docs/incident-response.md` "Region failover").
- **Trading app = deploy conservatively.** Prefer config-only deploys (`--image <current>`) when you're only changing `fly.toml`, so the running binary doesn't change. Rollback: `flyctl releases rollback <vN> -a kite-mcp-server`. SQLite migrations are forward-only but additive/idempotent.

## Current operational status (2026-06-14)

**Hosted Fly app flipped to scale-to-zero (cost).** Operator-directed. Was `auto_stop_machines = false` / `min_machines_running = 1` (always-on, ~$3/mo for the machine); now `auto_stop_machines = "stop"` / `min_machines_running = 0`. Shipped **config-only** (`flyctl deploy --image registry.fly.io/kite-mcp-server:deployment-01KRRG6EE4009WSKM16ZF8X6QD --config fly.toml`) so the binary is unchanged - now **v277**, machine `2863d22b7eee18`, bom, healthy on `:8080`, `ENABLE_TRADING=false` (93 tools registered, 18 trading tools gated). Egress IP `209.71.68.157` unchanged -> SEBI-safe. `auto_start_machines` defaults true -> wakes on inbound request (~12s cold start (measured; dominated by a synchronous api.kite.trade instruments fetch at boot)). Full safety reasoning is inline in the `fly.toml` `[http_service]` comment.

**Residuals to be aware of (honest tradeoffs of scale-to-zero):**
1. While the machine is auto-stopped, the in-process **scheduler tasks** (`pnl_snapshot` ~15:40, `audit_cleanup` ~03:00) and the litestream replica loop are paused; they resume on the next wake. A scheduled task whose entire window falls inside an idle period won't fire that day unless a request happens to wake the machine. Acceptable for a near-idle read-only hosted instance (~1 user); revisit if the hosted app gains real traffic or alert-firing duties.
2. Fly "stuck-stopped after platform churn" bug class - recoverable via `flyctl machine start <id>` / a manual restart.
3. Pre-existing (image-level, **NOT** caused by this flip) boot ERROR: `Failed to initialize domain_events table: no such column: email_hash`. It surfaces on every boot of the current image regardless of auto_stop - a latent migration issue to fix separately when next touching the schema.
4. **Worst-case boot crash-loop if Kite API is unreachable at wake.** Boot does a *synchronous* `api.kite.trade/instruments.json` fetch before the port binds; if Kite is down/slow at wake, boot can hang ~96s then exit 1 and crash-loop until Kite recovers (self-heals once Kite is back). Now more exposure with scale-to-zero (every wake re-fetches). **Deferred fix:** make the instruments load async / non-fatal so cold start shrinks and a Kite-API hiccup at wake can't crash-loop boot. (This is also why `kill_timeout = "15s"` was added — frequent stops need room for HTTP drain + litestream final WAL sync + the audit async write-buffer flush before SIGKILL.)
5. **`pnl_snapshot` (~15:40) misses on idle days.** Under scale-to-zero, if no request wakes the machine across the 15:40 window the daily P&L snapshot doesn't fire. It is **analytics-only** (~0 impact on the idle ~1-user demo). Likewise **Telegram briefings are not wired on the hosted build**, so no alerting is lost by stopping.

**Safety audit (2026-06-14): compliance/data SAFE.** A dedicated audit confirmed scale-to-zero is compliance- and data-safe: the **audit hash-chain re-seeds the prev-hash from the DB's last row on every boot** (audit module `SeedChain`), so "audit chain needs continuity" was a **FALSE** justification for always-on — chain continuity is preserved across stop/start via the DB re-seed (the real stop-time concern is flushing the async audit write-buffer + litestream's final WAL sync before SIGKILL, addressed by `kill_timeout`). Durability (SQLite on the Fly volume + litestream→S3), sessions, and 90-day retention are all fine across stop/start. The only behavioral deltas are the analytics-only `pnl_snapshot` miss (residual 5) and that Telegram briefings aren't wired on hosted anyway. Durable write-up: `.research/2026-06-14-scale-to-zero-safety-audit.md`.

**To revert to always-on:** set `auto_stop_machines = false` / `min_machines_running = 1` in `fly.toml` and redeploy config-only.
