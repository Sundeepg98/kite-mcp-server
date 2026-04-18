# Self-hosting kite-mcp-server

Run locally with `ENABLE_TRADING=true` to unlock order placement, alerts, and
the Telegram bot. This is the **personal-use safe-harbor path** — single-user,
your own Kite developer app, your own machine. Analogous to running your own
algo script (see [OpenAlgo's framing][openalgo] of the compliance landscape for
Indian algo vendors and [`sebi-paths-comparison.md`](sebi-paths-comparison.md)
for Path 1-4 detail).

The hosted deployment at `kite-mcp-server.fly.dev` is read-only by design
(Path 2; order-placement tools are gated off pursuant to NSE/INVG/69255
Annexure I Para 2.8). Self-hosting is how you get the full server.

[openalgo]: https://www.marketcalls.in/fintech/exchange-compliance-for-algo-vendors-what-you-need-to-know.html

---

## Prerequisites

- **Go 1.25+** (`go version` — the `go.mod` pins `1.25`). Alternatively,
  Docker + `docker compose` works via `Dockerfile.selfhost`.
- **Zerodha Kite Connect developer app** — Rs 500/month subscription at
  <https://kite.trade>
  - Create the app at <https://developers.kite.trade/apps>
  - Note the API Key + API Secret
  - Set **Redirect URL** to `http://127.0.0.1:8080/callback` (must match
    `EXTERNAL_URL` exactly)
- **SQLite3 CLI** (optional, for audit-trail introspection)
- **Telegram bot token** (optional, for briefings + inline trading commands)

---

## Quick setup (5 minutes)

### 1. Clone and build

```sh
git clone https://github.com/Sundeepg98/kite-mcp-server.git
cd kite-mcp-server
go build -o kite-mcp-server .
```

(The `main.go` entry point lives at the repo root — not under `cmd/`.)

### 2. Create `.env`

```sh
cp .env.example .env
```

Minimum edits for a personal self-host with trading enabled:

```sh
# === Required ===
OAUTH_JWT_SECRET=<generate 64+ char high-entropy string>
EXTERNAL_URL=http://127.0.0.1:8080

# === Path 2: local build enables trading ===
ENABLE_TRADING=true

# === Server ===
APP_MODE=http
APP_PORT=8080
APP_HOST=127.0.0.1
LOG_LEVEL=info

# === Persistence (audit, riskguard, tokens, alerts) ===
ALERT_DB_PATH=./data/alerts.db

# === Admin (your own email) ===
ADMIN_EMAILS=you@example.com
ADMIN_PASSWORD=<first-boot password; unset after first login>

# === Optional: Telegram ===
# TELEGRAM_BOT_TOKEN=
```

**Generating `OAUTH_JWT_SECRET`:** must be at least 32 bytes of high-entropy
material. `openssl rand -hex 32` produces 64 hex chars; good enough. The
startup validator (`app/envcheck.go:55-71`) refuses placeholder values like
`your-secret`, `changeme`, `placeholder`.

**Do NOT set `KITE_API_KEY` / `KITE_API_SECRET` globally.** The server runs in
per-user OAuth mode when these are unset — you supply your developer app
credentials once at MCP-client OAuth time, and they're cached (AES-256-GCM
encrypted) in the local SQLite DB. This keeps a single `.env` usable for family
members on the same machine.

### 3. Run

```sh
mkdir -p data
./kite-mcp-server
```

Expected log lines on a healthy boot:

```
env var OAUTH_JWT_SECRET set ... value=****
env var EXTERNAL_URL set ... value=http://127.0.0.1:8080
env var ALERT_DB_PATH set ... value=./data/alerts.db
env var APP_MODE set ... value=http
env var ENABLE_TRADING=true — order-placement tools ENABLED (intended for local single-user only)
Starting Kite MCP Server... version=...
HTTP server listening ... addr=127.0.0.1:8080
```

Sanity-check: `curl http://127.0.0.1:8080/healthz` should return `ok`.

### 4. Connect an MCP client

**Claude Code:**

```sh
claude mcp add kite-local npx -y mcp-remote http://127.0.0.1:8080/mcp
```

**Claude Desktop** — edit `%APPDATA%\Claude\claude_desktop_config.json`
(Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS):

```json
{
  "mcpServers": {
    "kite-local": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8080/mcp"]
    }
  }
}
```

Restart the client. The first tool call triggers the MCP OAuth handshake —
browser opens, you paste your Kite app's API Key + Secret into the consent
page (one-time), then complete Kite login. Token caches locally.

---

## What's different from the hosted demo

| Capability | Hosted `kite-mcp-server.fly.dev` | Self-host (`ENABLE_TRADING=true`) |
|---|---|---|
| Portfolio, holdings, positions, margins | Yes | Yes |
| Market data, quotes, historical candles | Yes | Yes |
| Technical indicators, Greeks, backtests | Yes | Yes |
| Paper trading | Yes | Yes |
| Order placement (place/modify/cancel) | Gated off | Enabled |
| GTT orders + native Kite alerts | Gated off | Enabled |
| Mutual fund / SIP orders | Gated off | Enabled |
| Trailing stops | Gated off | Enabled |
| Telegram `/buy`, `/sell`, `/quick` commands | Gated off | Enabled |
| Compliance classification | Path 2 (read-only infra) | Personal-use safe harbor |

Gating is enforced at middleware (`app/wire.go` billing layer) — tools return
a typed `trading_disabled` error on the hosted deployment, cleanly bypassed
when the local env flag flips.

---

## First trade

1. Ask your MCP client: *"Show my holdings"* — confirms read-path works.
2. Ask: *"Place a limit order for 1 share of INFY at Rs 1"* — triggers the
   RiskGuard checks + elicitation confirmation (pop-up in supported clients).
   Confirm. Order will almost certainly reject at Zerodha for below-market
   price — which is the safe test: you've verified the full chain through
   your exchange without risking capital.
3. Check your Kite console — the order attempt should appear in the Orders
   tab regardless of rejection.

---

## Daily maintenance

- **Token re-auth (~06:00 IST):** Zerodha expires every Kite access token
  daily. On first call after 06:00 IST the server auto-returns 401; your MCP
  client auto-triggers a Kite login tab. One click, ~10 seconds. See
  [`kite-token-refresh.md`](kite-token-refresh.md) for the full flow.
- **Audit trail inspection:**
  ```sh
  sqlite3 ./data/alerts.db \
    "SELECT timestamp, email, tool, status FROM tool_calls ORDER BY timestamp DESC LIMIT 20;"
  ```
- **Backup:** the SQLite DB holds every stateful thing (tokens, alerts,
  audit, riskguard limits, billing). Copy `./data/alerts.db` periodically —
  it's self-contained. For continuous replication to R2/S3, configure the
  `LITESTREAM_*` env block (see [`env-vars.md`](env-vars.md) § Litestream).
- **Upgrades:**
  ```sh
  git pull && go build -o kite-mcp-server . && # restart
  ```

---

## Running as a background service

### macOS (launchd)

`~/Library/LaunchAgents/com.user.kite-mcp-server.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.user.kite-mcp-server</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/kite-mcp-server/kite-mcp-server</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/you/kite-mcp-server</string>
  <key>EnvironmentVariables</key>
  <dict><!-- or use `EnvironmentFile` via launchctl setenv --></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/kite-mcp.log</string>
  <key>StandardErrorPath</key><string>/tmp/kite-mcp.err</string>
</dict>
</plist>
```

Load: `launchctl load ~/Library/LaunchAgents/com.user.kite-mcp-server.plist`.

### Linux (systemd user unit)

`~/.config/systemd/user/kite-mcp-server.service`:

```ini
[Unit]
Description=Kite MCP Server (self-hosted)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/kite-mcp-server
EnvironmentFile=%h/kite-mcp-server/.env
ExecStart=%h/kite-mcp-server/kite-mcp-server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
```

Enable: `systemctl --user daemon-reload && systemctl --user enable --now kite-mcp-server`.

### Windows

Simplest path: [NSSM](https://nssm.cc/) wrapping `kite-mcp-server.exe` with
`AppDirectory` set to the repo root and `AppEnvironmentExtra` pointing at the
`.env` line-by-line. Task Scheduler with "At log on" + "Run whether user is
logged on or not" also works; see `run-server.cmd` at the repo root for the
PowerShell `Start-Process` detach pattern.

---

## Security posture

A self-host is a **single-user** deployment. Your Rs 500/month Kite Connect
app talks directly to Zerodha from your own machine — no third party sees
your credentials, your tokens, or your order flow. Every sensitive value
(Kite tokens, API secrets, OAuth client secrets, audit payloads) is AES-256-GCM
encrypted at rest using HKDF-derived keys from `OAUTH_JWT_SECRET`.

**Do:**
- Keep `.env` out of git (it's in `.gitignore`)
- Bind to `127.0.0.1` only (`APP_HOST=127.0.0.1`) unless you deliberately
  need LAN access
- Rotate `OAUTH_JWT_SECRET` if you suspect compromise — use
  `cmd/rotate-key/` to re-encrypt the DB

**Don't:**
- Expose port 8080 to the public internet. If you need remote access, use
  an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`) or Tailscale — not a
  naked port forward
- Share `OAUTH_JWT_SECRET`, your Kite API Secret, or `.env` contents
- Run with `DEV_MODE=true` against a real Kite account — that downgrades
  audit/riskguard failures to warnings

See [`SECURITY.md`](../SECURITY.md) and [`THREAT_MODEL.md`](../THREAT_MODEL.md)
for the full posture.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ENABLE_TRADING ... is invalid` at startup | Typo (e.g. `yes`, `True`, `1`) | Only `true`/`false` accepted (case-insensitive). See `app/envcheck.go:161-173`. |
| `OAUTH_JWT_SECRET too short` | < 32 bytes | Re-generate: `openssl rand -hex 32` |
| `OAUTH_JWT_SECRET looks like placeholder` | Literal `your-secret-key-here` from `.env.example` | Replace with a real random value |
| `ALERT_DB_PATH parent directory does not exist` | `./data/` not created | `mkdir -p data` before starting |
| OAuth callback fails in browser | Redirect URI mismatch | Kite app settings redirect URL must equal `EXTERNAL_URL + /callback` exactly |
| `token_expired` on every call | ~06:00 IST daily expiry | Re-login via the Kite tab your client opens; see [`kite-token-refresh.md`](kite-token-refresh.md) |
| Order tools return `trading_disabled` | `ENABLE_TRADING` not `true` | Check env; restart after change (env is read once at startup) |
| Claude Desktop can't connect to `http://127.0.0.1:8080/mcp` | `mcp-remote` HTTPS requirement | Add `--allow-http` to the mcp-remote args, or use a client that accepts plain HTTP for localhost |

---

## Related docs

- [README](../README.md) — project overview, hosted option, feature list
- [Environment variables inventory](env-vars.md) — every env var the server reads
- [Daily token refresh runbook](kite-token-refresh.md)
- [Operator playbook](operator-playbook.md)
- [Incident response](incident-response.md) — Scenario 1-C is the
  `ENABLE_TRADING=false` kill-switch flow
- [Pre-deploy checklist](pre-deploy-checklist.md) — Fly.io multi-user deploy
- [Monitoring](monitoring.md)
- [SEBI paths comparison](sebi-paths-comparison.md) — Path 1-4 detail
- [SECURITY.md](../SECURITY.md) & [THREAT_MODEL.md](../THREAT_MODEL.md)
