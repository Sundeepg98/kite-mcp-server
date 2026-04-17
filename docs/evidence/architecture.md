# Architecture — kite-mcp-server

Snapshot for evidence purposes. For deeper detail see `/ARCHITECTURE.md` and `/docs/callback-deep-dive-13-levels.md`.

## One-line description

A self-hosted MCP (Model Context Protocol) server that brokers OAuth-authenticated access between AI assistants (Claude, ChatGPT) and a user's own Zerodha Kite Connect developer app, with layered risk controls.

## ASCII diagram

```
                                                            +---------------------+
                                                            |  Zerodha Kite       |
                                                            |  Connect (kite.)    |
                                                            |  - login.kite.tr..  |
                                                            |  - api.kite.trade   |
                                                            +----------+----------+
                                                                       ^  OAuth + REST
                                                                       |  (per-user
                                                                       |   Kite app creds)
                                                                       |
 +--------------------+    +-------------------+    +------------------+---------+
 |  User @ Claude.ai  |    |  mcp-remote       |    |   kite-mcp-server          |
 |  / Claude Desktop  |----|  (OAuth bridge    |----|   (Fly.io region bom)      |
 |  / ChatGPT         |    |   on user host)   |    |   static egress IP         |
 +--------------------+    +-------------------+    |   209.71.68.157            |
                                 MCP over            |                            |
                                 Streamable HTTP     |  +---------------------+  |
                                                     |  | per-user AES-256-GCM|  |
                                                     |  | creds + tokens      |  |
                                                     |  +---------------------+  |
                                                     |  +---------------------+  |
                                                     |  | riskguard (8 checks)|  |
                                                     |  | kill switch, caps,  |  |
                                                     |  | rate, dup, freeze   |  |
                                                     |  +---------------------+  |
                                                     |  +---------------------+  |
                                                     |  | audit trail (SQLite)|  |
                                                     |  | hash-chain tamper   |  |
                                                     |  | evident             |  |
                                                     |  +---------------------+  |
                                                     |  +---------------------+  |
                                                     |  | elicitation dialogs |  |
                                                     |  | (confirm-to-trade)  |  |
                                                     |  +---------------------+  |
                                                     +--------+-------------------+
                                                              |
                                     +------------------------+---------------------+
                                     |                        |                     |
                          +----------v-----------+  +---------v--------+  +---------v---------+
                          | Litestream           |  | Telegram Bot     |  | Dashboard (HTTP) |
                          | SQLite WAL -> R2     |  | notifications,   |  | /dashboard      |
                          | (Cloudflare APAC)    |  | /buy /sell /brief|  | /admin/ops      |
                          +----------------------+  +------------------+  +-------------------+
```

## Core design choices (for regulator / compliance audience)

### 1. Per-user BYO Kite developer app

Every end user registers their own Zerodha developer app (API key + secret). Our server never holds a pooled/shared Kite credential. This means:

- Each user's trading activity is attributed to *their* app in Zerodha's OMS logs
- Compliance liability for algo-tagging, SEBI Algo-ID, rate limits, etc. stays with the user's app registration
- Our server is an OAuth relay + UX layer, not a broker intermediary

### 2. Encrypted credential + token storage

- `KiteCredentialStore` — per-user API key + secret (AES-256-GCM, HKDF-derived from `OAUTH_JWT_SECRET`)
- `KiteTokenStore` — cached Kite access tokens (same encryption)
- `ClientStore` — OAuth client registrations for mcp-remote (client_secret encrypted)
- All persisted in SQLite, all backed up via Litestream

### 3. Risk controls (riskguard)

Eight layered checks executed on every order attempt, before it reaches the Kite API:

1. Kill switch (global halt)
2. Per-order value cap (default ₹5 lakh)
3. Quantity cap per instrument
4. Daily order count (default 200/day/user)
5. Rate limit (10 orders/minute/user)
6. Duplicate order detection (30s window + idempotency keys)
7. Daily aggregate value cap (default ₹10 lakh/day)
8. Auto-freeze circuit breaker on repeated violations

Anomaly detection layer: rolling-baseline comparison + off-hours block.

### 4. Audit trail

- Every MCP tool call logged to SQLite `tool_calls` table
- Middleware-driven (guaranteed coverage — not opt-in)
- Buffered async writer to avoid tool-latency impact
- Hash-chain (commit `3591cc6`) for tamper-evident append-only log
- PII redaction before write
- 90-day retention cleanup
- CSV/JSON export for regulator requests
- Viewable at `/dashboard/activity` per user; `/admin/ops` for admin

### 5. Network posture

- Deployment: Fly.io, region `bom` (Mumbai), 512MB RAM
- Static egress IP: `209.71.68.157` — must be whitelisted in each user's Kite developer console per SEBI April 2026 mandate
- Per-IP rate limiting on all endpoints (auth 2/sec, token 5/sec, MCP 20/sec)
- OAuth-protected MCP endpoint; no anonymous tool calls possible
- MCP bearer JWT: 24h expiry; dashboard cookie JWT: 7 days; Kite access token: daily refresh ~6 AM IST

### 6. Notification channel

Telegram bot (separate from MCP transport) for:
- Morning 9 AM IST briefing (alerts, token status)
- Daily 3:35 PM IST P&L digest
- /buy /sell /quick /setalert commands with inline confirmation
- Every outbound trading-related message prefixed with SEBI disclaimer (commit `3879aba`)

### 7. Data residency + backup

- Primary data: SQLite on Fly.io bom region (India)
- Backup: Cloudflare R2 bucket `kite-mcp-backup` (APAC region) via Litestream continuous replication (10s sync)
- Auto-restore on server restart

## Boundaries — what we explicitly do NOT do

- We do not touch user funds directly — all order placement goes through Kite's OMS, which has its own broker-level controls
- We do not pool users under a single Kite app — the BYO model means no commingling
- We do not provide investment advice — tool names were renamed to avoid advisory language (commit `78301d6`), every output appends a legal disclaimer
- We do not retain user data beyond the audit retention window (90 days) except for operational metadata

## Source references

- `kc/riskguard/` — the 8 risk checks
- `oauth/` — the OAuth + JWT layer
- `audit/` — the tool-call audit trail
- `app/app.go` — service wiring + middleware chain
- `Dockerfile` + `fly.toml` — deployment configuration
- `cmd/rotate-key/` — encryption key rotation tool
