# Environment Variables — Consolidated Inventory

Authoritative reference for every environment variable read by the Kite MCP
server. Generated from a `os.Getenv`/`os.LookupEnv` grep of all `*.go` files
plus `.env.example`, `fly.toml`, and `etc/litestream.yml`. Sorted by category
then by name.

Columns:
- **Env var** — name as read from the environment
- **Required** — `Yes` means the server refuses to start (or the feature
  refuses to run) without it; `Opt` means feature is gated on presence
- **Default** — value applied when unset (blank `—` means the var is
  strictly opt-in and has no default)
- **Consumed by** — `file:line` reference; use this to chase context
- **Set in fly.toml?** — `yes` = baked into `[env]` block (non-secret,
  committed); `secret` = set via `flyctl secrets set` (never in the
  repo); `no` = feature not used on the Fly.io deployment

---

## Core (server lifecycle and transport)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `ALERT_DB_PATH` | SQLite database file path (backs alerts, tokens, users, audit, risk limits, billing). | Opt (production) | `` (unset) | `app/app.go:260`, `kc/ops/data.go:79`, `kc/ops/handler_metrics.go:54`, `mcp/observability_tool.go:130` | yes (`/data/alerts.db`) |
| `APP_HOST` | HTTP listen host. | Opt | `localhost` | `app/app.go:251` | yes (`0.0.0.0`) |
| `APP_MODE` | Transport: `http`, `sse`, `stdio`, `hybrid`. | Opt | `http` | `app/app.go:249` | yes (`http`) |
| `APP_PORT` | HTTP listen port. | Opt | `8080` | `app/app.go:250` | yes (`8080`) |
| `EXCLUDED_TOOLS` | Comma-separated tool names to disable at registration time. | Opt | `` (unset) | `app/app.go:253` | no |
| `LOG_LEVEL` | slog level: `debug`, `info`, `warn`, `error`. | Opt | `info` | `main.go:26` | yes (`info`) |

## OAuth (multi-user HTTP mode, dashboards)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `ADMIN_EMAILS` | Comma-separated admin emails — used for dashboard RBAC and first-boot admin seeding. | Opt | `` (unset) | `app/app.go:261` | secret |
| `ADMIN_ENDPOINT_SECRET_PATH` | Secret URL path segment for Prometheus/admin metrics endpoints. | Opt | `` (unset) | `app/app.go:241` | secret |
| `ADMIN_PASSWORD` | First-boot bcrypt-hashed password for every email in `ADMIN_EMAILS`. Intended to be unset after first successful login. | Opt | `` (unset) | `app/http.go:192` | no |
| `EXTERNAL_URL` | Public URL; used to build OAuth callbacks, invitation links, and Stripe return URLs. **Required when `OAUTH_JWT_SECRET` is set.** | Yes (OAuth mode) | `http://localhost:8080` (Stripe checkout fallback only) | `app/app.go:257`, `kc/billing/checkout.go:55`, `kc/billing/portal.go:30`, `mcp/admin_family_tools.go:63` | secret |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID for admin-console SSO. Both this and `GOOGLE_CLIENT_SECRET` must be set to enable. | Opt | `` (unset) | `app/app.go:263` | no |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret (pair with `GOOGLE_CLIENT_ID`). | Opt | `` (unset) | `app/app.go:264` | no |
| `OAUTH_JWT_SECRET` | HMAC signing secret for OAuth 2.1 JWT bearer tokens, OAuth client-secret encryption, and audit-chain HMAC fallback. **Server refuses to start in multi-user mode without it.** | Yes | `` (unset) | `app/app.go:256` | secret |

## Kite Connect (broker credentials)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `KITE_ACCESS_TOKEN` | Pre-obtained Kite access token (bypasses browser login). **Local dev only** — expires daily ~6 AM IST. | Opt | `` (unset) | `app/app.go:248` | no |
| `KITE_API_KEY` | Global Kite developer app API key. Unset on Fly.io — per-user OAuth handles auth there. | Opt | `` (unset) | `app/app.go:246` | no |
| `KITE_API_SECRET` | Global Kite developer app API secret. | Opt | `` (unset) | `app/app.go:247` | no |

Note: when both `KITE_API_KEY`/`KITE_API_SECRET` are empty and
`OAUTH_JWT_SECRET` is set, the server runs purely in per-user OAuth mode
(users supply their own app credentials during MCP OAuth). See
`app/app.go:302-310`.

## Telegram (price alerts, daily briefings)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token for alert notifications, morning briefings, and inline trading commands. Feature is disabled if unset. | Opt | `` (unset) | `app/app.go:259` | secret |

## Billing (Stripe paid tiers)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `STRIPE_PRICE_PREMIUM` | Stripe Price ID for the Premium tier (up to 20 family users). | Opt | `` (unset) | `app/wire.go:299`, `kc/billing/checkout.go:46`, `kc/billing/webhook.go:27` | no |
| `STRIPE_PRICE_PRO` | Stripe Price ID for the Pro tier (up to 5 family users). Webhook falls back to Pro when unset. | Opt | `` (unset) | `app/wire.go:299`, `kc/billing/checkout.go:43`, `kc/billing/webhook.go:26` | no |
| `STRIPE_PRICE_SOLO_PRO` | Stripe Price ID for the Solo Pro tier (1 user). | Opt | `` (unset) | `kc/billing/checkout.go:40`, `kc/billing/webhook.go:28` | no |
| `STRIPE_SECRET_KEY` | Stripe secret API key. Enables billing middleware and tier enforcement. Skipped entirely in `DEV_MODE`. | Opt | `` (unset) | `app/wire.go:273` | no |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret; required to register `/webhooks/stripe` endpoint. | Opt | `` (unset) | `app/http.go:384` | no |

## Audit (hash-chain external anchoring, SEBI CSCRF)

All five `AUDIT_HASH_PUBLISH_*` "connection" vars must be set together to
enable the publisher; it silently no-ops otherwise. See
`kc/audit/hashpublish.go:78-80`.

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `AUDIT_HASH_PUBLISH_ACCESS_KEY` | S3/R2 access key ID. | Opt | `` (unset) | `kc/audit/hashpublish.go:89` | no |
| `AUDIT_HASH_PUBLISH_BUCKET` | S3/R2 bucket name for uploaded chain-tip payloads. | Opt | `` (unset) | `kc/audit/hashpublish.go:88` | no |
| `AUDIT_HASH_PUBLISH_INTERVAL` | Go `time.ParseDuration` interval between uploads. | Opt | `1h` | `kc/audit/hashpublish.go:101` | no |
| `AUDIT_HASH_PUBLISH_KEY` | Dedicated HMAC signing key. When unset, HMAC falls back to `OAUTH_JWT_SECRET` bytes. | Opt | `OAUTH_JWT_SECRET` | `kc/audit/hashpublish.go:108` | no |
| `AUDIT_HASH_PUBLISH_REGION` | S3/R2 region. | Opt | `auto` | `kc/audit/hashpublish.go:91` | no |
| `AUDIT_HASH_PUBLISH_S3_ENDPOINT` | S3-compatible endpoint URL (e.g. `https://<account>.r2.cloudflarestorage.com`). | Opt | `` (unset) | `kc/audit/hashpublish.go:87` | no |
| `AUDIT_HASH_PUBLISH_SECRET_KEY` | S3/R2 secret access key. | Opt | `` (unset) | `kc/audit/hashpublish.go:90` | no |

## Litestream (SQLite replication to R2/S3)

Consumed by `etc/litestream.yml` at container start, not by the Go binary
itself. Referenced here for completeness.

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `LITESTREAM_ACCESS_KEY_ID` | R2/S3 access key ID for replication. | Opt | `` (unset) | `etc/litestream.yml:9` | secret |
| `LITESTREAM_BUCKET` | Target bucket name. | Opt | `` (unset) | `etc/litestream.yml:5` | secret |
| `LITESTREAM_R2_ACCOUNT_ID` | Cloudflare R2 account ID (used to build the endpoint URL). | Opt | `` (unset) | `etc/litestream.yml:7` | secret |
| `LITESTREAM_SECRET_ACCESS_KEY` | R2/S3 secret access key. | Opt | `` (unset) | `etc/litestream.yml:10` | secret |

## TLS self-host (off-Fly.io deployments only)

Inline TLS via `golang.org/x/crypto/acme/autocert`. Set on VPS / bare-metal
deployments where you want HTTPS directly on the binary; leave unset on
Fly.io / Cloudflare-fronted setups (TLS terminated upstream). See
[`tls-self-host.md`](tls-self-host.md) for the operator runbook (DNS
prerequisites, port forwarding, capability grants for non-root binding,
Cloudflare interaction).

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `TLS_AUTOCERT_DOMAIN` | Single hostname for ACME http-01 validation. When set, server binds `:443` with autocert + `:80` for ACME challenges + 301 redirect. Comma-separated, bare IPs, and wildcards are rejected at startup. | Opt | `` (unset) | `app/config.go`, `app/tls.go`, `app/http.go:serveHTTPSWithAutocert` | no |
| `TLS_AUTOCERT_CACHE_DIR` | Filesystem path for autocert's DirCache (issued certs + ACME account state). **MUST be on persistent storage** — Let's Encrypt rate-limits 50 certs/domain/week and losing the cache forces re-issuance. | Opt | `${HOME}/.cache/kite-mcp/autocert` (or `/var/lib/kite-mcp/autocert` if no `HOME`) | `app/tls.go` | no |

## Dev (local development only, never set in production)

| Env var | Purpose | Required | Default | Consumed by | fly.toml |
|---|---|---|---|---|---|
| `DEV_MODE` | When `true`: mock broker, audit/riskguard failures downgrade to warnings, billing is skipped. **Never set in production.** | Opt | `false` | `app/app.go:242` | no |

## Test-only (not read by the production binary)

These appear in `*_test.go` files and are documented for completeness; the
validator in `app/envcheck.go` ignores them.

| Env var | Purpose | Consumed by |
|---|---|---|
| `BE_MAIN_MISSING_FLAGS` | Drives subprocess test helper for `cmd/rotate-key` arg validation. | `cmd/rotate-key/main_test.go:737` |
| `BE_MAIN_RUN_ERROR` | Drives subprocess test helper for `cmd/rotate-key` error path. | `cmd/rotate-key/main_test.go:758` |
| `BE_MAIN_SUCCESS` | Drives subprocess test helper for `cmd/rotate-key` happy path. | `cmd/rotate-key/main_test.go:788` |
| `CI` | Skips slow or flaky tests in CI. | `app/server_test.go:5587`, `app/server_edge_test.go:1786`, `kc/users/store_test.go:327` |
| `TEST_DB_PATH` | Overrides the SQLite path inside subprocess test helpers. | `cmd/rotate-key/main_test.go:759,789` |

---

## Required at startup

Minimum set to boot the server in each mode.

### Multi-user HTTP (production, Fly.io profile)

Mandatory — server refuses to start without these:

1. `OAUTH_JWT_SECRET` — enables OAuth; also used to derive the audit-log
   encryption key, the HMAC for hash chaining, the AES-GCM key for stored
   Kite tokens and client secrets (via HKDF), and the fallback HMAC key
   for external hash publishing. Must be at least 32 bytes of
   high-entropy material. (`app/app.go:305`.)
2. `EXTERNAL_URL` — required whenever `OAUTH_JWT_SECRET` is set; used to
   build OAuth callback URLs that the browser redirects to. (`app/app.go:313`.)

Effectively required for correct operation in production mode:

3. `ALERT_DB_PATH` — when OAuth is on, the audit store, riskguard
   limits, token store, client store, user store, and alert store all
   need a SQLite path. Without it, audit initialization fails and the
   server exits. (`app/wire.go:107`.)
4. `ADMIN_EMAILS` — no ops-dashboard access is possible without at least
   one admin email; `ADMIN_PASSWORD` seeds a first-boot password.

### Single-user (desktop client, stdio)

Either the `KITE_API_KEY` + `KITE_API_SECRET` pair, or `DEV_MODE=true`
with the mock broker. `OAUTH_JWT_SECRET` can be omitted; HTTP-mode safety
checks do not trigger. (`app/app.go:302-310`.)

### Dev (local, mock broker)

`DEV_MODE=true` is sufficient. Everything else becomes optional — audit
and riskguard failures downgrade to warnings, billing is skipped, Kite
credentials are not required, and `ALERT_DB_PATH` can be omitted.
