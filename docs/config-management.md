# Configuration Management — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: PR.IP-1 (Baseline configuration), PR.IP-3 (Configuration change control), PR.AC-1 (Identities and credentials), PR.DS-3 (Asset / configuration data protection).*
*Companion to: [`env-vars.md`](env-vars.md), [`change-management.md`](change-management.md), [`asset-inventory.md`](asset-inventory.md), [`recovery-plan.md`](recovery-plan.md), [`access-control.md`](access-control.md).*

This document is the operational policy for managing **configuration state** — env vars, secrets, deploy-time settings, and infrastructure configuration — across the lifecycle of `kite-mcp-server`. [`env-vars.md`](env-vars.md) is the *inventory*; this is the *policy* that governs how that inventory is populated, audited, and changed.

---

## 1. Configuration surfaces

`kite-mcp-server` reads configuration from five surfaces. Each has different durability, change-control, and audit characteristics.

| Surface | Durability | Audit trail | Change control | Examples |
|---|---|---|---|---|
| **Source-tree files** (committed) | Immutable per-commit | Git history | PR / commit gate | `fly.toml`, `Dockerfile`, `.github/workflows/*.yml`, `etc/litestream.yml` |
| **Non-secret env vars** (committed) | Per-deploy | Git history (`fly.toml [env]`) | PR / commit gate | `APP_HOST`, `APP_PORT`, `LOG_LEVEL`, `ALERT_DB_PATH`, `ENABLE_TRADING` |
| **Secret env vars** (Fly.io secrets) | Per-`flyctl secrets set` | Fly.io release history (presence only) | Direct `flyctl` operation | `OAUTH_JWT_SECRET`, `ADMIN_EMAILS`, `STRIPE_SECRET_KEY`, `LITESTREAM_*` |
| **Runtime DB state** (`config` table) | Per-row | `config` table writes | Server boot or admin action | `hkdf_salt`, future schema-version flags |
| **External vendor consoles** | Per-vendor | Vendor-side audit log | Vendor-specific UI | Stripe webhook URL, Cloudflare R2 bucket policy, Telegram bot token, Kite developer console |

The boundary between "non-secret" and "secret" is critical: anything that, if disclosed, lets an attacker impersonate the server, decrypt user data, or charge users money goes in the secret surface.

---

## 2. Env-var inventory and change policy

[`env-vars.md`](env-vars.md) is the canonical inventory (auto-validated against `os.Getenv`/`os.LookupEnv` grep of all `*.go` files plus `.env.example`, `fly.toml`, and `etc/litestream.yml`). This section adds the *policy* layer.

### 2.1 Categorisation

Per [`env-vars.md`](env-vars.md), env vars cluster into seven categories:

| Category | Count (approx) | Secret? | Change frequency |
|---|---|---|---|
| Core (server lifecycle, transport) | 6 | No | Rare (per-fly.toml-edit) |
| OAuth (multi-user HTTP) | 7 | Mixed (`OAUTH_JWT_SECRET` is secret) | Rare |
| Kite Connect (broker) | 3 | Yes | Per credential rotation |
| Telegram | 1 | Yes | On bot rotation |
| Billing (Stripe) | 5 | Yes | On Stripe API key rotation |
| Audit (hash chain external) | 7 | Yes | On bucket / credential change |
| Litestream (replication) | 4 | Yes | On R2 credential rotation |
| Dev | 1 | No | Per developer environment |

**Server refuses to start without** (`app/app.go:302-310`):
- `OAUTH_JWT_SECRET` (multi-user HTTP mode)
- `EXTERNAL_URL` (when `OAUTH_JWT_SECRET` is set)

### 2.2 Setting non-secret env vars

Non-secret env (e.g. `APP_PORT`, `ENABLE_TRADING=false`) lives in `fly.toml` `[env]`:

```toml
[env]
  APP_MODE = "http"
  APP_PORT = "8080"
  ENABLE_TRADING = "false"
```

Change procedure:

1. Edit `fly.toml` in a feature branch.
2. Commit and push (Gate A → B per [`change-management.md`](change-management.md) §4).
3. `flyctl deploy` picks up the change on next deploy.

### 2.3 Setting secret env vars

Secrets NEVER live in git. Set via:

```bash
flyctl secrets set OAUTH_JWT_SECRET=<value> -a kite-mcp-server
```

Fly.io stores secrets server-side; the value is exposed to the running container as an environment variable but is opaque from outside the machine.

`flyctl secrets list -a kite-mcp-server` shows secret *names* only — never values. Fly.io's release history records that a secret was changed, but not what it changed to.

### 2.4 Local development

`.env` files are git-ignored (`.gitignore` excludes `.env`, `.env.local`). The reference template is `.env.example` (committed). To bootstrap:

```bash
cp .env.example .env
# Fill in OAUTH_JWT_SECRET=$(openssl rand -hex 32) etc.
```

DEV_MODE=true unlocks the in-memory mock broker and skips most production gates. Per [`env-vars.md`](env-vars.md): "**Never set in production.**"

---

## 3. Secret rotation policy

### 3.1 `OAUTH_JWT_SECRET` (master encryption key)

**Status**: rotation CLI implemented at `cmd/rotate-key/main.go` (168 LOC + 878 LOC tests). Maintenance-window procedure documented below.

This single env var is the HKDF input for ALL T1 encryption-at-rest:
- `kite_credentials` (api_key, api_secret)
- `kite_tokens` (access_token)
- `oauth_clients` (client_secret)
- `mcp_sessions` (session_id_enc)

Rotation re-encrypts all rows from the old key to the new key in a single pass; correctly-rotated rows continue to decrypt with the new secret. Procedure:

1. Schedule a maintenance window (users will need to re-authenticate after step 6 because session decryption keys flip).
2. Take the service offline: `flyctl scale count 0 -a kite-mcp-server`.
3. Snapshot the DB: `flyctl ssh sftp get /data/alerts.db ./pre-rotation.db`.
4. Generate the new secret locally: `NEW_SECRET=$(openssl rand -hex 32)`.
5. Run the rotation CLI against the snapshot:
   ```bash
   go run ./cmd/rotate-key \
     -db ./pre-rotation.db \
     -old-secret "$OLD_SECRET" \
     -new-secret "$NEW_SECRET"
   ```
   Output enumerates rows rotated per table (`kite_tokens`, `kite_credentials`, `oauth_clients`, `mcp_sessions`).
6. Upload the rotated DB: `flyctl ssh sftp put ./pre-rotation.db /data/alerts.db`.
7. Set new secret: `flyctl secrets set OAUTH_JWT_SECRET="$NEW_SECRET"`.
8. Verify migration via re-encrypted hash chain: `auditStore.VerifyChain(...)`.
9. Bring service back: `flyctl scale count 1 -a kite-mcp-server`.

The CLI handles legacy nil-salt databases (pre-`EnsureEncryptionSalt`) and current salted databases transparently; it reads the `hkdf_salt` config-table value when present. Reference test coverage at `cmd/rotate-key/main_test.go` covers happy path, missing flags, error path, and subprocess behaviour.

**Today's reality**: full rotation requires service downtime; ad-hoc rotation invalidates all sessions and requires user re-auth. The CLI is binary-shippable today; the operational gap is real-time rotation (zero-downtime) which would require dual-key support at the encryption layer.

### 3.2 `ADMIN_EMAILS`

Adding or removing admin emails:

```bash
flyctl secrets set ADMIN_EMAILS="email1@example.com,email2@example.com"
```

Behaviour:
- Add: new email gains admin role on next restart (`Store.EnsureAdmin` at `kc/users/store.go:471`).
- Remove: email loses admin role on next restart, but their existing JWT (24h) and dashboard cookie (7d) remain valid until expiry.
- **No active kick-out**: removed admins retain access until session expiry. For immediate kick-out, additionally rotate `OAUTH_JWT_SECRET`.

### 3.3 `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET`

Rotation when Stripe rotates its keys (per Stripe security advisory) or when key compromise is suspected:

```bash
flyctl secrets set STRIPE_SECRET_KEY=sk_live_<new>
flyctl secrets set STRIPE_WEBHOOK_SECRET=whsec_<new>
```

Stripe webhook URL must be updated server-side via the Stripe dashboard to point at our new server URL if `EXTERNAL_URL` changes. If only the key rotates (URL unchanged), no Stripe-dashboard action required.

In-flight webhooks during rotation may fail signature validation (~minutes). The `webhook_events` table provides idempotency, so missed webhooks can be replayed by Stripe automatically.

### 3.4 `TELEGRAM_BOT_TOKEN`

Rotation: BotFather → `/revoke` → `/newtoken`:

```bash
flyctl secrets set TELEGRAM_BOT_TOKEN=<new-token>
```

Old subscribers continue working (chat IDs are stable). Telegram briefings, alerts, and inline trading commands all use the new token after machine restart.

### 3.5 `LITESTREAM_*` (R2 credentials)

Cloudflare R2 credentials rotate per Cloudflare's R2 console. To re-issue:

1. Cloudflare dashboard → R2 → Manage API Tokens → New token (scoped to bucket).
2. Update Fly.io secrets: `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY`.
3. Restart: `flyctl machine restart -a kite-mcp-server`.
4. Verify replication resumes: `/healthz?level=deep` `litestream` component.

### 3.6 `AUDIT_HASH_PUBLISH_*`

Same procedure as Litestream credentials (also R2-targeted typically). Currently OFF on the production deployment per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.1.

### 3.7 Kite Connect API key/secret (per-user)

Per-user Kite credentials (`kite_credentials` table) are stored AES-256-GCM-encrypted at rest. Rotation:

- **User-initiated**: user revokes their developer app on developers.kite.trade, creates a new one, re-uploads via dashboard → `KiteCredentialStore.Set` overwrites the encrypted row.
- **Server-initiated** (forced — if compromise suspected): admin marks the row `status=revoked`; user is locked out until they re-upload.

See [`incident-response.md`](incident-response.md) §"Credential compromise — Kite API key/secret" for the single-user vs server-side variants.

### 3.8 Rotation cadence (recommended)

| Secret | Cadence | Trigger |
|---|---|---|
| `OAUTH_JWT_SECRET` | (Deferred) | On suspected compromise, post-incident |
| `ADMIN_EMAILS` | Per personnel change | Admin add/remove |
| `STRIPE_SECRET_KEY` | Annual | Stripe security advisory |
| `STRIPE_WEBHOOK_SECRET` | Annual | Stripe security advisory |
| `TELEGRAM_BOT_TOKEN` | Annual | BotFather revoke event |
| `LITESTREAM_*` | Annual | Cloudflare R2 console |
| `AUDIT_HASH_PUBLISH_*` | Annual | (When enabled) |
| Per-user Kite | User-initiated | User-side token leak |

Annual rotation hygiene defends against unnoticed long-term compromise. Implementation today is manual; future: scheduled GitHub Actions workflow to remind quarterly.

---

## 4. Configuration baseline

The "known-good" state of every configuration surface as of HEAD `3501a11`:

### 4.1 `fly.toml` baseline

| Key | Value | Why |
|---|---|---|
| `app` | `"kite-mcp-server"` | Fly.io app slug |
| `primary_region` | `"bom"` | Mumbai (closest to Kite API + SEBI static-IP whitelist) |
| `internal_port` | `8080` | Container HTTP port |
| `force_https` | `true` | TLS-only enforcement at Fly.io edge |
| `min_machines_running` | `1` | At least one machine always up |
| `auto_stop_machines` | `false` | Don't suspend (audit chain needs continuity) |
| `mounts.source` | `"kite_data"` | Persistent volume for SQLite |
| `mounts.destination` | `"/data"` | Mount point |
| `[env].APP_MODE` | `"http"` | HTTP transport (not stdio/SSE) |
| `[env].APP_PORT` | `"8080"` | Match `internal_port` |
| `[env].APP_HOST` | `"0.0.0.0"` | Bind all interfaces |
| `[env].LOG_LEVEL` | `"info"` | Production log verbosity |
| `[env].ALERT_DB_PATH` | `"/data/alerts.db"` | Match volume mount |
| `[env].ENABLE_TRADING` | `"false"` | Path-2 compliance gate |

### 4.2 Required Fly.io secrets at HEAD `3501a11`

Confirmed via `flyctl secrets list -a kite-mcp-server` (names only — values opaque):

- `OAUTH_JWT_SECRET` — master encryption key
- `EXTERNAL_URL` — public URL for OAuth callbacks
- `ADMIN_EMAILS` — admin allowlist
- `ADMIN_ENDPOINT_SECRET_PATH` — secret URL path for admin metrics
- `TELEGRAM_BOT_TOKEN` — alerts/briefings
- `LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_BUCKET`, `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY` — replication

Optional secrets currently UNSET:

- `KITE_API_KEY`, `KITE_API_SECRET` — pure per-user OAuth on Fly.io
- `STRIPE_*` family — billing not active in production
- `AUDIT_HASH_PUBLISH_*` — external chain anchor opt-in (off by default)
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — Google SSO not active

### 4.3 Static egress IP

`209.71.68.157` (bom region) — referenced in:
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §5
- [`incident-response.md`](incident-response.md) §"Region failover"
- User-facing copy on the `byo-api-key.md` page

### 4.4 TLS termination

Fly.io's edge terminates TLS with a Let's Encrypt cert managed by Fly.io (renewed automatically). The `fly.toml [http_service] force_https = true` directive 301-redirects plain HTTP to HTTPS at the edge. The binary itself sees plain HTTP on `internal_port` (8080) and emits OAuth redirects + dashboard links via `EXTERNAL_URL` (which is `https://kite-mcp-server.fly.dev`). No TLS-related env vars are set in the Fly.io deployment.

For **off-Fly.io self-host deployments** (VPS, bare-metal, on-prem), two TLS env vars enable inline TLS via `golang.org/x/crypto/acme/autocert`:

| Var | Purpose | Example |
|---|---|---|
| `TLS_AUTOCERT_DOMAIN` | When set, server binds `:443` with autocert + `:80` for ACME challenges + 301 redirects to HTTPS. When unset, plain HTTP only (the Fly.io / Cloudflare-terminated default). | `mcp.example.com` |
| `TLS_AUTOCERT_CACHE_DIR` | Filesystem path for autocert's DirCache (issued certs + ACME account state). Defaults to `${HOME}/.cache/kite-mcp/autocert`. **MUST be on persistent storage** — Let's Encrypt's rate limit is 50 certs/domain/week; losing the cache forces re-issuance and rapidly exhausts the budget. | `/var/lib/kite-mcp/autocert` |

When `TLS_AUTOCERT_DOMAIN` is set, `APP_HOST` and `APP_PORT` are ignored (TLS needs the privileged port `:443`). Operators who want the binary on a non-standard port behind their own reverse proxy should use the reverse-proxy path instead — see [`tls-self-host.md`](tls-self-host.md) Path 2.

Misconfiguration is rejected at startup:
- Comma-separated domains (e.g. `a.com,b.com`) — multi-domain not yet supported
- Bare IPs (`1.2.3.4`) — ACME does not issue certs for IPs
- Wildcards (`*.example.com`) — wildcard requires DNS-01 challenge (provider-specific), not yet implemented

The Fly.io deployment intentionally leaves both vars unset; flipping them on Fly.io would conflict with Fly.io's edge TLS. See [`tls-self-host.md`](tls-self-host.md) for the full operator runbook (DNS prerequisites, port-forwarding, capability grants for non-root binding, certificate transparency considerations, Cloudflare interaction).

This IP must be whitelisted in each user's Kite developer console for order placement (SEBI April 2026 mandate). It changes only if Fly.io re-provisions our region (rare; would require manual user notification).

---

## 5. Configuration audit trail

Three intersecting trails together form the audit-of-configuration-changes record:

### 5.1 Git history (committed config)

Every change to `fly.toml`, `Dockerfile`, `.github/workflows/*.yml`, `etc/litestream.yml`, `.env.example` is in `git log`. Use:

```bash
git log --oneline -p fly.toml
git log --oneline -p Dockerfile
git log --oneline -- .github/workflows/
```

Configuration rollback is `git revert <bad-sha>` followed by `flyctl deploy` (per [`change-management.md`](change-management.md) §5).

### 5.2 Fly.io release history (deployed config)

```bash
flyctl releases -a kite-mcp-server
```

Returns:
- Release version (`vNNN`)
- Image SHA (Docker)
- Timestamp
- User who triggered (Fly.io API token owner)
- Whether it was a code or config change

For each release, `flyctl releases <vN>` (verbose) shows the env-var diff (names only for secrets; full values for non-secret).

### 5.3 GitHub Actions log (CI-validated config)

Workflow runs are preserved 90 days. The `ci.yml` and `security.yml` runs against each config change provide independent confirmation that the change passed CI before deploy.

### 5.4 Cross-trail correlation

Single audit query: "what was deployed at 14:30 IST on 2026-04-15?"

1. `flyctl releases` → release version at that time → image SHA.
2. Image SHA → CI workflow run that built it.
3. CI run → commit SHA.
4. Commit SHA → `git show <sha>` → exact code/config diff.
5. Cross-reference `tool_calls` audit trail for the same window — verifies the runtime behaviour matched the deployed code.

---

## 6. Configuration validation

`app/envcheck.go` validates required env vars at startup. Mode-specific validation:

| Mode | Required | Refuses to start without |
|---|---|---|
| Multi-user HTTP (Fly.io) | `OAUTH_JWT_SECRET`, `EXTERNAL_URL`, `ALERT_DB_PATH` | Any missing → `app/app.go:305` panic |
| Single-user (stdio) | `KITE_API_KEY` + `KITE_API_SECRET` (or `DEV_MODE=true`) | Missing → fall back to login flow |
| Dev | `DEV_MODE=true` | Nothing — all features become optional |

Misconfiguration surfaces FAST: bad env at startup either fails to bind (port busy), refuses to open SQLite (path missing), or panics on `app/app.go:305` with a clear message. Silent failure modes are documented in [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.7 (audit drop visibility) and the H1/H2/H3 known production issues in [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §13a.

---

## 7. Configuration drift detection

Two surfaces detect drift between source-of-truth and live:

### 7.1 Server version probe

`server_version` MCP tool (admin-callable) returns:
- Git SHA (via `runtime/debug.ReadBuildInfo()`)
- Build time
- Region (`bom`)
- Env flags (e.g. `ENABLE_TRADING`)

Compare against `git log --oneline -1` on master + expected env flags. Drift = unexpected version on production.

Source: `mcp/observability_tool.go` (referenced from [`monitoring.md`](monitoring.md) §3 and [`continuous-monitoring.md`](continuous-monitoring.md)).

### 7.2 Healthz JSON

`/healthz?format=json` returns runtime configuration state:

```json
{
  "version": "v1.0.0",
  "components": {
    "audit": {"status": "ok"},
    "riskguard": {"status": "ok"},
    "litestream": {"status": "unknown"}
  }
}
```

`status: defaults-only` on `riskguard` indicates per-user limits weren't loaded (DB unreachable or env mismatch). `status: disabled` on `audit` indicates audit middleware was skipped at startup. Both are silent-config-failure detectors per H1/H2 in [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §13a.

---

## 8. Out of scope

- **Application config files** (e.g. `config.yaml`, `app.json`): not used; all config is env-var driven.
- **Per-user preferences**: stored in the runtime DB (`users.preferences`, etc.); not part of the *server* config.
- **Browser-side state**: covered by [`data-classification.md`](data-classification.md) §"Out of scope."
- **Kite-side configuration**: each user owns their developer-console settings; we don't manage them.

---

## 9. Cross-references

- [`env-vars.md`](env-vars.md) — full env-var inventory with `file:line` references
- [`change-management.md`](change-management.md) — change-control gates
- [`asset-inventory.md`](asset-inventory.md) — services, deps, third-party APIs
- [`access-control.md`](access-control.md) — RBAC, admin gating
- [`recovery-plan.md`](recovery-plan.md) — RTO/RPO, DR drills
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.1, §4.2 — encryption baseline + rotation deferral
- [`vendor-management.md`](vendor-management.md) — vendor consoles + risk tiers
- [`incident-response.md`](incident-response.md) §"Credential compromise" — emergency rotation
- [`monitoring.md`](monitoring.md), [`continuous-monitoring.md`](continuous-monitoring.md) — drift detection
