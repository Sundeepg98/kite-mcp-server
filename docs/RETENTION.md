# Data Retention Policy — kite-mcp-server

*Last reviewed: 2026-04-26*
*Scope: hosted instance at `https://kite-mcp-server.fly.dev` and self-host forks. Companion to [`data-classification.md`](data-classification.md).*

## 1. Purpose

This document specifies the **lifecycle** of every persisted data class — when it
is written, what triggers its deletion, and which Go code performs the cleanup.
It is the operational counterpart to [`data-classification.md`](data-classification.md)
(which defines tiers and encryption) and is intended to be the answer key for
DPDP §8 erasure requests, SEBI cyber-audit-trail evidence requests, and
incident-recovery playbooks.

Every retention claim below points to a `file:line` so an auditor can verify
the policy is enforced in code, not aspirational.

## 2. Summary Table

| Data class                | Storage                          | Trigger              | Window           | Code reference |
|---------------------------|----------------------------------|----------------------|------------------|----------------|
| Tool-call audit trail     | `tool_calls` (SQLite)            | Daily scheduler      | 5 years (default in prod) | `app/wire.go:824-841`, `kc/audit/retention.go:34-40` |
| Audit chain break-marker  | `tool_calls` row + `__chain_break` | At delete time | Permanent (1 row per cleanup batch) | `kc/audit/retention.go:31-33` |
| Encrypted Kite credentials| `kite_credentials`               | Explicit user/admin delete | Until consent withdrawn or account deleted | `kc/credential_store.go:137`, `kc/alerts/db_commands.go:187-188` |
| Encrypted Kite tokens     | `kite_tokens`                    | Daily Kite expiry detection + explicit delete | ~24 h cycle (~06:00 IST refresh) | `kc/expiry.go:15-23`, `kc/token_store.go:120-130`, `kc/alerts/db_commands.go:155-156` |
| OAuth client registrations| `oauth_clients` (encrypted secret) | Explicit revoke    | Until client revokes | `oauth/handlers.go` (issued at register) |
| MCP bearer JWT            | Stateless (no DB row)            | Self-expiring claim  | 24 hours         | `oauth/config.go:30-31` |
| Dashboard SSO JWT (cookie)| Stateless (browser cookie)       | Self-expiring claim  | 7 days           | `oauth/middleware.go:131-144` |
| Google SSO state cookie   | Browser cookie                   | OAuth handshake end  | 5 minutes        | `oauth/google_sso.go:88` |
| MCP session registry      | `mcp_sessions` + RAM             | 30-min cleanup tick  | 12 h since last use | `kc/session.go:34-35`, `kc/session.go:375-419`, `kc/session.go:466-486` |
| Family invitations        | `family_invitations`             | 6-h cleanup tick     | 7 days unless accepted | `kc/usecases/family_usecases.go:168`, `kc/users/invitations.go:163-180`, `app/wire.go:590-612` |
| Price alerts              | `alerts`                         | Explicit user/admin delete | Until user-delete or account-delete | `kc/alerts/db_commands.go:80-91`, `kc/alerts/store.go:235-256` |
| Trailing stops, GTT-style | `trailing_stops`                 | Filled / cancelled / explicit delete | Until terminal | `kc/alerts/db.go:133` |
| Watchlists                | `watchlists`, `watchlist_items`  | Explicit delete      | Until user-delete | `kc/watchlist/db.go` |
| Daily P&L snapshots       | `daily_pnl`                      | None (append-only)   | Until account-delete | `kc/alerts/briefing.go` (PnL snapshot service) |
| Paper-trading state       | `paper_*` tables                 | User reset / account-delete | Until reset      | `kc/papertrading/store.go` |
| Riskguard dedup keys      | RAM-only `Dedup`                 | TTL eviction         | 15 minutes       | `kc/riskguard/dedup.go:10-13` |
| Anomaly baseline cache    | RAM-only `statsCache`            | TTL + size cap (10K) | 15 minutes / random eviction at cap | `kc/audit/anomaly_cache.go:11-44` |
| Per-tool rate-limiter buckets | RAM-only                     | 10-min sweeper       | 10 minutes idle  | `app/ratelimit.go:147,195,205` |
| Telegram pending-confirm cache | RAM-only                    | 2-min cleanup tick   | 2 minutes        | `kc/telegram/bot.go:171-194` |
| Consent log               | `consent_log`                    | None (append-only)   | Indefinite (regulatory evidence) | `kc/audit/consent.go` |
| Domain events             | `domain_events`                  | None (event source-of-truth) | Indefinite (`email_hash` only) | `kc/eventsourcing/store.go` |
| Litestream replicas (R2)  | Cloudflare R2 bucket             | Litestream retention | 24 h default WAL window | `etc/litestream.yml` |

## 3. Per-Class Detail

### 3.1 Tool-call audit trail

The `tool_calls` table records every MCP tool invocation (params summarised and
PII-redacted at write time — see `kc/audit/store.go`).

**Production (`app/wire.go:824-841`):** the in-process scheduler fires
`DeleteOlderThan(now - 1825d)` daily at **03:00 IST**, retaining **5 years** to
satisfy SEBI algo-trading audit requirements (the `retentionDays = 1825`
constant is wired explicitly).

**In-package backstop (`kc/audit/retention.go:34-129`):** when an external
scheduler is **not** wired (self-host, dev), `Store.StartRetentionWorker(days)`
runs `CleanupOldRecords(days)` every 24 h. The default window is
`DefaultRetentionDays = 90` (DPDP-compliance minimum, line 16). Operators
override with `AUDIT_RETENTION_DAYS=N`; setting `AUDIT_RETENTION_DAYS=0`
**disables** the in-package worker entirely (used in production where the
external scheduler owns retention to avoid double-deletion).

**Hash-chain integrity:** `DeleteOlderThan` writes a `__chain_break` marker row
so `VerifyChain` can detect retention boundaries vs. tampering
(`kc/audit/retention.go:31-33`).

### 3.2 Encrypted Kite credentials (`kite_credentials`)

User-supplied Kite developer-app `api_key` + `api_secret`, encrypted at rest with
AES-256-GCM (HKDF-derived from `OAUTH_JWT_SECRET`).

**Trigger-based only.** No automatic cleanup. Removed when:
1. User explicitly clears credentials via the dashboard / `kc.Manager` API →
   `KiteCredentialStore.Delete()` (`kc/credential_store.go:137`) →
   `DB.DeleteCredential(email)` (`kc/alerts/db_commands.go:187-188`).
2. Admin-driven user deletion (DPDP erasure path; see §4).

There is **no time-based expiry** — credentials remain encrypted at rest until
explicit removal. This is intentional: Kite developer-app credentials don't
auto-rotate, and proactive deletion would force users to re-register on every
visit.

### 3.3 Kite access tokens (`kite_tokens`)

Per-user Kite access tokens, encrypted at rest.

**Logical expiry: ~24 h.** Kite issues a fresh token on each `request_token →
access_token` exchange; the token is invalidated by Kite around **06:00 IST
daily** regardless of when issued. `IsKiteTokenExpired(storedAt)`
(`kc/expiry.go:15-23`) computes "is the most recent 06:00 IST in the past
since storedAt?" and returns true once expired.

**No proactive deletion** — expired rows are left in place; the OAuth middleware
returns 401 when a stored token fails the freshness check, prompting
mcp-remote to re-auth, which **overwrites** the row with a fresh token. Explicit
deletion happens via `KiteTokenStore.Delete()` (`kc/token_store.go:120-130`).

### 3.4 OAuth client registrations (`oauth_clients`)

Dynamic-client-registration records issued by `/oauth/register`. The
`client_secret` is AES-256-GCM encrypted at rest.

**Indefinite retention** — kept until the client explicitly revokes. There is
no current automatic cleanup of stale clients; this is acceptable because
client_secret is a high-entropy random string with no time-based attack surface
and the table is small (one row per MCP client install).

### 3.5 MCP bearer JWT

The bearer token clients send on every MCP request.

**24-hour self-expiry.** `oauth/config.go:30-31` defaults `TokenExpiry =
24*time.Hour`; the JWT `exp` claim is the only enforcement — no DB row, so no
cleanup needed. After expiry, mcp-remote refreshes via the standard OAuth flow.

### 3.6 Dashboard SSO JWT (cookie)

Set when the user signs into the web dashboard via Google SSO.

**7-day self-expiry.** `oauth/middleware.go:131-132`:
```go
const dashboardTokenExpiry = 7 * 24 * time.Hour
```
Cookie `MaxAge=604800` (`oauth/middleware.go:144`). Browser drops it
automatically; no server-side row.

### 3.7 Google SSO state cookie

Anti-CSRF nonce during the SSO handshake.

**5-minute self-expiry.** `oauth/google_sso.go:88` sets `MaxAge: 300`. Cleared
on completion via `MaxAge: -1` (line 128).

### 3.8 MCP session registry (`mcp_sessions` + RAM)

Maps an MCP session ID to an authenticated email so tool calls survive a server
restart.

**12-hour idle expiry.** `kc/session.go:34-35` defines:
```go
DefaultSessionDuration = 12 * time.Hour
DefaultCleanupInterval = 30 * time.Minute
```

The cleanup goroutine (`kc/session.go:466-486`) wakes every 30 minutes and
calls `CleanupExpiredSessions()` (`kc/session.go:375-419`), which:
1. Removes RAM entries whose `ExpiresAt` is past.
2. Calls each registered cleanup hook (these tear down the per-session Kite
   client).
3. Deletes the corresponding row from `mcp_sessions` via `db.DeleteSession()`.

### 3.9 Family invitations (`family_invitations`)

Pending invites the family-billing admin sends to grant a sub-account access.

**7-day creation-side expiry.** `kc/usecases/family_usecases.go:168` sets
`invitationTTL: 7 * 24 * time.Hour` when creating the invite row.

**6-hour cleanup tick.** `app/wire.go:590-612` runs a goroutine that calls
`InvitationStore.CleanupExpired()` (`kc/users/invitations.go:163-180`) every
6 hours. The cleanup transitions any `pending` invite past its `ExpiresAt`
to status `expired` — rows are **not** physically deleted (kept for the audit
trail).

The 6 h interval is independent of the 7 d expiry: the cleanup just
re-classifies; the user-visible expiry is enforced at acceptance time
(`app/http.go:378` returns "invitation expired").

### 3.10 Price alerts (`alerts`)

Live price alerts the user has configured.

**Trigger-based only.** Removed when:
- User cancels via tool / dashboard → `DeleteAlert(email, alertID)`
  (`kc/alerts/db_commands.go:80-87`).
- User account is wiped → `DeleteAlertsByEmail(email)`
  (`kc/alerts/db_commands.go:89-94`).

There is no time-based pruning; an alert that has fired is marked
`status='triggered'` in place and remains queryable as part of the user's
trading record.

### 3.11 Riskguard dedup keys

In-RAM idempotency check keying on SHA256(email + client_order_id).

**15-minute TTL.** `kc/riskguard/dedup.go:10-13`:
```go
const DefaultDedupTTL = 15 * time.Minute
```

Data: a tiny map; eviction is lazy on `SeenOrAdd`. Never persisted.

### 3.12 Anomaly baseline cache

In-RAM cache of per-user 30-day order statistics used by riskguard's
anomaly check.

**15-minute TTL + 10K entry cap.** `kc/audit/anomaly_cache.go:11-44`:
```go
const DefaultMaxStatsCacheEntries = 10_000
```
TTL eviction on read (line ~50); on insert overflow, one random entry is
dropped (Go's randomised map iteration provides cheap random eviction).
Invalidated for an email whenever a new order is recorded, so cached
baselines never lag a real trade by more than one tick.

### 3.13 Per-tool rate limiter buckets

In-RAM token-bucket limiters keyed by user/IP.

**10-minute idle eviction.** `app/ratelimit.go:195`:
```go
cleanupInterval: 10 * time.Minute
```
A background goroutine (`app/ratelimit.go:205`) sweeps idle buckets every
10 minutes. Active clients recreate their bucket on next request.

### 3.14 Telegram pending-confirm cache

In-RAM map of pending /buy /sell confirmation prompts.

**2-minute cleanup tick.** `kc/telegram/bot.go:171,177-194`:
```go
cleanupInterval = 2 * time.Minute
```

### 3.15 Consent log (`consent_log`)

Append-only log of every consent grant/withdraw event. PII-minimised: stores
`user_email_hash` (SHA-256 of lowercased email), never the raw email.

**Indefinite retention** — required as evidence under DPDP §6(4). Withdrawal
is recorded by INSERTING a `withdraw` row and stamping the matching grant row
with `withdrawn_at` (`kc/audit/consent.go:265-275`); the grant row itself is
**never** deleted.

### 3.16 Domain events (`domain_events`)

Event-sourcing source-of-truth — all domain mutations.

**Indefinite retention** — by definition; events are the system of record.
Privacy minimisation is achieved by storing `email_hash`, not the raw email,
in event payloads (`kc/eventsourcing/store.go`).

## 4. User Deletion Request Flow (DPDP §8)

> Status: **partial — manual operator path; self-service deletion not yet implemented.**

The codebase already has the **export** half of DPDP rights:
`kc/usecases/data_export_usecases.go:41-44` defines `DataExportRetention =
5 years` and `ExportMyDataUseCase` aggregates eight per-user data sources
(`tool_calls`, `alerts`, `watchlists`, `paper_trades`, `sessions`,
`credentials`, `consent_log`, `domain_events`). This is the right of access
under DPDP §11.

The **erasure** path (DPDP §12 right to correction & erasure) is intended to be
fulfilled per-class via the existing per-class `Delete*` primitives in this
order:

1. `KiteCredentialStore.Delete(email)` — `kc/credential_store.go:137`
2. `KiteTokenStore.Delete(email)` — `kc/token_store.go:120-130`
3. `DB.DeleteAlertsByEmail(email)` — `kc/alerts/db_commands.go:89-94`
4. Watchlists, paper-trading, daily P&L — per-store delete-by-email helpers in
   `kc/watchlist`, `kc/papertrading`, `kc/alerts`.
5. `mcp_sessions` — `CleanupExpiredSessions()` covers in-flight sessions; an
   explicit `DeleteSessionsByEmail` would be additive.
6. **Tool-call audit trail and consent log are NOT deleted**: SEBI mandates the
   audit trail be retained 5 years; the consent log is the regulator's
   evidence the user actually consented. DPDP §17(1)(c) permits retention
   "for compliance with any law" — these classes fall under that exemption.
7. `domain_events` are not deleted; the `email_hash` substitute is the
   minimisation that makes retention DPDP-compatible.

A single orchestrating `EraseMyData` use case covering steps 1-5 is on the
roadmap; today the operator chains them manually after verifying the request.
Tracked as a Wave 2 follow-up.

## 5. Backup Retention (Litestream → Cloudflare R2)

The production SQLite database (`/data/alerts.db` on Fly.io `bom`) is
continuously replicated to Cloudflare R2 by Litestream.

`etc/litestream.yml`:
```yaml
dbs:
  - path: /data/alerts.db
    replicas:
      - type: s3
        bucket: ${LITESTREAM_BUCKET}
        path: alerts.db
        endpoint: https://${LITESTREAM_R2_ACCOUNT_ID}.r2.cloudflarestorage.com
        region: auto
        sync-interval: 10s
```

**Sync window:** 10 seconds — write-path RPO.
**Retention:** Litestream's default WAL-segment retention (`retention: 24h`
implicit when not overridden) — point-in-time restore is supported within the
last ~24 hours.

When a user deletes data per §4, the deletion **propagates to R2 within 10
seconds** (the next sync cycle removes the row from the streamed snapshot).
Restoring the DB from a >24 h-old backup would resurrect deleted rows; this is
documented as the trade-off in the disaster-recovery runbook.

WAL freshness is exposed by the `/healthz?level=deep` endpoint — see
`app/http.go:670-700` (`litestreamDeepStatus`) — which flags `stale` if the
WAL file mtime is older than the configured threshold.

## 6. Out of Scope

- **PII-redacted log content.** Application logs (stdout / Fly.io tail) contain
  metadata only — params are summarised by `kc/audit/store.go` before being
  written to the DB or logs. Log retention is governed by the hosting platform
  (Fly.io defaults), not this policy.
- **Kite session keys.** The Kite-side session lifecycle (request_token →
  access_token, ~06:00 IST daily expiry, explicit logout) is owned by Zerodha;
  we cache the access token under §3.3 but cannot directly invalidate the
  upstream session.
- **Browser local storage on the dashboard.** Anything stored client-side by the
  dashboard widget code is governed by browser policy and the user's session
  cookie under §3.6.
- **Stripe billing webhook events.** Retained 7 years per Indian tax law — see
  `data-classification.md` row "Billing tier + Stripe webhook events" — and
  governed by Stripe's own retention.

## 7. Change Log

| Date       | Change                                                                |
|------------|-----------------------------------------------------------------------|
| 2026-04-26 | Initial policy. Pulled retention rules out of `data-classification.md` and grounded each in `file:line` references. |
