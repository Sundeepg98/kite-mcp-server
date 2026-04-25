# Data Classification — kite-mcp-server

*Last reviewed: 2026-04-25*
*Scope: hosted instance at `https://kite-mcp-server.fly.dev` and self-host forks. Companion to [`PRIVACY.md`](PRIVACY.md) and [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md).*

## 1. Purpose

Engineers and external auditors need a single page that maps every persisted data type to (a) a sensitivity tier, (b) the controls protecting it, and (c) the DPDP / SEBI obligations it falls under. This document is that page. Every classification claim links to the SQLite migration that creates the table and to the Go code that handles encryption.

This is a control-mapping document; the legal narrative lives in [`PRIVACY.md`](PRIVACY.md).

## 2. Tiers

| Tier | Definition | Default controls |
|---|---|---|
| **T1 — Highly Sensitive** | Credentials whose disclosure lets an attacker impersonate the user against Zerodha or place orders. DPDP §8 "personal data of significant harm potential". | AES-256-GCM at rest (HKDF-derived key); TLS 1.2+ in transit; access scoped to authenticated email; never logged. |
| **T2 — Sensitive** | User-identifiable trading state and audit trail. DPDP §6 personal data; SEBI cyber audit trail evidence. | TLS in transit; per-user `WHERE email = ?` scoping; email hashed in domain events; redacted in logs. |
| **T3 — Internal** | Non-personal operational data — server config, plugin manifests, dedup keys. | Process-local or disk-only; access bounded by file-system perms. |
| **T4 — Public** | Static market metadata + published documentation. | None required. |

Tier assignment uses the **highest classification of any field**, not the average. A T1 field anywhere in a row promotes the whole row to T1.

## 3. Classification Matrix

| Data | Storage | Tier | Encryption at rest | Retention | DPDP / SEBI hook |
|---|---|---|---|---|---|
| Kite API key + secret | `kite_credentials` (`kc/alerts/db.go:103`) | **T1** | AES-256-GCM via `kc/alerts/crypto.go` | Until consent-withdraw or account-delete | DPDP §6 consent + §8 protection |
| Kite access token | `kite_tokens` (`kc/alerts/db.go:95`) | **T1** | AES-256-GCM | Daily Kite expiry (~06:00 IST) | DPDP §8 |
| OAuth client secret (issued to MCP clients) | `oauth_clients` (`kc/alerts/db.go:110`) | **T1** | AES-256-GCM | Until client revoke | DPDP §8 |
| Dashboard SSO bcrypt password hash | `users.password_hash` (`kc/users/store.go:139`) | **T1** | bcrypt cost 12 (one-way) | Until account-delete | DPDP §8 |
| MCP session JWT | `mcp_sessions` (`kc/alerts/db.go:119`) | **T2** | None — opaque ID, secret lives in HMAC key | 7-day MCP / 24-hour bearer | DPDP §6 |
| OAuth email address | `users.email`, foreign key everywhere | **T2** | None — primary identifier; hashed when copied into domain events | Until account-delete | DPDP §6, §8 portability |
| Tool-call audit trail | `tool_calls` (`kc/audit/store.go:193`) | **T2** | None — params summarised + redacted at write-time | 90 days default (`AUDIT_RETENTION_DAYS`, `=0` disables) | SEBI cyber audit; DPDP §8 incident response |
| Domain events (event-sourcing) | `domain_events` (`kc/eventsourcing/store.go:64`) | **T2** | None — `email_hash` column substitutes for plaintext email | Indefinite (event source-of-truth) | DPDP §6 — hash satisfies "minimisation" guidance |
| Outbox (in-flight events) | `event_outbox` (`kc/eventsourcing/outbox.go:124`) | **T2** | None | Drained ≤ a few seconds; cleared on success | SEBI continuity |
| Consent log | `consent_log` (`kc/audit/consent.go:93`) | **T2** | None | Indefinite (regulatory evidence) | DPDP §6(4) consent + withdrawal trail |
| Telegram chat ID | `telegram_chat_ids` (`kc/alerts/db.go:90`) | **T2** | None — opt-in, can be cleared by user | Until user disables | DPDP §6 |
| Price alerts | `alerts` (`kc/alerts/db.go:69`) | **T2** | None | Until user-delete or account-delete | DPDP §6 |
| Trailing stops | `trailing_stops` (`kc/alerts/db.go:133`) | **T2** | None | Until user-cancel or filled | DPDP §6 |
| Watchlists + items | `watchlists`, `watchlist_items` (`kc/watchlist/db.go:11,21`) | **T2** | None | Until user-delete | DPDP §6 |
| Daily P&L snapshots | `daily_pnl` (`kc/alerts/db.go:155`) | **T2** | None | Until account-delete | DPDP §6 |
| Family invitations | `family_invitations` (`kc/users/invitations.go:39`) | **T2** | None — bcrypt token hash for one-shot acceptance | Until accepted/expired | DPDP §6 |
| Paper-trading accounts + orders | `paper_accounts`, `paper_orders`, `paper_positions`, `paper_holdings` (`kc/papertrading/store.go`) | **T2** | None — virtual money, not real | Until user-reset or account-delete | DPDP §6 |
| Billing tier + Stripe webhook events | `billing`, `webhook_events` (`kc/billing/store.go:56,247`) | **T2** | None — Stripe customer ID is reversible to email at Stripe end | 7 years (Indian tax record-keeping) | Tax law — separate from DPDP |
| Per-user risk limits | `risk_limits` (`kc/riskguard/limits.go:205`) | **T2** | None | Until user-edit or account-delete | DPDP §6 |
| App registry (plugin manifest) | `app_registry` (`kc/alerts/db.go:167`) | **T3** | None | Restart-survivable until uninstall | — |
| Server config (non-secret) | `config` (`kc/alerts/db.go:128`) | **T3** | None | Indefinite | — |
| Idempotency dedup keys | RAM only (`kc/riskguard/dedup.go`) | **T3** | None | 15-minute TTL | — |
| ltpCache, anomaly cache | RAM only | **T3** | None | TTL bounded | — |
| Tool integrity manifest | RAM only (`mcp/integrity.go`) | **T3** | None | Process lifetime | — |
| Static instrument list, sector map | embedded `.csv` / `.go` | **T4** | n/a | Compile-time | — |
| Public documentation | `docs/*.md` | **T4** | n/a | Repo lifetime | — |

## 4. Cryptographic baseline (T1)

All T1 data shares one envelope: **AES-256-GCM with a per-record 12-byte nonce, key derived from `OAUTH_JWT_SECRET` via HKDF-SHA-256** (label per record type). Implementation: `kc/alerts/crypto.go`. Properties:

- Authenticated encryption — ciphertext tampering is detected at decrypt.
- Forward-rotation: changing `OAUTH_JWT_SECRET` invalidates every existing T1 record. Operators run a one-shot rotation tool (see `docs/incident-response.md` Scenario 5).
- No key escrow — losing `OAUTH_JWT_SECRET` is unrecoverable; backup is the operator's responsibility.

Disk-level controls (Fly.io volume LUKS, R2 bucket SSE-S3 encryption-at-rest) sit underneath but are **not** counted as the primary T1 control — application-layer crypto is the canonical protection because it survives volume snapshots, backup theft, and operator-side reads.

## 5. Access control mapping

| Tier | Read path | Write path | Export path |
|---|---|---|---|
| T1 | Authenticated tool handler scoped to `oauth.EmailFromContext(ctx)` only. Never returned in responses. | Authenticated user (`update_my_credentials`); admin cannot impersonate. | `delete_my_account` zeroises rows; no other export. |
| T2 | Per-user dashboard at `/dashboard/*` (cookie JWT) and per-user MCP tools (`list_alerts`, `get_pnl_journal`, etc.); admin tools (`admin_list_users`, etc.) gated by `users.role = 'admin'`. | Same handlers; CQRS command bus routes writes through `kc/cqrs`. | `data-export` use case (`kc/usecases/data_export.go`) bundles per-user T2 data as JSON for DPDP §11 portability. |
| T3 | Operator-side log + admin tools. | Server boot or admin tool. | Not exported per-user. |
| T4 | Anyone. | Repo commits. | n/a. |

## 6. DPDP §6 + §8 obligation map

- **§6 consent capture** — recorded in `consent_log` at OAuth-authorize and credential-submit (`kc/audit/consent.go`).
- **§6 consent withdrawal** — `delete_my_account` tool zeroises T1 + T2 in a single transaction; consent record is preserved for audit. SLA 7 days.
- **§8(5) breach notification** — CERT-In within 6 hours, DPB India per Rule 7, affected users via email within 72 hours. See [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §11.
- **§11 data portability** — `data-export` use case returns the user's T2 footprint as canonical JSON.
- **§17(2) auditability** — `tool_calls` + hash-chained `domain_events` give an operator-side trail; `consent_log` gives the user-side trail.

## 7. Self-host operator notes

A self-hosted fork inherits this matrix as the **default** classification, but the operator is the Data Fiduciary and may have stricter requirements (e.g. employer policy, sector regulation). Operators should:

1. Set `OAUTH_JWT_SECRET` to a 32-byte random value and back it up out-of-band.
2. Choose `AUDIT_RETENTION_DAYS` to match local retention obligations (90 default; SEBI-regulated entities typically need 5 years).
3. If using Postgres rather than SQLite, ensure column-level encryption matches the AES-256-GCM contract above.
4. Publish their own privacy notice — this document is engineering reference, not a customer-facing policy.

## 8. Review cadence

This document is reviewed when:

- A new persisted data type is added (the migration commit must update §3).
- A control changes (e.g. cryptographic library swap, retention default change).
- A regulator adds a new obligation hook (DPDP rule revisions, SEBI circulars).

Without a triggering change, the document is re-validated annually against the table inventory in `kc/alerts/db.go` and friends.
