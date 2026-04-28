# Access Control — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: PR.AC-1 (Identities and credentials), PR.AC-3 (Remote access), PR.AC-4 (Access permissions / RBAC), PR.AC-6 (Identities are proofed and bound), PR.AC-7 (Authentication of users / devices / processes), PR.PT-3 (Least functionality).*
*Companion to: [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md), [`config-management.md`](config-management.md), [`asset-inventory.md`](asset-inventory.md), [`audit-export.md`](audit-export.md), [`threat-model-extended.md`](threat-model-extended.md).*

This document is the operational policy for **identity, authentication, authorization, and the audit trail** in `kite-mcp-server`. It is the single answer to "who can do what, and how do we prove who did what."

---

## 1. Identity model

The server has three identity surfaces:

| Surface | Identity source | Use |
|---|---|---|
| **MCP user** | OAuth bearer JWT (issued by our OAuth server) | All MCP tool calls; ties to email |
| **Dashboard user** | SSO cookie JWT (signed with `OAUTH_JWT_SECRET`) | Web dashboard at `/dashboard` |
| **Admin** | Same as dashboard user, BUT `users.role = 'admin'` flag set in DB | Admin pages + admin MCP tools |

Identity is **email-keyed** throughout. Email is the primary key in `kite_credentials`, `kite_tokens`, `users`, and is HMAC'd into the `email` column of `tool_calls` for audit. Cross-tenant isolation hinges on this single property.

### 1.1 Identity proofing

| Identity | Proofing flow |
|---|---|
| MCP user | OAuth 2.1 with PKCE (S256) → Kite login (Zerodha handles password + TOTP) → access token cached → bearer JWT issued |
| Dashboard user | Two paths: (a) email + password (bcrypt cost 12), or (b) Google SSO if `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` set (currently inactive in production) |
| Admin | Same as dashboard user; admin role assigned via `ADMIN_EMAILS` env var at server startup (`Store.EnsureAdmin`, `kc/users/store.go:471`) |

Per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.12: Kite handles Zerodha-side identity (password + TOTP); we never see raw user passwords.

---

## 2. Authentication mechanics

### 2.1 MCP bearer JWT

| Property | Value |
|---|---|
| Algorithm | HMAC-SHA256 (HS256) |
| Signing key | `OAUTH_JWT_SECRET` (env var) |
| Expiry | 24 hours (`oauth/config.go:31`) |
| Claims | `email`, `client_id`, `iat`, `exp`, `iss`, `aud` |
| Issuer | server's own OAuth (per `oauth/handlers_oauth.go`) |
| Refresh | mcp-remote auto-refreshes via OAuth flow before expiry |

Token storage: in-memory (mcp-remote caches per-server in `~/.mcp-auth/`); never written to our DB.

### 2.2 Dashboard SSO cookie

| Property | Value |
|---|---|
| Algorithm | HMAC-SHA256 (HS256) |
| Signing key | Same `OAUTH_JWT_SECRET` |
| Expiry | 7 days (`oauth/middleware.go:131-132`) |
| Cookie | `MaxAge=604800`; HTTP-only; `Secure`; `SameSite=Lax` |
| Set when | OAuth callback succeeds (auto-set during MCP OAuth flow) OR Google SSO callback |

Cookie cannot be read by JavaScript (HTTP-only) and is bound to TLS (Secure).

### 2.3 Google SSO state cookie

Per [`RETENTION.md`](RETENTION.md) §3.7:
- 5-minute self-expiry; anti-CSRF nonce.
- `oauth/google_sso.go:88` — `MaxAge: 300`.
- Cleared on completion (`MaxAge: -1`).

### 2.4 Stripe webhook signature (machine identity)

Stripe-Signature HMAC validated against `STRIPE_WEBHOOK_SECRET`. Replay protection via `webhook_events` idempotency table. Per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.

### 2.5 Telegram bot binding

`telegram_chat_ids` table maps user email to Telegram chat ID. Users opt in by sending a one-time pairing code; the bot auto-binds the chat ID on receipt. After binding, all alerts/briefings deliver to that chat ID. The bot token (`TELEGRAM_BOT_TOKEN`) is the SERVER's identity to Telegram.

---

## 3. Authorization model (RBAC)

Two roles. Simple by design.

| Role | Capability |
|---|---|
| **`user`** (default) | Own-data access only. Self-scoped MCP tools. Self-scoped dashboard at `/dashboard`. |
| **`admin`** | Everything `user` plus admin tools, admin dashboard pages, cross-tenant reads. |

Roles persist in the `users` table (`kc/users/store.go:44` `IsAdmin()`). Source of truth: `ADMIN_EMAILS` env var at server startup; the `EnsureAdmin` helper at `kc/users/store.go:471` syncs the env list into the DB. Changes require server restart — there is **no runtime role-edit path**.

### 3.1 RBAC enforcement points

| Layer | Check | Code reference |
|---|---|---|
| MCP tool handler | `adminCheck()` / `withAdminCheck()` helpers | `mcp/admin_tools.go` |
| HTTP route (admin pages) | Cookie JWT + DB role check | `kc/ops/handler_admin.go` |
| Dashboard page (per-user) | Cookie JWT scope only (no role required) | `kc/ops/` various |
| Sensitive admin tool | `confirm: true` parameter + elicitation | `mcp/elicit.go` |

Destructive admin tools wrap with two layers: the role check (above) AND an explicit `confirm: bool = true` parameter. The MCP client must echo the confirmation; the server emits an elicitation prompt. This is anti-mis-click, not anti-credential-theft per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.3.

### 3.2 Admin scope

Admin-callable MCP tools (per `mcp/admin_tools.go` and sibling files):

| Tool | Purpose | Destructive? |
|---|---|---|
| `admin_list_users` | List all users | No |
| `admin_get_user_baseline` | Per-user baseline stats | No |
| `admin_freeze_user` | Block a user from placing orders | Yes |
| `admin_unfreeze_user` | Restore order privileges | Yes |
| `admin_list_anomaly_flags` | Inspect anomaly detector flags | No |
| `admin_set_kill_switch` | Global trading kill switch | Yes (critical) |
| `admin_set_user_role` | Reassign role (rare) | Yes |
| `admin_stats_cache_info` | Cache hit-rate / size | No |
| `server_metrics` | Per-tool latency / error rate | No |
| `server_version` | Build SHA / uptime | No |
| `admin_get_audit_export` | Audit trail export (CSV/JSON) | No (but PII-handling required) |

Admin HTTP endpoints under `/admin/ops/*`. See [`asset-inventory.md`](asset-inventory.md) §1.

### 3.3 Per-user scope (default)

A `user` (non-admin) can:

- Call any non-admin MCP tool (~80 tools).
- Read their own data via `/dashboard/*`.
- Manage their own credentials (`update_my_credentials`), alerts (`list_alerts`, `delete_alert`), watchlists, paper trading, etc.
- Export their own data via the data-export use case (`kc/usecases/data_export_usecases.go`) — DPDP §11 right to access.
- Delete their own account via the data-deletion path (DPDP §12 right to erasure; partial — see [`RETENTION.md`](RETENTION.md) §4).

A `user` CANNOT:

- Call any admin tool (`adminCheck()` returns 401/403).
- Read another user's data (every SQL query has `WHERE email = ?` bound to `oauth.EmailFromContext(ctx)`).
- Change their own role to `admin` (no API for runtime role change; admin role is `ADMIN_EMAILS`-driven only).
- Bypass riskguard (8-check middleware applies regardless of user-supplied params).
- Bypass billing tier (Stripe middleware enforces; `DEV_MODE=true` skips, but DEV_MODE never true in prod).

### 3.4 Per-tool annotations

Every MCP tool carries annotations that downstream clients may consume for UX (per [`MEMORY.md`](../MEMORY.md) tool annotations note):

| Annotation | Meaning |
|---|---|
| `Title` | Human-friendly label |
| `ReadOnlyHint` | True if the tool only reads (e.g., `get_holdings`) |
| `DestructiveHint` | True if the tool can lose data or money (e.g., `place_order`, `delete_alert`) |
| `IdempotentHint` | True if calling twice has the same effect as once |
| `OpenWorldHint` | True if the tool reaches outside the server (Kite API, Telegram, etc.) |

These annotations don't enforce authorization; they help clients render UI hints. Authorization is RBAC (§3) + RiskGuard + elicitation.

---

## 4. Cross-tenant isolation

The single most important property of the server: User A cannot read or modify User B's data.

| Isolation layer | Enforcement |
|---|---|
| **Identity** | Bearer JWT contains exactly one email; mcp-remote per-user cache prevents cross-account JWT confusion |
| **Tool handlers** | Email pulled from `oauth.EmailFromContext(ctx)`, NEVER from a tool parameter |
| **SQL queries** | All queries include `WHERE email = ?` with the ctx email as parameter |
| **Dashboard reads** | Cookie JWT email scopes per-user data fetches |
| **Per-user rate limits** | Authenticated rate limit keyed by email, not just IP (`app/ratelimit.go:rateLimitUser`) |
| **Encrypted credentials** | One AES-GCM ciphertext per user in `kite_credentials`; key derived from server master via HKDF |
| **OAuth scope** | Dynamic client registration scopes per user; tokens are not transferable |
| **Audit chain** | HMAC'd email column; the chain itself doesn't aid cross-tenant access (defence-in-depth) |

Empirical verification: `Grep "EmailFromContext" mcp/` returns >40 sites; every tool handler uses ctx email exclusively. No `args.GetString("email")` followed by a privileged data read.

### 4.1 What admins CAN do across tenants

Admins explicitly bypass per-user scoping for moderation. The capability is necessary for incident response.

| Admin action | Cross-tenant effect | Audit visibility |
|---|---|---|
| `admin_list_users` | Reads all rows of `users` | Tool call logged with admin email + target query |
| `admin_freeze_user` | Writes to `users.frozen` for any email | Tool call logged with target user |
| `admin_get_audit_export` | Reads `tool_calls` for any user | Action logged in `tool_calls` itself (recursive — admin's own action is recorded) |
| `admin_set_kill_switch` | Affects ALL users | Logged + emits `GlobalFreezeEvent` |

Every admin action is logged with the admin's email AND the target user's email. The hash chain makes deletion of admin actions tamper-evident.

---

## 5. Audit trail of access

### 5.1 Per-tool-call audit

Every MCP tool call is recorded to the `tool_calls` SQLite table by the audit middleware (`kc/audit/middleware.go`). Properties:

| Property | Value |
|---|---|
| Trigger | Every tool call passes through audit middleware (chain order #3 per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §6) |
| Async | Buffered async writer (drops counted in `dropped_count` health surface) |
| PII redaction | `kc/audit/sanitize.go:7` `sensitiveKeys` redacts `access_token`, `api_key`, `api_secret`, `password`, `secret`, `token` |
| Newline sanitisation | `kc/audit/summarize.go:557` `sanitizeForLog` strips control chars |
| Email | HMAC'd in `email` column; AES-GCM'd into `email_encrypted` for authorised export |
| Hash chain | HMAC-SHA256 chain (`kc/audit/store_worker.go:37` `computeChainLink`) |
| Retention | 5 years (SEBI requirement; `app/wire.go:824-841`) |
| External anchor | Optional via `AUDIT_HASH_PUBLISH_*` (per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.11) |
| Export | CSV / JSON via `/dashboard/activity?export=csv` (admin only) |

Per [`audit-export.md`](audit-export.md) for the export schema and PII-redaction guarantees.

### 5.2 Authentication-event audit

Every successful authentication and every authorization failure is logged via slog (operational logs):

| Event | Log line | Source |
|---|---|---|
| OAuth token issued | `INFO oauth: token issued email=<email>` | `oauth/handlers_oauth.go` |
| OAuth token expired (re-auth needed) | `WARN oauth: token expired email=<email>` | `oauth/middleware.go` |
| RequireAuth 401 | `WARN auth: 401 path=<path> reason=<reason>` | `oauth/middleware.go` |
| Admin action invoked | (logged in `tool_calls`; not separate slog) | `mcp/admin_tools.go` via audit middleware |
| Per-user rate limit hit | `WARN ratelimit: blocked email=<email> tool=<tool>` | `app/ratelimit.go` |
| Per-IP rate limit hit | `WARN ratelimit: blocked ip=<ip>` | `app/ratelimit.go` |
| Kill switch engaged | (logged in `tool_calls` for `admin_set_kill_switch`) + `WARN riskguard: kill_switch_engaged` | `kc/riskguard/` |

These slog lines feed `flyctl logs`. For long-term audit (SEBI-compliant), the `tool_calls` SQLite trail is the source of truth.

### 5.3 Configuration-change audit

Per [`config-management.md`](config-management.md) §5:
- Git history for committed config (e.g., `fly.toml`).
- Fly.io release history for secret changes (presence only).
- GitHub Actions log for CI-validated config.

Together these provide a "who deployed what, when, and was CI green" trail that links code, config, and runtime behaviour.

### 5.4 Consent log (DPDP §6(4))

`consent_log` table records every consent grant/withdraw event. Per [`RETENTION.md`](RETENTION.md) §3.15:
- PII-minimised: stores `user_email_hash` (SHA-256 of lowercased email), never the raw email.
- Indefinite retention (regulatory evidence).
- Withdrawal recorded by INSERTING a `withdraw` row + stamping the original grant with `withdrawn_at`. The grant row itself is never deleted.

Source: `kc/audit/consent.go`.

---

## 6. Session management

### 6.1 MCP sessions (`mcp_sessions` table)

| Property | Value |
|---|---|
| Lifetime | 12 hours idle expiry (`kc/session.go:34-35` `DefaultSessionDuration`) |
| Cleanup | Every 30 minutes (`DefaultCleanupInterval`) |
| Storage | SQLite with `session_id_enc` AES-GCM encrypted |
| Restart-survivable | Yes — sessions resume after server restart with lazy Kite client re-creation |

### 6.2 Dashboard sessions (cookie)

Per §2.2 — 7 days self-expiry; HTTP-only; Secure; SameSite=Lax.

### 6.3 Session revocation

| Trigger | Effect | How |
|---|---|---|
| User-initiated logout | Cookie deleted | `/dashboard/logout` clears cookie |
| Admin freezes user | Existing JWT remains valid until expiry | Hard kick-out requires `OAUTH_JWT_SECRET` rotation |
| Server detects token theft | Manual rotation | Per [`config-management.md`](config-management.md) §3.1 |
| MCP session timeout (12h idle) | Server closes session | Automatic (cleanup goroutine) |
| Server restart | Sessions re-load from DB | Lazy Kite client re-creation |

There is currently NO active "kick this user out NOW" affordance short of `OAUTH_JWT_SECRET` rotation. Per [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.3 / §"Admin role change process" — old admin sessions remain valid until JWT expiry. Mitigation: short JWT lifetime (24h).

---

## 7. Least-privilege enforcement

Per NIST CSF 2.0 PR.PT-3 (Least functionality):

| Principle | How enforced |
|---|---|
| Tool exposure minimised | Hosted instance defaults to `ENABLE_TRADING=false` — order tools NOT registered |
| Default deny on auth | RequireAuth middleware returns 401 if no JWT (`oauth/middleware.go`) |
| Per-tool destructiveness gate | Destructive tools require `confirm: true` parameter + elicitation |
| Admin role is opt-in | Default user role is `user`; admin requires explicit `ADMIN_EMAILS` |
| Encryption-at-rest by default | T1 data is AES-256-GCM encrypted; cannot read SQLite file alone |
| Riskguard caps default-on | All users get system defaults (₹5L/order, 200 orders/day) without manual configuration |
| Logging minimised at level=info | Debug-only paths use `slog.Debug` (silenced in prod) |

A "least functionality" audit walks every tool / endpoint and asks: *Is the default behaviour the most restrictive viable?* For the production deployment at HEAD `3501a11`, the answer is yes for all entry points enumerated in [`threat-model-extended.md`](threat-model-extended.md) §2.

---

## 8. MFA / second factor

| Surface | MFA status | Note |
|---|---|---|
| Kite-side login (Zerodha) | Required (TOTP) | Zerodha enforces; we don't see |
| MCP bearer JWT issuance | Single-factor (OAuth flow) | Strong because Kite TOTP is upstream |
| Dashboard email/password login | Single-factor (bcrypt) | Admin passwords are first-boot only |
| Google SSO (when active) | Per Google account | Google enforces |
| Admin actions (`/admin/ops/*`) | **TOTP MFA required (RFC 6238)** | Shipped commits `8c19202` (storage) + `0d18593` (HTTP gate) |
| Admin destructive actions | `confirm: true` + TOTP MFA | `confirm` is anti-mis-click; MFA is anti-credential-theft |

### 8.1 Admin TOTP MFA — what shipped

Per the SEBI RIA framework expectation for MFA on privileged actions, every authenticated admin must complete a TOTP challenge before the admin dashboard is reachable. This closes the deferral that was originally documented at [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.3.

| Aspect | Details |
|---|---|
| Algorithm | RFC 6238 TOTP / RFC 4226 HOTP — HMAC-SHA1, 30s step, 6 digits, ±1-step skew (90s window). Pure-Go implementation at `kc/users/totp.go`; no new dependencies. |
| Secret storage | Per-admin AES-256-GCM-encrypted secret in `users.totp_secret_enc` (SQLite). Key is the same HKDF-derived AES-256 from `OAUTH_JWT_SECRET` used by other T1 storage. Rotation via the existing `cmd/rotate-key` path. |
| Enrollment flow | `GET /auth/admin-mfa/enroll` shows the freshly-generated secret + an `otpauth://` URI for one-tap mobile add. `POST` validates the user's first 6-digit code against the form's secret and persists on success (handler: `oauth.HandleAdminMFAEnroll`). |
| Verification flow | `GET /auth/admin-mfa/verify` shows the 6-digit form. `POST` validates against the persisted secret. On success mints `kite_admin_mfa` JWT cookie (15-min, audience `admin-mfa`, HttpOnly + Secure + SameSite=Lax). Handler: `oauth.HandleAdminMFAVerify`. |
| Gate middleware | `oauth.RequireAdminMFA` — wraps `/admin/ops/*` after the email/role check. Routes un-enrolled admins to `/enroll`, enrolled admins without active cookie to `/verify`. Subject-binding (`claims.Subject == ctx email`) defends against stolen-cookie replay against another email. |
| CSRF | Double-submit cookie (`csrf_token_admin_mfa`) on both enrollment and verification POSTs. Same hardening as the existing admin login form. |
| Defence in depth | The store layer (`kc/users/mfa.go:SetTOTPSecret`) rejects non-admin users explicitly so a misconfigured route can't widen the gate. |

### 8.2 Authenticator app compatibility

The implementation produces standard `otpauth://totp/<issuer>:<account>?secret=...&algorithm=SHA1&digits=6&period=30` URIs. Tested-compatible apps (consumed unchanged):

- Google Authenticator
- Authy
- 1Password
- Microsoft Authenticator
- Bitwarden

The setup form also displays the base32 secret for manual entry — no QR code is rendered server-side (avoids pulling in an additional dependency for QR generation). Mobile authenticator apps register the `otpauth://` URL handler so the shown link adds the entry on tap.

### 8.3 Deferred work (documented honestly)

What this slice does NOT ship:

- **Recovery codes**: an admin who loses their phone today must have another admin clear their TOTP via DB write (`UPDATE users SET totp_secret_enc='' WHERE email=?`). A first-class admin-recovery flow (e.g. another admin issues a recovery code) is deferred — single-admin deployments handle this via cmd-line, multi-admin deployments handle it via peer admin.
- **Non-admin user MFA**: scoped out of this slice (would need user-flow design for retail users). The store-layer enforces "admin role only" for now.
- **WebAuthn / passkeys**: Go ecosystem support is shakier than TOTP and the SEBI / RIA framework does not require it. Tracked for a future slice if user demand surfaces.
- **DPoP / request signing**: SEP-1932 in MCP spec is still in draft. Continues to be the canonical longer-term hardening path for the MCP transport itself; admin-dashboard MFA is the immediate close-out.

---

## 9. Access review cadence

| Activity | Cadence | Output |
|---|---|---|
| Review `ADMIN_EMAILS` membership | Quarterly | Removed-staff explicitly cleared |
| Review per-user `frozen` flags | Quarterly | Zombie freezes (>90 days) cleared with note |
| Review `users` table for departed accounts | Annual | Deletion per DPDP §12 path ([`RETENTION.md`](RETENTION.md) §4) |
| Review consent log | Annual | Validate `withdrawn_at` is correctly applied |
| Review tool annotations | Per-release | New tools have proper destructive/idempotent hints |
| Review `confirm: bool` coverage on destructive tools | Per-release | New destructive tools must require confirm |
| Review elicitation prompts | Per-release | Confirm prompts state risk clearly |

---

## 10. Incident-response access controls

During an incident (per [`incident-response-runbook.md`](incident-response-runbook.md) §1):

| Phase | Access action |
|---|---|
| Containment | `admin_set_kill_switch` (global freeze); `admin_freeze_user` (targeted); `OAUTH_JWT_SECRET` rotation (force re-auth) |
| Eradication | Patch + redeploy; restored sessions re-load roles from DB |
| Recovery | Verify role assignments correct (no drift); admin actions logged |
| Notification | Affected users emailed; CERT-In informed if PII exposed |

Per [`incident-response.md`](incident-response.md) §"Things to NEVER do" — admin actions during an incident are logged. Deleting audit rows is itself a violation, regardless of the original incident.

---

## 11. Self-host operator considerations

A fork-and-host operator inherits:
- The same identity model (per-user OAuth, per-user encryption).
- Their own `ADMIN_EMAILS` list (they pick).
- Their own `OAUTH_JWT_SECRET` (they generate; back up out-of-band).
- Their own dashboard SSO (they choose Google / password).
- Their own role-elevation gates.

They take on:
- Operator-host security ([`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §"Operator must").
- TLS termination (their own reverse proxy).
- `ADMIN_EMAILS` review cadence (per their staff).
- Audit-log retention review (their own regulatory regime; we default to 5 years).

Self-host operators MUST NOT:
- Pre-pool Kite API credentials (defeats per-user encryption).
- Run with `DEV_MODE=true` in production (skips audit + riskguard).
- Share `OAUTH_JWT_SECRET` across multiple deployments (cross-deployment encryption breakage).

---

## 12. Out of scope

- **Operator host-machine login** — covered by Fly.io's Linux + 2FA on Fly.io account.
- **Physical access to Fly.io data centres** — Fly.io's controls.
- **mcp-remote local cache theft** — user-side concern; we HMAC-bind state to client ID to limit blast radius.
- **Browser-side local-storage exfiltration** — user-side; per [`data-classification.md`](data-classification.md).

---

## 13. Cross-references

- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) — overall security posture, encryption, RBAC §3.12 / §4.3
- [`config-management.md`](config-management.md) §3 — secret rotation
- [`asset-inventory.md`](asset-inventory.md) §3 — software components / dependencies
- [`audit-export.md`](audit-export.md) — audit trail export procedures
- [`threat-model-extended.md`](threat-model-extended.md) §1 — adversary categories C (privilege escalation)
- [`incident-response.md`](incident-response.md) — incident scenarios + "Things to NEVER do"
- [`incident-response-runbook.md`](incident-response-runbook.md) §4 — roles & decision authorities
- [`RETENTION.md`](RETENTION.md) §3.15 / §4 — consent log + DPDP erasure path
- [`vulnerability-management.md`](vulnerability-management.md) — supply-chain controls protecting access path
- [`continuous-monitoring.md`](continuous-monitoring.md) §7 — detection of access-control violations
