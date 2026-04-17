# Security Posture — SEBI Cybersecurity Framework Self-Assessment

*Last reviewed: 2026-04-17 (commit `8edc863`)*
*Scope: kite-mcp-server, self-hosted and Fly.io-hosted deployments*

---

## 1. Introduction

`kite-mcp-server` is a self-hosted / Fly.io-hosted MCP server that brokers
access to Zerodha's Kite Connect API. It lets a user drive their own brokerage
account from an MCP client (Claude Desktop, claude.ai, ChatGPT, VS Code) using
their own Kite Connect developer app credentials.

This document honestly describes our security posture against the SEBI
Cybersecurity & Cyber Resilience Framework (CSCRF) — as far as it applies to
regulated entities and to non-regulated API consumers — and our own threat
model.

**This is NOT a compliance attestation.**
- The project is not SEBI-registered.
- We do NOT claim to pass a formal SEBI cyber audit.
- We are the plumbing between an MCP client and the Kite Connect API — we do
  not run the broker, the OMS, or the exchange.

This document exists so that:
- A user deciding whether to trust us with their Kite credentials can read
  what we actually do, not marketing claims.
- An external auditor can verify each control claim against the code.
- A prospective operator (fork-and-host) understands what they inherit and
  what they must still do themselves.

Accuracy beats marketing. If a control is partial, this document says
partial. If deferred, it says deferred. Every control claim links to a
concrete `file:line` reference or commit SHA.

---

## 2. Threat Model

The STRIDE analysis lives in [`../THREAT_MODEL.md`](../THREAT_MODEL.md). This
section frames the same threats through the lens of three concrete adversaries
we actively defend against — all of whom authenticate successfully at least
once.

### Adversary A — Legitimate user trying to access user B's data

A real, registered user attempts cross-tenant reads / writes against another
user's portfolio, alerts, orders, or audit entries. They hold a valid JWT but
target data they do not own.

Primary defences:
- Per-user credential isolation — `KiteCredentialStore` keyed by email,
  AES-256-GCM at rest (`kc/alerts/crypto.go`).
- Middleware-enforced email-from-JWT scoping — the MCP tool handlers pull the
  authenticated email from `oauth.EmailFromContext(r.Context())` rather than
  from client-supplied parameters.
- SQL queries always include `WHERE email = ?` — there is no per-request
  email override path.
- SSO cookies are signed and scoped — `/dashboard` data reads scope by the
  email in the dashboard JWT, not the URL.

### Adversary B — Legitimate user trying to escalate to admin

A regular user attempts to invoke admin-only tools, hit admin HTTP endpoints,
or have their role silently upgraded without being on the `ADMIN_EMAILS`
allowlist.

Primary defences:
- Role stored in DB (`kc/users/store.go:44` `IsAdmin()`), seeded from the
  `ADMIN_EMAILS` env var at startup (`Store.EnsureAdmin`, line 471). Changes
  require restart — no runtime role edit path.
- Admin tools wrap with `adminCheck()` / `withAdminCheck()` in the MCP
  handler layer. Gate is role, not billing tier.
- Admin dashboard login is a separate flow (`/auth/admin-login`) with bcrypt
  password verification (cost 12).
- Destructive admin tools also require `confirm: bool = true` and emit an
  elicitation prompt — the MCP client must echo the confirmation.

### Adversary C — Legitimate user trying to poison widgets or audit logs

A real user injects control characters, line terminators, or markup into
fields they legitimately control (watchlist names, order tags, symbols), with
the intent of forging audit entries or executing JavaScript inside a widget
iframe rendered on claude.ai or the dashboard.

Primary defences:
- Audit log newline sanitisation — `kc/audit/summarize.go:557` `sanitizeForLog`.
  Applied inside both `strVal` (tool input args — the main attack surface)
  and `jsonString` (Kite responses — defence-in-depth against round-trip
  poisoning via order tags). Shipped in commit `0b1724d`.
- Widget data JSON injection — `mcp/ext_apps.go:279` `injectData` escapes
  `</`, `<!--`, U+2028, U+2029 before embedding JSON inside `<script>`.
  U+2028/U+2029 hardening shipped in commit `0b1724d`.
- Content-Security-Policy header on all dashboard responses caps script
  origins. (HSTS + X-Frame-Options: DENY also set.)

### Out of scope

- Physical compromise of the host machine or Fly.io infrastructure.
- Zero-days in the Go standard library, `gokiteconnect`, or other third-party
  dependencies — we patch upstream when a fix lands.
- DNS hijacking of `kite-mcp-server.fly.dev` or the operator's domain.
- The Kite Connect API itself — compromise of Zerodha's infrastructure is
  outside our control.
- Anthropic / OpenAI / Microsoft infrastructure — if the MCP client platform
  is compromised, our server cannot help.
- End-user machine compromise — if the user's laptop is infected, the MCP
  tokens cached by `mcp-remote` are exposed regardless of our controls.
- Denial-of-service via raw traffic on the hosted Fly.io instance, beyond
  what per-IP / per-user rate limits and Fly.io edge DDoS mitigation absorb.

---

## 3. Controls Implemented

For every control below, the file path, line reference, or commit SHA lets an
auditor verify the claim against the source.

### 3.1 Token and credential encryption at rest

AES-256-GCM with HKDF-SHA256 key derivation and a per-database random 32-byte
salt. One master secret (`OAUTH_JWT_SECRET`) is the HKDF input; compromising
it compromises all encrypted tokens.

- Implementation: `kc/alerts/crypto.go` (`encrypt` / `decrypt` — lines 198
  and 230; `DeriveEncryptionKeyWithSalt` — line 38; `EnsureEncryptionSalt` —
  line 59).
- Wrappers: `kc/alerts/db_commands.go` (token, credential, OAuth client
  stores all re-use the same primitives).
- Encrypted columns:
  - `kite_tokens.access_token` — cached per-user Kite access tokens
  - `kite_credentials.api_key`, `kite_credentials.api_secret` — per-user
    Kite developer-app credentials
  - `oauth_clients.client_secret` — dynamically registered MCP OAuth clients
  - `mcp_sessions.session_id_enc` — MCP session identifiers
- Random 32-byte HKDF salt is generated on first run and stored in the
  `config` table (key `hkdf_salt`). First-run migration re-encrypts any
  pre-salt data under the new key.

### 3.2 Per-user rate limiting

**Shipped in commit `0b1724d`** (2026-04-17).

Previously keyed by IP only. A legitimate authenticated user hammering from a
rotating VPN/botnet bypassed per-IP limits entirely. Now two layers apply,
both must pass.

- Implementation: `app/ratelimit.go`.
  - `userRateLimiter` type — lines 59-98.
  - `rateLimitUser` middleware — lines 195-215.
  - Key: email from `oauth.EmailFromContext(r.Context())`.
  - Limits match IP tiers 1:1: auth 2/sec, token 5/sec, MCP 20/sec.
  - Blocked responses return `429` with `X-RateLimit-Scope: user` so clients
    distinguish user-level blocks from IP-level.
- Handler-chain wire-up: `app/http.go:724-821` — MCP, SSE, and message
  endpoints all apply `rateLimit(...)` → `RequireAuth` → `rateLimitUser(...)`.
- Tests: `app/ratelimit_test.go` — `TestRateLimitUser_BlocksSameUserAcrossIPs`
  exercises the botnet scenario.
- Behaviour: unauthenticated requests fall back to IP-only limits (middleware
  is no-op if no email in context).

### 3.3 Audit log injection prevention

**Shipped in commit `0b1724d`** (2026-04-17).

Audit `InputSummary` rendering interpolates user-controlled strings
(watchlist names, symbols, tags, etc.) into one-line summaries. Without
sanitisation, an attacker who names a watchlist
`"foo\nFAKE LOG: admin_change_role target=victim"` can inject a forged row
that looks like a real admin action when the activity widget renders it.

- Implementation: `kc/audit/summarize.go:557` `sanitizeForLog` replaces
  `\n`/`\r`/`\t` with their backslash-escape forms.
- Applied inside:
  - `strVal` — line 543, covers every tool-arg extraction site.
  - `jsonString` — line 419, covers round-trip from Kite responses (order
    tags, user-searched symbols).
- A single helper covers ~50 summariser call sites without touching each.
- Tests: `kc/audit/summarize_test.go` —
  `TestSummarizeInput_CreateWatchlist_InjectionAttempt` exercises the exact
  attack scenario.

### 3.4 Widget XSS hardening — JS line separators

**Shipped in commit `0b1724d`** (2026-04-17).

`mcp/ext_apps.go`'s `injectData` embeds tool response JSON inside an inline
`<script>` tag in widget HTML. `</` and `<!--` were already escaped. Go's
`json.Marshal` does NOT escape U+2028 (LINE SEPARATOR) and U+2029
(PARAGRAPH SEPARATOR) — they are valid JSON whitespace but ILLEGAL line
terminators inside JS string literals, which breaks out of the JSON literal
and lets subsequent bytes execute as script.

- Implementation: `mcp/ext_apps.go:302-303` — two `strings.ReplaceAll` calls
  replace raw U+2028/U+2029 with their `\u2028`/`\u2029` text forms.
- Tests: `mcp/ext_apps_test.go` — two subtests under `TestInjectData` cover
  both codepoints.
- Defence-in-depth context: the existing `</` and `<!--` escapes were
  documented in the same function (lines 291-295) as guards against future
  regressions in JSON encoding.

### 3.5 Audit buffer drop observability

**Shipped in commit `4a37f10`** (2026-04-17).

`Enqueue` drops entries when the buffer is full or when the synchronous
fallback fails. Previously both paths were silent — a buffer backlog could
accumulate undetected, creating a compliance gap.

- Implementation: `kc/audit/store_worker.go`.
  - Sync-fallback path (worker not started) logs `Error` on every drop
    (rare — worker is normally running) — lines 63-74.
  - Buffer-full path logs `Warn` every 100 drops with cumulative
    `dropped_total` so noisy backlogs don't spam error logs but ops can still
    chart the trend — lines 76-91.
- Exposed counter: `Store.DroppedCount()` — `kc/audit/store.go:75`. Surfaced
  via `/healthz?format=json` (see §3.7).

### 3.6 CQRS registration failure — fail-startup instead of panic

**Shipped in commit `4a37f10`** (2026-04-17).

`InMemoryBus.Register` previously panicked on duplicate handler registration.
That is a crash-level response to a wiring bug — an orchestrator that
restarts the pod 5 times in 30 seconds then gives up has lost forward
progress. Now returns a typed error so startup can surface the mistake
cleanly and exit 1 with a log message.

- Implementation: `kc/cqrs/bus.go:56-64` — signature now
  `func (...) error`. Returns `fmt.Errorf("cqrs: duplicate handler for %s", ...)`.
- Call-site updates: `kc/manager.go`, `kc/manager_commands_*.go`,
  `kc/manager_queries_*.go` — registration helpers thread the error back to
  `manager.New()`.

### 3.7 `/healthz` component status visibility

**Shipped in commit `bd3398e`** (2026-04-17).

Operators had no way to detect silent failures (audit disabled, riskguard on
defaults only, audit buffer dropping) without waiting for user complaints.

- Implementation: `app/http.go` — `handleHealthz`.
  - `GET /healthz` → legacy flat JSON body (byte-for-byte unchanged for load
    balancers).
  - `GET /healthz?format=json` → rich component map with per-component
    `status` and human-readable `note`.
- Components surfaced:
  - `audit`: `ok` / `disabled` / `dropping` + `dropped_count`.
  - `riskguard`: `ok` / `defaults-only` (DevMode / per-user limits not
    loaded).
  - `kite_connectivity`: `unknown` (no active session in healthz context).
  - `litestream`: `unknown` (external binary — no in-process accessor).
- Top-level `status` degrades if any component is `disabled` / `dropping` /
  `defaults-only`; `unknown` is neutral to avoid false alarms.
- Pure read path — no I/O, no probes, no background polling. Constant-time.
- Tests: `app/server_edge_test.go` — 5 cases covering all healthy + audit
  disabled + riskguard defaults-only + buffer dropping.

### 3.8 RiskGuard — pre-trade order safety

8 checks enforced by middleware before any order tool reaches the Kite API.
All limits are per-user (DB-backed) with system defaults as fallback.

- Implementation: `kc/riskguard/` — `guard.go`, `middleware.go`.
- System defaults (`kc/riskguard/guard.go:14`):
  - Max single order value: ₹5,00,000
  - Max orders per day: 200
  - Max orders per minute: 10 (rate limit)
  - Duplicate-order window: 30 seconds
  - Max daily order value: ₹10,00,000
  - Auto-freeze on repeated rejections: true (3 rejections in 5 min)
- Rejection reasons are typed (`RejectionReason` — line 35): `global_freeze`,
  `trading_frozen`, `order_value_limit`, `quantity_limit`,
  `daily_order_limit`, `rate_limit`, `duplicate_order`,
  `daily_value_limit`, `auto_freeze`.
- Covers: `place_order`, `modify_order`, `close_position`,
  `close_all_positions`, `place_gtt_order`, `modify_gtt_order`,
  `place_mf_order`, `place_mf_sip` (`orderTools` map — line 24).
- Killswitch: global freeze bypasses all other checks and blocks all order
  tools.

### 3.9 Audit trail — tamper-evident hash chain

Every MCP tool call is logged to `tool_calls` (SQLite) with an HMAC-SHA256
chain: `entry_hash = HMAC(hashKey, prev_hash || call_id || email || tool ||
started_at)`.

- Schema: `kc/audit/store.go:139` `InitTable` — `prev_hash`, `entry_hash`
  columns.
- Chain computation: `kc/audit/store_worker.go:37` `computeChainLink`.
- Domain-separated key: `hashKey = HMAC(OAUTH_JWT_SECRET, "audit-chain-key-v1")`
  — `store.go:103`.
- Resume after restart: `SeedChain` — `store.go:120`. If no prior entries,
  genesis hash is `HMAC(hashKey, "genesis-v1")`.
- Verification helper: `VerifyChain` reports divergence position.
- Email in the `email` column is HMAC'd; the plaintext is AES-GCM'd into
  `email_encrypted` for authorised export.

### 3.10 Audit trail — 5-year retention

SEBI broker audit-trail requirement is 5 years. Implemented as a nightly
scheduler task.

- Implementation: `app/wire.go:415-417`:
  ```go
  const retentionDays = 1825 // 5 years — SEBI algo trading audit trail requirement
  ```
- Task name: `audit_cleanup`, scheduled daily at 03:00 IST.
- Delete path: `kc/audit/store_query.go:234` `DeleteOlderThan` — also writes
  a chain-break marker row so verification can detect the deletion window.

### 3.11 Audit hash-chain external publication — opt-in

External anchor for the chain tip, so an attacker who gains write access to
the audit DB cannot silently rewrite history.

- Implementation: `kc/audit/hashpublish.go`.
- Uploads `HashTipPublication{ tip_hash, entry_count, timestamp, signature }`
  to an S3-compatible bucket every hour (configurable).
- Signature: HMAC-SHA256 over the payload, default key is
  `OAUTH_JWT_SECRET`, overrideable via `AUDIT_HASH_PUBLISH_KEY`.
- **Status: opt-in.** Publishes only when all four env vars are set:
  `AUDIT_HASH_PUBLISH_S3_ENDPOINT`, `AUDIT_HASH_PUBLISH_BUCKET`,
  `AUDIT_HASH_PUBLISH_ACCESS_KEY`, `AUDIT_HASH_PUBLISH_SECRET_KEY`.
- **Not enabled on the default Fly.io deployment.** See §4 for what
  "enabled but unpublished" means from an audit standpoint.

### 3.12 OAuth 2.1 with PKCE

All MCP authentication uses PKCE (S256) via `mcp-remote` → server.

- Implementation: `oauth/handlers.go`, `oauth/handlers_oauth.go`.
- Dynamic client registration — clients are scoped per-user.
- Kite itself handles password + TOTP (2FA) authentication; the server never
  sees user passwords.
- JWT expiry: 24 hours for MCP bearer tokens (`oauth/config.go:31`), 7 days
  for dashboard cookies (`oauth/middleware.go:120`).

### 3.13 TLS on the hosted instance

Terminated at the Fly.io edge. `fly.toml` sets `force_https = true` on the
`http_service`, so HTTP is redirected to HTTPS at the proxy layer.

**Self-hosted deployments are responsible for their own TLS** — see §5.

### 3.14 Rate limiting — per-IP baseline

Per-IP rate limits precede per-user limits (§3.2), so a brand-new
unauthenticated IP is still capped.

- Implementation: `app/ratelimit.go` — `ipRateLimiter`, `rateLimit`
  middleware.
- Tiers (same as user limits): auth 2/sec burst 5, token 5/sec burst 10,
  MCP 20/sec burst 40.
- IP source: Fly.io `Fly-Client-IP` header first, else `r.RemoteAddr` with
  port stripped.
- Periodic map-flush (10 min) to bound memory.

### 3.15 Security headers

- `Strict-Transport-Security` with 1-year max-age
- `Content-Security-Policy` (scoped script origins)
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

Referenced in `SECURITY.md:74` and implemented in the HTTP middleware stack.

### 3.16 Sensitive parameter redaction in audit

`kc/audit/sanitize.go:7` `sensitiveKeys` lists parameters that are replaced
with `<redacted>` before the summary is rendered: `access_token`, `api_key`,
`api_secret`, `password`, `secret`, `token`. Case-insensitive match.

### 3.17 Supply-chain scanning

- `gosec`, `go vet` on every CI build.
- Dependabot monitors Go modules, GitHub Actions, and Docker base image.
- Manual pen-test notes: [`../SECURITY_PENTEST_RESULTS.md`](../SECURITY_PENTEST_RESULTS.md).
- Security audit history: [`../SECURITY_AUDIT_REPORT.md`](../SECURITY_AUDIT_REPORT.md).

### 3.18 SQLite WAL backup via Litestream

WAL replicated to Cloudflare R2 (APAC region) on 10-second sync-interval.

- Config: `etc/litestream.yml` — S3-compatible replica to R2 bucket
  `${LITESTREAM_BUCKET}`.
- Runs as a sidecar process inside the container (see Dockerfile).
- Purpose: disaster recovery and point-in-time restore of the audit trail
  and encrypted credential store.

---

## 4. Controls Deferred or Not Implemented

Honest accounting of gaps. Each is either explicitly deferred or
not-yet-implemented. Nothing here is "we meant to mention but forgot."

### 4.1 Audit hash-chain external publication — disabled by default

§3.11 documents that publication is **opt-in**. On the default Fly.io
deployment the required env vars are unset, so the chain is kept in-DB only
and not externally anchored. An attacker with DB write access who recomputes
the entire chain leaves no independent evidence.

- To enable: set the four `AUDIT_HASH_PUBLISH_*` env vars (see
  `kc/audit/hashpublish.go:82`).
- Operator action required for each new deployment.

### 4.2 Secret rotation runbook

No documented SOP for rotating `OAUTH_JWT_SECRET` or
`ADMIN_ENDPOINT_SECRET_PATH`.

Impact of an ad-hoc rotation today:
- All encrypted credentials must be re-encrypted with the new HKDF-derived
  key (the re-encryption loop exists in `kc/alerts/crypto.go:106`
  `migrateEncryptedData` but is only wired to the first-run salt migration).
- All dashboard session cookies (7-day expiry) become invalid.
- All MCP bearer tokens (24-hour expiry) become invalid.
- All dynamically registered OAuth clients must re-register via `mcp-remote`
  cache wipe.

**Status: deferred.** Current guidance is "if you must rotate, schedule a
maintenance window, users re-auth." A proper CLI (`rotate-key` flag, phased
key roll-over) is not implemented.

### 4.3 MFA on admin actions

Admin role is gated by `ADMIN_EMAILS` env var + JWT email claim + optional
`ADMIN_PASSWORD` for the dashboard login. No TOTP / WebAuthn / hardware-key
step for destructive admin operations.

- `confirm: true` elicitation provides a second-step confirmation per call,
  but this is anti-mis-click, not anti-credential-theft.
- If the admin's MCP client session is stolen, the attacker has full admin
  access until the session expires.

**Status: deferred.** SEP-1932 (DPoP / request signing) in MCP spec could
close this but is not adopted yet.

### 4.4 Self-hosted TLS configuration

The Fly.io instance is covered by edge TLS (§3.13). Self-hosted Docker
deployments (`Dockerfile.selfhost`) rely on the operator to put the server
behind a TLS-terminating reverse proxy (Caddy, nginx, Traefik) and configure
certificate lifecycle. No bundled TLS automation.

**Status: operator responsibility, documented here.** We ship HSTS so an
operator who forgets HTTPS on the first request will break every subsequent
request — a fail-loud signal.

### 4.5 Incident response plan

No formally documented incident response runbook (triage steps, user
communication templates, post-mortem format).

**Status: deferred.** Informal practice: email `sundeepg8@gmail.com`,
investigate, coordinate disclosure per `../SECURITY.md`.

### 4.6 Third-party SLA (Kite Connect API)

We depend on the availability, correctness, and security of the Kite Connect
API. Zerodha's terms of service apply to that relationship; we add nothing.
If Kite is down, we are down. If Kite exposes user data through its own
flaws, we cannot protect the user.

**Status: pass-through dependency.** Documented in `SECURITY.md:58`.

### 4.7 Formal request signing / DPoP

All MCP calls after authentication rely on a bearer JWT. A stolen bearer
token grants full access until expiry (24h). DPoP or mTLS would bind the
token to a specific key, making stolen tokens less useful.

**Status: not implemented.** The MCP spec has not yet ratified DPoP
(SEP-1932 is in draft). We will adopt when the spec stabilises.

### 4.8 Kite connectivity health probe

`/healthz?format=json` exposes `kite_connectivity` with `status: unknown`
because there is no active session inside the healthz handler to probe with.
A canary account probe would require running credentials — not desirable in
a shared health endpoint.

**Status: deferred.** Litestream health probe is deferred for the same
reason (no in-process accessor — it runs as a separate binary).

### 4.9 Widget CSP nonce / subresource integrity

Widgets inject inline scripts + inline CSS via the `/*__INJECTED_CSS__*/`
and `__INJECTED_DATA__` placeholders. CSP `script-src` allows `'unsafe-inline'`
in widget contexts for this reason. An attacker who finds a bypass around
`injectData` escaping (§3.4) is not caught by a nonce policy.

**Status: partial.** The defence-in-depth escapes in `injectData` close the
known bypasses, but a strict CSP with per-response nonce is not yet
deployed.

---

## 5. Assumptions and Operator Responsibilities

Fork-and-host operators inherit these responsibilities. The defaults below
are the Fly.io deployment's responsibility split; self-hosted is up to you.

### Operator must

- **Patch dependencies.** Dependabot opens PRs but does not merge them.
- **Configure TLS.** Self-hosted deployments must put the server behind a
  TLS-terminating reverse proxy. HSTS is set so HTTP-only deployments break
  fast.
- **Manage `OAUTH_JWT_SECRET`.** This key is the master for all encryption
  at rest (§3.1) AND JWT signing AND audit chain HMAC. Rotate carefully;
  store in a secret manager (Fly.io secrets, Vault, AWS Secrets Manager).
  Loss of this secret means loss of all encrypted data.
- **Back up the SQLite database.** Litestream config is shipped (§3.18) but
  the operator provides the R2/S3 credentials and pays for the bucket.
- **Review audit logs.** The scheduler cleans up past 5 years; before that
  the operator is expected to monitor `audit.status=dropping`
  (§3.7) and investigate.
- **Set `ADMIN_EMAILS` carefully.** Every email listed gains admin role at
  next startup. Remove departed staff explicitly.
- **Enable hash-chain external publication** if regulatory posture requires
  it (§3.11 / §4.1).

### Users must

- **Bring their own Kite developer app.** The server does not own any Kite
  credentials on behalf of users.
- **Rotate stolen credentials immediately.** If a user's API key/secret is
  leaked, they rotate on Kite's developer console and then re-register via
  the dashboard credential widget or `/auth/browser-login`.
- **Whitelist the server's static egress IP.** Per SEBI (April 2026), order
  placement requires the broker's IP to be whitelisted in the user's Kite
  developer console. The Fly.io deployment's egress is `209.71.68.157`
  (bom region).
- **Understand that admin role is granted by the operator.** Users should
  verify that the operator of a hosted instance is someone they trust.

### Admin role change process

- Add or remove from `ADMIN_EMAILS` env var.
- Redeploy (Fly.io) or restart (self-host).
- Old admin sessions remain valid until JWT expiry (24h) or cookie expiry
  (7d). There is no active kick-out.

---

## 6. Vulnerability Disclosure

Reporting process, SLA, and scope are documented in
[`../SECURITY.md`](../SECURITY.md). Summary:

- **Email:** `sundeepg8@gmail.com`
- **Acknowledgement:** within 72 hours for critical reports
- **Initial assessment:** within 7 days
- **Coordinated disclosure preferred**; we credit researchers who
  responsibly disclose (request attribution in the initial email).

Do NOT open a public GitHub issue for security bugs.

---

## 7. What Passes a Formal SEBI Cyber Audit vs. What Does Not

This section is a candid map from control to audit outcome. It helps an
operator deciding whether to pursue SEBI RIA / Algo registration
understand what remains.

### Would pass

- **Token and credential encryption at rest** (§3.1) — AES-256-GCM with HKDF
  key derivation meets CSCRF encryption requirements.
- **Audit log integrity** (§3.9) — HMAC hash chain per entry, resumable
  across restarts.
- **5-year audit retention** (§3.10) — matches SEBI broker audit-trail
  requirement.
- **Per-IP and per-user rate limiting** (§3.2, §3.14) — defence against
  credential-stuffing and brute-force.
- **Pre-trade risk controls** (§3.8) — RiskGuard's 8 checks materially
  reduce fat-finger and runaway-algo risk.
- **TLS with HSTS + security headers** (§3.13, §3.15) — on the Fly.io
  deployment. Self-hosted depends on operator.
- **Supply-chain scanning** (§3.17) — `gosec`, `go vet`, Dependabot.

### Would NOT pass as-is

- **Offshore backup in Cloudflare R2** (§3.18) — APAC region is closest but
  data-localisation requirements for SEBI-regulated entities (especially
  after the 2024 MII circular) may require India-domiciled backup. An
  operator pursuing registration must replace the bucket with an
  India-domiciled S3-compatible provider.
- **No MFA on admin actions** (§4.3) — the RIA framework's operational
  requirements expect MFA for privileged actions.
- **No external hash-chain anchor by default** (§3.11 → §4.1) — opt-in is
  not the same as enabled; an auditor would expect the anchor to be running.
- **No formal incident response plan** (§4.5) — required documentation.
- **No documented secret-rotation runbook** (§4.2) — required documentation.
- **Operator-provided TLS for self-hosted** (§4.4) — acceptable if the
  operator documents their configuration; not acceptable as "user's problem."

### If the operator is pursuing SEBI RIA registration

Close the gaps in priority order:

1. Enable hash-chain external publication (set
   `AUDIT_HASH_PUBLISH_*` env vars — §3.11).
2. Move Litestream replica to an India-domiciled bucket.
3. Document secret rotation, incident response, and admin-change runbooks.
4. Add TOTP (or WebAuthn) for admin dashboard login.
5. Complete an external penetration test and address findings.

Note: a detailed compliance path document is **not yet written**. When it
is, it will live at `docs/COMPLIANCE_PATHS.md`.

---

## 8. Change History

| Date | Commit | Change |
|------|--------|--------|
| 2026-04-17 | `0b1724d` | Per-user rate limiting + audit log newline escape + JS line-separator XSS hardening |
| 2026-04-17 | `4a37f10` | CQRS duplicate-registration returns error; audit drop logging throttled |
| 2026-04-17 | `bd3398e` | `/healthz?format=json` component status |
| 2026-04-17 | `cd3f7de` | Landing page redesign (informational; not a security change — listed for traceability) |
| 2026-04-17 | (this doc) | Initial SECURITY_POSTURE.md |

---

*Questions about this document: email `sundeepg8@gmail.com`.*
*Related: [`../SECURITY.md`](../SECURITY.md), [`../THREAT_MODEL.md`](../THREAT_MODEL.md), [`../SECURITY_AUDIT_REPORT.md`](../SECURITY_AUDIT_REPORT.md), [`../SECURITY_PENTEST_RESULTS.md`](../SECURITY_PENTEST_RESULTS.md).*
