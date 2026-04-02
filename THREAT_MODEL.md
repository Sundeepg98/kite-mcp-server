# STRIDE Threat Model - Kite MCP Server

This document provides a formal threat analysis of the Kite MCP Server using the STRIDE framework. Each category identifies threats, assesses likelihood and impact, documents current mitigations, and notes residual risk.

---

## 1. Spoofing

### Threat: Attacker impersonates a legitimate user

An attacker attempts to authenticate as another user to gain access to their portfolio, place orders, or read sensitive financial data.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Medium |
| **Impact** | Critical |

### Current Mitigations

- **OAuth 2.1 with PKCE (S256)**: All MCP authentication uses proof-key code exchange, preventing authorization code interception attacks.
- **Kite handles identity verification**: Users authenticate via Kite's own login page with credentials + TOTP (two-factor). The server never sees or stores user passwords.
- **JWT with HMAC-SHA256**: Session tokens are signed with a server-side secret. Tokens expire after 4 hours.
- **Per-user credential isolation**: Each user's Kite API key and secret are stored separately, encrypted with AES-256-GCM.
- **Dynamic client registration**: OAuth clients are registered per-user, preventing cross-user token reuse.

### Residual Risk

- If `OAUTH_JWT_SECRET` is compromised, an attacker could forge JWTs. Mitigation: secret is stored as a Fly.io secret, never in code.
- Kite access tokens expire daily (~6 AM IST) but are valid for a full trading session. A stolen token grants access until expiry.

---

## 2. Tampering

### Threat: Attacker modifies data in transit or at rest

An attacker intercepts or modifies API requests, order parameters, or stored credentials to alter trading behavior or steal secrets.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Low |
| **Impact** | Critical |

### Current Mitigations

- **TLS enforcement**: `force_https` middleware redirects all HTTP to HTTPS. Fly.io terminates TLS at the edge with valid certificates.
- **AES-256-GCM encryption at rest**: All sensitive data (Kite tokens, API keys, API secrets, OAuth client secrets) is encrypted in SQLite using AES-256-GCM with HKDF-SHA256 key derivation and random salts.
- **HMAC hash-chained audit trail**: Every tool call is logged with a hash chain. Each entry's hash includes the previous entry's hash, making retroactive tampering detectable.
- **MaxBytesReader on request bodies**: Prevents oversized request payloads from being processed.
- **Order validation**: Server-side validation of order parameters (price required for LIMIT/SL, iceberg constraints) prevents malformed orders from reaching Kite.

### Residual Risk

- SQLite database file is not encrypted at the filesystem level (relies on Fly.io volume encryption).
- An attacker with server access could read the encryption key from environment variables and decrypt stored credentials.

---

## 3. Repudiation

### Threat: User denies placing an order or performing an action

A user places a trade through the MCP interface and later claims they did not authorize it, creating a dispute with no evidence trail.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Medium |
| **Impact** | High |

### Current Mitigations

- **Tamper-evident audit trail**: Every MCP tool call is logged to the `tool_calls` SQLite table with timestamp, user email (HMAC-hashed), tool name, parameters, and result summary.
- **Hash chaining**: Each audit entry includes a SHA-256 hash of the previous entry, creating a blockchain-like chain. Any deletion or modification breaks the chain and is detectable.
- **5-year retention**: Audit records are retained for 5 years (SEBI compliance requirement for broker audit trails).
- **Per-tool-call summaries**: Smart summarization captures the intent and outcome of each tool call (e.g., "Placed BUY order for 10 INFY at market price").
- **CSV/JSON export**: Audit trail can be exported for external archival or regulatory review.
- **Buffered async writer**: Audit writes are buffered and flushed asynchronously, ensuring logging does not impact trading latency while maintaining durability.

### Residual Risk

- HMAC-hashed emails cannot be reversed, but an admin with access to the HMAC key and user list could correlate entries to users. This is by design for regulatory compliance.
- If the SQLite database is deleted entirely, the audit trail is lost. Mitigation: regular backups recommended.

---

## 4. Information Disclosure

### Threat: Attacker reads sensitive financial or personal data

An attacker gains unauthorized access to user portfolios, trading history, API credentials, or personally identifiable information.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Medium |
| **Impact** | Critical |

### Current Mitigations

- **Encrypted secrets at rest**: AES-256-GCM encryption for all tokens, API keys, and client secrets stored in SQLite.
- **HMAC email hashing in audit**: User emails in the audit trail are HMAC-SHA256 hashed, preventing casual disclosure while allowing correlation by authorized admins.
- **Session ID hashing**: Session identifiers stored in the database are hashed, preventing session hijacking from database access alone.
- **Security headers**: All responses include:
  - `Strict-Transport-Security` (HSTS) with 1-year max-age
  - `Content-Security-Policy` restricting script and resource origins
  - `X-Frame-Options: DENY` preventing clickjacking
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Per-user data scoping**: Dashboard and API endpoints only return data belonging to the authenticated user. Admin endpoints require admin role verification.
- **PII redaction in logs**: Structured logging avoids logging sensitive fields. Audit summaries redact credential values.

### Residual Risk

- Kite API responses (portfolio, orders) are held in memory during processing. A memory dump could expose financial data.
- Server logs on Fly.io may contain request metadata (IPs, user-agents) that could aid correlation attacks.

---

## 5. Denial of Service

### Threat: Attacker overwhelms the server, preventing legitimate trading

An attacker floods the server with requests, exhausting resources and preventing users from placing time-sensitive trades during market hours.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Medium |
| **Impact** | High |

### Current Mitigations

- **Per-IP rate limiting**: Differentiated limits by endpoint sensitivity:
  - Auth endpoints: 2 requests/second
  - Token endpoints: 5 requests/second
  - MCP endpoints: 20 requests/second
- **MaxBytesReader**: Request body size limits prevent memory exhaustion from oversized payloads.
- **Fly.io infrastructure DDoS protection**: Fly.io's edge network provides basic DDoS mitigation at the infrastructure level.
- **Pagination caps**: API responses are capped at 500 items per page, preventing memory exhaustion from unbounded queries.
- **Buffered async audit writes**: Audit logging does not block request processing, maintaining responsiveness under load.
- **Graceful shutdown**: Server handles SIGTERM gracefully, completing in-flight requests before shutting down.

### Residual Risk

- Rate limiting is per-IP; a distributed attack from many IPs could bypass limits. Fly.io's infrastructure-level protection is the primary defense here.
- A single Fly.io instance (512MB RAM) could be overwhelmed by sustained legitimate load. Horizontal scaling is not currently configured.
- WebSocket/SSE connections consume server resources and are not individually rate-limited after establishment.

---

## 6. Elevation of Privilege

### Threat: A viewer becomes a trader, or a trader becomes an admin

An attacker with limited access (viewer role or regular user) escalates their privileges to place trades, access admin dashboards, or modify other users' settings.

| Attribute | Value |
|-----------|-------|
| **Likelihood** | Low |
| **Impact** | Critical |

### Current Mitigations

- **RBAC with viewer role enforcement**: Users with the "viewer" role are blocked from 21 write tools (place_order, modify_order, cancel_order, etc.). Enforcement is in the MCP tool handler middleware, not just the UI.
- **Admin from database**: Admin role is stored in the SQLite user store, seeded from the `ADMIN_EMAILS` environment variable at startup. Runtime role changes require database modification.
- **User status checks in middleware**: Every MCP request checks the user's current status and role from the database. Suspended or deleted users are immediately blocked.
- **Separate admin login flow**: Admin dashboard access requires a separate `/auth/admin-login` endpoint with bcrypt password verification (cost 12).
- **OAuth scope isolation**: Each user's OAuth session is scoped to their own credentials and data. Cross-user access is not possible through the OAuth flow.

### Residual Risk

- If the `ADMIN_EMAILS` environment variable is modified on Fly.io, new admins are seeded at next restart. An attacker with Fly.io access could add themselves.
- The viewer role enforcement is in application code. A bug in the tool handler middleware could bypass role checks. Mitigation: 270+ tests cover authorization paths.

---

## Architecture Diagram

```
                    Internet
                       |
                   [Fly.io Edge]
                   TLS + DDoS
                       |
              [Rate Limiter (per-IP)]
                       |
              [OAuth 2.1 + PKCE Auth]
                       |
            [RBAC Middleware (role check)]
                       |
         +-------------+-------------+
         |             |             |
    [MCP Tools]  [Dashboard]   [Admin Ops]
         |             |             |
    [Kite API]   [SQLite DB]   [Audit Trail]
         |        (AES-256)    (hash-chain)
         |
    [Kite Connect]
    (static IP: 209.71.68.157)
```

---

## Review Schedule

This threat model should be reviewed:
- After any significant architecture change
- After any security incident
- At least annually (next review: April 2027)

---

*Last updated: 2026-04-02*
*Author: Sundeep G*
