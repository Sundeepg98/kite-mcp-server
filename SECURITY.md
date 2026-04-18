# Security Policy

We take the security of this project seriously. Because it mediates access to
live brokerage accounts, bugs here can have real financial consequences — so
please help us find and fix them responsibly.

## Supported Versions

Security fixes are shipped only for the latest released line.

| Version | Supported       |
|---------|-----------------|
| 1.0.x   | Yes             |
| < 1.0   | No (pre-release)|

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security bugs.**

Email: **sundeepg8@gmail.com**

Include as much of the following as you can:

- A clear description of the issue and its impact
- Steps to reproduce (proof-of-concept code welcome)
- Affected version / commit SHA
- Any suggested mitigation

If the report is sensitive and you need encrypted communication, say so in
your first email and we'll exchange a key.

### Response SLA

Best effort, typically:

- **Acknowledgement:** within 72 hours for critical reports
- **Initial assessment:** within 7 days
- **Fix & disclosure timeline:** agreed with the reporter; coordinated
  disclosure preferred

## Scope

### In scope

- The server code in this repository (`app/`, `kc/`, `mcp/`, `oauth/`, etc.)
- OAuth 2.1 flows, JWT issuance and validation, session handling
- Audit log integrity (hash chain, tamper detection)
- Rate limiting and abuse prevention bypasses
- XSS / CSRF / clickjacking in dashboard pages and inline widgets
- Encryption of secrets at rest (tokens, API keys, client secrets)
- Admin endpoint access control (role gating via `ADMIN_EMAILS`)
- Supply-chain issues specific to our build (Dockerfile, CI)

### Out of scope

- Third-party dependencies — please report those upstream. We'll pull the fix
  in once it lands.
- The Kite Connect API itself, or any Zerodha infrastructure — contact
  Zerodha directly for those.
- Issues that require a compromised end-user machine (e.g. reading a
  plaintext `.env` that the user themselves stored).
- Denial-of-service via raw volume on the hosted instance (Fly.io) unless
  it demonstrates an amplification or logic flaw.
- Missing "best-practice" headers that have no demonstrable impact.

## Hardening Measures In Place

### Authentication & cryptography

- OAuth 2.1 with PKCE (S256) for all authentication
- AES-256-GCM encryption for secrets at rest (tokens, API keys, client secrets)
- HKDF-SHA256 key derivation with random salt
- HMAC-SHA256 email hashing in audit trail
- bcrypt password hashing for admin login (cost 12)
- OAuth consent cookie ordering verified with regression tests (prevents
  pre-consent callback races)

### Audit trail integrity

- Hash-chained tamper-evident audit log (HMAC-SHA256 per entry, prev_hash
  linkage, chain-break markers for retention deletions, `VerifyChain()` walks
  the full chain to detect tampering)
- **External hash-chain anchoring** — on opt-in, the chain tip (latest
  `entry_hash` + entry count) is published hourly to S3-compatible storage
  (Cloudflare R2) signed with HMAC-SHA256. Closes the gap where an attacker
  with DB write access could rewrite every row's hash consistently and still
  pass local `VerifyChain()`. Verifiers can compare local chain state against
  the independently-stored anchor. See `AUDIT_HASH_PUBLISH_*` env vars in
  `.env.example` and `kc/audit/hashpublish.go` for details.
- **X-Request-ID correlation** — every HTTP request is assigned (or inherits)
  a `X-Request-ID` header that is threaded through the MCP handler, RiskGuard,
  audit store, and outbound logs. Support queries can pivot from a user report
  to the exact tool call, credentials used, and downstream broker call.

### Order / trade safety

- RiskGuard pre-trade checks (kill switch, order value cap, daily value cap,
  daily order count cap, per-IP rate limit, duplicate-order window,
  auto-freeze circuit breaker)
- **Default caps tightened**: 20 orders/day, ₹2L notional/day, ₹50k per-order
- **Idempotency keys** — `client_order_id` on `place_order` / `modify_order`
  dedupes retry storms from a misbehaving client or LLM-driven loop
- **Anomaly detection** — 30-day rolling baseline (μ + 3σ) per user on order
  value / order count; orders that fall outside the band are flagged. A
  dedicated off-hours block rejects orders submitted between 2 AM and 6 AM IST
  unless explicitly overridden
- **15-min TTL cache** on user order statistics reduces SQLite load while
  keeping the anomaly check warm
- **Path 2 env gate** — `ENABLE_TRADING` must be set explicitly for
  order-placement tools to register. The public hosted deployment ships with
  order placement disabled; only users self-hosting (and accepting the
  liability) see the order tools
- Order confirmation elicitation on 8 tools (fail-open for older MCP clients
  that can't render an elicitation prompt)

### Network & abuse prevention

- Per-IP rate limiting on all endpoints (auth 2/sec, token 5/sec, MCP 20/sec)
- Security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy)
- **SSRF blocklist** on the audit publish endpoint — blocks loopback, link-local,
  multicast, IPv4/IPv6 private ranges, and cloud metadata (169.254.169.254,
  fd00::/8) before HTTP dial. Belt-and-braces against a misconfigured
  `AUDIT_HASH_PUBLISH_ENDPOINT` pointing inward.

### Attack-surface minimization

- **Tool-description integrity manifest** — on startup, the server logs a
  SHA-256 of every registered tool's name + description. A diff in that
  manifest between deploys catches "line-jumping" / instruction-injection
  attacks where a tool description is silently mutated to change LLM
  behaviour (e.g. "…always confirm=true"). Operators can alert on unexpected
  manifest changes in their log pipeline.
- MCP Apps widgets gated on client capability — not advertised to hosts that
  can't render them

### Compliance & legal posture

- SEBI-compliant static egress IP (209.71.68.157 from bom region)
- 5-year audit retention, 90-day in-app retention window
- Telegram disclaimer prefix on all financial messages (SEBI classification
  drift protection) + `/disclaimer` command
- MIT attribution shipped in Docker images and surfaced in the landing-page
  footer

## Automated Scanning

- `gosec`, `go vet`, and `govulncheck` run weekly in CI; findings uploaded to
  GitHub Code Scanning as SARIF
- **SBOM** (CycloneDX) generated on every master push and release tag, also
  uploaded to GitHub Code Scanning for supply-chain auditability
- `testing.F` fuzz harnesses on the ArgParser, widget-injection path, and
  Telegram command parser — run locally on demand, seed corpus checked in
- Dependabot monitors Go modules, GitHub Actions, and the Docker base image
- Manual pen-test notes live in [`SECURITY_PENTEST_RESULTS.md`](SECURITY_PENTEST_RESULTS.md)
- Full audit history in [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md)

## Recent hardening (2026-04-17)

The most recent security-adjacent commits, for reviewers who want a
diff-level view:

- Idempotency keys (`client_order_id`) on `place_order` / `modify_order` (commit `2780329`)
- Tool-description integrity manifest logged at startup (`5a82032`)
- X-Request-ID header propagation across HTTP/MCP/audit (`676c71f`)
- Anomaly detection: 30-day rolling μ+3σ + 2-6 AM IST off-hours block (`792c687`)
- 15-min TTL cache on stats lookups (`543d3f2`)
- SBOM generation in CI → GitHub Code Scanning (`dc9cca3`)
- SSRF blocklist on audit publish endpoints (`e561377`)
- Riskguard default caps tightened: 20 orders/day, ₹2L notional, ₹50k cap (`7cd7b35`)
- Telegram disclaimer prefix on all financial messages (`3879aba`)
- MIT attribution in Docker images + landing footer (`9b787e0`)
- Path 2 env gate: order placement disabled on hosted deployment (`04f4b18`)
- Fuzz harnesses on ArgParser + widget injection + Telegram parser (`96e0e4b`)
- `gosec` + `govulncheck` CI (`503a860`)
- OAuth consent cookie ordering verified + regression tests (`e561377`)

## Full Posture Assessment

For the honest, audit-grade self-assessment against the SEBI Cybersecurity
Framework — including what's implemented, what's deferred, and what would
NOT pass a formal cyber audit today — see
[`docs/SECURITY_POSTURE.md`](docs/SECURITY_POSTURE.md).

## Credits

We credit researchers who responsibly disclose vulnerabilities. If you'd
like public recognition, tell us the name and link (GitHub / site / handle)
you want us to use — otherwise we'll keep the report private.
