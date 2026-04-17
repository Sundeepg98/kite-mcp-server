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

- OAuth 2.1 with PKCE (S256) for all authentication
- AES-256-GCM encryption for secrets at rest (tokens, API keys, client secrets)
- HKDF-SHA256 key derivation with random salt
- HMAC-SHA256 email hashing in audit trail
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
- bcrypt password hashing for admin login (cost 12)
- Per-IP rate limiting on all endpoints (auth 2/sec, token 5/sec, MCP 20/sec)
- Security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy)
- SEBI-compliant static egress IP + 5-year audit retention
- RiskGuard pre-trade checks (kill switch, order cap, daily value cap, etc.)

## Automated Scanning

- `gosec` and `go vet` run on every CI build
- Dependabot monitors Go modules, GitHub Actions, and the Docker base image
- Manual pen-test notes live in [`SECURITY_PENTEST_RESULTS.md`](SECURITY_PENTEST_RESULTS.md)
- Full audit history in [`SECURITY_AUDIT_REPORT.md`](SECURITY_AUDIT_REPORT.md)

## Full Posture Assessment

For the honest, audit-grade self-assessment against the SEBI Cybersecurity
Framework — including what's implemented, what's deferred, and what would
NOT pass a formal cyber audit today — see
[`docs/SECURITY_POSTURE.md`](docs/SECURITY_POSTURE.md).

## Credits

We credit researchers who responsibly disclose vulnerabilities. If you'd
like public recognition, tell us the name and link (GitHub / site / handle)
you want us to use — otherwise we'll keep the report private.
