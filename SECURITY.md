# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

- Email: sundeepg8@gmail.com
- Do NOT open a public GitHub issue for security vulnerabilities
- Include: description, steps to reproduce, potential impact
- Expected response time: 48 hours

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.0.x  | Yes       |

## Security Measures

- OAuth 2.1 with PKCE (S256) for all authentication
- AES-256-GCM encryption for secrets at rest (tokens, API keys, client secrets)
- HMAC-SHA256 email hashing in audit trail
- Hash-chained tamper-evident audit log
- bcrypt password hashing for admin login (cost 12)
- Per-IP rate limiting on all endpoints
- HKDF-SHA256 key derivation with random salt
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- SEBI-compliant static egress IP + 5-year audit retention

## Automated Security Scanning

This project runs automated security scans:
- gosec (Go static analysis)
- go vet
- Manual web vulnerability checks (documented in SECURITY_PENTEST_RESULTS.md)
