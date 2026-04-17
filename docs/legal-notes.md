# Legal & Compliance Index

Where to find what.

## User-facing

- **Terms of Service** — `TERMS.md`
- **Privacy Policy** — `PRIVACY.md`

## Security & compliance

- **Security policy** (vuln disclosure) — `SECURITY.md`
- **Full security posture assessment** — `docs/SECURITY_POSTURE.md`
- **Threat model** — `THREAT_MODEL.md`
- **Security audit report (2026-02)** — `SECURITY_AUDIT_REPORT.md`

## Trading compliance

- **SEBI algo framework compliance** — see `SECURITY_POSTURE.md` §7
  "What passes a formal SEBI cyber audit"
- **"Not investment advice." disclaimer** — applied to every advisory-
  framed tool description. See `mcp/*.go` tool definitions.
- **Static egress IP** — `209.71.68.157` (Fly.io bom region). Must
  be whitelisted in Kite developer console per SEBI April-2026 mandate.
- **Order tag** — All orders tagged `mcp` for SEBI traceability.

## Operator responsibilities (self-hosted)

- TLS termination (we assume HTTPS; `scripts/deploy.sh` deploys
  behind Fly.io's TLS — self-hosted operators provide their own)
- Secret management (`OAUTH_JWT_SECRET`, Kite credentials, Stripe
  keys if billing activated)
- Backup encryption keys for the encrypted SQLite volume
- Incident response (none documented — ad-hoc today)

## What we DON'T claim

- Not a SEBI Registered Investment Adviser (RIA)
- Not SEBI-registered as an algo provider
- No SEBI cyber audit attestation
- No SLA on Kite API pass-through; their terms govern
- No guarantees on order fills, paper-trading outcomes, or
  backtest accuracy reflecting live market behavior
