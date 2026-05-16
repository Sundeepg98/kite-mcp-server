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
- **Known gap — SEBI MARKET/IOC algo prohibition (April-2026 mandate)** —
  SEBI's April-2026 framework prohibits MARKET orders and IOC (Immediate-
  or-Cancel) validity for algorithmic trades. Our RiskGuard surface
  (`algo2go/kite-mcp-riskguard`) implements 11 pre-trade checks (order-
  value cap, qty limit, daily count, rate limit, per-second rate,
  duplicate, daily notional, idempotency key, confirmation, anomaly μ+3σ,
  off-hours) but does NOT currently block MARKET/IOC orders even when
  `ENABLE_TRADING=true`. The framework distinguishes "algo trades" from
  manual user-initiated orders; an MCP-tool-call IS algo-classified under
  SEBI's definition. Operators running with `ENABLE_TRADING=true` should
  treat MARKET/IOC as out-of-policy for algo workflows until a 12th
  RiskGuard check lands. Tracked as a launch blocker for any
  `ENABLE_TRADING=true` production-algo deployment. Hosted Fly.io
  deployment runs `ENABLE_TRADING=false` (read-only) per Path 2
  compliance, so this gap does not affect the hosted instance.

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
