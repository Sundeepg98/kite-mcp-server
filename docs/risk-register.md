# Risk Register — kite-mcp-server

*Last reviewed: 2026-04-26*
*Owner: maintainer (single-maintainer OSS project)*
*Cadence: annual review at minimum, ad-hoc on incident or major architecture change*

---

## 1. Purpose

Honest enumeration of operational, security, regulatory, and product risks
the project carries today. This is **not** a SEBI/ISO 27001 attestation — it
is a maintainer-honest list of what could go wrong, the current mitigation
posture, and the residual risk if the mitigation fails. Companion to
[`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) (controls catalogue) and
[`incident-response.md`](incident-response.md) (response runbooks).

Every risk is rated against:
- **Likelihood**: Low / Medium / High over a 12-month horizon
- **Impact**: Low (annoyance) / Medium (data loss bounded by recovery RTO) / High (account-level user harm) / Critical (mass exposure or regulatory action)
- **Residual**: severity once stated mitigations have applied

## 2. Register

| ID | Risk | Likelihood | Impact | Mitigation | Residual | Owner |
|---|---|---|---|---|---|---|
| R-01 | Kite credential database compromise (cleartext access key/secret) | Low | Critical | AES-256-GCM at rest via HKDF-derived key from `OAUTH_JWT_SECRET`; SQLite file perms; no network exposure of `/data/alerts.db`; Litestream-replicated R2 bucket has separate creds | Medium — encrypted-at-rest survives DB-file leak; `OAUTH_JWT_SECRET` leak compromises everything | maintainer |
| R-02 | Kite access-token theft via OAuth callback intercept | Low | High | mcp-remote uses HTTPS to `https://kite-mcp-server.fly.dev`; token-cache encrypted; daily expiry (~06:00 IST) limits blast radius | Low | maintainer |
| R-03 | Stripe webhook replay / forgery | Low | High | Stripe-Signature verified before processing; idempotent via `webhook_events` table; 65 KB body cap | Low | maintainer |
| R-04 | Plugin registry tampering / tool poisoning | Low | High | `mcp/integrity.go` SHA-256 manifests every tool description at startup; mismatch logged at WARN; SBOM with optional signatures via `mcp/plugin_sbom_signature.go` | Low | maintainer |
| R-05 | RiskGuard bypass (over-cap order placed) | Low | Critical | 9 pre-trade checks (kill switch, cap, count, rate, duplicate, idempotency, confirmation, anomaly, off-hours); CircuitBreaker freezes on error spike; `ENABLE_TRADING=false` on Fly.io is the kill switch | Low — defense-in-depth; user-defined limits are advisory, broker-side limits are authoritative | maintainer |
| R-06 | SEBI regulatory action (algorithmic trading without registration) | Medium | Critical | `ENABLE_TRADING=false` on hosted Fly.io instance (Path 2 read-only); local self-hosted preserves trading via personal-use safe harbor (OpenAlgo precedent); `kc/riskguard/otr_band.go` enforces SEBI Feb-2026 OTR exemption bands | Medium — first regulator inquiry could force feature gate or shutdown of hosted; local fork persists | maintainer |
| R-07 | DPDP §6 consent-trail failure | Low | Medium | `consent_log` append-only; revoke flow at `kc/usecases/consent_usecases.go`; DPDP reply templates at `docs/dpdp-reply-templates.md`; no PII in logs (email-hashed in domain events) | Low | maintainer |
| R-08 | Single-maintainer bus factor | High | High | OSS MIT licence permits fork-and-host; documentation extensive (71 docs in `docs/`); CI auto-tests on PR; dependency upgrades via Renovate-equivalent process | High — no second maintainer or commit-rights backup. Fork is the recovery path, not a hand-off. | maintainer |
| R-09 | Litestream/R2 backup chain silently broken | Low | High | `scripts/dr-drill.sh` + `.github/workflows/dr-drill.yml` monthly cron exercises restore; Telegram success ping; failure → workflow fail → notification | Low | maintainer |
| R-10 | Go dependency CVE (e.g., supply-chain attack on vendored module) | Medium | High | `go mod` with `go.sum` verification; `.github/workflows/security-scan.yml` runs govulncheck on PR; SBOM generated at `.github/workflows/sbom.yml` | Low — patches typically land within 24h of disclosure; manual review for transitive deps | maintainer |
| R-11 | Anomaly detector false-positive freezes legitimate user | Low | Medium | μ+3σ baseline computed over rolling 30-day window; warmup period suppresses freezes for first 7d; admin can `unfreeze_user` immediately | Low | maintainer |
| R-12 | Telegram bot token compromise | Low | Medium | Stored in Fly.io secrets only; not in git; revocable via @BotFather; bot-level command-allowlist | Low | maintainer |
| R-13 | OAuth client credential theft (mcp-remote cache file) | Medium | Medium | mcp-remote stores under `~/.mcp-auth/` with user-only file perms; per-server cache; rotation requires user action | Medium — user-side compromise is outside server's mitigation surface; documented in `docs/byo-api-key.md` | user/operator |
| R-14 | Race condition in 22-tool deps surface causing inconsistent state | Low | Medium | 7050+ `t.Parallel` test sites; `-race` clean across 32 packages; `LockDefaultRegistryForTest` pattern for parallel-safe registry mutation | Low | maintainer |
| R-15 | Premature feature deprecation on upstream Kite Connect API breaking change | Medium | Medium | `gokiteconnect` SDK pin in `go.mod`; `docs/kite-version-hedge.md` documents the hedge; `kite-mcp-server` exposes minimal set of Kite types (DTOs not SDK types) | Low | maintainer |
| R-16 | Misconfiguration on operator self-host (trading enabled without local-only IP binding) | Medium | High | `ENABLE_TRADING` defaults to `false`; `docs/byo-api-key.md` documents safe-harbor footprint; admin endpoint requires `ADMIN_ENDPOINT_SECRET_PATH` | Medium — operator-side risk; mitigation depends on operator reading docs | operator |
| R-17 | Cloudflare R2 outage during DR event | Low | High | Litestream replicates continuously (10s sync); SQLite WAL on Fly.io disk is the primary; R2 is the off-site copy. Outage → no real-time loss, only DR-window degradation | Low | maintainer |
| R-18 | Fly.io platform discontinues free/Connect tier | Medium | Medium | Self-host runbook in `docs/byo-api-key.md`; deployment artifact (`Dockerfile`) is platform-portable; documented egress IP whitelisting | Low — migration path exists | maintainer |

## 3. Top residual risks

After mitigations, the highest residual risks are:
1. **R-08 — Single-maintainer bus factor (High)**: structural to the project size; mitigated only by fork-readiness and licence permissiveness.
2. **R-06 — SEBI regulatory action (Medium)**: kill-switch (`ENABLE_TRADING=false`) is the panic button; uncertainty in regulator interpretation persists.
3. **R-13 — OAuth client cred theft (Medium)**: client-side compromise outside server mitigation surface.
4. **R-16 — Operator misconfiguration (Medium)**: documentation-mitigated only.

## 4. Review cadence

- **Annual**: full register walk-through; update likelihood/impact based on incident history and threat-landscape changes.
- **Ad-hoc**: on any P1 incident, on major architecture change (e.g., new aggregate, new external dependency), on regulatory framework change (SEBI circulars, DPDP rules notification).
- **Linked to**: [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §2 control mapping; [`incident-response.md`](incident-response.md) Scenario list.
