# NIST CSF 2.0 Mapping — kite-mcp-server

*Last reviewed: 2026-04-26*
*Framework: NIST Cybersecurity Framework v2.0 (Feb 2024)*
*Companion to: [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) (SEBI CSCRF self-assessment), [`risk-register.md`](risk-register.md), [`threat-model.md`](threat-model.md)*

---

## 1. Purpose

NIST CSF 2.0 organises cybersecurity outcomes into 6 Functions:
**Govern, Identify, Protect, Detect, Respond, Recover**. This document
maps each Function's relevant Categories to specific code, configuration,
and operational evidence in `kite-mcp-server`.

This is **maintainer self-assessment**, not an externally-audited CSF
profile. The mapping exists so:
- A user can verify each control claim against repo evidence.
- An external auditor (SOC 2, ISO 27001 prep) has a starting Pulse line.
- A fork-and-host operator inherits a known control posture with file-line traceability.

For SEBI-specific mapping see [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md).
For per-risk mitigation status see [`risk-register.md`](risk-register.md).

---

## 2. Govern (GV)

| Category | Outcome | Evidence |
|---|---|---|
| GV.OC — Organisational context | Single-maintainer OSS project; mission stated in `README.md` | `README.md`; `LICENSE` (MIT); `funding.json` |
| GV.RM — Risk management strategy | Annual risk register review cadence | `docs/risk-register.md` §4 |
| GV.RR — Roles & responsibilities | Maintainer is sole risk owner; operators inherit on fork | `docs/risk-register.md` §2 (Owner column); `CODEOWNERS` |
| GV.PO — Policy | Security policy formalised; vulnerability disclosure documented | `SECURITY.md`; `docs/SECURITY_POSTURE.md` |
| GV.OV — Oversight | Public GitHub issue tracker; pull-request review by maintainer | GitHub repo settings; branch protection on `master` |
| GV.SC — Cybersecurity supply chain | Go module pinning + `govulncheck` in CI; SBOM generated monthly | `.github/workflows/security-scan.yml`; `.github/workflows/sbom.yml`; `mcp/plugin_sbom.go` |

## 3. Identify (ID)

| Category | Outcome | Evidence |
|---|---|---|
| ID.AM — Asset management | Data classification table; SBOM enumerates plugins | `docs/data-classification.md`; `mcp/plugin_sbom.go`; `mcp/plugin_manifest.go` |
| ID.RA — Risk assessment | 18-row risk register with likelihood/impact/residual | `docs/risk-register.md` §2 |
| ID.IM — Improvement | This document; `.research/blockers-to-100.md` per-dim gap analysis | `.research/blockers-to-100.md` |

## 4. Protect (PR)

| Category | Outcome | Evidence |
|---|---|---|
| PR.AA — Identity & access | Per-user OAuth bearer JWT (24h); admin allowlist via `ADMIN_EMAILS` | `oauth/middleware.go`; `mcp/admin_check.go`; `kc/users/store.go` (role) |
| PR.DS — Data security | AES-256-GCM at rest via HKDF; TLS 1.2+ in transit; bcrypt cost 12 for SSO | `kc/alerts/crypto.go`; `kc/users/store.go:139` |
| PR.PS — Platform security | Read-only filesystem on Fly.io image; minimal Alpine base; non-root user | `Dockerfile` |
| PR.IR — Technology infrastructure resilience | Goroutine leak detection; `-race` clean across 32 packages; circuit breaker on error spike | `kc/ticker/race_flag_*_test.go`; `mcp/circuitbreaker.go` |
| PR.PT — Protective technology | Tool-integrity manifest detects line-jumping; plugin SBOM checksums | `mcp/integrity.go`; `mcp/plugin_sbom_signature.go` |

## 5. Detect (DE)

| Category | Outcome | Evidence |
|---|---|---|
| DE.AE — Anomalies & events | Rolling μ+3σ baseline per user; tool-call latency tracking | `kc/audit/anomaly.go`; `mcp/observability_tool.go` |
| DE.CM — Continuous monitoring | Per-tool error rate; per-user request rate; freeze threshold | `kc/riskguard/guard.go`; `kc/audit/anomaly_cache.go` |
| DE.DP — Detection processes | Audit trail every tool call; admin-visible anomaly flags | `kc/audit/store.go`; `mcp/admin_tools.go` (`admin_list_anomaly_flags`) |

## 6. Respond (RS)

| Category | Outcome | Evidence |
|---|---|---|
| RS.MA — Management | Incident-response runbooks for 6 scenarios | `docs/incident-response.md` |
| RS.AN — Analysis | Tool-call audit trail with `CallID`/`RequestID` correlation; per-user activity dashboard | `kc/audit/store.go`; `kc/ops/handler_admin.go` (timeline) |
| RS.MI — Mitigation | Auto-freeze on circuit breaker trip; manual `unfreeze_user` admin tool; `ENABLE_TRADING=false` global kill switch | `kc/riskguard/circuit_limit.go`; `mcp/admin_tools.go` |
| RS.CO — Communication | Telegram briefings on critical events; admin email allowlist for ops messaging | `kc/telegram/`; `docs/incident-response.md` Communication §s |

## 7. Recover (RC)

| Category | Outcome | Evidence |
|---|---|---|
| RC.RP — Recovery planning | Litestream → R2 continuous replication; documented restore procedure | `etc/litestream.yml`; `scripts/dr-drill.sh` |
| RC.IM — Improvements | Monthly DR drill cron validates restore chain | `.github/workflows/dr-drill.yml` |
| RC.CO — Communications | Telegram success ping on DR drill; failure → workflow failure notification | `scripts/dr-drill.sh:60-65`; GH Actions notification settings |

---

## 8. Gap analysis (honest)

| Function | Maturity | Gap | Closure path |
|---|---|---|---|
| Govern | Partial | No external policy review; no third-party governance audit | Trigger: FLOSS/fund grant → SOC 2 prep |
| Identify | Strong | No automated asset-discovery for new tables/plugins | Manual ADR review on schema change |
| Protect | Strong | No MFA on dashboard SSO; secrets not rotated automatically | MFA queued (~80 LOC); Fly.io secret rotation manual |
| Detect | Moderate | Anomaly detection is statistical, not behaviour-graph | Acceptable for OSS-MCP scale |
| Respond | Moderate | No on-call rotation (single maintainer); response is best-effort | Structural to single-maintainer project |
| Recover | Strong | DR drill validates monthly; live failover not tested under load | Acceptable until enterprise deployment |

## 9. Review cadence

- **Annual**: walk every Function row; align with risk-register update.
- **Ad-hoc**: on incident, on new persistence sink, on new external integration.
- **Maintained alongside**: `SECURITY_POSTURE.md` (SEBI mapping) and `risk-register.md` (operational risks).
