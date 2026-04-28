# Continuous Monitoring — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: DE.CM-1 (Network monitored), DE.CM-3 (Personnel activity monitored), DE.CM-4 (Malicious code), DE.CM-7 (Monitoring for unauthorized personnel/connections), DE.CM-8 (Vulnerability scans), DE.AE (Anomalies & events), GV.OV-1 (Cybersecurity strategy oversight).*
*Companion to: [`monitoring.md`](monitoring.md), [`security-scanning.md`](security-scanning.md), [`incident-response-runbook.md`](incident-response-runbook.md), [`audit-export.md`](audit-export.md), [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md).*

This document EXTENDS [`monitoring.md`](monitoring.md). The base file describes *what* surfaces are observable and the alerts to wire from each. This document adds the *policy* layer:
- continuous-monitoring strategy (DE.CM)
- log aggregation architecture
- alert policies and SLAs
- correlation and SIEM-readiness

[`monitoring.md`](monitoring.md) is the operational reference; this is the strategic / compliance layer.

---

## 1. Monitoring philosophy

Three principles drive the monitoring architecture:

1. **Detect silent failures, not just hard ones.** A 500 response is loud; an audit-trail gap is silent. The architecture in [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.7 added `/healthz?format=json` specifically to detect H1/H2/H3 silent failures (see [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §13a).
2. **Fail loud over fail noisy.** Every alert has a clear remediation path — vague alerts ("error rate elevated") are worse than no alert.
3. **Correlate at the request level.** The X-Request-ID propagation lets every log line for a single request be retrieved with one query (`flyctl logs | jq 'select(.request_id=="<id>")'`).

These principles inform what we monitor (§2), what we alert on (§3), and how we correlate (§5).

---

## 2. Monitoring surfaces

[`monitoring.md`](monitoring.md) §"Surfaces" enumerates 9 observable surfaces:

1. `/healthz?format=json` — component health (audit, riskguard, kite_connectivity, litestream)
2. `server_metrics` MCP tool — per-tool latency p50/p95/p99, error rate, call count
3. `server_version` MCP tool — git SHA, build time, region, uptime, env flags
4. Audit trail (`tool_calls` SQLite table)
5. Anomaly stats cache hit rate
6. RiskGuard structured log lines (per block reason)
7. X-Request-ID correlation (every HTTP/MCP layer)
8. Fly.io platform signals (machine restarts, memory, CPU, egress bandwidth)
9. Telegram bot health (briefings, command success rate)

Each surface is also a NIST CSF 2.0 monitoring control:

| Surface | DE control |
|---|---|
| `/healthz` | DE.CM-1 (network monitored — synthetic probe) |
| `server_metrics` | DE.AE-2 (anomalies analyzed); DE.CM-7 (monitoring for unauthorized) |
| `server_version` | DE.CM-1 (configuration drift); ID.AM-2 (software inventory) |
| Audit trail | DE.AE-1 (baseline established); DE.CM-3 (personnel activity) |
| Anomaly stats cache | DE.AE-2 (anomalies analyzed) |
| RiskGuard logs | DE.CM-4 (malicious code prevented); DE.AE-2 |
| X-Request-ID | RS.AN-1 (notifications investigated) |
| Fly.io signals | DE.CM-1 |
| Telegram health | DE.CM-1 |

---

## 3. Alert policies and SLAs

Alerts are categorised by severity. Each tier has a response SLA matching [`incident-response-runbook.md`](incident-response-runbook.md) §2.

### 3.1 Critical alerts (response: <1 hour, 24×7)

These wake the maintainer (when on-call). False positives are tolerated; missed signals are not.

| Trigger | Source | First action |
|---|---|---|
| `/healthz` top-level `status != "ok"` >5 min | Healthz JSON | [`operator-playbook.md`](operator-playbook.md) §1 morning routine, jump to relevant section |
| `components.audit.status != "ok"` (any value) | Healthz JSON | Compliance gap. [`monitoring.md`](monitoring.md) §1 + investigate SQLite/Litestream |
| `components.audit.dropped_count > 100` sustained | Healthz JSON | [`operator-playbook.md`](operator-playbook.md) §1.3 escalate |
| Audit hash chain verification failure | Server log on startup | Forensic snapshot BEFORE any change; jump to [`incident-response.md`](incident-response.md) §Scenario 3 |
| Per-user `place_order` 10x spike | Audit trail watch | [`operator-playbook.md`](operator-playbook.md) §6 — freeze user; review audit |
| `auto_freeze` event triggered | RiskGuard log | [`incident-response.md`](incident-response.md) §Scenario 3 — investigate why circuit broke |
| Mass HTTP 429 from `api.kite.trade` | App log | [`incident-response.md`](incident-response.md) §Scenario 2 |
| Stripe webhook signature failure spike >10/min | App log | Suspected secret leak; rotate `STRIPE_WEBHOOK_SECRET` |
| Cloudflare R2 unreachable >10 min | Litestream sidecar log | [`vendor-management.md`](vendor-management.md) §6 + Cloudflare status |
| Memory usage >90% sustained | Fly.io metrics | OOM imminent; scale up (`flyctl scale memory 1024`) |

### 3.2 High alerts (response: <4 hours, business hours)

Important but not service-down.

| Trigger | Source | First action |
|---|---|---|
| `/healthz` top-level `status: degraded` (any component degraded) | Healthz JSON | Investigate the degraded component |
| `components.audit.dropped_count` 10-100 sustained 30 min | Healthz JSON | [`operator-playbook.md`](operator-playbook.md) §1.3 |
| `components.riskguard.status: defaults-only` | Healthz JSON | Risk limits weren't loaded; restart machine |
| p95 latency on `place_order` >3000ms | server_metrics | Kite API slow or adapter retrying; check upstream |
| Tool error rate >5% sustained 15 min (any tool) | server_metrics | Schema drift, broken integration, vendor issue |
| User reports `/dashboard/activity` empty | User report | Audit middleware not wired (regression); rollback |
| 429 spike per-user (one user only) | App log + audit | Single-user runaway LLM or attack; freeze user |
| Litestream WAL freshness >10 min | `/healthz?level=deep` | R2 connectivity; replication backlog |
| Memory usage 80-90% sustained 1 hr | Fly.io metrics | Scale-up signal; not yet emergency |
| CPU >70% sustained during market hours | Fly.io metrics | Scale-up signal |

### 3.3 Medium alerts (response: <24 hours)

Watch-and-investigate.

| Trigger | Source | First action |
|---|---|---|
| Anomaly cache hit rate <70% sustained 1 hr | StatsCacheHitRate | Investigate cache TTL / eviction |
| Anomaly cache hit rate 100% over multiple days | StatsCacheHitRate | Cache may not be invalidating |
| Telegram briefing not delivered by 09:10 IST weekday | Scheduler log | Check scheduler; bot token; Telegram status |
| Daily P&L not delivered by 15:40 IST weekday | Scheduler log | Same as above |
| `/buy` Telegram command success <95% | Telegram bot logs | Inline-keyboard flow regression |
| Riskguard ZERO blocks for days on live deployment | RiskGuard log | Likely silent regression — check middleware wiring |
| New gosec findings (Code Scanning alert) | GitHub Code Scanning | Triage per [`security-scanning.md`](security-scanning.md) §"Responding to findings" |
| New Dependabot alert (any severity) | Dependabot | Triage per [`vulnerability-management.md`](vulnerability-management.md) §3 |
| Egress bandwidth spike without tool-call surge | Fly.io metrics | Potential exfil; review audit trail |

### 3.4 Low alerts (response: <1 week)

Informational; batch with weekly review.

| Trigger | Source | Action |
|---|---|---|
| Machine restart outside release window | Fly.io | Investigate panic / OOM root cause |
| `kite_connectivity` `unknown` (no active session) | Healthz | Expected for healthcheck context — informational only |
| `litestream` `unknown` (external binary) | Healthz | Expected — informational |
| Build time >5 min on CI | GitHub Actions | Investigate; not blocking |

---

## 4. Log aggregation

### 4.1 Current architecture

```
Server slog JSON to stdout
        │
        ▼
   Fly.io log capture
        │
        ▼
flyctl logs -a kite-mcp-server (operator pulls on demand)
```

Single-tier today: stdout → Fly.io → operator on-demand. No persistent SIEM. Log retention is bounded by Fly.io's default (typically days, not months).

### 4.2 Log structure

All log lines are JSON via `slog`:

```json
{
  "level": "INFO",
  "time": "2026-04-26T14:30:00Z",
  "msg": "...",
  "request_id": "<uuidv7>",
  "email": "<user>",
  "tool": "<name>",
  "call_id": "<uuid>"
}
```

Common fields preserved across the request:
- `request_id` — HTTP-layer UUIDv7 (set by `withRequestID` middleware in `app/requestid.go`).
- `email` — from `oauth.EmailFromContext(ctx)`; redacted via HMAC for sensitive contexts (audit chain).
- `tool` — MCP tool name.
- `call_id` — per-tool-call UUID set by Correlation middleware.

PII redaction at log time: `kc/audit/sanitize.go` `sensitiveKeys` substitutes `<redacted>` for `access_token`, `api_key`, `api_secret`, `password`, `secret`, `token` (case-insensitive). Audit summariser strips control characters.

### 4.3 Audit trail (parallel persistence)

Distinct from log aggregation: every MCP tool call is also persisted to SQLite (`tool_calls` table) with a hash chain. This is REGULATORY audit, not OPERATIONAL log. See [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.9 / [`audit-export.md`](audit-export.md).

| Aspect | Operational logs (stdout) | Regulatory audit (SQLite) |
|---|---|---|
| Source | `slog` Logger calls | Audit middleware on every tool call |
| Sink | stdout → Fly.io | `tool_calls` table |
| Retention | ~days (Fly.io default) | 5 years (SEBI) |
| Tamper-evident | No (process-local) | Yes (HMAC hash chain) |
| Replication | No | Yes (Litestream → R2) |
| Search | Full-text via `flyctl logs | jq` | SQL via dashboard / `audit-export.sh` |

### 4.4 Future SIEM integration (deferred)

For SOC 2 / ISO 27001 prep, we'd typically wire stdout → Loki / Datadog / ELK. Today's posture: deferred until at least 50 paid users (per [`MEMORY.md`](../MEMORY.md) growth thresholds).

When activated, the integration plan:

1. **Loki + Grafana** (cheapest) — Fly.io has a Loki addon; structured JSON logs land directly.
2. **Alert routing** to Telegram (already wired for DR drill notifications) or Slack via webhook.
3. **Dashboards** for the §3 critical/high triggers.
4. **Retention extension** to 90 days for operational logs (matches DPDP minimum); audit trail is already 5 years.

Cost projection: Grafana Cloud free tier (50 GB ingest/30 days) covers expected volume at <500 paid users.

---

## 5. Correlation strategy

The single most useful query: "what happened to request X?"

```bash
# Trace a request end-to-end
flyctl logs -a kite-mcp-server | jq 'select(.request_id=="<id>")'

# Trace everything for a single user
flyctl logs -a kite-mcp-server | jq 'select(.email=="<email>")'

# Trace a tool call
flyctl logs -a kite-mcp-server | jq 'select(.call_id=="<call-uuid>")'
```

The X-Request-ID is exposed in HTTP response headers, so when a user reports an issue:

1. Ask for the request ID from their failing response.
2. Run the `jq 'select(.request_id=="<id>")'` query.
3. All log lines for that request are grouped — handler, MCP tool, use case, broker adapter, audit.

For multi-tool flows (e.g., LLM agent loop): one request can spawn multiple tool calls. The `call_id` distinguishes individual tool invocations within the same `request_id`.

---

## 6. Continuous-monitoring controls

Per NIST CSF 2.0, continuous monitoring requires automated, not just on-demand, observation. Status:

| Control | Status | Implementation |
|---|---|---|
| **Synthetic probe** (DE.CM-1) | Manual / external | `curl -s /healthz?format=json` from operator's monitor; can be wired to UptimeRobot / Better Uptime. Deferred to external uptime monitor. |
| **Vulnerability scans** (DE.CM-8) | Continuous | Weekly cron in `.github/workflows/security-scan.yml` |
| **Anomaly detection** (DE.AE-2) | Continuous (in-process) | `kc/audit/anomaly.go` rolling μ+3σ baseline per user |
| **Personnel activity** (DE.CM-3) | Continuous (in-process) | Audit trail every tool call |
| **Configuration drift** (PR.IP-1) | On-demand | `server_version` MCP tool; `/healthz` `version` field |
| **Boundary monitoring** (DE.CM-1) | Per-IP rate limit | `app/ratelimit.go`; blocked requests visible in logs |
| **Authentication monitoring** (PR.AC-7) | In-process | OAuth token issuance / failure logged |

Gap: external synthetic probe wiring is deferred. Acceptable today (single-region, single-machine, single-maintainer); will be required for SOC 2.

---

## 7. Detection-source mapping (DE.AE)

Cross-link from observable signal to threat model:

| Signal | Threat-model linkage | Detection control |
|---|---|---|
| 401 spike | Adversary A (unauthenticated outsider) — credential stuffing | Per-IP rate limit + 401 log |
| 429 spike one user | Adversary B (authenticated cross-tenant) or LLM loop | Per-user rate limit + audit |
| Audit-log injection attempt | Adversary D (content injector) | `sanitizeForLog` test ([`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.3) |
| Hash chain divergence | Adversary post-compromise | Chain verify on startup; external publication when active |
| `auto_freeze` event | Adversary B / F escalating | RiskGuard log; admin notification |
| Place_order anomaly (μ+3σ outlier) | Adversary B / F | Anomaly cache + RiskGuard anomaly check |
| Litestream replication lag | Vendor failure (R2) or Adversary G (host compromise) | Litestream healthz |
| Stripe webhook signature failure | Adversary attempting signature forgery | Stripe-Signature HMAC + webhook_events idempotency |
| Tool integrity mismatch | Adversary tampering with tool descriptions | `mcp/integrity.go` startup check |

---

## 8. Compliance-evidence outputs

For an external audit (SOC 2, ISO 27001, SEBI CSCRF), the monitoring-evidence package includes:

1. **Healthz JSON snapshots** — record at start of audit window, mid-window, end-of-window.
2. **Audit-trail export** — full `tool_calls` rows for the audit window via `audit-export.sh` or `/dashboard/activity?export=csv`.
3. **CI run history** — GitHub Actions runs covering the window (security.yml, security-scan.yml).
4. **Code Scanning alerts** — open findings + closed-with-fix during the window.
5. **DR drill results** — monthly `dr-drill.yml` runs.
6. **Incident-response evidence** — any incident timeline + post-mortem from the window (per [`incident-response-runbook.md`](incident-response-runbook.md) §8).

Pre-built evidence at `docs/evidence/` — refresh monthly per [`incident-response.md`](incident-response.md) §"Pre-built evidence package."

---

## 9. Out of scope

- **Application performance monitoring (APM).** No Datadog, New Relic, etc. Today's scale doesn't justify the cost.
- **Real user monitoring (RUM).** No browser-side tracking on `/dashboard`. Page views can be inferred from server logs.
- **Distributed tracing.** Single-process, no service mesh; X-Request-ID is sufficient for correlation.
- **Network packet capture.** Out of scope at host layer; Fly.io handles network observability at the edge.
- **Personnel UEBA (User Entity Behaviour Analytics).** No employees yet; admin actions logged via audit trail.

---

## 10. Cross-references

- [`monitoring.md`](monitoring.md) — operational monitoring reference (surfaces, common scenarios)
- [`security-scanning.md`](security-scanning.md) — gosec + govulncheck workflow
- [`audit-export.md`](audit-export.md) — audit trail export procedures
- [`incident-response-runbook.md`](incident-response-runbook.md) — alert escalation
- [`operator-playbook.md`](operator-playbook.md) — day-2 ops decision tree
- [`recovery-plan.md`](recovery-plan.md) — DR drills + RTO/RPO
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3.7 — `/healthz` component status
- [`threat-model-extended.md`](threat-model-extended.md) — adversary categories ground for §7
- [`config-management.md`](config-management.md) §7 — drift detection
- [`vendor-management.md`](vendor-management.md) — vendor health signals
