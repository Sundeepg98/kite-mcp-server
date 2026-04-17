# Commit History Highlights — Security & Compliance Diligence

Curated list of commits that demonstrate systematic attention to security, risk, and regulatory posture. For a full chronological record, run `git log --oneline` in the repo root.

Format: `SHA — title — why it matters`

Updated: 2026-04-17

---

## Risk controls (riskguard)

- `792c687` — `feat(riskguard): anomaly detection — rolling baseline + off-hours block` — Behavioural anomaly detection that catches orders outside a user's normal trading pattern and outside market hours. Defense-in-depth beyond static limits.
- `2780329` — `feat(riskguard): idempotency keys on place_order/modify_order (client_order_id dedup)` — Prevents duplicate orders from retry storms or adversarial repetition.
- `7cd7b35` — `riskguard: tighten default caps + default-on order confirmation (mitigate prompt-injection risk)` — Specifically sized for the AI-assistant threat model: tighter caps + mandatory confirmation dialog by default.
- `041533a` / `5137db2` — `feat(riskguard): phase 3 circuit breaker` / `phase 2 rate limit, duplicate detection, daily value limit` — Layered risk logic: per-order, per-window, per-day caps, auto-freeze on repeated violations.

## Audit trail

- `3591cc6` — `feat(audit): hash-chain external publisher + SEBI cybersecurity posture doc` — Append-only tamper-evident log. Directly supports SEBI cybersecurity framework expectations.
- `4a37f10` — `fix(cqrs,audit): replace panic with error return + throttle audit drop logs` — Resilience improvement: audit subsystem never takes down the server, degrades gracefully.
- `90d8a95` — `test: audit 96% — middleware, chain verification, summarize, closed-DB paths` — Coverage focus on the audit layer specifically.

## Crypto / at-rest protection

- `1b97d20` — `test: main.go + cmd/rotate-key — binary integration + encryption rotation tests` — Key rotation tooling exists and is tested, supporting a secret-rotation incident-response path.
- `acd7714` — `test: alerts 96%, users 96%, papertrading 94% — crypto edge cases, concurrent race, monitor fill` — Explicit crypto edge-case + concurrency coverage.

## OAuth / authentication

- `0b1724d` — `fix(security): per-user rate limiting + audit log escape + JS line-separator XSS` — Three distinct classes of attack surface closed in one pass.
- `0038a23` — `feat(oauth): short-circuit /authorize when dashboard session is live` — Eliminates the double-login friction + closes a re-consent drift vector.

## Injection / anti-prompt-injection

- `5a82032` — `feat(security): tool-description integrity manifest (detect line-jumping attacks)` — Novel mitigation for AI-specific attacks: a content-addressable manifest verifies tool descriptions haven't been injected with malicious instructions.
- `035e2b8` — `feat: CSS injection, sample plugin, retry in broker, LTP cache, rate limiter, downgrade validation` — Broad hardening sweep.

## Compliance posture

- `04f4b18` — `feat: ENABLE_TRADING env gate for order-placement tools (Path 2 compliance)` — Default-off for order placement; self-hosters explicitly opt in. Mitigates "shipped a broker to the world" framing.
- `18aa136` — `legal: mark TERMS/PRIVACY as draft under review (mitigate DPDP exposure)` — Honest documentation about legal review status; reduces DPDP misrepresentation risk.
- `78301d6` — `refactor(tools): rename advisory-sounding tools + append legal disclaimer` — Tool names scrubbed of advisory language; every output appends disclaimer. Reduces SEBI investment-adviser classification drift.
- `3879aba` — `telegram: prefix outbound with disclaimer + /disclaimer command (SEBI classification drift protection)` — Same principle applied to the Telegram notification channel.
- `9b787e0` — `legal: complete MIT attribution — Dockerfile LICENSE copy + NOTICE + landing footer` — Proper open-source license attribution end-to-end.
- `6f6b0af` — `feat: add sebi_compliance_status + sector_exposure analysis tools` — Users can self-serve SEBI-relevant checks.
- `ac104eb` — `docs: add Terms of Service and Privacy Policy` — Baseline legal docs in place (later marked DRAFT per `18aa136`).

## Observability / ops

- `676c71f` — `feat(app): X-Request-ID header propagation (correlation across HTTP/MCP/audit)` — End-to-end request correlation: an incident investigator can trace one request through every layer.
- `dc9cca3` — `chore(ci): SBOM generation on master push + release tags` — Software Bill of Materials auto-generated; supports supply-chain incident response.
- `6e40124` / `b67ca86` — `server_metrics tool — tool-level observability` — Per-tool latency, error rates, call counts.
- `bd3398e` — `feat(ops): add component-status JSON mode to /healthz` — Machine-readable health probe.

## Incident response

- `2c72647` — `docs: incident response runbook (crisis playbook made actionable)` — The runbook this evidence package supports. Addresses regulator / Zerodha / user-comms timelines.
- `31109e3` / `d9fc47c` — `security: dual-port admin separation` + `tool filter to hide admin tools from non-admin users` — Least-privilege + blast-radius limiting.

## Testing posture

- `e1de677` — `test: riskguard+watchlist+scheduler 100%, eventsourcing 99.2% (unreachable documented)` — Near-full coverage on the safety-critical paths.
- `9bbe69c` — `test: domain 100%, eventsourcing 99.2%, riskguard 99.4% — near-perfect coverage` — Consistent coverage investment over time.
- `07eea7e` — `test: injection point tests — mock Kite HTTP, BotAPI, shutdown, token refresh` — Specifically targeted at adversarial injection paths.

## Transparency / trust signals

- `501c141` — `docs: rewrite README with trust signals + compliance framing` — Public-facing README frames the project around trust + compliance, not just features.
- `cd3f7de` — `feat(landing): redesign for algorithmic-developer persona` — Positioning the tool for informed developers, not retail investors.
- `7402241` — `docs: add funding.json + FLOSS/fund proposal (Zerodha open source grant application)` — Open invitation for Zerodha to fund/scrutinise the project directly.

---

## How to refresh this list

Quarterly, run:

```bash
git log --oneline --since="3 months ago" | grep -iE 'security|audit|compliance|riskguard|sebi|legal|privacy|terms|crypto|encrypt|injection|oauth|sbom|cve'
```

Filter the output for genuinely substantive commits (skip pure chore / lint / rename changes unless they are security-relevant). Add a bullet above with SHA + title + 1-line justification.
