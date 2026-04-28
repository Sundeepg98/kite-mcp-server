# Vendor / Third-Party Risk Management — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: GV.SC (Cybersecurity supply chain), ID.AM-4 (External information systems), ID.SC-1 / ID.SC-2 (Cyber supply-chain risk identification + assessment).*
*Companion to: [`asset-inventory.md`](asset-inventory.md), [`sbom.md`](sbom.md), [`incident-response.md`](incident-response.md), [`config-management.md`](config-management.md), [`recovery-plan.md`](recovery-plan.md).*

This document is the third-party risk register. Every external service, API, or vendor that `kite-mcp-server` depends on at runtime or build-time is enumerated, risk-tiered, and assigned a review cycle. This satisfies NIST CSF 2.0 GV.SC and ID.SC, and provides the substrate for SOC 2 / ISO 27001 / SEBI CSCRF "third-party risk management" sections.

The `asset-inventory.md` lists *what* depends on each vendor; this lists *how* we manage that dependency.

---

## 1. Risk-tier definitions

We classify every vendor by **business criticality** — the impact if the vendor fails or is compromised.

| Tier | Definition | Vendors |
|---|---|---|
| **V1 — Critical** | Vendor failure makes the service unusable; their compromise compromises our users' funds or PII. | Zerodha (Kite Connect), Fly.io |
| **V2 — High** | Vendor failure degrades a major feature; their compromise affects user data but not funds. | Cloudflare R2 (backup), Stripe (billing), Telegram (notifications), GitHub (source + CI) |
| **V3 — Medium** | Vendor failure degrades a minor feature; data exposure is limited. | Google (OAuth SSO; optional), Anthropic / OpenAI / Microsoft (MCP clients) |
| **V4 — Low** | Vendor failure has minimal user-visible impact. | OSV.dev, vuln.go.dev, Dependabot infrastructure |

Tier influences review cadence (§5) and incident-response priority ([`incident-response-runbook.md`](incident-response-runbook.md) §3).

---

## 2. Vendor register

### 2.1 V1 — Critical

#### Zerodha (Kite Connect)

| Attribute | Value |
|---|---|
| **Service** | Kite Connect REST API + WebSocket Ticker |
| **Endpoint** | `api.kite.trade`, `ws.kite.trade` |
| **Auth** | Per-user OAuth access token; per-app API key + secret (`KITE_API_KEY`, `KITE_API_SECRET` — currently unset on Fly.io; pure per-user OAuth) |
| **Data flow** | Outbound (we authenticate users + send orders/queries); inbound (real-time ticker) |
| **Data sensitivity** | T1 (broker credentials, orders, positions, holdings) |
| **Failure mode** | Service unusable. Per-user 429s indicate user issue. Mass 429 indicates contract issue. |
| **Failover** | None today (single-broker dependency). Multi-broker abstraction exists per `broker.Client` interface but no second adapter (per `ARCHITECTURE.md` §3 / ADR 0001). |
| **Contract / SLA** | Kite Connect terms (`kite.trade/connect/terms`); §9a 10-day cure notice; pricing ₹500/month per app |
| **Compliance docs** | Zerodha is SEBI-registered Stock Broker; we do not assume regulatory pass-through. |
| **Contact (technical)** | `kiteconnect@zerodha.com` |
| **Contact (escalation)** | Forum: `kite.trade/forum`; Twitter: @Nithin0dha (CEO, public criticism context only) |
| **Review cycle** | Quarterly (V1) |

**Specific risks**:

- **R-Z1: Connect tier revocation.** Zerodha can revoke our developer app for any §9a violation. Mitigation: `ENABLE_TRADING=false` Path-2 compliance per [`fly.toml`](../fly.toml) annotation; no pooled API keys; per-user OAuth only.
- **R-Z2: Static-IP whitelist mandate.** SEBI April 2026 mandate ties our `209.71.68.157` (`bom`) egress IP to each user's Kite developer console allow-list. Multi-region failover blocked on this. See [`incident-response.md`](incident-response.md) §"Region failover (deferred)."
- **R-Z3: API rate limit / suspension.** Per [`incident-response.md`](incident-response.md) §Scenario 2.
- **R-Z4: SDK major-version drift.** `gokiteconnect/v4` could ship a v5; manual migration. Watcher: `.github/workflows/v4-watchdog.yml`.

#### Fly.io

| Attribute | Value |
|---|---|
| **Service** | Container hosting + edge TLS + persistent volumes |
| **App** | `kite-mcp-server` |
| **Region** | `bom` (Mumbai) |
| **Spec** | shared-cpu-1x, 512 MB RAM, 1 GB volume |
| **Auth** | Fly.io API token (per developer); 2FA on account |
| **Data sensitivity** | T1 (host runs encrypted credentials at rest in volume) |
| **Failure mode** | Service offline. Single region today (multi-region deferred per `fly.toml`). |
| **Failover** | None today. Litestream R2 replica supports recovery (RTO ~10 min). |
| **Contract / SLA** | Fly.io Hobby + Performance plan SLAs (`fly.io/docs/about/sla`) — bom 99.9% (~8.7h/yr unplanned). |
| **Compliance docs** | SOC 2 (Fly.io); we don't claim pass-through. |
| **Contact (technical)** | `flyctl support`, `community.fly.io` (paying tier) |
| **Review cycle** | Quarterly (V1) |

**Specific risks**:

- **R-F1: bom region outage.** Single-region deployment. Mitigation: Litestream R2 replica enables restore-elsewhere; multi-region failover deferred per [`incident-response.md`](incident-response.md).
- **R-F2: Volume corruption.** Litestream replica is the recovery path; RPO ~10s; tested monthly via `dr-drill.yml`.
- **R-F3: Fly.io API token theft.** All deploy operations auth through this; mitigation: token stored in operator's secret manager; 2FA on Fly.io account.
- **R-F4: Region scheduler drift.** Fly.io may relocate machines; egress IP could change. Mitigation: monitor `flyctl machines list`; user-facing notification if IP changes.

### 2.2 V2 — High

#### Cloudflare R2

| Attribute | Value |
|---|---|
| **Service** | S3-compatible object storage |
| **Bucket** | `kite-mcp-backup` (APAC region per [`MEMORY.md`](../MEMORY.md)) |
| **Endpoint** | `<account>.r2.cloudflarestorage.com` |
| **Auth** | R2 access key ID + secret access key (set via `LITESTREAM_*` secrets) |
| **Data flow** | Outbound (Litestream WAL ship); inbound (DR drill restore + manual restore) |
| **Data sensitivity** | T1 (mirrors source SQLite — encrypted at rest at app layer, plus R2 SSE) |
| **Failure mode** | Replication backlog; SQLite local continues. Restore path blocked. |
| **Contract / SLA** | Cloudflare R2 SLA (99.9%); zero egress fees |
| **Compliance docs** | SOC 2 (Cloudflare) |
| **Contact (technical)** | Cloudflare dashboard → Support |
| **Review cycle** | Annual (V2) |

**Specific risks**:

- **R-CR1: R2 outage.** Replication backlog; resumes on recovery. Watch `litestream` healthz component.
- **R-CR2: R2 credential leak.** Mitigation: AES-256-GCM at app layer means R2 bucket dump alone reveals no plaintext credentials. R2 SSE adds another layer.
- **R-CR3: Bucket deletion (operator error).** Litestream auto-recreates on next sync; lost WAL window = max 24h of data (Litestream WAL retention).

#### Stripe

| Attribute | Value |
|---|---|
| **Service** | Subscription billing + webhook delivery |
| **Endpoint** | `api.stripe.com`, webhook URL `<EXTERNAL_URL>/webhooks/stripe` |
| **Auth** | `STRIPE_SECRET_KEY` (outbound), `STRIPE_WEBHOOK_SECRET` (inbound HMAC verification) |
| **Data flow** | Outbound (subscription mgmt); inbound (webhook events) |
| **Data sensitivity** | T2 (customer ID is reversible to email at Stripe; we don't store card data) |
| **Failure mode** | Billing tier enforcement disabled. Tools continue to function. |
| **Contract / SLA** | Stripe service agreement (no formal SLA tier; standard ~99.99%) |
| **Compliance docs** | PCI DSS Level 1 (Stripe); we don't process card data ourselves (Checkout-hosted) |
| **Contact (technical)** | Stripe dashboard → Support |
| **Review cycle** | Annual (V2) |

**Specific risks**:

- **R-ST1: Webhook signature failure spike.** Indicates either webhook secret rotation drift or attempted forgery. Mitigation: alert thresholds in [`continuous-monitoring.md`](continuous-monitoring.md).
- **R-ST2: Stripe API key compromise.** Mitigation: `STRIPE_SECRET_KEY` rotation per [`config-management.md`](config-management.md) §3.3.
- **R-ST3: Tax / pricing changes.** Stripe pricing changes don't affect our infra; user-facing pricing is independent.

#### Telegram

| Attribute | Value |
|---|---|
| **Service** | Bot API |
| **Endpoint** | `api.telegram.org` |
| **Auth** | `TELEGRAM_BOT_TOKEN` |
| **Data flow** | Outbound (alerts, briefings); inbound (chat commands) |
| **Data sensitivity** | T2 (chat IDs linked to email; messages contain financial data) |
| **Failure mode** | Notifications silently disabled. Tools continue. |
| **Contract / SLA** | No commercial SLA (Telegram free tier) |
| **Compliance docs** | None claimed |
| **Contact (technical)** | BotFather (Telegram); no support tickets |
| **Review cycle** | Annual (V2) |

**Specific risks**:

- **R-TG1: Bot token leak.** Mitigation: rotation via BotFather `/revoke`; chat IDs stable across rotations.
- **R-TG2: Telegram outage.** Best-effort delivery; no retry buffer; missed briefings recovered next cycle.
- **R-TG3: Telegram regional ban (e.g. India).** Risk: low historically; mitigation: feature degrades gracefully.

#### GitHub

| Attribute | Value |
|---|---|
| **Service** | Source hosting, CI (Actions), Code Scanning, Dependabot, Advisory database |
| **Repo** | `Sundeepg98/kite-mcp-server` (fork) |
| **Auth** | OAuth (web), SSH keys (CLI), GitHub Actions tokens (CI) |
| **Data flow** | Outbound (push); inbound (pull, PRs, advisories) |
| **Data sensitivity** | T4 (code is OSS) + T2 (CI secrets in workflow env) |
| **Failure mode** | Deploy blocked (CI not running). Source still local. |
| **Contract / SLA** | GitHub Free tier (no SLA); Pro/Enterprise has 99.95% |
| **Compliance docs** | SOC 2 (GitHub); used as evidence of supply-chain controls |
| **Contact (technical)** | `support.github.com` |
| **Review cycle** | Annual (V2) |

**Specific risks**:

- **R-GH1: Repo compromise / takeover.** Mitigation: 2FA + SSH keys; branch protection on `master`; GPG signing planned.
- **R-GH2: GitHub Actions secret leak.** Mitigation: secrets are masked in logs; secret scope limited per workflow.
- **R-GH3: Dependabot / Advisory missing.** Mitigation: govulncheck independently scans against `vuln.go.dev`.
- **R-GH4: GitHub-side outage.** Mitigation: deploy from local clone if needed; CI gate skipped only with explicit override.

### 2.3 V3 — Medium

#### Google (OAuth SSO; optional)

| Attribute | Value |
|---|---|
| **Service** | Google OAuth 2.0 (admin dashboard SSO) |
| **Endpoint** | `accounts.google.com`, `oauth2.googleapis.com` |
| **Auth** | `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` (currently unset on production — Google SSO not active) |
| **Data flow** | Outbound (OAuth flow) |
| **Data sensitivity** | T2 (admin email) |
| **Failure mode** | Google SSO unavailable; admin password fallback works. |
| **Contract / SLA** | Google Workspace SLA tiers; Free is no-SLA |
| **Review cycle** | Annual (when active) |

#### MCP Clients (Anthropic, OpenAI, Microsoft, etc.)

| Attribute | Value |
|---|---|
| **Service** | MCP client implementations connecting to our server |
| **Direction** | Inbound (clients connect to us) |
| **Auth** | Each client authenticates per OAuth flow; we don't authenticate ourselves to them |
| **Data flow** | Inbound tool calls; outbound tool responses |
| **Failure mode** | Specific client unable to connect; other clients unaffected. |
| **Review cycle** | Per-client breaking changes only |

The MCP protocol is standardised; client behaviour shouldn't differ materially. Specific quirks tracked per-client:

| Client | Known quirks |
|---|---|
| Claude Desktop | Required for production launch; uses mcp-remote bridge |
| claude.ai | Apps SDK widget rendering; `ui://` resource fetching |
| ChatGPT | Apps SDK; `openai/outputTemplate` shim required (per [`MEMORY.md`](../MEMORY.md)) |
| Cowork | Multi-tenant; shares OAuth client_info per server URL |
| VS Code 1.95+ | Native MCP; widget host detection via `ui://` capability |
| Microsoft Copilot | (planned; tracked) |

### 2.4 V4 — Low

These are public, free, well-known infrastructure providers. Failure has minimal direct impact.

| Vendor | Service | Failure mode |
|---|---|---|
| OSV.dev | Vulnerability database | govulncheck offline mode falls back to last-known DB |
| `vuln.go.dev` | Go vuln DB | Same as above |
| Dependabot infra | Auto-PR for vuln deps | Manual `go get -u` works equally well |

---

## 3. Risk-tier review cycle

| Tier | Cadence | Review activity |
|---|---|---|
| V1 | Quarterly | Walk every "Specific risks" entry; update mitigation status; confirm contact list current |
| V2 | Annual | Walk vendor entry; update deployment-relevant config (secrets, auth, SLAs); validate failover procedure |
| V3 | Per-major-change | Review when client/integration breaks something; otherwise dormant |
| V4 | Ad-hoc | Update when vendor changes (e.g., OSV.dev rebrand) |

Review output: append timestamp + reviewer initials to this file's changelog (§7).

---

## 4. Vendor onboarding

A new vendor / integration MUST go through this gate before going live:

1. **Risk classification.** Where in V1-V4 does the vendor sit? Document in §2.
2. **Data flow analysis.** What data leaves us / arrives from them? Map to T1-T4 per [`data-classification.md`](data-classification.md).
3. **Auth design.** How do we authenticate to them and they to us? Document in §2 row.
4. **Failure mode.** What happens if they're down / compromised? Document mitigation.
5. **Contract review.** Read the SLA / TOS / DPA. Pull-quote the relevant clauses to a `docs/contracts/<vendor>.md` file (deferred — currently informal).
6. **Compliance docs.** Get their SOC 2 / ISO 27001 / DPA if they hold T1/T2 data.
7. **Test integration.** Stage / canary first; cap blast radius.
8. **Add monitoring.** Healthz component, error rate alert, dashboard widget.
9. **Update inventory.** This file + [`asset-inventory.md`](asset-inventory.md) + [`config-management.md`](config-management.md).
10. **ADR if architectural.** Per [`change-management.md`](change-management.md) §3.4.

---

## 5. Vendor offboarding

Stopping a vendor relationship requires:

1. **Identify all integrations.** Code search (`grep -ri <vendor>`), env var search ([`env-vars.md`](env-vars.md)), monitoring dashboards.
2. **Drain in-flight transactions.** E.g., for Stripe — wait for in-flight subscription cycles; honor existing entitlements.
3. **Rotate / revoke credentials.** Vendor-side: revoke API keys; our side: remove env vars.
4. **Migrate data.** If data is leaving the vendor (e.g., changing R2 → backblaze), test the migration path on a snapshot first.
5. **Update inventory.** Remove from this file and [`asset-inventory.md`](asset-inventory.md).
6. **Document the cutover** in CHANGELOG.md with a date.

---

## 6. Vendor incident response

When a vendor experiences an incident affecting us:

| Vendor | Detection signal | First action |
|---|---|---|
| Zerodha | Mass 429, suspension email | [`incident-response.md`](incident-response.md) §Scenario 2 |
| Fly.io | `flyctl status` red; `/healthz` unreachable | Watch `community.fly.io`; file ticket; consider rollback |
| Cloudflare R2 | `litestream` healthz `unknown`/`stale` | Check Cloudflare status page; pause Litestream worker if persistent |
| Stripe | Webhook signature failures spike | Check Stripe status; webhook URL config; signature key rotation |
| Telegram | Briefings missing | Check Telegram status; bot token rotation if compromise suspected |
| GitHub | CI workflows failing without code changes | Check GitHub status; re-run workflow; deploy from local clone if blocked |
| Google | OAuth SSO 5xx | Disable Google SSO; password fallback works |
| MCP clients | Specific client reports widgets blank | Verify host detection (`mcp/ext_apps.go`); check capability negotiation |

Cross-reference: [`incident-response-runbook.md`](incident-response-runbook.md) §3 escalation tree.

---

## 7. Compliance attestation evidence

For a SOC 2 / ISO 27001 / SEBI CSCRF audit, the auditor will ask for vendor risk-management evidence. Pre-built artefacts:

- This document (§2 vendor register).
- Per-vendor SOC 2 / DPA / contract docs (deferred — currently informal; consolidate at `docs/contracts/`).
- Monitoring evidence: dashboard screenshots showing per-vendor signals over the audit window.
- Incident-response evidence: any past incident traceable to a vendor failure (none material so far at HEAD `3501a11`).
- `asset-inventory.md` cross-reference for the vendors that surface in the SBOM (Stripe Go SDK, Telegram Go SDK, etc.).

---

## 8. Out of scope

- **Self-hosted operator vendor relationships.** A fork-and-host operator inherits our vendor list and adds their own (e.g., their own R2 / S3 provider). They run their own register.
- **User-side third-party services.** Each user has their own MCP client + their own Kite developer app. We document the boundary; they manage their side.
- **Anthropic / OpenAI / Microsoft as LLM vendors.** Their LLM behaviour drives prompt-injection threat (see [`threat-model-extended.md`](threat-model-extended.md) §1, Adversary F); operationally they're MCP clients (V3 row above).

---

## 9. Changelog

| Date | Reviewer | Notes |
|---|---|---|
| 2026-04-26 | Maintainer | Initial vendor register; V1-V4 tiering; per-vendor risks; review cycle established. |

---

## 10. Cross-references

- [`asset-inventory.md`](asset-inventory.md) — full asset inventory (services, deps, vendors)
- [`sbom.md`](sbom.md) — software-side SBOM (CycloneDX)
- [`config-management.md`](config-management.md) — secret rotation per vendor
- [`incident-response.md`](incident-response.md) — vendor-related scenarios
- [`incident-response-runbook.md`](incident-response-runbook.md) — escalation tree §3
- [`recovery-plan.md`](recovery-plan.md) — RTO/RPO per vendor failure
- [`continuous-monitoring.md`](continuous-monitoring.md) — vendor health signals
- [`threat-model-extended.md`](threat-model-extended.md) — Adversary E (compromised infra)
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.6 — Kite as pass-through dependency
- [`vulnerability-management.md`](vulnerability-management.md) — supply-chain controls (§7)
