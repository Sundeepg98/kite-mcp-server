# Asset Inventory — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: ID.AM-1 (Physical devices and systems), ID.AM-2 (Software platforms and applications), ID.AM-3 (Communication and data flows), ID.AM-4 (External information systems), ID.AM-5 (Resources prioritized).*
*Companion to: [`data-classification.md`](data-classification.md), [`config-management.md`](config-management.md), [`vendor-management.md`](vendor-management.md), [`sbom.md`](sbom.md), [`../ARCHITECTURE.md`](../ARCHITECTURE.md).*

This document is the **enumerable inventory** of every system, service, dependency, and third-party API that comprises `kite-mcp-server`. NIST CSF 2.0 ID.AM expects an organisation to have a current asset inventory; this is ours. SBOM-format dependency inventory is at [`sbom.md`](sbom.md); this layer adds runtime services, vendor APIs, and infrastructure assets.

---

## 1. Hosted production assets (Fly.io)

The single production deployment.

| Asset | Identifier | Region | Tier | Purpose |
|---|---|---|---|---|
| Fly.io application | `kite-mcp-server` | `bom` (Mumbai) | T1 | Production server |
| Fly.io machine | (one machine, ID via `flyctl machine list`) | `bom` | T1 | Container runtime |
| Fly.io persistent volume | `kite_data` | `bom` | T1 | SQLite + WAL on `/data` |
| Static egress IP | `209.71.68.157` | `bom` | T2 | Whitelisted on user Kite developer consoles |
| Public hostname | `kite-mcp-server.fly.dev` | Edge / global | T3 | TLS-terminated by Fly.io |
| Cloudflare R2 bucket | `kite-mcp-backup` (APAC) | APAC | T1 | Litestream WAL replica (per [`MEMORY.md`](../MEMORY.md)) |
| Domain (planned) | `algo2go.in` (placeholder; pending rename per [`MEMORY.md`](../MEMORY.md)) | — | T4 | Future canonical domain |

Tiers reference [`data-classification.md`](data-classification.md) §2: T1 = highest sensitivity (compromise enables impersonation); T4 = public, no controls required.

### 1.1 Fly.io machine specs

| Spec | Value | Source |
|---|---|---|
| Memory | 512 MB | `fly.toml` (default config) |
| CPU | shared 1 vCPU | Fly.io default for shared-cpu-1x |
| Volume | persistent, 1 GB | `[mounts]` in `fly.toml` |
| Auto-stop | disabled | `fly.toml` `auto_stop_machines = false` |
| Min running | 1 | `fly.toml` `min_machines_running = 1` |
| Image | Alpine 3.21 + Go 1.25 binary | `Dockerfile` |

### 1.2 Container processes

Per `Dockerfile`:

| Process | Binary | Purpose |
|---|---|---|
| `kite-mcp-server` | Go binary, built from repo HEAD | Main server |
| `litestream` | sidecar binary | Continuous WAL → R2 replication |

Both run inside the same container; Litestream is supervised by the entrypoint script.

---

## 2. Source-tree assets (committed to repo)

### 2.1 Top-level Go packages

Per [`../ARCHITECTURE.md`](../ARCHITECTURE.md) §2:

| Package | Responsibility | Tier |
|---|---|---|
| `app/` | Composition root: config, wiring, HTTP server, middleware | T2 (config + wiring) |
| `app/providers/` | Fx provider files for graph-resolved wiring | T2 |
| `broker/` | Port: `Client` interface + types; broker-agnostic DTOs | T2 |
| `broker/zerodha/` | Zerodha adapter wrapping `gokiteconnect/v4` | T2 |
| `broker/mock/` | In-memory mock broker (DEV_MODE + tests) | T3 |
| `kc/` | Application core: Manager, services, use cases, domain, stores | T2 |
| `kc/audit/` | Tool-call audit log + middleware + HMAC hash chain | T2 |
| `kc/alerts/` | Alert store + crypto primitives + briefing service | T1 |
| `kc/billing/` | Stripe subscription store + middleware | T2 |
| `kc/cqrs/` | Command/Query types, in-memory bus | T2 |
| `kc/credstore/` (alias of `kc/credential_store.go`) | Encrypted Kite credentials | T1 |
| `kc/decorators/` | Typed-generic decorator factory (per ADR 0006 successor) | T3 |
| `kc/domain/` | Value Objects, Spec[T], domain events | T2 |
| `kc/eventsourcing/` | Append-only `domain_events` table | T2 |
| `kc/instruments/` | Instrument master download + in-memory index | T3 |
| `kc/ops/` | Dashboard/admin HTTP handlers, SSR renderers | T2 |
| `kc/papertrading/` | Virtual portfolio + middleware | T2 |
| `kc/registry/` | OAuth client registrations | T1 |
| `kc/riskguard/` | 8-check financial safety engine + middleware | T2 |
| `kc/scheduler/` | Cron tasks (briefings, P&L, audit cleanup) | T3 |
| `kc/templates/` | HTML templates for dashboard + landing pages | T4 (public-facing) |
| `kc/telegram/` | Bot handler + trading commands | T2 |
| `kc/ticker/` | WebSocket ticker (per-user) | T2 |
| `kc/usecases/` | 28 use-case files for write/read flows | T2 |
| `kc/users/` | User store + family/invitation store | T1 |
| `kc/watchlist/` | Per-user watchlists | T2 |
| `mcp/` | MCP adapter: tool registry, handlers, middleware, prompts, widgets | T2 |
| `oauth/` | OAuth2 server for mcp-remote (DCR + JWT) | T1 |
| `cmd/` | Helper binaries (rotate-key) | T2 |
| `testutil/` | Shared test infrastructure (`MockKiteServer`, kcfixture) | T3 |
| `etc/` | Sidecar config (`litestream.yml`) | T2 |
| `scripts/` | Build, deploy, DR drill scripts | T3 |
| `plugins/` | Optional external plugin directory | T3 |

Total non-test packages: ~30. Total test files: ~330 tests (per [`MEMORY.md`](../MEMORY.md)).

### 2.2 Configuration assets

| Asset | Location | Purpose |
|---|---|---|
| `fly.toml` | repo root | Fly.io app config |
| `Dockerfile` | repo root | Container image (production) |
| `Dockerfile.selfhost` | repo root | Self-hosted operator image |
| `.env.example` | repo root | Local dev env-var template |
| `etc/litestream.yml` | `etc/` | Litestream sidecar config |
| `go.mod`, `go.sum` | repo root | Go dependency manifest |
| `.github/workflows/*.yml` | `.github/workflows/` | CI workflows (12 files) |
| `.github/dependabot.yml` (if present) | `.github/` | Dependabot config |

### 2.3 CI workflows

Per `.github/workflows/`:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push, PR | Build + test on Linux |
| `security.yml` | Push, PR | gosec + govulncheck (lightweight) |
| `security-scan.yml` | Push, weekly cron, dispatch | gosec SARIF + govulncheck (full) |
| `test-race.yml` | Push, PR | Race detector across packages |
| `sbom.yml` | Push, tag | CycloneDX SBOM publishing |
| `playwright.yml` | Push, PR | UI smoke tests |
| `mutation.yml` | Schedule | Mutation testing on critical packages |
| `benchmark.yml` | Schedule | Performance benchmarks |
| `dr-drill.yml` | Monthly cron, dispatch | R2 restore validation |
| `v4-watchdog.yml` | Schedule | Kite SDK major-version drift watcher |
| `release.yml` | Tag push | Release artefact publishing |
| `docker.yml` | Push | Docker image build |

---

## 3. Software dependencies

Authoritative inventory in CycloneDX SBOM (`sbom.cdx.json`); see [`sbom.md`](sbom.md). Critical direct dependencies from `go.mod`:

| Module | Version | Tier | Purpose |
|---|---|---|---|
| `github.com/zerodha/gokiteconnect/v4` | v4.4.0 | T1 (broker SDK) | Kite Connect API client |
| `github.com/mark3labs/mcp-go` | v0.46.0 | T1 (transport) | MCP protocol library |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | T1 (auth) | JWT signing/verification |
| `golang.org/x/crypto` | v0.48.0 | T1 (crypto) | AES-GCM, HKDF, bcrypt |
| `golang.org/x/oauth2` | v0.36.0 | T1 (auth) | Google SSO |
| `modernc.org/sqlite` | v1.46.1 | T1 (storage) | Pure-Go SQLite (no CGo) |
| `github.com/stripe/stripe-go/v82` | v82.5.1 | T1 (billing) | Stripe payment SDK |
| `github.com/go-telegram-bot-api/telegram-bot-api/v5` | v5.5.1 | T2 (notifications) | Telegram bot |
| `go.uber.org/fx` | v1.24.0 | T2 (DI) | Composition-root wiring (per ADR 0006) |
| `github.com/google/uuid` | v1.6.0 | T3 | UUIDv7 for X-Request-ID |
| `github.com/yuin/goldmark` | v1.8.2 | T3 | Markdown rendering for legal pages |
| `github.com/fsnotify/fsnotify` | v1.9.0 | T3 | File watcher (plugin reload) |
| `github.com/hashicorp/go-plugin` | v1.7.0 | T2 | Plugin RPC (per ADR 0007) |
| `github.com/hashicorp/go-hclog` | v1.6.3 | T3 | Plugin logging |
| `golang.org/x/time` | v0.15.0 | T3 | Rate-limit token bucket |
| `pgregory.net/rapid` | v1.2.0 | T4 (test only) | Property-based testing |
| `github.com/stretchr/testify` | v1.10.0 | T4 (test only) | Test assertions |
| `go.uber.org/goleak` | v1.3.0 | T4 (test only) | Goroutine leak detection |

Indirect deps: 23 (per `go.mod`); see SBOM for full list.

Hot-path dependencies (extra scrutiny per [`vulnerability-management.md`](vulnerability-management.md) §4.2): all T1-marked rows above.

---

## 4. Third-party APIs (external information systems)

These external systems are accessed at runtime. For each: vendor, scope, auth, fallback. See [`vendor-management.md`](vendor-management.md) for risk tiering.

| Vendor | API | Scope | Auth | Fallback if down |
|---|---|---|---|---|
| Zerodha | Kite Connect REST API (`api.kite.trade`) | Order placement, market data, holdings, MF, GTT | Per-user OAuth access token | Hard dependency — service unusable without it |
| Zerodha | Kite WebSocket Ticker (`ws.kite.trade`) | Live tick stream | Per-user access token | Tools fall back to REST quote endpoints |
| Stripe | Stripe API (`api.stripe.com`) | Subscription management | `STRIPE_SECRET_KEY` | Billing tier enforcement disabled (DEV_MODE-style) |
| Stripe | Stripe webhooks | Subscription event delivery | `Stripe-Signature` HMAC verification | Idempotent retry via `webhook_events` table |
| Telegram | Bot API (`api.telegram.org`) | Alert notifications, briefings, inline trading | `TELEGRAM_BOT_TOKEN` | Feature silently disabled; no impact on tools |
| Cloudflare | R2 (S3-compatible) (`<account>.r2.cloudflarestorage.com`) | Litestream replica + audit hash chain anchor | R2 access keys | Local SQLite continues; replication backlog accumulates |
| Google | OAuth (`accounts.google.com`) | Dashboard SSO (optional) | `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` | Email/password fallback for admins |
| GitHub | API (`api.github.com`) | Dependabot, Actions, Code Scanning | GitHub-managed | None — affects CI only, not runtime |
| OSV.dev | Vulnerability database | Used by govulncheck during CI | None (public) | govulncheck local mode falls back to last-known DB |
| Go vuln database (`vuln.go.dev`) | Vulnerability database | govulncheck source | None (public) | Same as OSV.dev fallback |

### 4.1 MCP client connections

Various MCP clients connect to our server. Each is a different consumer surface, not an outgoing dependency:

| Client | Transport | Tier | Notes |
|---|---|---|---|
| Claude Desktop | HTTP via mcp-remote | T2 | OAuth bearer JWT |
| claude.ai | HTTP via mcp-remote | T2 | Same as Desktop |
| Cowork | HTTP via mcp-remote | T2 | Multi-tenant SaaS |
| Claude Code (CLI) | HTTP via mcp-remote | T2 | Per-developer instance |
| ChatGPT (with Apps SDK) | HTTP | T2 | Apps SDK widget rendering |
| VS Code (1.95+) | HTTP | T2 | Native MCP support |
| Microsoft Copilot | HTTP | T2 | (planned) |
| Custom mcp-remote consumer | HTTP | T2 | Self-hosted with `--static-oauth-client-info` |

The server treats every MCP client identically — auth is per-user OAuth, no client-specific paths.

---

## 5. Data assets

Authoritative inventory: [`data-classification.md`](data-classification.md). Summary by tier:

| Tier | Count | Storage | Retention |
|---|---|---|---|
| T1 (Highly Sensitive) | 4 classes | `kite_credentials`, `kite_tokens`, `oauth_clients`, `users.password_hash` | Trigger-based |
| T2 (Sensitive) | ~20 classes | `tool_calls`, `domain_events`, `mcp_sessions`, `alerts`, `consent_log`, billing, etc. | Mostly trigger; tool_calls 5 years; domain_events indefinite |
| T3 (Internal) | 6 classes | `app_registry`, `config`, in-RAM caches | Process lifetime to indefinite |
| T4 (Public) | 2 classes | embedded CSV/Go data, public docs | Compile-time / repo lifetime |

Total persisted SQLite tables (post-migration at HEAD `3501a11`): ~28. Authoritative table list: `kc/alerts/db.go` migration slice.

---

## 6. Operational tooling

Tools used by the operator (not runtime dependencies):

| Tool | Purpose | Source |
|---|---|---|
| `flyctl` | Fly.io CLI | `https://fly.io/docs/flyctl/` |
| `gh` | GitHub CLI | `https://cli.github.com/` |
| `git` | Version control | system |
| `litestream` | SQLite replication binary | sidecar in container; standalone for restore |
| `sqlite3` | DB inspection | system |
| `cyclonedx-gomod` | SBOM generation | `github.com/CycloneDX/cyclonedx-gomod` |
| `govulncheck` | Go vuln scanner | `golang.org/x/vuln/cmd/govulncheck` |
| `gosec` | Go static analyzer | `github.com/securego/gosec/v2/cmd/gosec` |
| `go vet` | Built-in static check | Go toolchain |
| `playwright` | UI smoke tests | `npm i -D playwright` |
| `wsl2` | Linux test harness on Windows | per [`wsl2-setup-runbook.md`](wsl2-setup-runbook.md) |

---

## 7. Documentation assets

`docs/` is git-ignored at the directory level (see `.gitignore`); individual docs require `git add -f`. Despite this, `docs/` is the canonical living-doc location.

Key documentation files (organised by NIST CSF 2.0 function):

| Function | Documents |
|---|---|
| **Govern** (GV) | `SECURITY.md`, `data-classification.md`, `RETENTION.md`, `access-control.md` |
| **Identify** (ID) | This doc (asset-inventory.md), `risk-register.md`, `threat-model.md`, `threat-model-extended.md`, `nist-csf-mapping.md`, `data-classification.md` |
| **Protect** (PR) | `SECURITY_POSTURE.md`, `vulnerability-management.md`, `change-management.md`, `config-management.md`, `access-control.md` |
| **Detect** (DE) | `monitoring.md`, `continuous-monitoring.md`, `security-scanning.md`, `audit-export.md` |
| **Respond** (RS) | `incident-response.md`, `incident-response-runbook.md`, `operator-playbook.md` |
| **Recover** (RC) | `recovery-plan.md`, `pre-deploy-checklist.md`, `push-deploy-playbook.md` |

---

## 8. Resource prioritisation (ID.AM-5)

Asset criticality ranking. Used in incident response to decide what to protect first.

### Tier 1 — Cannot lose

1. **Encrypted credential store** (`kite_credentials`) — losing this kicks every user off Kite; rebuilding requires every user to re-register their developer app.
2. **`OAUTH_JWT_SECRET`** — losing this means re-encrypting all T1 records via [`config-management.md`](config-management.md) §3.1; partial rotation still in scope of deferred work.
3. **Fly.io app authentication** — losing this means losing deploy access; recovery requires Fly.io support escalation.
4. **GitHub access** — losing this means losing the source code; mitigation: regular local clones + `git remote -v` shows fork at `Sundeepg98/kite-mcp-server`.
5. **Audit hash chain** — losing this breaks regulatory audit-trail evidence; Litestream replication preserves it within RPO.

### Tier 2 — Recoverable but expensive

1. **Cloudflare R2 bucket** — losing this loses Litestream replica; SQLite still local; new R2 bucket can be provisioned in <30 min.
2. **Stripe configuration** — losing this means re-creating webhooks; user subscriptions preserved on Stripe side.
3. **Telegram bot token** — losing this means re-pairing every Telegram user; `telegram_chat_ids` table preserved.

### Tier 3 — Replaceable

1. **Domain `kite-mcp-server.fly.dev`** — built into the Fly.io app slug; replacing requires a new app deployment.
2. **Static egress IP** — Fly.io-provisioned; changing requires every user to re-whitelist.

---

## 9. Inventory cadence

| Trigger | Action |
|---|---|
| New service / dep / vendor added | Add row in §1, §3, or §4. |
| Vendor outage / replacement | Update §4 + [`vendor-management.md`](vendor-management.md). |
| Schema migration | Update §5 + [`data-classification.md`](data-classification.md) + [`RETENTION.md`](RETENTION.md). |
| New CI workflow | Update §2.3. |
| Quarterly | Walk every row; remove deprecated; add missed. |
| Pre-audit (SOC 2 / SEBI / ISO) | Full §1-§7 walk; cross-reference against deployed artefacts. |

Last full walk: 2026-04-26 (this revision). Next due: 2026-07-26.

---

## 10. Cross-references

- [`data-classification.md`](data-classification.md) — per-data-class tiers + DPDP/SEBI hooks
- [`RETENTION.md`](RETENTION.md) — per-class retention triggers
- [`config-management.md`](config-management.md) — env-var + secret policy
- [`vendor-management.md`](vendor-management.md) — third-party risk register
- [`sbom.md`](sbom.md) — CycloneDX dependency SBOM
- [`security-scanning.md`](security-scanning.md) — gosec + govulncheck
- [`vulnerability-management.md`](vulnerability-management.md) — CVE response policy
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — directory layout + architecture
- [`access-control.md`](access-control.md) — RBAC over the asset inventory
- [`recovery-plan.md`](recovery-plan.md) — recovery RTO/RPO per asset tier
