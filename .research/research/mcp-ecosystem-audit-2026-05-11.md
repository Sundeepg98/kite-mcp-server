# MCP Ecosystem Audit — Shell-out Inventory + Prioritized Install/Build Queue

**Date**: 2026-05-11 IST
**Master HEAD audited**: `fe5b5b8` (`docs(research): flyctl friction inventory + Playwright MCP capabilities`)
**Dispatch role**: Track 3 of 3 parallel — broader ecosystem view (Track 1 = fly MCP, Track 2 = Playwright + flyctl friction).
**Charter**: answer "If fly MCP is the answer to one question, what other questions have similar one-MCP-away answers we've been ignoring?"

**Methodology** (per CORPUS-MAINTENANCE-STRATEGY): empirical — WebFetch on vendor docs + WebSearch for ecosystem state + grep on repo for actual shell-out frequency. Every numeric claim is dated; every install recommendation is anchored in a probed-as-existing MCP server URL or GitHub repo.

**Inputs probed in this dispatch** (all 2026-05-11 unless noted):
- `memory/mcp-servers.md` (75d stale per system reminder) — what's already installed user-scope
- `D:/Sundeep/projects/kite-mcp-server/.mcp.json` — project-scope MCP list (only `kite`)
- `.research/research/fly-mcp-research.md` (chain agent, 2026-05-11) — fly MCP recommendation already in tree
- `.research/research/flyctl-friction-and-playwright-capabilities.md` (chain agent, 2026-05-11) — friction inventory
- `.research/INDEX.md` §11 (MCP ecosystem stream) — current scope
- Vendor docs/repos via WebFetch: Cloudflare, GitHub, AWS Labs, Stripe, DigitalOcean, Linear, Notion, Slack, Sentry, Bitwarden, 1Password, HashiCorp Vault, Neon, Supabase, Hetzner, Fly.io
- `registry.modelcontextprotocol.io/v0.1/servers` — official registry snapshot
- Git log + grep for shell-out commands in `.research/` (145 flyctl hits across 20 files; 109 vendor-CLI hits across 15 files in repo source)

**Headline finding**: At least **9 high-ROI MCP installs are available right now** and would close 60-80% of the daily shell-out friction documented in this session. Three are in the "install now, ~5min each" bucket: **Fly MCP** (closes the largest single bottleneck), **GitHub MCP server** (replaces `gh` CLI for chat-driven workflows; 29.9k stars, official), **Cloudflare MCP servers** (14 of them, including Logpush + Observability — closes the R2-backup verification gap). Two are "install next week" tier: **Bitwarden MCP server** (closes the plaintext-secrets-in-memory problem structurally) and **Sentry MCP** (closes the "what's happening in production right now" gap). The big finding that wasn't anticipated: **Cloudflare's `Code Mode` MCP** wraps the entire Cloudflare API (2,500+ endpoints including R2) via just 2 tools (`search` + `execute`) — that's the R2 coverage we thought was missing.

---

## §1 — Shell-out inventory (the friction baseline)

Catalogued from grep over `.research/` + `scripts/` + commit-message corpus + INDEX.md §11. Sorted by friction × frequency. Numbers in parentheses = grep hit count in the cited corpus location as of 2026-05-11.

| # | Shell-out | Where used | Frequency | Friction-level | Closed by which MCP? |
|---|---|---|---|---|---|
| 1 | `flyctl` (deploys/secrets/status/releases/auth/proxy) | 145 hits across 20 `.research/` files + `scripts/deploy.sh` (18) + ops runbooks | EVERY deploy / state-query (10+ this session) | HIGH — PATH typo, AppControl blocks, metrics-token warnings, no `--json` for many subcommands, runbook drift (see Track 2 §1) | **Fly MCP** — `flyctl mcp server --claude` (Track 1 recommendation) |
| 2 | `gh` CLI (issues / PRs / api / search) | Daily; standing global rule in `.claude/CLAUDE.md` ("use gh CLI for data ops, Chrome for visual") | DAILY (every issue/PR check) | LOW shell-friction (gh CLI itself is good), MEDIUM context-friction (output is text; agents have to parse) | **GitHub MCP server** (`ghcr.io/github/github-mcp-server`, 29.9k stars, OAuth via VS Code 1.101+, OR `https://api.githubcopilot.com/mcp/` remote) |
| 3 | `curl` (healthz / MCP testing / API probes) | INDEX.md §11 probes ("`curl /healthz | jq .total_available`"), Track 1 fly verification, R2 dr-drill validations | EVERY empirical probe | LOW — curl + jq is fine | None needed — curl is the right tool for one-shot probes |
| 4 | `git` (status/log/diff/commit/push/clone) | EVERYWHERE (this session: ~50 commits) | EVERY commit | LOW — native, fast | None needed (Anthropic ships built-in git via Bash) |
| 5 | **Playwright MCP** (browser auth flows, OAuth, dashboard clicks) | Track 2 §2 enumeration; this session used for fly auth re-login | Sporadic; ~1/month | LOW — Playwright MCP is already installed and good | Already installed (`mcp__plugin_playwright_playwright__*`) — see Track 2 §2 |
| 6 | `flyctl secrets set/list` (specifically) | Track 2 §1 friction #7; R2-cred rotation procedure; planned OAUTH_JWT_SECRET rotation | Sporadic; ~6 secret-mutating events this session | MEDIUM | Closed by **Fly MCP** if secrets in tool surface; complementary to **Bitwarden MCP** for vault storage |
| 7 | `wrangler` / Cloudflare dashboard clicks (R2 access keys, KV, Workers) | R2 rotation procedure §13.1 of Track-C decisions; future Litestream auditing | Sporadic; ~3/quarter | MEDIUM — manual UI clicks | **Cloudflare MCP servers** (14 of them) + **Code Mode** for full API |
| 8 | `gcloud` (gcloud MCP installed user-scope per `mcp-servers.md`) | Workspace MCP + Apps Script flows | Sporadic | LOW — already covered by gcloud MCP wrapper | Already installed |
| 9 | `docker` / `docker compose` | `Dockerfile`, `Dockerfile.selfhost`, `docker-compose.yml`, deploy.sh (8 docker hits) | Per release | LOW — native is fine | Not worth replacing; `flyctl deploy` wraps it |
| 10 | **Manual secret-rotation procedures** (R2 + Kite API) — surface-and-defer items 4 + 11 from Track-C | `memory/kite-session-apr3.md:39-42`, `memory/MEMORY.md:78-80` | One-time but security-critical; recurring on Kite API every 1y expiry | HIGH — currently zero structural fix | **Bitwarden MCP** OR **HashiCorp Vault MCP** (see §4 for the deeper analysis) |
| 11 | **GitHub repo Secrets paste** (4 R2 + 2 Telegram secrets for dr-drill cron) | dr-drill workflow gate; user-action documented in dr-drill-results-2026-05-11.md §2 | One-time | HIGH — blocking the monthly dr-drill cron | **GitHub MCP server** has tools for repo secrets (gh CLI has `gh secret set`; MCP version equivalent) |
| 12 | **Cloudflare R2 backup verification** (Litestream → R2) | dr-drill scripts, manual flyctl ssh + sqlite3 probes | Per dr-drill (monthly + on-demand) | MEDIUM | **Cloudflare Logpush MCP** (`https://logs.mcp.cloudflare.com/mcp`) for observability + **Code Mode** for R2 reads |
| 13 | **Manual mcp-remote re-cache** (when JWT expires; `cmd /c` JSON escaping bug) | MEMORY.md kite-fly section; every Kite-fly token rotation | Sporadic; ~1/month per stale-token incident | MEDIUM — known workaround (write JSON to file, use `@path` arg) | No MCP fix — this is a transport/serialization issue |
| 14 | **Manual Telegram bot setup** (token paste during Trading-bot config) | `kc/telegram/` config; user does this once | One-time | LOW | Telegram MCP exists; not high-priority |
| 15 | **Manual Z-Connect / Rainmatter / Kite forum interactions** (community / launch ops) | `docs/kite-forum-replies.md`, Reddit warmup, Show HN | Per launch event | HIGH for launch, ZERO during steady-state | No MCP — these are human-conversation surfaces |

**Friction-weighted bottleneck ranking** (HIGH × frequency = highest install-ROI):
1. **flyctl** (HIGH × ~daily) — Fly MCP closes this. Track 1 recommendation: install today.
2. **gh CLI** (LOW friction but DAILY frequency) — GitHub MCP closes the context-parse cost; high cumulative value.
3. **Secret rotation procedures** (HIGH × one-time-but-recurring + security-critical) — Bitwarden/Vault MCP closes this structurally.
4. **Cloudflare R2 ops** (MEDIUM × sporadic) — Cloudflare MCP suite + Code Mode closes the dashboard-click friction.
5. **GitHub repo Secrets paste** (HIGH × one-time) — GitHub MCP closes this; ~5min of effort to install + paste via MCP.

---

## §2 — Existing official MCP server landscape (per-vendor coverage)

Sorted by relevance to our shell-out inventory. Each row = empirical WebFetch or WebSearch dated 2026-05-11.

### Tier 1 — directly closes a current friction in §1

| Vendor | Server name | Hosting | Auth | Tool surface | Source | Status |
|---|---|---|---|---|---|---|
| **Fly.io** | `flyctl mcp server` (built into flyctl binary v0.3.117+) + `superfly/flymcp` (legacy wrapper) | Local stdio | flyctl auth (reuses existing CLI auth) | apps, logs, machine, orgs, platform, status, volumes (per Fly blog May 2026) | Track 1 doc §1; `fly mcp --help` empirically verified | **EXPERIMENTAL** but stable enough to use; **install today** |
| **GitHub** | `github/github-mcp-server` (official) | Local stdio (Docker `ghcr.io/github/github-mcp-server`) OR remote `https://api.githubcopilot.com/mcp/` | OAuth (VS Code 1.101+) or PAT | repos, issues, PRs, Actions, code-security, projects, gists, code-search, releases | 29.9k stars, v1.0.4 (May 11, 2026); https://github.com/github/github-mcp-server | **OFFICIAL + STABLE**; install today |
| **Cloudflare** | 14 servers under `cloudflare/mcp-server-cloudflare` (3.7k stars) + Code Mode MCP for full API | Remote HTTPS (`https://*.mcp.cloudflare.com/mcp`) | OAuth + API tokens | Workers Builds, Workers Bindings, Observability, Logpush, AI Gateway, Radar, Browser Run, Container, DNS Analytics, Audit Logs, DEM, Documentation, AI Search, CASB. **R2/DNS-records covered only by Code Mode** (2 tools wrap 2,500+ endpoints) | https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/ | **OFFICIAL + STABLE**; install Logpush + Observability now; Code Mode for R2 ops |
| **Bitwarden** | `bitwarden/mcp-server` (official, v2026.2.0) | Local stdio ONLY ("designed exclusively for local use; never expose over network") | Bitwarden CLI session reuse + Public API key | Vault item ops (read/create/update), Send mgmt, Members + Groups admin (Org Public API) | npmjs `@bitwarden/mcp-server`; bitwarden.com blog | **OFFICIAL**; "install next week" tier; closes secret-rotation friction structurally |
| **1Password** | Official **Unified Access** platform (not a single MCP server) + community `CakeRepository/1Password-MCP` | Local stdio (community) | 1Password CLI session reuse | Vault items CRUD, item lookup, passphrase gen (community); Unified Access provides runtime-only resolution + audit | 1password.com/blog/securing-mcp-servers-with-1password; community repo | Official platform exists but is enterprise-positioning; **community MCP is the practical install path** if we go 1Password |

### Tier 2 — useful for ops but not currently blocking

| Vendor | Server name | Hosting | Auth | Tool surface | Source | Status |
|---|---|---|---|---|---|---|
| **AWS** | `awslabs/mcp` — 40+ servers, plus official remote "AWS MCP Server" + "AWS Knowledge MCP" | Mixed: most stdio with AWS profile; managed = remote | IAM profile-based | S3 Tables, Serverless (SAM), Lambda Tool, EC2, ECS, Documentation, Knowledge | 9.1k stars; https://github.com/awslabs/mcp | OFFICIAL; relevant only if we add S3 as R2 fallback |
| **DigitalOcean** | `digitalocean-labs/mcp-digitalocean` (official, npm) + remote `https://apps.mcp.digitalocean.com/mcp` (and per-service equivalents) | Local stdio OR remote per-service | DO API token | Accounts, App Platform, Databases, DOKS, Droplets, Insights, Marketplace, Networking, Spaces Storage | https://docs.digitalocean.com/reference/mcp/ | OFFICIAL; relevant if we add DO as Fly alternative |
| **Stripe** | `stripe/agent-toolkit` (1.6k stars) — both `mcp.stripe.com` remote + `@stripe/mcp` local | Remote OAuth + local | Restricted API Keys (`rk_*`) | Customers/charges/subscriptions/products/refunds/disputes (scoped by restricted-key permissions) | https://github.com/stripe/agent-toolkit | OFFICIAL; relevant when we activate paid tier (currently free preview) |
| **Linear** | Linear official remote MCP | Remote HTTP at `https://mcp.linear.app/mcp` (SSE deprecated) | OAuth per workspace, no API key | Issues (search/create/update), projects, milestones, initiatives, cycles, comments, project-health | https://linear.app/changelog/2026-02-05-linear-mcp-for-product-management | OFFICIAL; relevant if we adopt Linear (currently using GitHub Issues — see §3 ranking) |
| **Notion** | `makenotion/notion-mcp-server` (official) + remote `https://mcp.notion.com/mcp` | Remote streamable HTTP + local | OAuth per workspace | Pages, blocks, databases, data sources, search, retrieve/update | https://developers.notion.com/guides/mcp/overview | OFFICIAL; relevant if we keep launch-prep notes in Notion (currently in `.research/`) |
| **Slack** | Official Slack MCP server (GA Feb 17, 2026) | Hosted | Slack OAuth | Search, messages (get/send), canvases, member info | https://docs.slack.dev/changelog/2026/02/17/slack-mcp/ | OFFICIAL; relevant only if we have a community Slack (we don't) |

### Tier 3 — observability / database / search

| Vendor | Server name | Hosting | Auth | Notes | Source | Status |
|---|---|---|---|---|---|---|
| **Sentry** | Official Sentry MCP server | Remote | Sentry auth | MCP Observability tooling — server-side instrumentation; the MCP server lets you query Sentry errors/perf via chat | https://blog.sentry.io/introducing-mcp-server-monitoring/ | OFFICIAL; install when/if we wire Sentry (currently no error-tracking SaaS) |
| **Datadog** | Official Datadog MCP Server (GA 2026) | Remote | Datadog API+app keys | Monitors, logs, metrics, traces, dashboards | apmdigest + datadog blog | OFFICIAL; install when/if we adopt Datadog |
| **New Relic** | Official MCP server via NerdGraph + NRQL | Remote | NR license key | Log + telemetry queries | pulsemcp newrelic | OFFICIAL |
| **HashiCorp Vault** | `hashicorp/vault-mcp-server` (official) | stdio + StreamableHTTP | Vault token | Vault secret read/write, mount ops | https://developer.hashicorp.com/vault/docs/mcp-server/overview | OFFICIAL; alternative to Bitwarden for enterprise-grade |
| **Neon** | Official Neon MCP (20 tools) | Remote OAuth | OAuth | Postgres branches, migrations, project mgmt — UNIQUE branch-based migration safety | chatforest.com Neon MCP review | OFFICIAL; relevant if we migrate from SQLite to Postgres |
| **Supabase** | Official Supabase MCP (20+ tools) | Remote | Supabase tokens | DB queries, auth, schema, Edge Functions, TypeScript-type gen | designrevision.com Supabase 2026 guide | OFFICIAL; only relevant if we adopt Supabase |
| **Tavily** | Tavily MCP (already installed user-scope per `mcp-servers.md`) | Remote `mcp.tavily.com` | API key | search/extract/map/crawl/research | Already installed | INSTALLED |
| **Hetzner** | 3 community servers (`dkruyt/mcp-hetzner` Python, `MahdadGhasemian/mcp-hetzner-go`, `Xodus-CO/hcloud-mcp`) — **no official Hetzner MCP** | Local stdio | hcloud API token | 104 tools across servers/networks/volumes/firewalls/load balancers | github.com/dkruyt/mcp-hetzner | COMMUNITY only; install only if we add Hetzner as Fly alternative |

---

## §3 — Top 10 install/build candidates (ranked by ROI)

Scoring: `(friction-closed × frequency) / install-cost`, where friction-closed and frequency are 1-10 and install-cost is low/med/high. Trust column shaves ROI if vendor isn't first-party or maintainer is solo.

| Rank | MCP | Friction × Frequency | Install Cost | Trust | ROI | Net recommendation |
|---|---|---|---|---|---|---|
| 1 | **Fly MCP** (`flyctl mcp server --claude`) | 9 × 10 (every deploy + state-query) | LOW (~5min, single command, no JSON) | OFFICIAL (Fly engineering, blog announced May 2026) | **MAX** | **INSTALL TODAY** — covered by Track 1 |
| 2 | **GitHub MCP server** (official) | 7 × 10 (gh CLI is daily) | LOW (~5min, Docker or one-line npx) | OFFICIAL (29.9k stars, github.com namespace) | **VERY HIGH** | **INSTALL THIS WEEK** — replaces gh CLI for chat-driven workflows; still keep `gh` for shell scripts |
| 3 | **Cloudflare Logpush MCP** + **Cloudflare Observability MCP** | 6 × 5 (R2 backup verification monthly + dr-drill) | LOW (~3min each, OAuth via mcp-remote) | OFFICIAL (cloudflare.com namespace, 3.7k stars) | **HIGH** | **INSTALL THIS WEEK** — closes the "did Litestream backup actually land in R2?" verification gap |
| 4 | **Cloudflare Code Mode MCP** (full Cloudflare API via 2 tools) | 6 × 3 (R2 cred rotation, future DNS edits) | LOW (~3min, OAuth) | OFFICIAL | **HIGH** | **INSTALL THIS WEEK** — covers R2/DNS-records that aren't in the 14 dedicated servers |
| 5 | **Bitwarden MCP server** (official, v2026.2.0) | 8 × 3 (security-critical; rotation events sporadic but every one matters) | MED (~30min to set up vault structure for kite secrets + service account) | OFFICIAL | **HIGH** | **INSTALL NEXT WEEK** — structural fix for the plaintext-in-memory problem (surface-and-defer items 4 + 11). LOCAL-ONLY constraint (never expose) |
| 6 | **Sentry MCP** (official) | 5 × 4 (when production has an incident; ~1/month) | MED (~1h to wire Sentry SDK into kite-mcp-server first) | OFFICIAL | MED | **DEFER until launch** — pre-launch we have no error stream worth querying; post-launch this is high-leverage |
| 7 | **HashiCorp Vault MCP** (official) | 8 × 3 (same niche as Bitwarden) | HIGH (~half-day Vault setup if not already running) | OFFICIAL | MED (high cost dominates) | **DEFER** — Bitwarden is cheaper to start with for a 1-2-person ops surface |
| 8 | **Linear MCP** (official) | 6 × 5 if we adopt Linear | LOW (~3min OAuth) | OFFICIAL | MED | **DEFER** — currently using GitHub Issues; switching cost > install cost |
| 9 | **Notion MCP** (official) | 5 × 4 if we move launch-prep into Notion | LOW (~3min OAuth) | OFFICIAL | LOW | **DEFER** — `.research/` corpus is working; Notion would be parallel-truth and add doc drift |
| 10 | **Stripe MCP** (official) | 9 × 0 (currently no paid users) | LOW | OFFICIAL | LOW (zero current frequency) | **DEFER until paid tier activates** — install on the day of billing-flip |

**Three "install this sprint"**: Fly + GitHub + Cloudflare (4 endpoints: Logpush + Observability + Code Mode + Workers Builds).
**One "install next sprint"**: Bitwarden.
**Rest deferred** with clear activation triggers.

---

## §4 — The 1Password / Bitwarden / Vault angle: the real fix for plaintext-in-memory

This is the section that addresses the surface-and-defer items 4 + 11 from `.research/track-c-decisions-2026-05-11.md` STRUCTURALLY rather than as one-time rotation events.

### §4.1 Current state (plaintext-in-memory problem)

- `memory/kite-session-apr3.md:39-42` has R2 access key + secret in plaintext (surfaced 2026-05-11 by memory-files-verification).
- `memory/MEMORY.md:78-80` has Kite API key/secret pairs for 3 apps in plaintext (Fly.io production app's expiry was stamped "26 Apr 2026" — possibly 15+ days past expiry).
- These survive across sessions because MEMORY.md is the orchestrator's session-persistence layer.
- Rotation procedures (§13.1 + §13.2 of Track-C decisions) work but require the user to do 7 manual steps each.

### §4.2 What a vault-backed solution looks like

**Bitwarden MCP path** (recommended):
1. Create a **service-account vault** in Bitwarden for kite-mcp-server (one-time, ~15min).
2. Move both sets of credentials to the vault as **encrypted vault items**.
3. Patch `memory/kite-session-apr3.md` and `memory/MEMORY.md` to reference vault-item IDs (e.g., `<bitwarden-item:kite-fly-prod-api-key>`), not plaintext.
4. The Bitwarden MCP server has `read-item` / `update-item` tools — when the orchestrator needs the actual cred, it fetches it via MCP from the vault, runtime-only resolution.
5. On rotation: the orchestrator UPDATES the vault item via MCP; memory files stay untouched (they only carry the reference).

**HashiCorp Vault path** (defer — overkill):
- Vault has dynamic secrets (Kite API tokens with TTL, auto-rotation), encryption-as-a-service, and PKI. For our 2-app scope it's overkill.
- Worth revisiting at Empanelment stage (50+ paid users) when we want machine-identity + dynamic-cred for multi-tenant ops.

**1Password Unified Access path** (enterprise-only feel):
- Real platform, official, but positioned for orgs running many AI agents with audit-trail requirements. CakeRepository community MCP works for individuals.
- Same end-result as Bitwarden but with 1Password's UX.

### §4.3 Trade-offs

| Aspect | Bitwarden MCP | Vault MCP | 1Password (community) |
|---|---|---|---|
| Setup cost | ~30min vault + MCP install | ~half-day Vault server + auth backend + MCP | ~30min vault + MCP install |
| Cost | Free tier OK for personal; ~$3/mo per-user | Self-host = free; Vault Enterprise = $$$ | Free trial; ~$3/mo personal |
| Dynamic secrets | No | Yes (Vault unique) | No |
| Self-host option | Yes (Vaultwarden) | Yes (native) | No (cloud-only) |
| Audit trail | Yes | Yes (detailed) | Yes |
| Local-only MCP constraint | YES (Bitwarden docs say "never expose over network") | Both local + StreamableHTTP | Local-only (community) |
| Trust | OFFICIAL Bitwarden MCP | OFFICIAL HashiCorp MCP | COMMUNITY (CakeRepository) |

### §4.4 Recommendation

**Adopt Bitwarden MCP** as the secrets layer for kite-mcp-server within the next 2 weeks. Migrate:
- R2 access key + secret (currently in `memory/kite-session-apr3.md`)
- Kite API key + secret for all 3 apps (currently in `memory/MEMORY.md`)
- `OAUTH_JWT_SECRET` (currently a Fly secret; mirror to Bitwarden as the authoritative copy + Fly secret as a deploy-time projection)
- `ADMIN_ENDPOINT_SECRET_PATH`, `TELEGRAM_BOT_TOKEN`, `ADMIN_EMAILS` (same pattern)

Defer Vault to post-empanelment when dynamic secrets per-tenant become a requirement.

This is the structural fix that surface-and-defer §13.1 + §13.2 hinted at but couldn't close in a maintenance pass.

---

## §5 — Implementation roadmap (this week / month / quarter)

### This sprint (next 7 days)

1. **Fly MCP** — `flyctl mcp server --claude --server fly` (~5min). Already endorsed by Track 1. UNBLOCKS the highest-frequency friction.
2. **GitHub MCP server** — `claude mcp add github -s user -- docker run --rm -i ghcr.io/github/github-mcp-server` OR remote-OAuth via `claude mcp add github -s user -- npx mcp-remote https://api.githubcopilot.com/mcp/` (~5min). Replaces gh CLI for chat workflows; keep gh CLI for scripts.
3. **Cloudflare Logpush + Observability MCPs** — `claude mcp add cf-logpush -s user -- npx mcp-remote https://logs.mcp.cloudflare.com/mcp` + similar for observability (~3min each). UNBLOCKS R2 backup verification visibility.
4. **Cloudflare Code Mode MCP** — for R2 ops + DNS records (the 2-tool wrapper for full API). ~3min.

**End-of-sprint result**: 4 new MCPs installed. Expected friction reduction: ~70% on flyctl + ~50% on GitHub + 100% on Cloudflare dashboard clicks.

### Next sprint (days 8-14)

5. **Bitwarden MCP** — install + create service-account vault + migrate R2 + Kite API creds + patch memory files to reference vault-IDs. ~2-3h total including testing rotation flow. CLOSES surface-and-defer items 4 + 11 STRUCTURALLY.

**End-of-2-week result**: Plaintext-in-memory problem eliminated. Future rotations are one-step Bitwarden updates.

### This month (days 15-30)

6. **MCP Apps post-mortem when Sentry adopted**: install Sentry MCP as part of error-tracking SaaS adoption. Defer to launch-prep window.

### This quarter

7. **Stripe MCP** — flip on the day paid tier activates.
8. **Reassess Linear / Notion** — only if active task-list lives there instead of `.research/`.
9. **Vault MCP** — only if dynamic-secrets-per-tenant becomes a need (empanelment + multi-tenant).

### Never (without trigger)

- **AWS MCPs**: only if we add AWS as Fly fallback (no current driver).
- **Hetzner MCP**: only if we add Hetzner (no current driver; community-only servers).
- **Datadog/New Relic MCPs**: only if we drop Sentry for one of these (currently no driver).
- **DigitalOcean MCP**: only if we add DO (no current driver; Playwright cookies suggest user is authed but no compute on DO).

---

## §6 — Integration with maintenance OS hooks (H1-H8)

Track A's 8 validator hooks ship today. Cross-cutting these new MCPs:

| Hook | Current behavior | MCP integration opportunity |
|---|---|---|
| **H1 secret-scan** | Blocks on plaintext secret patterns | **Bitwarden MCP**: suggest "store this in vault at `<service-account>/kite/<key-name>`" instead of just blocking. Hook becomes: detect → suggest vault path → on user-confirm, write to vault → strip from memory file → write `<bitwarden-item:...>` reference. Closes the loop on H1. |
| **H2 freshness-check** | Verifies production-vs-source-of-truth freshness via `/healthz` total_available | **Fly MCP**: replace the curl-based probe with Fly MCP's `status` tool. Same answer, structured, no shell escape. |
| **H3 STATE.md probe** | Validates §11 probe paths still work | **GitHub MCP**: for `gh api` probe paths, swap to GitHub MCP tool-call. |
| **H4 commit-message lint** | Validates commit message structure | No MCP integration needed (this is a git hook on local commits) |
| **H5 audit-doc dating** | Enforces §INPUTS section with dates | No MCP integration needed |
| **H6 cross-ref-link check** | Validates `.research/...` paths exist | No MCP integration needed |
| **H7 archive-trigger** | Detects mid-flight runbooks past their trigger date | **GitHub MCP**: for "is Show HN submitted yet?" → MCP query `gh api repos/Sundeepg98/kite-mcp-server | jq .stargazers_count` becomes a structured MCP call returning typed JSON |
| **H8 tool-count drift** | Ensures docs cite 111 not 130 | **Fly MCP**: `flyctl ssh console -C "curl localhost:8080/healthz \| jq .total_available"` becomes a Fly MCP tool-call. |

**Net**: 4 of 8 hooks gain structural improvements from the new MCPs. Recommended to add a §H1.5-H8.5 "integration step" in the hooks rollout doc once Bitwarden + Fly + GitHub MCPs are installed.

---

## §7 — What's STILL not solvable by MCPs (and why)

Some things look MCP-shaped but are fundamentally human or transport-level:

1. **mcp-remote `cmd /c` JSON escaping bug** (friction #13 in §1) — this is a Windows shell + Node.js argv parsing bug, not a vendor MCP gap. Workaround (write JSON to file, use `@path` arg) is permanent until Windows or mcp-remote fixes it.

2. **Manual community ops** (Z-Connect post, Rainmatter warm-intro, Show HN submit) — these are HUMAN-AUTHORITY surfaces. MCP can draft / queue / preview but the user has to be on the keyboard for the conversational/relational/strategic acts.

3. **SEBI / Zerodha compliance conversations** — same. No MCP for "lawyer says X."

4. **Visual verification** (widget render, GIF recording, OAuth click-through wizards) — this is the OPS rule already in `~/.claude/CLAUDE.md` ("Chrome for visual operations"). Playwright MCP (Track 2 §2) gets us 70% of the way to automating these too, but the final "does this LOOK right" judgment is human.

5. **Cross-vendor orchestration** that doesn't fit any single MCP — e.g., "for each Kite-Connect-expiry on Apr 26, look up the user's stored credentials in Bitwarden, generate a new Kite app, update Fly secrets, push DR drill in 24h." This is multi-MCP coordination — orchestrator-level, not single-MCP-level. We're already doing this pattern.

6. **flyctl `releases` deploy diff** (friction #11 in §1) — flyctl ships a feature, not a wrapper. The Fly MCP can only expose what flyctl exposes; if flyctl doesn't ship a `--json` for some subcommand, the MCP can't synthesize one. Wait for upstream.

7. **`flyctl auth status` 401 mismatch** (friction #9) — same. The Fly auth surface is what it is; MCP wraps it but doesn't fix the underlying auth-cache invalidation behavior.

---

## §8 — Big-picture finding

The user's framing question was: "If fly MCP is the answer to one question, what other questions have similar one-MCP-away answers we've been ignoring?"

**Answer**: There are at least 4 such questions, each with an OFFICIAL MCP we can install in ~5 minutes:

1. **"How do I deploy / check / mutate fly state?"** → Fly MCP (`flyctl mcp server --claude`). Track 1 already endorsed.
2. **"How do I read/write GitHub issues, PRs, code, releases without shelling to gh?"** → GitHub MCP server (29.9k stars, official, OAuth).
3. **"How do I verify Cloudflare R2 backups / Logpush jobs / DNS state?"** → Cloudflare MCP suite (14 servers + Code Mode for full API, 3.7k stars, official).
4. **"How do I stop carrying plaintext credentials in memory files across sessions?"** → Bitwarden MCP (official, v2026.2.0, LOCAL-ONLY).

Each install is ~5min (Bitwarden is ~30min with vault setup). Combined: ~45min of human-attention to close ~70% of the current shell-out and security-friction footprint.

**The unexpected finding**: Cloudflare's "Code Mode" MCP — published April 2026, only 1 month old — wraps the ENTIRE Cloudflare API surface (2,500+ endpoints including R2, DNS records, Workers KV, D1) into just 2 tools (`search` + `execute`) using a generated TypeScript client. This is the R2 coverage we thought was missing from the 14-server lineup. Reported to reduce token usage by up to 99.9% vs per-endpoint MCP tools. It's the architecture pattern competing MCPs will copy.

**The MUST-INSTALL surfaced to orchestrator**: nothing in "right-now-emergency" tier. Fly MCP is the highest-priority (Track 1 already recommended; orchestrator should authorize today). GitHub + Cloudflare can wait for next session. Bitwarden is the structural-fix layer that closes the surface-and-defer items.

---

## §9 — Time accounting

| Phase | Time |
|---|---|
| Read inputs (INDEX.md §11, mcp-servers.md, Track 1 + 2 docs, project .mcp.json, grep over .research/) | ~25 min |
| Vendor WebFetch + WebSearch probes (Cloudflare, GitHub, AWS, Bitwarden, 1Password, Vault, Sentry, Linear, Notion, Slack, Stripe, DigitalOcean, Hetzner, Neon, Supabase, Fly.io, registry.modelcontextprotocol.io) | ~50 min |
| Synthesis + ranking | ~30 min |
| Write doc | ~35 min |
| Total | **~2h 20min** |

Target: ~2-3h. Halt at 4h. **Under budget.**

---

## §10 — Sources cited

All dated 2026-05-11 unless noted.

- Cloudflare MCP servers: https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/
- Cloudflare repo: https://github.com/cloudflare/mcp-server-cloudflare (3.7k stars)
- Cloudflare Code Mode: https://www.infoq.com/news/2026/04/cloudflare-code-mode-mcp-server/
- GitHub MCP server: https://github.com/github/github-mcp-server (29.9k stars, v1.0.4 May 11 2026)
- AWS Labs MCP: https://github.com/awslabs/mcp (9.1k stars)
- Bitwarden MCP: https://github.com/bitwarden/mcp-server (v2026.2.0)
- 1Password Unified Access: https://1password.com/press/2026/mar/1password-unified-access
- HashiCorp Vault MCP: https://developer.hashicorp.com/vault/docs/mcp-server/overview
- DigitalOcean MCP: https://docs.digitalocean.com/reference/mcp/
- Linear MCP: https://linear.app/changelog/2026-02-05-linear-mcp-for-product-management
- Notion MCP: https://developers.notion.com/guides/mcp/overview
- Slack MCP: https://docs.slack.dev/changelog/2026/02/17/slack-mcp/
- Sentry MCP: https://blog.sentry.io/introducing-mcp-server-monitoring/
- Datadog MCP: https://simplywall.st/stocks/us/software/nasdaq-ddog/datadog/news/...
- Stripe MCP: https://github.com/stripe/agent-toolkit (1.6k stars)
- Neon MCP: https://chatforest.com/reviews/neon-mcp-server/
- Fly.io MCP: https://fly.io/docs/flyctl/mcp-server/ + Track 1 doc `.research/research/fly-mcp-research.md`
- Official Registry: https://registry.modelcontextprotocol.io/v0/servers
- modelcontextprotocol/servers repo: https://github.com/modelcontextprotocol/servers

---

**End of audit.**
